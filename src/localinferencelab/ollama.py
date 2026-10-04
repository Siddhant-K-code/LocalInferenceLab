"""Fail-closed prospective Ollama execution and synthetic transport evidence."""

from __future__ import annotations

import errno
import http.client
import ipaddress
import json
import os
import stat
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_json_bytes,
    validate_json_value,
)
from localinferencelab.contracts import (
    ConcurrencyIdentity,
    HostIdentity,
    Measurement,
    ModelIdentity,
    ModelInstance,
    ProcessInstance,
    RunRecord,
    RuntimeIdentity,
    record_id,
)
from localinferencelab.custody import publish_bundle_at, read_closed_bundle

SCHEMA_VERSION = "1.0"
OUTPUT_ROOT_MARKER = ".localinferencelab-output-root.json"
_DIGEST_LENGTH = 71
_GENERATE_FIELDS = {
    "context",
    "created_at",
    "done",
    "done_reason",
    "eval_count",
    "eval_duration",
    "load_duration",
    "model",
    "prompt_eval_cached_count",
    "prompt_eval_count",
    "prompt_eval_duration",
    "response",
    "thinking",
    "total_duration",
}
_IDENTITY_OPERATIONS = ("version", "tags", "show", "ps")
_CACHE_COHORTS = {
    "cold_model_warm_process",
    "cold_process_model",
    "warm_model_cold_prompt_cache",
    "warm_prompt_kv_cache",
}
_ABSENCE_VALUES = {"", "n/a", "none", "not_observed", "unavailable", "unknown", "unobserved"}
_CONTROL_CHARACTER_LIMIT = 32
_MANIFEST_SCHEMA_VERSION = 2
_MILLION = 1_000_000
_ACTION_COUNT = 9
_IDENTITY_ACTION_COUNT = 4
_GENERATION_SEQUENCE = 5
_HTTP_OK = 200
_MAX_AUTHORIZATION_NONCE_BYTES = 1024


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _list(value: JsonValue, label: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return value


def _keys(data: Mapping[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - data.keys()
    extra = data.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ContractError(f"{label} must be a{' non-empty' if not empty else ''} string")
    return value


def _public_text(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    lowered = text.casefold()
    if (
        any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in text)
        or text.startswith(("/", "\\", "~/", "~\\"))
        or "/users/" in lowered
        or "/home/" in lowered
        or "\\users\\" in lowered
        or "file://" in lowered
        or "username=" in lowered
        or "hostname=" in lowered
        or "token=" in lowered
    ):
        raise ContractError(f"{label} contains private or path-like data")
    return text


def _integer(value: JsonValue, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    return value


def _boolean(value: JsonValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _literal(value: JsonValue, allowed: set[str], label: str) -> str:
    text = _text(value, label)
    if text not in allowed:
        raise ContractError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return text


def _sha256(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if len(text) != _DIGEST_LENGTH or not text.startswith("sha256:") or text != text.lower():
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    try:
        int(text[7:], 16)
    except ValueError as error:
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest") from error
    return text


def _canonical_file(path: Path, label: str) -> JsonValue:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ContractError(f"{label} must not be a symlink") from error
        raise
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"{label} must be a regular file")
        blocks: list[bytes] = []
        while block := os.read(descriptor, 1024 * 1024):
            blocks.append(block)
        data = b"".join(blocks)
    finally:
        os.close(descriptor)
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        written = 0
        while written < len(data):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_private_output_root(output_root: Path) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(output_root.absolute(), flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ContractError("output root must be a directory")
    if metadata.st_uid != os.geteuid():
        os.close(descriptor)
        raise ContractError("output root must be owned by the current effective user")
    if metadata.st_mode & 0o022:
        os.close(descriptor)
        raise ContractError("output root must not be group/world writable")
    return descriptor


def _write_exclusive_at(directory_descriptor: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    try:
        view = memoryview(data)
        written = 0
        while written < len(data):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_descriptor)


def _canonical_at(directory_descriptor: int, name: str, label: str) -> JsonValue:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"{label} must be a regular file")
        blocks: list[bytes] = []
        while block := os.read(descriptor, 1024 * 1024):
            blocks.append(block)
        data = b"".join(blocks)
    finally:
        os.close(descriptor)
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def _digest_regular_file(path: Path, label: str) -> tuple[str, int]:
    data = _read_regular_file(path, label)
    return digest_bytes(data), len(data)


def _read_regular_file(path: Path, label: str) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ContractError(f"{label} must not be a symlink") from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{label} must be a regular file")
        blocks: list[bytes] = []
        while block := os.read(descriptor, 1024 * 1024):
            blocks.append(block)
        data = b"".join(blocks)
        if len(data) != metadata.st_size:
            raise ContractError(f"{label} changed while it was read")
        return data
    finally:
        os.close(descriptor)


def read_authorization_nonce(path: Path) -> bytes:
    """Read an owner-only one-shot nonce without following a final symlink."""
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ContractError("authorization nonce file must not be a symlink") from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
            or metadata.st_size < 1
            or metadata.st_size > _MAX_AUTHORIZATION_NONCE_BYTES
        ):
            raise ContractError(
                "authorization nonce file must be an owner-only 1..1024-byte regular file"
            )
        nonce = os.read(descriptor, 1025)
        if len(nonce) != metadata.st_size:
            raise ContractError("authorization nonce file changed while it was read")
        return nonce
    finally:
        os.close(descriptor)


def create_authorization_nonce(path: Path) -> str:
    """Create one owner-only high-entropy authorization nonce without replacement."""
    nonce = os.urandom(32)
    _write_exclusive(path, nonce)
    return digest_bytes(nonce)


def _blob_path(blob_root: Path, digest: str) -> Path:
    return blob_root / digest.replace(":", "-", 1)


@dataclass(frozen=True, slots=True)
class EndpointIdentity:
    """One exact numeric-loopback Ollama HTTP endpoint."""

    scheme: Literal["http"]
    host: Literal["127.0.0.1", "::1"]
    port: int
    version_path: Literal["/api/version"]
    tags_path: Literal["/api/tags"]
    show_path: Literal["/api/show"]
    ps_path: Literal["/api/ps"]
    generate_path: Literal["/api/generate"]

    @classmethod
    def from_value(cls, value: JsonValue) -> EndpointIdentity:
        data = _mapping(value, "endpoint")
        _keys(
            data,
            {
                "scheme",
                "host",
                "port",
                "version_path",
                "tags_path",
                "show_path",
                "ps_path",
                "generate_path",
            },
            "endpoint",
        )
        scheme = _literal(data["scheme"], {"http"}, "endpoint.scheme")
        host = _literal(data["host"], {"127.0.0.1", "::1"}, "endpoint.host")
        paths = {
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        }
        for field, expected in paths.items():
            if data[field] != expected:
                raise ContractError(f"endpoint.{field} must be exactly {expected}")
        return cls(
            cast("Literal['http']", scheme),
            cast("Literal['127.0.0.1', '::1']", host),
            _integer(data["port"], "endpoint.port", minimum=1),
            "/api/version",
            "/api/tags",
            "/api/show",
            "/api/ps",
            "/api/generate",
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "version_path": self.version_path,
            "tags_path": self.tags_path,
            "show_path": self.show_path,
            "ps_path": self.ps_path,
            "generate_path": self.generate_path,
        }

    @property
    def identity(self) -> str:
        return canonical_identity(self.to_dict())


@dataclass(frozen=True, slots=True)
class ModelBlob:
    """One exact config or model layer in an Ollama manifest."""

    media_type: str
    digest: str
    size: int

    @classmethod
    def from_value(cls, value: JsonValue, label: str) -> ModelBlob:
        data = _mapping(value, label)
        _keys(data, {"mediaType", "digest", "size"}, label)
        return cls(
            _public_text(data["mediaType"], f"{label}.mediaType"),
            _sha256(data["digest"], f"{label}.digest"),
            _integer(data["size"], f"{label}.size"),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {"media_type": self.media_type, "digest": self.digest, "size": self.size}


@dataclass(frozen=True, slots=True)
class ModelArtifactClosure:
    """Raw manifest and complete ordered config/layer digest closure."""

    manifest_sha256: str
    manifest_digest: str
    config: ModelBlob
    layers: tuple[ModelBlob, ...]
    closure_sha256: str

    @classmethod
    def from_value(cls, value: JsonValue) -> ModelArtifactClosure:
        data = _mapping(value, "model_artifact")
        _keys(
            data,
            {
                "manifest_sha256",
                "manifest_digest",
                "config",
                "layers",
                "closure_sha256",
            },
            "model_artifact",
        )
        config_data = _mapping(data["config"], "model_artifact.config")
        _keys(config_data, {"media_type", "digest", "size"}, "model_artifact.config")
        config = ModelBlob(
            _public_text(config_data["media_type"], "model_artifact.config.media_type"),
            _sha256(config_data["digest"], "model_artifact.config.digest"),
            _integer(config_data["size"], "model_artifact.config.size"),
        )
        layers: list[ModelBlob] = []
        for index, item in enumerate(_list(data["layers"], "model_artifact.layers")):
            layer_data = _mapping(item, f"model_artifact.layers[{index}]")
            _keys(
                layer_data,
                {"media_type", "digest", "size"},
                f"model_artifact.layers[{index}]",
            )
            layers.append(
                ModelBlob(
                    _public_text(
                        layer_data["media_type"],
                        f"model_artifact.layers[{index}].media_type",
                    ),
                    _sha256(
                        layer_data["digest"],
                        f"model_artifact.layers[{index}].digest",
                    ),
                    _integer(layer_data["size"], f"model_artifact.layers[{index}].size"),
                ),
            )
        if not layers:
            raise ContractError("model_artifact.layers cannot be empty")
        manifest_sha = _sha256(data["manifest_sha256"], "model_artifact.manifest_sha256")
        manifest_digest = _sha256(data["manifest_digest"], "model_artifact.manifest_digest")
        closure = {
            "manifest_sha256": manifest_sha,
            "manifest_digest": manifest_digest,
            "config": config.to_dict(),
            "layers": [layer.to_dict() for layer in layers],
        }
        closure_sha = _sha256(data["closure_sha256"], "model_artifact.closure_sha256")
        if canonical_identity(closure) != closure_sha:
            raise ContractError("model artifact closure digest mismatch")
        return cls(manifest_sha, manifest_digest, config, tuple(layers), closure_sha)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "manifest_sha256": self.manifest_sha256,
            "manifest_digest": self.manifest_digest,
            "config": self.config.to_dict(),
            "layers": [layer.to_dict() for layer in self.layers],
            "closure_sha256": self.closure_sha256,
        }


def inspect_model_artifacts(manifest_path: Path, blob_root: Path) -> ModelArtifactClosure:
    """Hash one preinstalled Ollama manifest and all of its declared local blobs."""
    manifest_bytes = _read_regular_file(manifest_path, "model manifest")
    manifest_value = load_json_bytes(manifest_bytes)
    manifest = _mapping(manifest_value, "ollama_manifest")
    _keys(manifest, {"schemaVersion", "mediaType", "config", "layers"}, "ollama_manifest")
    if manifest["schemaVersion"] != _MANIFEST_SCHEMA_VERSION:
        raise ContractError("Ollama manifest schemaVersion must be 2")
    _public_text(manifest["mediaType"], "ollama_manifest.mediaType")
    config = ModelBlob.from_value(manifest["config"], "ollama_manifest.config")
    layers = tuple(
        ModelBlob.from_value(item, f"ollama_manifest.layers[{index}]")
        for index, item in enumerate(_list(manifest["layers"], "ollama_manifest.layers"))
    )
    if not layers:
        raise ContractError("Ollama manifest must contain at least one model layer")
    blobs = (("config", config),) + tuple(
        (f"layer[{index}]", layer) for index, layer in enumerate(layers)
    )
    config_bytes: bytes | None = None
    for label, blob in blobs:
        blob_path = _blob_path(blob_root, blob.digest)
        blob_bytes = _read_regular_file(blob_path, f"model {label} blob")
        digest = digest_bytes(blob_bytes)
        size = len(blob_bytes)
        if digest != blob.digest or size != blob.size:
            raise ContractError(f"model {label} blob does not match the manifest")
        if label == "config":
            config_bytes = blob_bytes
    if config_bytes is None:
        raise ContractError("Ollama manifest lacks a verified config blob")
    config_value = load_json_bytes(config_bytes)
    config_data = _mapping(config_value, "model_config")
    for field in ("remote_host", "remote_model"):
        if config_data.get(field) not in {None, ""}:
            raise ContractError("remote-backed Ollama model configs are forbidden")
    manifest_sha = digest_bytes(manifest_bytes)
    manifest_digest = digest_bytes(manifest_bytes)
    closure = {
        "manifest_sha256": manifest_sha,
        "manifest_digest": manifest_digest,
        "config": config.to_dict(),
        "layers": [layer.to_dict() for layer in layers],
    }
    return ModelArtifactClosure(
        manifest_sha,
        manifest_digest,
        config,
        layers,
        canonical_identity(closure),
    )


def _millionths(value: int) -> str:
    sign = "-" if value < 0 else ""
    absolute = abs(value)
    whole, remainder = divmod(absolute, _MILLION)
    if remainder == 0:
        return f"{sign}{whole}"
    return f"{sign}{whole}.{remainder:06d}".rstrip("0")


def _json_string(value: str) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


def build_generate_request(
    *,
    model_name: str,
    prompt: bytes,
    think_mode: str,
    seed: int,
    temperature_millionths: int,
    top_p_millionths: int,
    top_k: int,
    min_p_millionths: int,
    repeat_penalty_millionths: int,
    context_tokens: int,
    max_output_tokens: int,
    keep_alive_seconds: int,
) -> bytes:
    """Build the exact closed-allowlist /api/generate request bytes."""
    try:
        prompt_text = prompt.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError("Ollama prompt bytes must be valid UTF-8") from error
    if think_mode not in {"false", "true", "omitted_unsupported"}:
        raise ContractError("think_mode is not supported")
    fields = [
        b'"keep_alive":' + str(keep_alive_seconds).encode(),
        b'"model":' + _json_string(model_name),
        b'"options":{'
        b'"min_p":'
        + _millionths(min_p_millionths).encode()
        + b',"num_ctx":'
        + str(context_tokens).encode()
        + b',"num_predict":'
        + str(max_output_tokens).encode()
        + b',"repeat_penalty":'
        + _millionths(repeat_penalty_millionths).encode()
        + b',"seed":'
        + str(seed).encode()
        + b',"temperature":'
        + _millionths(temperature_millionths).encode()
        + b',"top_k":'
        + str(top_k).encode()
        + b',"top_p":'
        + _millionths(top_p_millionths).encode()
        + b"}",
        b'"prompt":' + _json_string(prompt_text),
        b'"raw":true',
        b'"shift":false',
        b'"stream":false',
        b'"truncate":false',
    ]
    if think_mode != "omitted_unsupported":
        fields.append(b'"think":' + (b"true" if think_mode == "true" else b"false"))
    fields.sort()
    request = b"{" + b",".join(fields) + b"}"
    parsed = json.loads(request)
    if not isinstance(parsed, dict) or set(parsed) - {
        "keep_alive",
        "model",
        "options",
        "prompt",
        "raw",
        "shift",
        "stream",
        "think",
        "truncate",
    }:
        raise ContractError("trusted Ollama request construction failed")
    return request


def _canonical_model_name(model_name: str) -> str:
    if not model_name.endswith(":local"):
        raise ContractError("Ollama model names must carry the explicit :local suffix")
    local_name = model_name.removesuffix(":local")
    if (
        not local_name
        or local_name.endswith(":")
        or any(character.isspace() for character in local_name)
    ):
        raise ContractError("Ollama local model name is not canonical")
    final_component = local_name.rsplit("/", 1)[-1]
    return local_name if ":" in final_component else f"{local_name}:latest"


def initialize_output_root(
    output_root: Path,
    nonce: str,
    *,
    synthetic_fixture: bool = False,
) -> str:
    """Create a no-clobber privacy-safe output-root binding marker."""
    nonce_text = _public_text(nonce, "output root nonce")
    descriptor = _open_private_output_root(output_root)
    try:
        metadata = os.fstat(descriptor)
        marker: dict[str, JsonValue] = {
            "record_type": "ollama_output_root_binding",
            "schema_version": SCHEMA_VERSION,
            "binding_mode": ("synthetic_fixture" if synthetic_fixture else "physical_instance"),
            "owner_uid": 0 if synthetic_fixture else metadata.st_uid,
            "device": 0 if synthetic_fixture else metadata.st_dev,
            "inode": 0 if synthetic_fixture else metadata.st_ino,
            "nonce_sha256": digest_bytes(nonce_text.encode()),
        }
        _write_exclusive_at(descriptor, OUTPUT_ROOT_MARKER, canonical_json(marker))
        return canonical_identity(marker)
    finally:
        os.close(descriptor)


def _output_root_marker_at(descriptor: int) -> dict[str, JsonValue]:
    marker = _mapping(
        _canonical_at(descriptor, OUTPUT_ROOT_MARKER, "output-root marker"),
        "output_root_marker",
    )
    _keys(
        marker,
        {
            "record_type",
            "schema_version",
            "binding_mode",
            "owner_uid",
            "device",
            "inode",
            "nonce_sha256",
        },
        "output_root_marker",
    )
    if (
        marker["record_type"] != "ollama_output_root_binding"
        or marker["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported output-root marker")
    mode = _literal(
        marker["binding_mode"],
        {"physical_instance", "synthetic_fixture"},
        "output_root_marker.binding_mode",
    )
    owner = _integer(marker["owner_uid"], "output_root_marker.owner_uid")
    device = _integer(marker["device"], "output_root_marker.device")
    inode = _integer(marker["inode"], "output_root_marker.inode")
    metadata = os.fstat(descriptor)
    if mode == "physical_instance":
        if (owner, device, inode) != (metadata.st_uid, metadata.st_dev, metadata.st_ino):
            raise ContractError("output-root marker does not bind this directory instance")
    elif (owner, device, inode) != (0, 0, 0):
        raise ContractError("synthetic output-root marker has physical identity fields")
    _sha256(marker["nonce_sha256"], "output_root_marker.nonce_sha256")
    return marker


def _output_root_identity_at(descriptor: int) -> str:
    return canonical_identity(_output_root_marker_at(descriptor))


def output_root_identity(output_root: Path) -> str:
    """Read and validate an existing output-root binding marker."""
    descriptor = _open_private_output_root(output_root)
    try:
        return _output_root_identity_at(descriptor)
    finally:
        os.close(descriptor)


def _runtime_fact(runtime: RuntimeIdentity, name: str) -> str:
    value = next((fact.value for fact in runtime.capability_facts if fact.name == name), None)
    if value is None or value.strip().casefold() in _ABSENCE_VALUES:
        raise ContractError(f"runtime identity lacks observed {name} evidence")
    return value


def _record_from_embedded(value: JsonValue, kind: str) -> object:
    data = _mapping(value, kind)
    loaders = {
        "runtime": RuntimeIdentity.from_dict,
        "model": ModelIdentity.from_dict,
        "host": HostIdentity.from_dict,
    }
    return loaders[kind](data)


def _validate_show_projection(value: JsonValue) -> dict[str, JsonValue]:
    data = _mapping(value, "show_projection")
    expected = {
        "modelfile_sha256",
        "parameters_sha256",
        "template_sha256",
        "details_sha256",
        "model_info_sha256",
        "thinking_sha256",
    }
    _keys(data, expected, "show_projection")
    return {key: _sha256(data[key], f"show_projection.{key}") for key in sorted(expected)}


def _sampler_from_spec(value: JsonValue) -> dict[str, int]:
    data = _mapping(value, "study_spec.sampler")
    fields = {
        "seed",
        "temperature_millionths",
        "top_p_millionths",
        "top_k",
        "min_p_millionths",
        "repeat_penalty_millionths",
    }
    _keys(data, fields, "study_spec.sampler")
    output = {
        "seed": _integer(data["seed"], "study_spec.sampler.seed", minimum=-1),
        "temperature_millionths": _integer(
            data["temperature_millionths"],
            "study_spec.sampler.temperature_millionths",
        ),
        "top_p_millionths": _integer(
            data["top_p_millionths"],
            "study_spec.sampler.top_p_millionths",
        ),
        "top_k": _integer(data["top_k"], "study_spec.sampler.top_k"),
        "min_p_millionths": _integer(
            data["min_p_millionths"],
            "study_spec.sampler.min_p_millionths",
        ),
        "repeat_penalty_millionths": _integer(
            data["repeat_penalty_millionths"],
            "study_spec.sampler.repeat_penalty_millionths",
        ),
    }
    if output["top_p_millionths"] > _MILLION or output["min_p_millionths"] > _MILLION:
        raise ContractError("Ollama probability controls cannot exceed 1.0")
    return output


def _action(
    sequence: int,
    phase: str,
    operation: str,
    method: str,
    path: str,
    request: bytes,
    max_response_bytes: int,
) -> dict[str, JsonValue]:
    return {
        "sequence": sequence,
        "phase": phase,
        "operation": operation,
        "method": method,
        "path": path,
        "request_sha256": digest_bytes(request),
        "request_size_bytes": len(request),
        "max_response_bytes": max_response_bytes,
        "response_read_budget_bytes": max_response_bytes + 1,
    }


def build_prospective_package(
    spec_value: JsonValue,
    *,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
) -> dict[str, JsonValue]:
    """Construct a frozen prospective package without opening a socket or running a model."""
    spec = _mapping(spec_value, "study_spec")
    fields = {
        "record_type",
        "schema_version",
        "study_name",
        "run_id",
        "endpoint",
        "runtime",
        "model",
        "host",
        "model_name",
        "prompt_base64",
        "prompt_sha256",
        "template_sha256",
        "raw_mode",
        "think_mode",
        "sampler",
        "context_tokens",
        "max_output_tokens",
        "keep_alive_seconds",
        "cache_cohort",
        "cache_support",
        "cache_evidence_sha256",
        "show_projection",
        "process_instance_label",
        "model_instance_label",
        "timeout_ms",
        "max_identity_response_bytes",
        "max_generate_response_bytes",
        "output_root_id",
        "authorization_nonce_sha256",
        "disposition",
    }
    _keys(spec, fields, "study_spec")
    if spec["record_type"] != "ollama_study_spec" or spec["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported Ollama study specification")
    endpoint = EndpointIdentity.from_value(spec["endpoint"])
    runtime = cast("RuntimeIdentity", _record_from_embedded(spec["runtime"], "runtime"))
    model = cast("ModelIdentity", _record_from_embedded(spec["model"], "model"))
    host = cast("HostIdentity", _record_from_embedded(spec["host"], "host"))
    if (
        runtime.backend != "ollama"
        or runtime.evidence_kind != "observed_execution"
        or not runtime.identity_complete
    ):
        raise ContractError("Ollama package requires a complete observed runtime identity")
    if model.backend != "ollama" or model.evidence_kind != "observed_execution":
        raise ContractError("Ollama package requires an observed Ollama model identity")
    if host.evidence_kind != "safe_host_probe":
        raise ContractError("Ollama package requires a safe observed host identity")
    runtime_digest, _runtime_size = _digest_regular_file(runtime_artifact, "runtime artifact")
    if runtime.artifact_sha256 != runtime_digest:
        raise ContractError("runtime artifact digest does not match the runtime identity")
    model_artifact = inspect_model_artifacts(model_manifest, blob_root)
    if (
        model.manifest_sha256 != model_artifact.manifest_sha256
        or model.config_sha256 != model_artifact.config.digest
        or model.metadata_sha256 != model_artifact.closure_sha256
    ):
        raise ContractError("model identity does not match the local manifest closure")
    prompt_base64 = _text(spec["prompt_base64"], "study_spec.prompt_base64", empty=True)
    prompt = decode_bytes(prompt_base64)
    prompt_sha = _sha256(spec["prompt_sha256"], "study_spec.prompt_sha256")
    if digest_bytes(prompt) != prompt_sha:
        raise ContractError("study prompt digest does not match prompt bytes")
    if spec["raw_mode"] is not True:
        raise ContractError("the Ollama runner currently requires pinned raw_mode=true")
    sampler = _sampler_from_spec(spec["sampler"])
    think_mode = _literal(
        spec["think_mode"],
        {"false", "true", "omitted_unsupported"},
        "study_spec.think_mode",
    )
    context_tokens = _integer(spec["context_tokens"], "study_spec.context_tokens", minimum=1)
    max_output_tokens = _integer(
        spec["max_output_tokens"],
        "study_spec.max_output_tokens",
        minimum=1,
    )
    keep_alive = _integer(spec["keep_alive_seconds"], "study_spec.keep_alive_seconds")
    model_name = _public_text(spec["model_name"], "study_spec.model_name")
    canonical_model_name = _canonical_model_name(model_name)
    request = build_generate_request(
        model_name=model_name,
        prompt=prompt,
        think_mode=think_mode,
        context_tokens=context_tokens,
        max_output_tokens=max_output_tokens,
        keep_alive_seconds=keep_alive,
        **sampler,
    )
    show_request = b'{"model":' + _json_string(model_name) + b"}"
    identity_limit = _integer(
        spec["max_identity_response_bytes"],
        "study_spec.max_identity_response_bytes",
        minimum=1,
    )
    generate_limit = _integer(
        spec["max_generate_response_bytes"],
        "study_spec.max_generate_response_bytes",
        minimum=1,
    )
    timeout_ms = _integer(spec["timeout_ms"], "study_spec.timeout_ms", minimum=1)
    cache_cohort = _literal(spec["cache_cohort"], _CACHE_COHORTS, "study_spec.cache_cohort")
    cache_support = _literal(
        spec["cache_support"],
        {"supported", "unsupported"},
        "study_spec.cache_support",
    )
    cache_evidence = _sha256(
        spec["cache_evidence_sha256"],
        "study_spec.cache_evidence_sha256",
    )
    if cache_support == "supported" and (
        cache_cohort != "cold_model_warm_process" or keep_alive != 0
    ):
        raise ContractError(
            "only cold_model_warm_process with keep_alive=0 is mechanically supported"
        )
    runner = _runtime_fact(runtime, "runner")
    metal = _runtime_fact(runtime, "metal")
    host_id = record_id(host)
    runtime_id = record_id(runtime)
    model_id = record_id(model)
    process = ProcessInstance.from_dict(
        {
            "record_type": "process_instance",
            "schema_version": "1.0",
            "backend": "ollama",
            "runtime_id": runtime_id,
            "host_id": host_id,
            "evidence_kind": "observed_execution",
            "instance_label": _public_text(
                spec["process_instance_label"],
                "study_spec.process_instance_label",
            ),
            "max_concurrency": 1,
        },
    )
    process_id = record_id(process)
    model_instance = ModelInstance.from_dict(
        {
            "record_type": "model_instance",
            "schema_version": "1.0",
            "backend": "ollama",
            "process_instance_id": process_id,
            "model_id": model_id,
            "evidence_kind": "observed_execution",
            "instance_label": _public_text(
                spec["model_instance_label"],
                "study_spec.model_instance_label",
            ),
            "context_tokens": context_tokens,
            "batch_size": 1,
            "gpu_layers": None,
        },
    )
    model_instance_id = record_id(model_instance)
    concurrency = ConcurrencyIdentity.from_dict(
        {
            "record_type": "concurrency_identity",
            "schema_version": "1.0",
            "max_concurrency": 1,
            "active_peers": 0,
            "worker_slot": 0,
            "scheduling_policy": "serial",
            "peer_request_sha256": [],
        },
    )
    concurrency_id = record_id(concurrency)
    cache_contract: dict[str, JsonValue] = {
        "record_type": "ollama_cache_contract",
        "schema_version": SCHEMA_VERSION,
        "model_instance_id": model_instance_id,
        "cache_cohort": cache_cohort,
        "support_status": cache_support,
        "keep_alive_seconds": keep_alive,
        "context_shift_policy": "forbid_by_context_and_output_bounds",
        "prompt_cache_policy": (
            "model_absent_before_and_after"
            if cache_cohort == "cold_model_warm_process"
            else "unobservable_refuse"
        ),
        "prompt_cache_evidence_sha256": cache_evidence,
        "warmup_request_sha256": [],
        "selected_runner": runner,
        "metal_state": metal,
        "expected_pre_loaded": False,
        "expected_post_loaded": False,
    }
    cache_id = canonical_identity(cache_contract)
    request_sha = digest_bytes(request)
    protocol: dict[str, JsonValue] = {
        "record_type": "ollama_protocol",
        "schema_version": SCHEMA_VERSION,
        "study_name": _public_text(spec["study_name"], "study_spec.study_name"),
        "run_id": _public_text(spec["run_id"], "study_spec.run_id"),
        "canonical_model_name": canonical_model_name,
        "endpoint_id": endpoint.identity,
        "runtime_id": runtime_id,
        "model_id": model_id,
        "host_id": host_id,
        "process_instance_id": process_id,
        "model_instance_id": model_instance_id,
        "cache_contract_id": cache_id,
        "concurrency_id": concurrency_id,
        "prompt_base64": prompt_base64,
        "prompt_sha256": prompt_sha,
        "template_sha256": _sha256(
            spec["template_sha256"],
            "study_spec.template_sha256",
        ),
        "raw_mode": True,
        "think_mode": think_mode,
        "sampler": cast("dict[str, JsonValue]", sampler),
        "context_tokens": context_tokens,
        "max_output_tokens": max_output_tokens,
        "keep_alive_seconds": keep_alive,
        "timeout_ms": timeout_ms,
        "retry_count": 0,
        "request_base64": encode_bytes(request),
        "request_sha256": request_sha,
        "exact_schedule": [
            {
                "sequence": 1,
                "run_id": _public_text(spec["run_id"], "study_spec.run_id"),
                "request_sha256": request_sha,
                "concurrency_wave": 1,
            },
        ],
    }
    protocol_id = canonical_identity(protocol)
    actions = [
        _action(1, "pre_identity", "version", "GET", endpoint.version_path, b"", identity_limit),
        _action(2, "pre_identity", "tags", "GET", endpoint.tags_path, b"", identity_limit),
        _action(
            3,
            "pre_identity",
            "show",
            "POST",
            endpoint.show_path,
            show_request,
            identity_limit,
        ),
        _action(4, "pre_identity", "ps", "GET", endpoint.ps_path, b"", identity_limit),
        _action(
            5,
            "generation",
            "generate",
            "POST",
            endpoint.generate_path,
            request,
            generate_limit,
        ),
        _action(6, "post_identity", "version", "GET", endpoint.version_path, b"", identity_limit),
        _action(7, "post_identity", "tags", "GET", endpoint.tags_path, b"", identity_limit),
        _action(
            8,
            "post_identity",
            "show",
            "POST",
            endpoint.show_path,
            show_request,
            identity_limit,
        ),
        _action(9, "post_identity", "ps", "GET", endpoint.ps_path, b"", identity_limit),
    ]
    disposition = _literal(
        spec["disposition"],
        {"authorized", "model_execution_forbidden"},
        "study_spec.disposition",
    )
    output_root_id = _sha256(spec["output_root_id"], "study_spec.output_root_id")
    authorization_nonces = _mapping(
        spec["authorization_nonce_sha256"],
        "study_spec.authorization_nonce_sha256",
    )
    _keys(
        authorization_nonces,
        {"preflight_only", "identity_guard", "generation"},
        "study_spec.authorization_nonce_sha256",
    )
    authorization_nonce_sha256 = {
        phase: _sha256(
            authorization_nonces[phase],
            f"study_spec.authorization_nonce_sha256.{phase}",
        )
        for phase in ("preflight_only", "identity_guard", "generation")
    }
    if len(set(authorization_nonce_sha256.values())) != len(authorization_nonce_sha256):
        raise ContractError("authorization nonce commitments must be pairwise distinct")
    authorized = disposition == "authorized"
    if authorized and cache_support != "supported":
        raise ContractError("authorized execution requires a mechanically supported cache contract")
    request_bytes = 2 * len(show_request) + len(request)
    declaration: dict[str, JsonValue] = {
        "record_type": "ollama_execution_declaration",
        "schema_version": SCHEMA_VERSION,
        "disposition": disposition,
        "protocol_id": protocol_id,
        "endpoint_id": endpoint.identity,
        "runtime_id": runtime_id,
        "model_id": model_id,
        "host_id": host_id,
        "process_instance_id": process_id,
        "model_instance_id": model_instance_id,
        "cache_contract_id": cache_id,
        "concurrency_id": concurrency_id,
        "output_root_id": output_root_id,
        "authorization_nonce_sha256": cast("dict[str, JsonValue]", authorization_nonce_sha256),
        "action_budget": {
            "model_process_starts": 0,
            "identity_requests": 8 if authorized else 0,
            "inference_requests": 1 if authorized else 0,
            "network_requests": 9 if authorized else 0,
            "total_request_bytes": request_bytes if authorized else 0,
            "total_response_bytes": (
                8 * (identity_limit + 1) + generate_limit + 1 if authorized else 0
            ),
            "per_request_timeout_ms": timeout_ms if authorized else 0,
            "retries": 0,
            "downloads": 0,
        },
    }
    declaration_id = canonical_identity(declaration)
    eligibility: dict[str, JsonValue] = {
        "record_type": "ollama_eligibility",
        "schema_version": SCHEMA_VERSION,
        "decision": "eligible" if authorized else "model_execution_forbidden",
        "declaration_id": declaration_id,
        "protocol_id": protocol_id,
        "endpoint_id": endpoint.identity,
        "runtime_id": runtime_id,
        "model_id": model_id,
        "host_id": host_id,
        "cache_contract_id": cache_id,
        "allowed_actions": (
            ["identity_request", "inference_request", "loopback_network_request"]
            if authorized
            else []
        ),
        "reasons": (
            ["exact identities, schedule, cache evidence, output root, and budgets are frozen"]
            if authorized
            else ["execution disposition is model_execution_forbidden"]
        ),
    }
    package: dict[str, JsonValue] = {
        "record_type": "ollama_prospective_package",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "prospective_not_execution_evidence",
        "endpoint": endpoint.to_dict(),
        "runtime": runtime.to_dict(),
        "model": model.to_dict(),
        "model_artifact": model_artifact.to_dict(),
        "host": host.to_dict(),
        "process": process.to_dict(),
        "model_instance": model_instance.to_dict(),
        "cache_contract": cache_contract,
        "concurrency": concurrency.to_dict(),
        "show_projection": _validate_show_projection(spec["show_projection"]),
        "protocol": protocol,
        "declaration": declaration,
        "eligibility": eligibility,
        "action_schedule": cast("list[JsonValue]", actions),
    }
    return verify_prospective_package(package).value


@dataclass(frozen=True, slots=True)
class VerifiedPackage:
    """Parsed immutable package plus frequently used identities and bytes."""

    value: dict[str, JsonValue]
    identity: str
    endpoint: EndpointIdentity
    runtime: RuntimeIdentity
    model: ModelIdentity
    host: HostIdentity
    model_artifact: ModelArtifactClosure
    request: bytes
    show_request: bytes
    protocol_id: str
    declaration_id: str
    output_root_id: str
    model_name: str
    canonical_model_name: str
    actions: tuple[dict[str, JsonValue], ...]


def verify_prospective_package(value: JsonValue) -> VerifiedPackage:
    """Strictly verify every linkage and derived byte field in a package."""
    package = _mapping(value, "ollama_package")
    fields = {
        "record_type",
        "schema_version",
        "evidence_status",
        "endpoint",
        "runtime",
        "model",
        "model_artifact",
        "host",
        "process",
        "model_instance",
        "cache_contract",
        "concurrency",
        "show_projection",
        "protocol",
        "declaration",
        "eligibility",
        "action_schedule",
    }
    _keys(package, fields, "ollama_package")
    if (
        package["record_type"] != "ollama_prospective_package"
        or package["schema_version"] != SCHEMA_VERSION
        or package["evidence_status"] != "prospective_not_execution_evidence"
    ):
        raise ContractError("unsupported prospective Ollama package")
    endpoint = EndpointIdentity.from_value(package["endpoint"])
    runtime = RuntimeIdentity.from_dict(_mapping(package["runtime"], "ollama_package.runtime"))
    model = ModelIdentity.from_dict(_mapping(package["model"], "ollama_package.model"))
    host = HostIdentity.from_dict(_mapping(package["host"], "ollama_package.host"))
    artifact = ModelArtifactClosure.from_value(package["model_artifact"])
    if (
        runtime.backend != "ollama"
        or runtime.evidence_kind != "observed_execution"
        or not runtime.identity_complete
        or model.backend != "ollama"
        or model.evidence_kind != "observed_execution"
        or host.evidence_kind != "safe_host_probe"
    ):
        raise ContractError("Ollama package contains incomplete or non-observed identities")
    if (
        model.manifest_sha256 != artifact.manifest_sha256
        or model.config_sha256 != artifact.config.digest
        or model.metadata_sha256 != artifact.closure_sha256
    ):
        raise ContractError("Ollama package model identity does not match its artifact closure")
    process = ProcessInstance.from_dict(_mapping(package["process"], "ollama_package.process"))
    model_instance = ModelInstance.from_dict(
        _mapping(package["model_instance"], "ollama_package.model_instance"),
    )
    concurrency = ConcurrencyIdentity.from_dict(
        _mapping(package["concurrency"], "ollama_package.concurrency"),
    )
    cache = _mapping(package["cache_contract"], "ollama_package.cache_contract")
    _keys(
        cache,
        {
            "record_type",
            "schema_version",
            "model_instance_id",
            "cache_cohort",
            "support_status",
            "keep_alive_seconds",
            "context_shift_policy",
            "prompt_cache_policy",
            "prompt_cache_evidence_sha256",
            "warmup_request_sha256",
            "selected_runner",
            "metal_state",
            "expected_pre_loaded",
            "expected_post_loaded",
        },
        "ollama_package.cache_contract",
    )
    if cache["record_type"] != "ollama_cache_contract" or cache["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported Ollama cache contract")
    cache_cohort = _literal(
        cache["cache_cohort"],
        _CACHE_COHORTS,
        "ollama_package.cache_contract.cache_cohort",
    )
    support = _literal(
        cache["support_status"],
        {"supported", "unsupported"},
        "ollama_package.cache_contract.support_status",
    )
    keep_alive = _integer(
        cache["keep_alive_seconds"],
        "ollama_package.cache_contract.keep_alive_seconds",
    )
    _sha256(
        cache["prompt_cache_evidence_sha256"],
        "ollama_package.cache_contract.prompt_cache_evidence_sha256",
    )
    if _list(cache["warmup_request_sha256"], "cache_contract.warmup_request_sha256"):
        raise ContractError("current Ollama cache contract does not permit hidden warm-up requests")
    if support == "supported" and (
        cache_cohort != "cold_model_warm_process"
        or keep_alive != 0
        or cache["prompt_cache_policy"] != "model_absent_before_and_after"
        or cache["expected_pre_loaded"] is not False
        or cache["expected_post_loaded"] is not False
    ):
        raise ContractError("Ollama cache support claim is not mechanically established")
    if cache["selected_runner"] != _runtime_fact(runtime, "runner"):
        raise ContractError("cache contract selected runner identity drift")
    if cache["metal_state"] != _runtime_fact(runtime, "metal"):
        raise ContractError("cache contract Metal identity drift")
    _validate_show_projection(package["show_projection"])
    protocol = _mapping(package["protocol"], "ollama_package.protocol")
    protocol_fields = {
        "record_type",
        "schema_version",
        "study_name",
        "run_id",
        "canonical_model_name",
        "endpoint_id",
        "runtime_id",
        "model_id",
        "host_id",
        "process_instance_id",
        "model_instance_id",
        "cache_contract_id",
        "concurrency_id",
        "prompt_base64",
        "prompt_sha256",
        "template_sha256",
        "raw_mode",
        "think_mode",
        "sampler",
        "context_tokens",
        "max_output_tokens",
        "keep_alive_seconds",
        "timeout_ms",
        "retry_count",
        "request_base64",
        "request_sha256",
        "exact_schedule",
    }
    _keys(protocol, protocol_fields, "ollama_package.protocol")
    if protocol["record_type"] != "ollama_protocol" or protocol["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported Ollama protocol")
    if protocol["raw_mode"] is not True or protocol["retry_count"] != 0:
        raise ContractError("Ollama protocol requires raw mode and zero retries")
    _sha256(protocol["template_sha256"], "protocol.template_sha256")
    prompt = decode_bytes(_text(protocol["prompt_base64"], "protocol.prompt_base64", empty=True))
    if digest_bytes(prompt) != _sha256(protocol["prompt_sha256"], "protocol.prompt_sha256"):
        raise ContractError("Ollama protocol prompt digest mismatch")
    sampler = _sampler_from_spec(protocol["sampler"])
    request_value = validate_json_value(
        json.loads(
            decode_bytes(_text(protocol["request_base64"], "protocol.request_base64")),
        ),
    )
    request_mapping = _mapping(request_value, "request")
    request = build_generate_request(
        model_name=_public_text(request_mapping["model"], "request.model"),
        prompt=prompt,
        think_mode=_literal(
            protocol["think_mode"],
            {"false", "true", "omitted_unsupported"},
            "protocol.think_mode",
        ),
        context_tokens=_integer(protocol["context_tokens"], "protocol.context_tokens", minimum=1),
        max_output_tokens=_integer(
            protocol["max_output_tokens"],
            "protocol.max_output_tokens",
            minimum=1,
        ),
        keep_alive_seconds=_integer(
            protocol["keep_alive_seconds"],
            "protocol.keep_alive_seconds",
        ),
        **sampler,
    )
    stored_request = decode_bytes(
        _text(protocol["request_base64"], "protocol.request_base64", empty=True),
    )
    if request != stored_request or digest_bytes(request) != _sha256(
        protocol["request_sha256"],
        "protocol.request_sha256",
    ):
        raise ContractError("Ollama protocol request-body bytes drifted")
    request_object = json.loads(request)
    model_name = cast("str", request_object["model"])
    if not model_name.endswith(":local"):
        raise ContractError("Ollama request model must retain the explicit :local suffix")
    canonical_model_name = _public_text(
        protocol["canonical_model_name"],
        "protocol.canonical_model_name",
    )
    if canonical_model_name != _canonical_model_name(model_name):
        raise ContractError("Ollama canonical model name is not derived from request.model")
    show_request = b'{"model":' + _json_string(model_name) + b"}"
    runtime_id = record_id(runtime)
    model_id = record_id(model)
    host_id = record_id(host)
    process_id = record_id(process)
    model_instance_id = record_id(model_instance)
    concurrency_id = record_id(concurrency)
    cache_id = canonical_identity(cache)
    expected_links = {
        "endpoint_id": endpoint.identity,
        "runtime_id": runtime_id,
        "model_id": model_id,
        "host_id": host_id,
        "process_instance_id": process_id,
        "model_instance_id": model_instance_id,
        "cache_contract_id": cache_id,
        "concurrency_id": concurrency_id,
    }
    if any(protocol[key] != expected for key, expected in expected_links.items()):
        raise ContractError("Ollama protocol identity linkage drift")
    if (
        process.runtime_id != runtime_id
        or process.host_id != host_id
        or model_instance.process_instance_id != process_id
        or model_instance.model_id != model_id
        or cache["model_instance_id"] != model_instance_id
        or model_instance.context_tokens != protocol["context_tokens"]
        or cache["keep_alive_seconds"] != protocol["keep_alive_seconds"]
        or concurrency.max_concurrency != 1
    ):
        raise ContractError("Ollama process/model/cache/concurrency state drift")
    schedule = _list(protocol["exact_schedule"], "protocol.exact_schedule")
    if schedule != [
        {
            "sequence": 1,
            "run_id": protocol["run_id"],
            "request_sha256": protocol["request_sha256"],
            "concurrency_wave": 1,
        },
    ]:
        raise ContractError("Ollama protocol must contain one exact scheduled run")
    protocol_id = canonical_identity(protocol)
    declaration = _mapping(package["declaration"], "ollama_package.declaration")
    declaration_fields = {
        "record_type",
        "schema_version",
        "disposition",
        "protocol_id",
        "endpoint_id",
        "runtime_id",
        "model_id",
        "host_id",
        "process_instance_id",
        "model_instance_id",
        "cache_contract_id",
        "concurrency_id",
        "output_root_id",
        "authorization_nonce_sha256",
        "action_budget",
    }
    _keys(declaration, declaration_fields, "ollama_package.declaration")
    if (
        declaration["record_type"] != "ollama_execution_declaration"
        or declaration["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported Ollama execution declaration")
    disposition = _literal(
        declaration["disposition"],
        {"authorized", "model_execution_forbidden"},
        "declaration.disposition",
    )
    declaration_links = {"protocol_id": protocol_id, **expected_links}
    if any(declaration[key] != expected for key, expected in declaration_links.items()):
        raise ContractError("Ollama declaration identity linkage drift")
    output_root_id = _sha256(declaration["output_root_id"], "declaration.output_root_id")
    authorization_nonces = _mapping(
        declaration["authorization_nonce_sha256"],
        "declaration.authorization_nonce_sha256",
    )
    _keys(
        authorization_nonces,
        {"preflight_only", "identity_guard", "generation"},
        "declaration.authorization_nonce_sha256",
    )
    for phase, nonce_sha256 in authorization_nonces.items():
        _sha256(nonce_sha256, f"declaration.authorization_nonce_sha256.{phase}")
    if len(set(authorization_nonces.values())) != len(authorization_nonces):
        raise ContractError("authorization nonce commitments must be pairwise distinct")
    budget = _mapping(declaration["action_budget"], "declaration.action_budget")
    budget_fields = {
        "model_process_starts",
        "identity_requests",
        "inference_requests",
        "network_requests",
        "total_request_bytes",
        "total_response_bytes",
        "per_request_timeout_ms",
        "retries",
        "downloads",
    }
    _keys(budget, budget_fields, "declaration.action_budget")
    actions = tuple(
        _mapping(item, f"action_schedule[{index}]")
        for index, item in enumerate(
            _list(package["action_schedule"], "ollama_package.action_schedule"),
        )
    )
    if len(actions) != _ACTION_COUNT:
        raise ContractError("Ollama action schedule must contain exactly nine ordered calls")
    for index, action in enumerate(actions, start=1):
        _keys(
            action,
            {
                "sequence",
                "phase",
                "operation",
                "method",
                "path",
                "request_sha256",
                "request_size_bytes",
                "max_response_bytes",
                "response_read_budget_bytes",
            },
            f"action_schedule[{index - 1}]",
        )
        if action["sequence"] != index:
            raise ContractError("Ollama action schedule must be ordered and contiguous")
    expected_actions = [
        _action(
            1,
            "pre_identity",
            "version",
            "GET",
            endpoint.version_path,
            b"",
            cast("int", actions[0]["max_response_bytes"]),
        ),
        _action(
            2,
            "pre_identity",
            "tags",
            "GET",
            endpoint.tags_path,
            b"",
            cast("int", actions[1]["max_response_bytes"]),
        ),
        _action(
            3,
            "pre_identity",
            "show",
            "POST",
            endpoint.show_path,
            show_request,
            cast("int", actions[2]["max_response_bytes"]),
        ),
        _action(
            4,
            "pre_identity",
            "ps",
            "GET",
            endpoint.ps_path,
            b"",
            cast("int", actions[3]["max_response_bytes"]),
        ),
        _action(
            5,
            "generation",
            "generate",
            "POST",
            endpoint.generate_path,
            request,
            cast("int", actions[4]["max_response_bytes"]),
        ),
        _action(
            6,
            "post_identity",
            "version",
            "GET",
            endpoint.version_path,
            b"",
            cast("int", actions[5]["max_response_bytes"]),
        ),
        _action(
            7,
            "post_identity",
            "tags",
            "GET",
            endpoint.tags_path,
            b"",
            cast("int", actions[6]["max_response_bytes"]),
        ),
        _action(
            8,
            "post_identity",
            "show",
            "POST",
            endpoint.show_path,
            show_request,
            cast("int", actions[7]["max_response_bytes"]),
        ),
        _action(
            9,
            "post_identity",
            "ps",
            "GET",
            endpoint.ps_path,
            b"",
            cast("int", actions[8]["max_response_bytes"]),
        ),
    ]
    if list(actions) != expected_actions:
        raise ContractError("Ollama action schedule bytes, methods, or paths drifted")
    positive_budget = {
        "model_process_starts": 0,
        "identity_requests": 8,
        "inference_requests": 1,
        "network_requests": 9,
        "total_request_bytes": sum(
            _integer(action["request_size_bytes"], "action.request_size_bytes")
            for action in actions
        ),
        "total_response_bytes": sum(
            _integer(
                action["response_read_budget_bytes"],
                "action.response_read_budget_bytes",
                minimum=2,
            )
            for action in actions
        ),
        "per_request_timeout_ms": _integer(
            protocol["timeout_ms"],
            "protocol.timeout_ms",
            minimum=1,
        ),
        "retries": 0,
        "downloads": 0,
    }
    parsed_budget = {
        key: _integer(value, f"declaration.action_budget.{key}") for key, value in budget.items()
    }
    expected_budget = (
        positive_budget if disposition == "authorized" else dict.fromkeys(positive_budget, 0)
    )
    if parsed_budget != expected_budget:
        raise ContractError("Ollama declaration action budget does not match its exact schedule")
    if disposition == "authorized" and support != "supported":
        raise ContractError("authorized Ollama declaration has unsupported cache semantics")
    declaration_id = canonical_identity(declaration)
    eligibility = _mapping(package["eligibility"], "ollama_package.eligibility")
    eligibility_fields = {
        "record_type",
        "schema_version",
        "decision",
        "declaration_id",
        "protocol_id",
        "endpoint_id",
        "runtime_id",
        "model_id",
        "host_id",
        "cache_contract_id",
        "allowed_actions",
        "reasons",
    }
    _keys(eligibility, eligibility_fields, "ollama_package.eligibility")
    expected_decision = "eligible" if disposition == "authorized" else "model_execution_forbidden"
    expected_allowed = (
        ["identity_request", "inference_request", "loopback_network_request"]
        if disposition == "authorized"
        else []
    )
    if (
        eligibility["record_type"] != "ollama_eligibility"
        or eligibility["schema_version"] != SCHEMA_VERSION
        or eligibility["decision"] != expected_decision
        or eligibility["declaration_id"] != declaration_id
        or eligibility["protocol_id"] != protocol_id
        or eligibility["endpoint_id"] != endpoint.identity
        or eligibility["runtime_id"] != runtime_id
        or eligibility["model_id"] != model_id
        or eligibility["host_id"] != host_id
        or eligibility["cache_contract_id"] != cache_id
        or eligibility["allowed_actions"] != expected_allowed
        or not _list(eligibility["reasons"], "eligibility.reasons")
    ):
        raise ContractError("Ollama eligibility does not match its declaration")
    return VerifiedPackage(
        dict(package),
        canonical_identity(package),
        endpoint,
        runtime,
        model,
        host,
        artifact,
        request,
        show_request,
        protocol_id,
        declaration_id,
        output_root_id,
        model_name,
        canonical_model_name,
        actions,
    )


def write_prospective_package(path: Path, package: Mapping[str, JsonValue]) -> None:
    """Write one prospective package without replacing an existing file."""
    verified = verify_prospective_package(validate_json_value(package))
    _write_exclusive(path, canonical_json(verified.value))


def load_prospective_package(path: Path) -> VerifiedPackage:
    """Read one canonical prospective package without following a final symlink."""
    return verify_prospective_package(_canonical_file(path, "prospective package"))


@dataclass(frozen=True, slots=True)
class OneShotAuthorization:
    """A phase-scoped, content-addressed authorization consumed before its first call."""

    phase: Literal["identity_guard", "generation", "preflight_only"]
    package_id: str
    declaration_id: str
    output_root_id: str
    nonce_base64: str
    nonce_sha256: str
    identity_requests: int
    inference_requests: int
    network_requests: int
    total_request_bytes: int
    total_response_bytes: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "record_type": "ollama_one_shot_authorization",
            "schema_version": SCHEMA_VERSION,
            "phase": self.phase,
            "package_id": self.package_id,
            "declaration_id": self.declaration_id,
            "output_root_id": self.output_root_id,
            "nonce_base64": self.nonce_base64,
            "nonce_sha256": self.nonce_sha256,
            "identity_requests": self.identity_requests,
            "inference_requests": self.inference_requests,
            "network_requests": self.network_requests,
            "total_request_bytes": self.total_request_bytes,
            "total_response_bytes": self.total_response_bytes,
        }

    @property
    def identity(self) -> str:
        return canonical_identity(self.to_dict())


def make_authorization(
    package: VerifiedPackage,
    phase: Literal["identity_guard", "generation", "preflight_only"],
    nonce: str | bytes,
) -> OneShotAuthorization:
    """Construct an exact separately supplied one-shot authorization artifact."""
    declaration = _mapping(package.value["declaration"], "declaration")
    if declaration["disposition"] != "authorized":
        raise ContractError("forbidden declaration cannot produce an authorization")
    nonce_bytes = nonce.encode() if isinstance(nonce, str) else nonce
    if not nonce_bytes or len(nonce_bytes) > _MAX_AUTHORIZATION_NONCE_BYTES:
        raise ContractError("authorization nonce must contain 1..1024 bytes")
    nonce_sha256 = digest_bytes(nonce_bytes)
    committed_nonces = _mapping(
        declaration["authorization_nonce_sha256"],
        "declaration.authorization_nonce_sha256",
    )
    if nonce_sha256 != committed_nonces[phase]:
        raise ContractError(
            f"{phase} authorization nonce does not match its prospective commitment"
        )
    budget = _authorization_budget(package, phase)
    return OneShotAuthorization(
        phase,
        package.identity,
        package.declaration_id,
        package.output_root_id,
        encode_bytes(nonce_bytes),
        nonce_sha256,
        *budget,
    )


def _authorization_budget(
    package: VerifiedPackage,
    phase: Literal["identity_guard", "generation", "preflight_only"],
) -> tuple[int, int, int, int, int]:
    selected: Sequence[dict[str, JsonValue]]
    if phase == "generation":
        selected = (package.actions[4],)
        identity_requests = 0
        inference_requests = 1
    elif phase == "identity_guard":
        selected = package.actions[:4] + package.actions[5:]
        identity_requests = 8
        inference_requests = 0
    else:
        selected = package.actions[:4]
        identity_requests = 4
        inference_requests = 0
    return (
        identity_requests,
        inference_requests,
        len(selected),
        sum(cast("int", action["request_size_bytes"]) for action in selected),
        sum(cast("int", action["response_read_budget_bytes"]) for action in selected),
    )


def write_authorization(path: Path, authorization: OneShotAuthorization) -> None:
    """Persist one authorization without replacement."""
    _write_exclusive(path, canonical_json(authorization.to_dict()))


def load_authorization(path: Path) -> OneShotAuthorization:
    """Load and strictly verify a one-shot authorization."""
    return _authorization_from_value(_canonical_file(path, "authorization"))


def _authorization_from_value(value: JsonValue) -> OneShotAuthorization:
    data = _mapping(value, "authorization")
    fields = {
        "record_type",
        "schema_version",
        "phase",
        "package_id",
        "declaration_id",
        "output_root_id",
        "nonce_base64",
        "nonce_sha256",
        "identity_requests",
        "inference_requests",
        "network_requests",
        "total_request_bytes",
        "total_response_bytes",
    }
    _keys(data, fields, "authorization")
    if (
        data["record_type"] != "ollama_one_shot_authorization"
        or data["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported one-shot authorization")
    phase = _literal(
        data["phase"],
        {"identity_guard", "generation", "preflight_only"},
        "authorization.phase",
    )
    nonce_base64 = _text(data["nonce_base64"], "authorization.nonce_base64")
    nonce_sha256 = _sha256(data["nonce_sha256"], "authorization.nonce_sha256")
    if digest_bytes(decode_bytes(nonce_base64)) != nonce_sha256:
        raise ContractError("authorization nonce preimage does not match its digest")
    return OneShotAuthorization(
        cast("Literal['identity_guard', 'generation', 'preflight_only']", phase),
        _sha256(data["package_id"], "authorization.package_id"),
        _sha256(data["declaration_id"], "authorization.declaration_id"),
        _sha256(data["output_root_id"], "authorization.output_root_id"),
        nonce_base64,
        nonce_sha256,
        _integer(data["identity_requests"], "authorization.identity_requests"),
        _integer(data["inference_requests"], "authorization.inference_requests"),
        _integer(data["network_requests"], "authorization.network_requests"),
        _integer(data["total_request_bytes"], "authorization.total_request_bytes"),
        _integer(data["total_response_bytes"], "authorization.total_response_bytes"),
    )


def _verify_authorization(
    package: VerifiedPackage,
    supplied: OneShotAuthorization,
    phase: Literal["identity_guard", "generation", "preflight_only"],
) -> None:
    declaration = _mapping(package.value["declaration"], "declaration")
    committed_nonces = _mapping(
        declaration["authorization_nonce_sha256"],
        "declaration.authorization_nonce_sha256",
    )
    expected_budget = _authorization_budget(package, phase)
    if (
        supplied.phase != phase
        or supplied.package_id != package.identity
        or supplied.declaration_id != package.declaration_id
        or supplied.output_root_id != package.output_root_id
        or digest_bytes(decode_bytes(supplied.nonce_base64)) != supplied.nonce_sha256
        or supplied.nonce_sha256 != committed_nonces[phase]
        or (
            supplied.identity_requests,
            supplied.inference_requests,
            supplied.network_requests,
            supplied.total_request_bytes,
            supplied.total_response_bytes,
        )
        != expected_budget
    ):
        raise ContractError(f"{phase} authorization does not match the prospective package")


def _consume_authorization_at(
    output_root_descriptor: int,
    expected_output_root_id: str,
    authorization: OneShotAuthorization,
) -> None:
    if _output_root_identity_at(output_root_descriptor) != expected_output_root_id:
        raise ContractError("authorization output-root identity drift")
    marker = {
        "record_type": "ollama_authorization_consumption",
        "schema_version": SCHEMA_VERSION,
        "authorization_id": authorization.identity,
        "phase": authorization.phase,
        "package_id": authorization.package_id,
    }
    _write_exclusive_at(
        output_root_descriptor,
        f".localinferencelab-consumed-{authorization.identity[7:]}.json",
        canonical_json(marker),
    )


@dataclass(frozen=True, slots=True)
class TransportRequest:
    """One exact HTTP call after budget consumption."""

    operation: str
    method: Literal["GET", "POST"]
    path: str
    body: bytes
    timeout_ms: int
    max_response_bytes: int
    response_read_budget_bytes: int


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """Bounded HTTP response bytes and peer evidence."""

    status: int
    content_type: str
    body: bytes
    peer: str


class OllamaTransport(Protocol):
    """Small transport boundary shared by direct loopback HTTP and deterministic tests."""

    def request(self, request: TransportRequest) -> TransportResponse:
        """Perform exactly one call with no retry."""


class TransportFailureError(ContractError):
    """A bounded transport call failed after its action budget was consumed."""

    def __init__(
        self,
        message: str,
        *,
        response_body: bytes = b"",
        status: int | None = None,
        content_type: str | None = None,
        response_complete: bool = False,
    ) -> None:
        """Retain bounded partial-response custody when a call fails."""
        super().__init__(message)
        self.response_body = response_body
        self.status = status
        self.content_type = content_type
        self.response_complete = response_complete


class LoopbackHTTPTransport:
    """Direct standard-library HTTP transport with no proxy or redirect support."""

    def __init__(self, endpoint: EndpointIdentity) -> None:
        """Bind one exact endpoint for all future calls."""
        self._endpoint = endpoint

    def request(self, request: TransportRequest) -> TransportResponse:
        """Call an exact allowlisted path on the pinned numeric-loopback peer."""
        allowed_paths = {
            self._endpoint.version_path,
            self._endpoint.tags_path,
            self._endpoint.show_path,
            self._endpoint.ps_path,
            self._endpoint.generate_path,
        }
        if request.path not in allowed_paths:
            raise ContractError("transport path is outside the endpoint allowlist")
        if request.method == "GET" and request.body:
            raise ContractError("GET identity requests cannot carry a body")
        connection = http.client.HTTPConnection(
            self._endpoint.host,
            self._endpoint.port,
            timeout=request.timeout_ms / 1000,
        )
        try:
            connection.connect()
            if connection.sock is None:
                raise TransportFailureError("Ollama connection has no connected socket")
            peer = connection.sock.getpeername()[0]
            peer_address = ipaddress.ip_address(peer)
            expected = ipaddress.ip_address(self._endpoint.host)
            if not peer_address.is_loopback or peer_address != expected:
                raise TransportFailureError(
                    "connected Ollama peer is not the exact pinned loopback host",
                )
            headers = {
                "Accept": "application/json",
                "Connection": "close",
                "Content-Type": "application/json",
            }
            connection.request(request.method, request.path, body=request.body, headers=headers)
            response = connection.getresponse()
            content_types = response.headers.get_all("Content-Type") or []
            content_type = content_types[0] if len(content_types) == 1 else None
            if response.getheader("Location") is not None:
                raise TransportFailureError(
                    "Ollama redirects are forbidden",
                    status=response.status,
                    content_type=content_type,
                )
            if response.getheader("Content-Encoding") is not None:
                raise TransportFailureError(
                    "compressed Ollama responses are forbidden",
                    status=response.status,
                    content_type=content_type,
                )
            content_lengths = response.headers.get_all("Content-Length") or []
            if len(content_lengths) > 1:
                raise TransportFailureError(
                    "multiple Content-Length headers are forbidden",
                    status=response.status,
                    content_type=content_type,
                )
            if content_lengths:
                try:
                    declared_length = int(content_lengths[0])
                except ValueError as error:
                    raise TransportFailureError(
                        "invalid Content-Length header",
                        status=response.status,
                        content_type=content_type,
                    ) from error
                if declared_length < 0:
                    raise TransportFailureError(
                        "invalid Content-Length header",
                        status=response.status,
                        content_type=content_type,
                    )
            blocks: list[bytes] = []
            remaining = request.response_read_budget_bytes
            while remaining:
                try:
                    block = response.read(min(64 * 1024, remaining))
                except (OSError, TimeoutError) as error:
                    raise TransportFailureError(
                        "Ollama response body read failed",
                        response_body=b"".join(blocks),
                        status=response.status,
                        content_type=content_type,
                    ) from error
                if not block:
                    break
                blocks.append(block)
                remaining -= len(block)
            body = b"".join(blocks)
            if len(body) > request.max_response_bytes:
                raise TransportFailureError(
                    "Ollama response exceeds the byte budget",
                    response_body=body,
                    status=response.status,
                    content_type=content_type,
                    response_complete=bool(remaining),
                )
            if len(content_types) != 1:
                raise TransportFailureError(
                    "Ollama response must have exactly one Content-Type",
                    response_body=body,
                    status=response.status,
                    content_type=content_type,
                    response_complete=True,
                )
            return TransportResponse(response.status, content_types[0], body, str(peer_address))
        except TimeoutError as error:
            raise TransportFailureError("Ollama request timed out") from error
        except OSError as error:
            raise TransportFailureError(
                f"Ollama loopback transport failed: {error.strerror}",
            ) from error
        finally:
            connection.close()


class FakeTransport:
    """Deterministic no-socket transport used only for synthetic contract evidence."""

    def __init__(self, outcomes: Sequence[TransportResponse | Exception]) -> None:
        """Load one finite ordered response script."""
        self._outcomes = list(outcomes)
        self.requests: list[TransportRequest] = []

    def request(self, request: TransportRequest) -> TransportResponse:
        """Return the next scripted bounded response without network or model action."""
        self.requests.append(request)
        if not self._outcomes:
            raise TransportFailureError("fake transport has no scripted response")
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        if len(outcome.body) > request.max_response_bytes:
            raise TransportFailureError(
                "fake response exceeds the byte budget",
                response_body=outcome.body[: request.response_read_budget_bytes],
                status=outcome.status,
                content_type=outcome.content_type,
                response_complete=len(outcome.body) <= request.response_read_budget_bytes,
            )
        return outcome


@dataclass(slots=True)
class ActionBudgetLedger:
    """Pre-action counters bounded by the two exact one-shot authorizations."""

    identity_requests: int
    inference_requests: int
    network_requests: int
    request_bytes: int
    response_bytes: int
    response_budget_reserved: int
    max_identity_requests: int
    max_inference_requests: int
    max_network_requests: int
    max_request_bytes: int
    max_response_bytes: int

    @classmethod
    def for_authorizations(
        cls,
        authorizations: Iterable[OneShotAuthorization],
    ) -> ActionBudgetLedger:
        items = tuple(authorizations)
        return cls(
            0,
            0,
            0,
            0,
            0,
            0,
            sum(item.identity_requests for item in items),
            sum(item.inference_requests for item in items),
            sum(item.network_requests for item in items),
            sum(item.total_request_bytes for item in items),
            sum(item.total_response_bytes for item in items),
        )

    def before(self, request: TransportRequest, *, identity: bool, inference: bool) -> None:
        if self.network_requests >= self.max_network_requests:
            raise ContractError("network request budget exhausted before action")
        if identity and self.identity_requests >= self.max_identity_requests:
            raise ContractError("identity request budget exhausted before action")
        if inference and self.inference_requests >= self.max_inference_requests:
            raise ContractError("inference request budget exhausted before action")
        if self.request_bytes + len(request.body) > self.max_request_bytes:
            raise ContractError("request-byte budget exhausted before action")
        if (
            self.response_budget_reserved + request.response_read_budget_bytes
            > self.max_response_bytes
        ):
            raise ContractError("response-byte budget exhausted before action")
        self.network_requests += 1
        self.request_bytes += len(request.body)
        self.response_budget_reserved += request.response_read_budget_bytes
        if identity:
            self.identity_requests += 1
        if inference:
            self.inference_requests += 1

    def after(self, response: TransportResponse) -> None:
        self.after_bytes(response.body)

    def after_bytes(self, body: bytes) -> None:
        if self.response_bytes + len(body) > self.response_budget_reserved:
            raise ContractError("response-byte budget exceeded")
        self.response_bytes += len(body)


def _content_type(value: str) -> None:
    media_type, separator, parameter = value.partition(";")
    if media_type.strip().casefold() != "application/json":
        raise ContractError("Ollama response Content-Type must be application/json")
    if separator and parameter.strip().casefold() not in {"charset=utf-8", 'charset="utf-8"'}:
        raise ContractError("Ollama response has an unsupported Content-Type parameter")


def _response_json(response: TransportResponse, operation: str) -> dict[str, JsonValue]:
    if response.status != _HTTP_OK:
        raise ContractError(f"Ollama {operation} returned HTTP status {response.status}")
    _content_type(response.content_type)
    return _mapping(load_json_bytes(response.body), f"Ollama {operation} response")


def _show_projection(response: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    required = {"modelfile", "parameters", "template", "details", "model_info"}
    missing = required - response.keys()
    if missing:
        raise ContractError(f"Ollama show response missing fields: {', '.join(sorted(missing))}")
    projection_values: dict[str, object] = {
        "modelfile_sha256": digest_bytes(
            _text(response["modelfile"], "show.modelfile", empty=True).encode(),
        ),
        "parameters_sha256": digest_bytes(
            _text(response["parameters"], "show.parameters", empty=True).encode(),
        ),
        "template_sha256": digest_bytes(
            _text(response["template"], "show.template", empty=True).encode(),
        ),
        "details_sha256": canonical_identity(response["details"]),
        "model_info_sha256": canonical_identity(response["model_info"]),
        "thinking_sha256": canonical_identity(response.get("thinking")),
    }
    return cast("dict[str, JsonValue]", validate_json_value(projection_values))


def _identity_projection(
    package: VerifiedPackage,
    responses: Mapping[str, TransportResponse],
) -> dict[str, JsonValue]:
    version = _response_json(responses["version"], "version")
    _keys(version, {"version"}, "Ollama version response")
    version_text = _public_text(version["version"], "Ollama version")
    if version_text != package.runtime.version:
        raise ContractError("Ollama runtime version identity drift")
    tags = _response_json(responses["tags"], "tags")
    _keys(tags, {"models"}, "Ollama tags response")
    matched_manifest: str | None = None
    for index, item in enumerate(_list(tags["models"], "Ollama tags models")):
        model = _mapping(item, f"Ollama tags models[{index}]")
        if (
            model.get("name") == package.canonical_model_name
            or model.get("model") == package.canonical_model_name
        ):
            digest_value = model.get("digest")
            matched_manifest = _sha256(
                digest_value,
                f"Ollama tags models[{index}].digest",
            )
    if matched_manifest is None:
        raise ContractError("Ollama tags response lacks the exact declared model name")
    if matched_manifest != package.model_artifact.manifest_digest:
        raise ContractError("Ollama model manifest identity drift")
    show = _response_json(responses["show"], "show")
    actual_show = _show_projection(show)
    expected_show = _validate_show_projection(package.value["show_projection"])
    if actual_show != expected_show:
        raise ContractError("Ollama show identity drift")
    ps = _response_json(responses["ps"], "ps")
    _keys(ps, {"models"}, "Ollama ps response")
    loaded = False
    for index, item in enumerate(_list(ps["models"], "Ollama ps models")):
        loaded_model = _mapping(item, f"Ollama ps models[{index}]")
        digest_value = loaded_model.get("digest")
        if digest_value is not None:
            loaded_digest = _sha256(
                digest_value,
                f"Ollama ps models[{index}].digest",
            )
            if loaded_digest == package.model_artifact.manifest_digest:
                loaded = True
            elif (
                loaded_model.get("name") == package.canonical_model_name
                or loaded_model.get("model") == package.canonical_model_name
            ):
                raise ContractError("loaded Ollama model identity drift")
        elif (
            loaded_model.get("name") == package.canonical_model_name
            or loaded_model.get("model") == package.canonical_model_name
        ):
            raise ContractError("loaded Ollama model lacks its manifest digest")
    return {
        "runtime_version": version_text,
        "model_manifest_digest": matched_manifest,
        "show_projection": actual_show,
        "model_loaded": loaded,
        "selected_runner": _runtime_fact(package.runtime, "runner"),
        "metal_state": _runtime_fact(package.runtime, "metal"),
    }


def _check_artifacts(
    package: VerifiedPackage,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
) -> None:
    runtime_digest, _size = _digest_regular_file(runtime_artifact, "runtime artifact")
    if runtime_digest != package.runtime.artifact_sha256:
        raise ContractError("runtime artifact identity drift")
    if inspect_model_artifacts(model_manifest, blob_root) != package.model_artifact:
        raise ContractError("model artifact identity drift")


def _require_load_state(
    projection: Mapping[str, JsonValue],
    expected: JsonValue,
    phase: str,
) -> None:
    if projection["model_loaded"] != expected:
        raise ContractError(
            f"{phase}-request Ollama load state does not match the cache contract",
        )


def _require_stable_projection(
    pre_projection: Mapping[str, JsonValue],
    post_projection: Mapping[str, JsonValue],
) -> None:
    if pre_projection != post_projection:
        raise ContractError("Ollama runtime/model identity drifted across generation")


def _call(
    *,
    action: Mapping[str, JsonValue],
    body: bytes,
    transport: OllamaTransport,
    ledger: ActionBudgetLedger,
    timeout_ms: int,
    logical_network: bool,
    action_records: list[JsonValue],
) -> TransportResponse:
    operation = cast("str", action["operation"])
    identity = operation in _IDENTITY_OPERATIONS
    inference = operation == "generate"
    request = TransportRequest(
        operation,
        cast("Literal['GET', 'POST']", action["method"]),
        cast("str", action["path"]),
        body,
        timeout_ms,
        cast("int", action["max_response_bytes"]),
        cast("int", action["response_read_budget_bytes"]),
    )
    ledger.before(request, identity=identity, inference=inference)
    started = time.monotonic_ns()
    try:
        response = transport.request(request)
    except Exception as error:
        failure = error if isinstance(error, TransportFailureError) else None
        response_body = failure.response_body if failure is not None else b""
        ledger.after_bytes(response_body)
        action_records.append(
            {
                "sequence": action["sequence"],
                "phase": action["phase"],
                "operation": operation,
                "method": action["method"],
                "path": action["path"],
                "request_sha256": action["request_sha256"],
                "request_size_bytes": len(body),
                "response_sha256": (digest_bytes(response_body) if response_body else None),
                "response_size_bytes": len(response_body),
                "response_complete": (failure.response_complete if failure is not None else False),
                "http_status": failure.status if failure is not None else None,
                "content_type": failure.content_type if failure is not None else None,
                "outcome": "transport_failure",
                "error_sha256": digest_bytes(str(error).encode()),
                "loopback_network_side_effect": logical_network,
                "elapsed_ns": time.monotonic_ns() - started if logical_network else 0,
            },
        )
        if isinstance(error, ContractError):
            raise
        raise TransportFailureError(str(error)) from error
    ledger.after(response)
    action_records.append(
        {
            "sequence": action["sequence"],
            "phase": action["phase"],
            "operation": operation,
            "method": action["method"],
            "path": action["path"],
            "request_sha256": action["request_sha256"],
            "request_size_bytes": len(body),
            "response_sha256": digest_bytes(response.body),
            "response_size_bytes": len(response.body),
            "response_complete": True,
            "http_status": response.status,
            "content_type": response.content_type,
            "outcome": "response_received",
            "error_sha256": None,
            "loopback_network_side_effect": logical_network,
            "elapsed_ns": time.monotonic_ns() - started if logical_network else 0,
        },
    )
    return response


def _identity_calls(
    package: VerifiedPackage,
    actions: Sequence[Mapping[str, JsonValue]],
    transport: OllamaTransport,
    ledger: ActionBudgetLedger,
    timeout_ms: int,
    *,
    logical_network: bool,
    action_records: list[JsonValue],
) -> dict[str, JsonValue]:
    responses: dict[str, TransportResponse] = {}
    for action in actions:
        operation = cast("str", action["operation"])
        body = package.show_request if operation == "show" else b""
        responses[operation] = _call(
            action=action,
            body=body,
            transport=transport,
            ledger=ledger,
            timeout_ms=timeout_ms,
            logical_network=logical_network,
            action_records=action_records,
        )
    return _identity_projection(package, responses)


def _unavailable_measurements() -> tuple[Measurement, ...]:
    return (
        Measurement("memory", "not_collected", None, "bytes", "unavailable", "not collected"),
        Measurement(
            "energy",
            "not_collected",
            None,
            "microjoules",
            "unavailable",
            "no reviewed energy protocol",
        ),
    )


def _parse_generate_response(
    package: VerifiedPackage,
    response: TransportResponse | None,
    *,
    synthetic: bool,
    declaration_id: str,
    invalid_reason: str | None,
) -> RunRecord:
    protocol = _mapping(package.value["protocol"], "protocol")
    process = ProcessInstance.from_dict(_mapping(package.value["process"], "process"))
    model_instance = ModelInstance.from_dict(
        _mapping(package.value["model_instance"], "model_instance"),
    )
    cache = _mapping(package.value["cache_contract"], "cache_contract")
    concurrency = ConcurrencyIdentity.from_dict(
        _mapping(package.value["concurrency"], "concurrency"),
    )
    common: dict[str, JsonValue] = {
        "record_type": "run_record",
        "schema_version": "1.0",
        "run_id": protocol["run_id"],
        "run_order": 1,
        "backend": "ollama",
        "protocol_id": package.protocol_id,
        "runtime_id": record_id(package.runtime),
        "model_id": record_id(package.model),
        "host_id": record_id(package.host),
        "declaration_id": declaration_id,
        "process_instance_id": record_id(process),
        "model_instance_id": record_id(model_instance),
        "cache_preparation_id": canonical_identity(cache),
        "concurrency_id": record_id(concurrency),
        "concurrency_wave": 1,
        "cache_cohort": "cold_model_warm_process",
        "evidence_kind": "synthetic_fixture" if synthetic else "observed_execution",
        "model_process_start_count": 0,
        "inference_request_count": 0 if synthetic else 1,
        "request_base64": encode_bytes(package.request),
        "request_sha256": digest_bytes(package.request),
        "measurements": [],
    }
    if invalid_reason is not None:
        common.update(
            {
                "validity": "invalid",
                "invalid_reason_sha256": digest_bytes(invalid_reason.encode()),
                "raw_response_base64": None,
                "raw_response_sha256": None,
                "text_utf8": None,
                "text_sha256": None,
                "token_ids": None,
                "token_ids_sha256": None,
                "finish_reason": None,
                "envelope_base64": None,
                "envelope_sha256": None,
                "native_metrics": [],
                "measurements": [measurement_to_dict(item) for item in _unavailable_measurements()],
            },
        )
        return RunRecord.from_dict(common)
    if response is None:
        raise ContractError("valid Ollama output requires a response envelope")
    body = _response_json(response, "generate")
    extra = set(body) - _GENERATE_FIELDS
    if extra:
        raise ContractError(
            f"Ollama generate response has unknown fields: {', '.join(sorted(extra))}",
        )
    required = {
        "model",
        "created_at",
        "response",
        "done",
        "done_reason",
        "total_duration",
        "load_duration",
        "prompt_eval_count",
        "prompt_eval_duration",
        "eval_count",
        "eval_duration",
    }
    missing = required - body.keys()
    if missing:
        raise ContractError(
            f"Ollama generate response missing fields: {', '.join(sorted(missing))}",
        )
    if body["model"] != package.canonical_model_name:
        raise ContractError("Ollama generate response model identity drift")
    if body["done"] is not True:
        raise ContractError("Ollama generate response is not terminal")
    _public_text(body["created_at"], "generate.created_at")
    text = _text(body["response"], "generate.response", empty=True)
    finish = _public_text(body["done_reason"], "generate.done_reason")
    if "thinking" in body:
        _text(body["thinking"], "generate.thinking", empty=True)
    if "context" in body:
        for index, token in enumerate(_list(body["context"], "generate.context")):
            _integer(token, f"generate.context[{index}]")
    metrics: list[JsonValue] = []
    evidence = "synthetic" if synthetic else "observed"
    metric_fields = (
        ("total_duration", "total_duration_ns", "nanoseconds"),
        ("load_duration", "load_duration_ns", "nanoseconds"),
        ("prompt_eval_count", "prompt_eval_count", "tokens"),
        ("prompt_eval_duration", "prompt_eval_duration_ns", "nanoseconds"),
        ("eval_count", "generation_count", "tokens"),
        ("eval_duration", "generation_duration_ns", "nanoseconds"),
    )
    for field, name, unit in metric_fields:
        metrics.append(
            {
                "name": name,
                "value": _integer(body[field], f"generate.{field}"),
                "unit": unit,
                "availability": evidence,
                "reason": None,
            },
        )
    if "prompt_eval_cached_count" in body:
        metrics.append(
            {
                "name": "prompt_eval_cached_count",
                "value": _integer(
                    body["prompt_eval_cached_count"],
                    "generate.prompt_eval_cached_count",
                ),
                "unit": "tokens",
                "availability": evidence,
                "reason": None,
            },
        )
    else:
        metrics.append(
            {
                "name": "prompt_eval_cached_count",
                "value": None,
                "unit": "tokens",
                "availability": "unavailable",
                "reason": "selected Ollama response omitted prompt_eval_cached_count",
            },
        )
    metrics.append(
        {
            "name": "ttft_ns",
            "value": None,
            "unit": "nanoseconds",
            "availability": "unavailable",
            "reason": "Ollama generate API does not expose a TTFT boundary",
        },
    )
    common.update(
        {
            "validity": "valid",
            "invalid_reason_sha256": None,
            "raw_response_base64": encode_bytes(text.encode()),
            "raw_response_sha256": digest_bytes(text.encode()),
            "text_utf8": text,
            "text_sha256": digest_bytes(text.encode()),
            "token_ids": None,
            "token_ids_sha256": None,
            "finish_reason": finish,
            "envelope_base64": encode_bytes(response.body),
            "envelope_sha256": digest_bytes(response.body),
            "native_metrics": metrics,
            "measurements": [measurement_to_dict(item) for item in _unavailable_measurements()],
        },
    )
    return RunRecord.from_dict(common)


def measurement_to_dict(measurement: Measurement) -> dict[str, JsonValue]:
    """Serialize a measurement without exposing dataclass implementation details."""
    return {
        "kind": measurement.kind,
        "method": measurement.method,
        "value": measurement.value,
        "unit": measurement.unit,
        "availability": measurement.availability,
        "reason": measurement.reason,
    }


def _terminal(
    *,
    package: VerifiedPackage,
    status: str,
    reason: str | None,
    synthetic: bool,
    action_records: Sequence[JsonValue],
    guard_id: str,
    generation_id: str | None,
    run: RunRecord | None,
) -> dict[str, JsonValue]:
    return {
        "record_type": "ollama_execution_terminal",
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "reason_sha256": None if reason is None else digest_bytes(reason.encode()),
        "evidence_kind": (
            "synthetic_transport_contract_evidence" if synthetic else "observed_execution"
        ),
        "performance_claim": "none",
        "model_quality_claim": "none",
        "determinism_claim": "none",
        "package_id": package.identity,
        "protocol_id": package.protocol_id,
        "declaration_id": package.declaration_id,
        "identity_authorization_id": guard_id,
        "generation_authorization_id": generation_id,
        "scheduled_runs": 1,
        "completed_runs": 1 if run is not None else 0,
        "logical_identity_requests": sum(
            1
            for item in action_records
            if isinstance(item, dict) and item.get("operation") in _IDENTITY_OPERATIONS
        ),
        "logical_inference_requests": sum(
            1
            for item in action_records
            if isinstance(item, dict) and item.get("operation") == "generate"
        ),
        "physical_network_requests": 0 if synthetic else len(action_records),
        "physical_model_inferences": (
            0
            if synthetic
            else sum(
                1
                for item in action_records
                if isinstance(item, dict) and item.get("operation") == "generate"
            )
        ),
        "model_process_starts": 0,
        "downloads": 0,
        "retries": 0,
    }


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Published terminal synthetic or observed execution evidence."""

    path: Path
    status: Literal["accepted", "invalid", "refused"]
    package_id: str
    run_validity: str | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "path": self.path.name,
            "status": self.status,
            "package_id": self.package_id,
            "run_validity": self.run_validity,
        }


@dataclass(frozen=True, slots=True)
class PreflightResult:
    """Published read-only identity preflight evidence."""

    path: Path
    status: Literal["accepted", "refused"]
    package_id: str

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "path": self.path.name,
            "status": self.status,
            "package_id": self.package_id,
            "inference_requests": 0,
            "model_process_starts": 0,
            "downloads": 0,
        }


def _preflight_at(
    *,
    package: VerifiedPackage,
    authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
    transport: OllamaTransport,
    synthetic: bool,
    bundle_prefix: str,
    output_root_descriptor: int,
) -> PreflightResult:
    _verify_authorization(package, authorization, "preflight_only")
    marker = _output_root_marker_at(output_root_descriptor)
    if canonical_identity(marker) != package.output_root_id:
        raise ContractError("preflight output-root identity mismatch")
    if not synthetic and marker["binding_mode"] != "physical_instance":
        raise ContractError("observed preflight requires a physical output-root binding")
    _check_artifacts(package, runtime_artifact, model_manifest, blob_root)
    _consume_authorization_at(
        output_root_descriptor,
        package.output_root_id,
        authorization,
    )
    ledger = ActionBudgetLedger.for_authorizations((authorization,))
    action_records: list[JsonValue] = []
    declaration = _mapping(package.value["declaration"], "declaration")
    timeout_ms = cast(
        "int",
        _mapping(declaration["action_budget"], "action_budget")["per_request_timeout_ms"],
    )
    projection: dict[str, JsonValue] | None = None
    reason: str | None = None
    try:
        projection = _identity_calls(
            package,
            package.actions[:4],
            transport,
            ledger,
            timeout_ms,
            logical_network=not synthetic,
            action_records=action_records,
        )
        cache = _mapping(package.value["cache_contract"], "cache_contract")
        _require_load_state(projection, cache["expected_pre_loaded"], "preflight")
    except ContractError as error:
        reason = str(error)
    status: Literal["accepted", "refused"] = "accepted" if reason is None else "refused"
    evidence: dict[str, bytes] = {
        "source/ollama-preflight.json": canonical_json(
            {
                "record_type": "ollama_preflight_source",
                "schema_version": SCHEMA_VERSION,
                "evidence_kind": (
                    "synthetic_transport_contract_evidence"
                    if synthetic
                    else "observed_loopback_identity_preflight"
                ),
                "read_only_identity_calls": len(action_records),
                "inference_requests": 0,
                "model_process_starts": 0,
                "downloads": 0,
                "external_network_actions": 0,
            },
        ),
        "prospective.json": canonical_json(package.value),
        "authorization/preflight.json": canonical_json(authorization.to_dict()),
        "actions.json": canonical_json(
            {
                "record_type": "ollama_preflight_action_log",
                "schema_version": SCHEMA_VERSION,
                "package_id": package.identity,
                "authorization_id": authorization.identity,
                "actions": action_records,
                "request_bytes_consumed": ledger.request_bytes,
                "response_bytes_consumed": ledger.response_bytes,
                "response_budget_reserved": ledger.response_budget_reserved,
                "network_requests_consumed": ledger.network_requests,
                "identity_requests_consumed": ledger.identity_requests,
                "inference_requests_consumed": 0,
            },
        ),
        "terminal.json": canonical_json(
            {
                "record_type": "ollama_preflight_terminal",
                "schema_version": SCHEMA_VERSION,
                "package_id": package.identity,
                "authorization_id": authorization.identity,
                "status": status,
                "reason_sha256": None if reason is None else digest_bytes(reason.encode()),
                "generation_path_called": False,
                "model_action_performed": False,
            },
        ),
    }
    if projection is not None:
        evidence["identity/preflight.json"] = canonical_json(
            {
                "record_type": "ollama_identity_snapshot",
                "schema_version": SCHEMA_VERSION,
                "phase": "preflight",
                "projection": projection,
            },
        )
    if _output_root_identity_at(output_root_descriptor) != package.output_root_id:
        raise ContractError("preflight output-root identity drift before publication")
    destination = publish_bundle_at(
        evidence,
        output_root,
        output_root_descriptor,
        name_prefix=bundle_prefix,
    )
    return PreflightResult(destination, status, package.identity)


def _preflight(
    *,
    package: VerifiedPackage,
    authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
    transport: OllamaTransport,
    synthetic: bool,
    bundle_prefix: str,
) -> PreflightResult:
    output_root_descriptor = _open_private_output_root(output_root)
    try:
        return _preflight_at(
            package=package,
            authorization=authorization,
            output_root=output_root,
            runtime_artifact=runtime_artifact,
            model_manifest=model_manifest,
            blob_root=blob_root,
            transport=transport,
            synthetic=synthetic,
            bundle_prefix=bundle_prefix,
            output_root_descriptor=output_root_descriptor,
        )
    finally:
        os.close(output_root_descriptor)


def preflight_synthetic(
    *,
    package: VerifiedPackage,
    authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
    transport: FakeTransport,
    bundle_prefix: str,
) -> PreflightResult:
    """Exercise only identity calls through a no-socket fake transport."""
    return _preflight(
        package=package,
        authorization=authorization,
        output_root=output_root,
        runtime_artifact=runtime_artifact,
        model_manifest=model_manifest,
        blob_root=blob_root,
        transport=transport,
        synthetic=True,
        bundle_prefix=bundle_prefix,
    )


def preflight_observed(
    *,
    package: VerifiedPackage,
    authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
) -> PreflightResult:
    """Run only the separately authorized read-only loopback identity preflight."""
    return _preflight(
        package=package,
        authorization=authorization,
        output_root=output_root,
        runtime_artifact=runtime_artifact,
        model_manifest=model_manifest,
        blob_root=blob_root,
        transport=LoopbackHTTPTransport(package.endpoint),
        synthetic=False,
        bundle_prefix="localinferencelab-ollama-preflight-v1",
    )


def _execute_at(
    *,
    package: VerifiedPackage,
    identity_authorization: OneShotAuthorization,
    generation_authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
    transport: OllamaTransport,
    synthetic: bool,
    bundle_prefix: str,
    output_root_descriptor: int,
) -> ExecutionResult:
    declaration = _mapping(package.value["declaration"], "declaration")
    if declaration["disposition"] != "authorized":
        raise ContractError("execution declaration is not authorized")
    _verify_authorization(package, identity_authorization, "identity_guard")
    _verify_authorization(package, generation_authorization, "generation")
    marker = _output_root_marker_at(output_root_descriptor)
    if canonical_identity(marker) != package.output_root_id:
        raise ContractError("execution output-root identity mismatch")
    _check_artifacts(package, runtime_artifact, model_manifest, blob_root)
    if not synthetic:
        if marker["binding_mode"] != "physical_instance":
            raise ContractError("observed execution requires a physical output-root binding")
        raise ContractError(
            "observed generation is disabled until the listening process and active "
            "runner/Metal state can be mechanically attested"
        )
    _consume_authorization_at(
        output_root_descriptor,
        package.output_root_id,
        identity_authorization,
    )
    ledger = ActionBudgetLedger.for_authorizations(
        (identity_authorization, generation_authorization)
    )
    action_records: list[JsonValue] = []
    timeout_ms = cast(
        "int",
        _mapping(declaration["action_budget"], "action_budget")["per_request_timeout_ms"],
    )
    logical_network = not synthetic
    status: Literal["accepted", "invalid", "refused"] = "refused"
    reason: str | None = None
    run: RunRecord | None = None
    generation_id: str | None = None
    pre_projection: dict[str, JsonValue] | None = None
    post_projection: dict[str, JsonValue] | None = None
    generation_response: TransportResponse | None = None
    generation_envelope: bytes | None = None
    try:
        pre_projection = _identity_calls(
            package,
            package.actions[:4],
            transport,
            ledger,
            timeout_ms,
            logical_network=logical_network,
            action_records=action_records,
        )
        cache = _mapping(package.value["cache_contract"], "cache_contract")
        _require_load_state(pre_projection, cache["expected_pre_loaded"], "pre")
    except ContractError as error:
        reason = str(error)
    else:
        _consume_authorization_at(
            output_root_descriptor,
            package.output_root_id,
            generation_authorization,
        )
        generation_id = generation_authorization.identity
        try:
            generation_response = _call(
                action=package.actions[4],
                body=package.request,
                transport=transport,
                ledger=ledger,
                timeout_ms=timeout_ms,
                logical_network=logical_network,
                action_records=action_records,
            )
            generation_envelope = generation_response.body
        except TransportFailureError as error:
            generation_envelope = error.response_body or None
            reason = str(error)
        except ContractError as error:
            reason = str(error)
        try:
            post_projection = _identity_calls(
                package,
                package.actions[5:],
                transport,
                ledger,
                timeout_ms,
                logical_network=logical_network,
                action_records=action_records,
            )
            _check_artifacts(package, runtime_artifact, model_manifest, blob_root)
            cache = _mapping(package.value["cache_contract"], "cache_contract")
            _require_load_state(post_projection, cache["expected_post_loaded"], "post")
            _require_stable_projection(pre_projection, post_projection)
        except ContractError as error:
            reason = str(error) if reason is None else f"{reason}; post-check: {error}"
        if generation_response is not None:
            if reason is None:
                try:
                    run = _parse_generate_response(
                        package,
                        generation_response,
                        synthetic=synthetic,
                        declaration_id=package.declaration_id,
                        invalid_reason=None,
                    )
                except ContractError as error:
                    reason = str(error)
            if reason is not None:
                run = _parse_generate_response(
                    package,
                    generation_response,
                    synthetic=synthetic,
                    declaration_id=package.declaration_id,
                    invalid_reason=reason,
                )
                status = "invalid"
            else:
                status = "accepted"
        elif generation_id is not None:
            run = _parse_generate_response(
                package,
                None,
                synthetic=synthetic,
                declaration_id=package.declaration_id,
                invalid_reason=reason or "generation transport failed",
            )
            status = "invalid"
    terminal = _terminal(
        package=package,
        status=status,
        reason=reason,
        synthetic=synthetic,
        action_records=action_records,
        guard_id=identity_authorization.identity,
        generation_id=generation_id,
        run=run,
    )
    evidence: dict[str, bytes] = {
        "source/ollama.json": canonical_json(
            {
                "record_type": "ollama_evidence_source",
                "schema_version": SCHEMA_VERSION,
                "evidence_kind": (
                    "synthetic_transport_contract_evidence" if synthetic else "observed_execution"
                ),
                "implementation_evidence_only": synthetic,
                "performance_evidence": False,
                "external_network_actions": 0,
                "model_downloads": 0,
                "model_process_starts": 0,
            },
        ),
        "prospective.json": canonical_json(package.value),
        "authorization/identity.json": canonical_json(identity_authorization.to_dict()),
        "actions.json": canonical_json(
            {
                "record_type": "ollama_action_log",
                "schema_version": SCHEMA_VERSION,
                "package_id": package.identity,
                "actions": action_records,
                "request_bytes_consumed": ledger.request_bytes,
                "response_bytes_consumed": ledger.response_bytes,
                "response_budget_reserved": ledger.response_budget_reserved,
                "network_requests_consumed": ledger.network_requests,
                "identity_requests_consumed": ledger.identity_requests,
                "inference_requests_consumed": ledger.inference_requests,
            },
        ),
        "terminal.json": canonical_json(terminal),
    }
    if pre_projection is not None:
        evidence["identity/pre.json"] = canonical_json(
            {
                "record_type": "ollama_identity_snapshot",
                "schema_version": SCHEMA_VERSION,
                "phase": "pre",
                "projection": pre_projection,
            },
        )
    if post_projection is not None:
        evidence["identity/post.json"] = canonical_json(
            {
                "record_type": "ollama_identity_snapshot",
                "schema_version": SCHEMA_VERSION,
                "phase": "post",
                "projection": post_projection,
            },
        )
    if run is not None:
        evidence["runs/0001.json"] = canonical_json(run.to_dict())
    if generation_envelope is not None:
        evidence["responses/generation.bin"] = generation_envelope
    if generation_id is not None:
        evidence["authorization/generation.json"] = canonical_json(
            generation_authorization.to_dict()
        )
    if _output_root_identity_at(output_root_descriptor) != package.output_root_id:
        raise ContractError("execution output-root identity drift before publication")
    destination = publish_bundle_at(
        evidence,
        output_root,
        output_root_descriptor,
        name_prefix=bundle_prefix,
    )
    return ExecutionResult(
        destination,
        status,
        package.identity,
        None if run is None else run.validity,
    )


def _execute(
    *,
    package: VerifiedPackage,
    identity_authorization: OneShotAuthorization,
    generation_authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
    transport: OllamaTransport,
    synthetic: bool,
    bundle_prefix: str,
) -> ExecutionResult:
    output_root_descriptor = _open_private_output_root(output_root)
    try:
        return _execute_at(
            package=package,
            identity_authorization=identity_authorization,
            generation_authorization=generation_authorization,
            output_root=output_root,
            runtime_artifact=runtime_artifact,
            model_manifest=model_manifest,
            blob_root=blob_root,
            transport=transport,
            synthetic=synthetic,
            bundle_prefix=bundle_prefix,
            output_root_descriptor=output_root_descriptor,
        )
    finally:
        os.close(output_root_descriptor)


def execute_synthetic(
    *,
    package: VerifiedPackage,
    identity_authorization: OneShotAuthorization,
    generation_authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
    transport: FakeTransport,
    bundle_prefix: str,
) -> ExecutionResult:
    """Exercise the full runner with a no-socket fake and synthetic evidence labels."""
    return _execute(
        package=package,
        identity_authorization=identity_authorization,
        generation_authorization=generation_authorization,
        output_root=output_root,
        runtime_artifact=runtime_artifact,
        model_manifest=model_manifest,
        blob_root=blob_root,
        transport=transport,
        synthetic=True,
        bundle_prefix=bundle_prefix,
    )


def execute_observed(
    *,
    package: VerifiedPackage,
    identity_authorization: OneShotAuthorization,
    generation_authorization: OneShotAuthorization,
    output_root: Path,
    runtime_artifact: Path,
    model_manifest: Path,
    blob_root: Path,
) -> ExecutionResult:
    """Execute exactly one authorized study against the pinned loopback endpoint."""
    return _execute(
        package=package,
        identity_authorization=identity_authorization,
        generation_authorization=generation_authorization,
        output_root=output_root,
        runtime_artifact=runtime_artifact,
        model_manifest=model_manifest,
        blob_root=blob_root,
        transport=LoopbackHTTPTransport(package.endpoint),
        synthetic=False,
        bundle_prefix="localinferencelab-ollama-observed-v1",
    )


@dataclass(frozen=True, slots=True)
class OllamaReplayResult:
    """Strict offline replay summary for one terminal Ollama evidence bundle."""

    bundle_root: str
    package_id: str
    status: Literal["accepted", "invalid", "refused"]
    evidence_kind: str
    action_count: int
    inference_request_count: int
    run_validity: str | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "package_id": self.package_id,
            "status": self.status,
            "evidence_kind": self.evidence_kind,
            "action_count": self.action_count,
            "inference_request_count": self.inference_request_count,
            "run_validity": self.run_validity,
        }


def _canonical_bundle_value(file_bytes: Mapping[str, bytes], name: str) -> JsonValue:
    try:
        data = file_bytes[name]
    except KeyError as error:
        raise ContractError(f"Ollama evidence bundle is missing {name}") from error
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{name} is not canonical JSON")
    return value


def _validate_action_log(
    package: VerifiedPackage,
    action_log: Mapping[str, JsonValue],
    *,
    synthetic: bool,
    preflight: bool,
) -> tuple[list[dict[str, JsonValue]], int, int]:
    common_fields = {
        "record_type",
        "schema_version",
        "package_id",
        "actions",
        "request_bytes_consumed",
        "response_bytes_consumed",
        "response_budget_reserved",
        "network_requests_consumed",
        "identity_requests_consumed",
        "inference_requests_consumed",
    }
    if preflight:
        common_fields.add("authorization_id")
    _keys(action_log, common_fields, "ollama_action_log")
    expected_type = "ollama_preflight_action_log" if preflight else "ollama_action_log"
    if (
        action_log["record_type"] != expected_type
        or action_log["schema_version"] != SCHEMA_VERSION
        or action_log["package_id"] != package.identity
    ):
        raise ContractError("Ollama action log identity drift")
    values = _list(action_log["actions"], "ollama_action_log.actions")
    if not values:
        raise ContractError("Ollama evidence must contain at least one authorized action")
    actions: list[dict[str, JsonValue]] = []
    request_bytes = response_bytes = reserved_bytes = 0
    identity_requests = inference_requests = 0
    for index, item in enumerate(values):
        action = _mapping(item, f"ollama_action_log.actions[{index}]")
        _keys(
            action,
            {
                "sequence",
                "phase",
                "operation",
                "method",
                "path",
                "request_sha256",
                "request_size_bytes",
                "response_sha256",
                "response_size_bytes",
                "response_complete",
                "http_status",
                "content_type",
                "outcome",
                "error_sha256",
                "loopback_network_side_effect",
                "elapsed_ns",
            },
            f"ollama_action_log.actions[{index}]",
        )
        sequence = _integer(action["sequence"], "action.sequence", minimum=1)
        if sequence != index + 1:
            raise ContractError("Ollama action log must be an ordered schedule prefix")
        planned = package.actions[index]
        for field in ("sequence", "phase", "operation", "method", "path", "request_sha256"):
            if action[field] != planned[field]:
                raise ContractError("Ollama action log does not match the frozen schedule")
        request_size = _integer(action["request_size_bytes"], "action.request_size_bytes")
        response_size = _integer(action["response_size_bytes"], "action.response_size_bytes")
        if request_size != planned["request_size_bytes"] or response_size > _integer(
            planned["response_read_budget_bytes"],
            "planned.response_read_budget_bytes",
        ):
            raise ContractError("Ollama action log byte accounting drift")
        if not isinstance(action["response_complete"], bool):
            raise ContractError("Ollama action response_complete must be Boolean")
        elapsed_ns = _integer(action["elapsed_ns"], "action.elapsed_ns")
        if synthetic and (action["loopback_network_side_effect"] is not False or elapsed_ns != 0):
            raise ContractError("synthetic Ollama evidence cannot claim network or timing")
        if not synthetic and action["loopback_network_side_effect"] is not True:
            raise ContractError("observed Ollama action lacks loopback side-effect accounting")
        outcome = _literal(
            action["outcome"],
            {"transport_failure", "response_received"},
            "action.outcome",
        )
        response_sha = action["response_sha256"]
        if outcome == "response_received":
            _sha256(response_sha, "action.response_sha256")
            if action["error_sha256"] is not None or action["response_complete"] is not True:
                raise ContractError("successful Ollama action has inconsistent custody")
            _integer(action["http_status"], "action.http_status", minimum=100)
            _text(action["content_type"], "action.content_type")
        else:
            _sha256(action["error_sha256"], "action.error_sha256")
            if response_size == 0:
                if response_sha is not None:
                    raise ContractError("empty failed response cannot have a digest")
            else:
                _sha256(response_sha, "action.response_sha256")
            if action["http_status"] is not None:
                _integer(action["http_status"], "action.http_status", minimum=100)
            if action["content_type"] is not None:
                _text(action["content_type"], "action.content_type")
        operation = cast("str", action["operation"])
        request_bytes += request_size
        response_bytes += response_size
        reserved_bytes += cast("int", planned["response_read_budget_bytes"])
        identity_requests += int(operation in _IDENTITY_OPERATIONS)
        inference_requests += int(operation == "generate")
        actions.append(action)
    expected_counts = {
        "request_bytes_consumed": request_bytes,
        "response_bytes_consumed": response_bytes,
        "response_budget_reserved": reserved_bytes,
        "network_requests_consumed": len(actions),
        "identity_requests_consumed": identity_requests,
        "inference_requests_consumed": inference_requests,
    }
    if any(action_log[key] != value for key, value in expected_counts.items()):
        raise ContractError("Ollama action log totals do not match its ordered actions")
    return actions, identity_requests, inference_requests


def _validate_identity_snapshot(
    value: JsonValue,
    package: VerifiedPackage,
    phase: str,
    *,
    require_declared_load_state: bool,
) -> dict[str, JsonValue]:
    snapshot = _mapping(value, f"{phase}_identity")
    _keys(snapshot, {"record_type", "schema_version", "phase", "projection"}, "identity")
    if (
        snapshot["record_type"] != "ollama_identity_snapshot"
        or snapshot["schema_version"] != SCHEMA_VERSION
        or snapshot["phase"] != phase
    ):
        raise ContractError("Ollama identity snapshot metadata drift")
    projection = _mapping(snapshot["projection"], "identity.projection")
    _keys(
        projection,
        {
            "runtime_version",
            "model_manifest_digest",
            "show_projection",
            "model_loaded",
            "selected_runner",
            "metal_state",
        },
        "identity.projection",
    )
    expected_immutable: dict[str, JsonValue] = {
        "runtime_version": package.runtime.version,
        "model_manifest_digest": package.model_artifact.manifest_digest,
        "show_projection": package.value["show_projection"],
        "selected_runner": _runtime_fact(package.runtime, "runner"),
        "metal_state": _runtime_fact(package.runtime, "metal"),
    }
    if any(projection[key] != expected for key, expected in expected_immutable.items()):
        raise ContractError("Ollama identity snapshot is not bound to the package")
    if not isinstance(projection["model_loaded"], bool):
        raise ContractError("Ollama identity snapshot load state must be Boolean")
    if require_declared_load_state and projection["model_loaded"] is not False:
        raise ContractError("accepted Ollama identity snapshot violates cache state")
    return projection


def _validate_run_static(
    run: RunRecord,
    package: VerifiedPackage,
    *,
    synthetic: bool,
) -> None:
    process = ProcessInstance.from_dict(_mapping(package.value["process"], "process"))
    model_instance = ModelInstance.from_dict(
        _mapping(package.value["model_instance"], "model_instance")
    )
    cache = _mapping(package.value["cache_contract"], "cache_contract")
    concurrency = ConcurrencyIdentity.from_dict(
        _mapping(package.value["concurrency"], "concurrency")
    )
    protocol = _mapping(package.value["protocol"], "protocol")
    expected: dict[str, object] = {
        "run_id": protocol["run_id"],
        "run_order": 1,
        "backend": "ollama",
        "protocol_id": package.protocol_id,
        "runtime_id": record_id(package.runtime),
        "model_id": record_id(package.model),
        "host_id": record_id(package.host),
        "declaration_id": package.declaration_id,
        "process_instance_id": record_id(process),
        "model_instance_id": record_id(model_instance),
        "cache_preparation_id": canonical_identity(cache),
        "concurrency_id": record_id(concurrency),
        "concurrency_wave": 1,
        "cache_cohort": "cold_model_warm_process",
        "evidence_kind": "synthetic_fixture" if synthetic else "observed_execution",
        "model_process_start_count": 0,
        "inference_request_count": 0 if synthetic else 1,
        "request_sha256": digest_bytes(package.request),
        "request_base64": encode_bytes(package.request),
    }
    if any(getattr(run, field) != value for field, value in expected.items()):
        raise ContractError("Ollama run record does not match every prospective identity")


def _replay_preflight(
    content_root: str,
    file_bytes: Mapping[str, bytes],
    content_names: set[str],
) -> OllamaReplayResult:
    required = {
        "source/ollama-preflight.json",
        "prospective.json",
        "authorization/preflight.json",
        "actions.json",
        "terminal.json",
    }
    allowed = required | {"identity/preflight.json"}
    if not required.issubset(content_names) or not content_names.issubset(allowed):
        raise ContractError("Ollama preflight bundle has an invalid content set")
    package = verify_prospective_package(_canonical_bundle_value(file_bytes, "prospective.json"))
    source = _mapping(
        _canonical_bundle_value(file_bytes, "source/ollama-preflight.json"),
        "ollama_preflight_source",
    )
    _keys(
        source,
        {
            "record_type",
            "schema_version",
            "evidence_kind",
            "read_only_identity_calls",
            "inference_requests",
            "model_process_starts",
            "downloads",
            "external_network_actions",
        },
        "ollama_preflight_source",
    )
    evidence_kind = _literal(
        source["evidence_kind"],
        {
            "synthetic_transport_contract_evidence",
            "observed_loopback_identity_preflight",
        },
        "ollama_preflight_source.evidence_kind",
    )
    synthetic = evidence_kind == "synthetic_transport_contract_evidence"
    authorization = _authorization_from_value(
        _canonical_bundle_value(file_bytes, "authorization/preflight.json")
    )
    _verify_authorization(package, authorization, "preflight_only")
    action_log = _mapping(_canonical_bundle_value(file_bytes, "actions.json"), "actions")
    actions, _identity_requests, inference_requests = _validate_action_log(
        package, action_log, synthetic=synthetic, preflight=True
    )
    terminal = _mapping(_canonical_bundle_value(file_bytes, "terminal.json"), "terminal")
    _keys(
        terminal,
        {
            "record_type",
            "schema_version",
            "package_id",
            "authorization_id",
            "status",
            "reason_sha256",
            "generation_path_called",
            "model_action_performed",
        },
        "ollama_preflight_terminal",
    )
    status = _literal(terminal["status"], {"accepted", "refused"}, "terminal.status")
    if (
        terminal["record_type"] != "ollama_preflight_terminal"
        or terminal["schema_version"] != SCHEMA_VERSION
        or terminal["package_id"] != package.identity
        or terminal["authorization_id"] != authorization.identity
        or action_log["authorization_id"] != authorization.identity
        or terminal["generation_path_called"] is not False
        or terminal["model_action_performed"] is not False
        or inference_requests != 0
        or source["read_only_identity_calls"] != len(actions)
        or source["inference_requests"] != 0
        or source["model_process_starts"] != 0
        or source["downloads"] != 0
        or source["external_network_actions"] != 0
    ):
        raise ContractError("Ollama preflight terminal or source accounting drift")
    if status == "accepted":
        if len(actions) != _IDENTITY_ACTION_COUNT or any(
            action["outcome"] != "response_received" for action in actions
        ):
            raise ContractError("accepted Ollama preflight did not complete its exact schedule")
        if terminal["reason_sha256"] is not None:
            raise ContractError("accepted Ollama preflight cannot contain a refusal reason")
        _validate_identity_snapshot(
            _canonical_bundle_value(file_bytes, "identity/preflight.json"),
            package,
            "preflight",
            require_declared_load_state=True,
        )
    else:
        _sha256(terminal["reason_sha256"], "terminal.reason_sha256")
        if len(actions) > _IDENTITY_ACTION_COUNT or "identity/preflight.json" in content_names:
            raise ContractError("refused Ollama preflight has impossible custody")
    return OllamaReplayResult(
        content_root,
        package.identity,
        cast("Literal['accepted', 'refused']", status),
        evidence_kind,
        len(actions),
        0,
        None,
    )


def replay_ollama_bundle(bundle: Path) -> OllamaReplayResult:
    """Replay one closed Ollama execution or preflight bundle entirely offline."""
    content_root, file_bytes = read_closed_bundle(bundle)
    content_names = set(file_bytes) - {"index.json", "receipt.json"}
    if "source/ollama-preflight.json" in content_names:
        return _replay_preflight(content_root, file_bytes, content_names)
    required = {
        "source/ollama.json",
        "prospective.json",
        "authorization/identity.json",
        "actions.json",
        "terminal.json",
    }
    allowed = required | {
        "authorization/generation.json",
        "identity/pre.json",
        "identity/post.json",
        "responses/generation.bin",
        "runs/0001.json",
    }
    if not required.issubset(content_names) or not content_names.issubset(allowed):
        raise ContractError("Ollama evidence bundle has an invalid content set")
    package = verify_prospective_package(_canonical_bundle_value(file_bytes, "prospective.json"))
    source = _mapping(
        _canonical_bundle_value(file_bytes, "source/ollama.json"),
        "ollama_evidence_source",
    )
    _keys(
        source,
        {
            "record_type",
            "schema_version",
            "evidence_kind",
            "implementation_evidence_only",
            "performance_evidence",
            "external_network_actions",
            "model_downloads",
            "model_process_starts",
        },
        "ollama_evidence_source",
    )
    evidence_kind = _literal(
        source["evidence_kind"],
        {"synthetic_transport_contract_evidence", "observed_execution"},
        "ollama_evidence_source.evidence_kind",
    )
    synthetic = evidence_kind == "synthetic_transport_contract_evidence"
    if not synthetic:
        raise ContractError(
            "observed execution replay is disabled until attestation is required by schema"
        )
    if (
        source["record_type"] != "ollama_evidence_source"
        or source["schema_version"] != SCHEMA_VERSION
        or source["implementation_evidence_only"] is not synthetic
        or source["performance_evidence"] is not False
        or source["external_network_actions"] != 0
        or source["model_downloads"] != 0
        or source["model_process_starts"] != 0
    ):
        raise ContractError("Ollama evidence source non-claims are inconsistent")
    action_log = _mapping(_canonical_bundle_value(file_bytes, "actions.json"), "actions")
    actions, identity_requests, inference_requests = _validate_action_log(
        package, action_log, synthetic=synthetic, preflight=False
    )
    identity_authorization = _authorization_from_value(
        _canonical_bundle_value(file_bytes, "authorization/identity.json")
    )
    _verify_authorization(package, identity_authorization, "identity_guard")
    terminal = _mapping(_canonical_bundle_value(file_bytes, "terminal.json"), "terminal")
    terminal_fields = {
        "record_type",
        "schema_version",
        "status",
        "reason_sha256",
        "evidence_kind",
        "performance_claim",
        "model_quality_claim",
        "determinism_claim",
        "package_id",
        "protocol_id",
        "declaration_id",
        "identity_authorization_id",
        "generation_authorization_id",
        "scheduled_runs",
        "completed_runs",
        "logical_identity_requests",
        "logical_inference_requests",
        "physical_network_requests",
        "physical_model_inferences",
        "model_process_starts",
        "downloads",
        "retries",
    }
    _keys(terminal, terminal_fields, "ollama_execution_terminal")
    status = _literal(terminal["status"], {"accepted", "invalid", "refused"}, "terminal.status")
    if (
        terminal["record_type"] != "ollama_execution_terminal"
        or terminal["schema_version"] != SCHEMA_VERSION
        or terminal["evidence_kind"] != evidence_kind
        or terminal["package_id"] != package.identity
        or terminal["protocol_id"] != package.protocol_id
        or terminal["declaration_id"] != package.declaration_id
        or terminal["identity_authorization_id"] != identity_authorization.identity
        or terminal["performance_claim"] != "none"
        or terminal["model_quality_claim"] != "none"
        or terminal["determinism_claim"] != "none"
        or terminal["scheduled_runs"] != 1
        or terminal["logical_identity_requests"] != identity_requests
        or terminal["logical_inference_requests"] != inference_requests
        or terminal["physical_network_requests"] != (0 if synthetic else len(actions))
        or terminal["physical_model_inferences"] != (0 if synthetic else inference_requests)
        or terminal["model_process_starts"] != 0
        or terminal["downloads"] != 0
        or terminal["retries"] != 0
    ):
        raise ContractError("Ollama terminal accounting or identity drift")
    generation_authorization: OneShotAuthorization | None = None
    if "authorization/generation.json" in content_names:
        generation_authorization = _authorization_from_value(
            _canonical_bundle_value(file_bytes, "authorization/generation.json")
        )
        _verify_authorization(package, generation_authorization, "generation")
        if terminal["generation_authorization_id"] != generation_authorization.identity:
            raise ContractError("Ollama generation authorization linkage drift")
    elif terminal["generation_authorization_id"] is not None:
        raise ContractError("Ollama terminal refers to a missing generation authorization")
    run: RunRecord | None = None
    if "runs/0001.json" in content_names:
        run = RunRecord.from_dict(
            _mapping(_canonical_bundle_value(file_bytes, "runs/0001.json"), "run")
        )
        _validate_run_static(run, package, synthetic=synthetic)
    if status == "accepted":
        if (
            len(actions) != _ACTION_COUNT
            or any(action["outcome"] != "response_received" for action in actions)
            or generation_authorization is None
            or run is None
            or run.validity != "valid"
            or terminal["reason_sha256"] is not None
        ):
            raise ContractError("accepted Ollama execution lacks exact completed custody")
        pre = _validate_identity_snapshot(
            _canonical_bundle_value(file_bytes, "identity/pre.json"),
            package,
            "pre",
            require_declared_load_state=True,
        )
        post = _validate_identity_snapshot(
            _canonical_bundle_value(file_bytes, "identity/post.json"),
            package,
            "post",
            require_declared_load_state=True,
        )
        if pre != post:
            raise ContractError("accepted Ollama evidence contains identity drift")
        if run.envelope_base64 is None or "responses/generation.bin" not in content_names:
            raise ContractError("accepted Ollama run lacks its exact response envelope")
        envelope = decode_bytes(run.envelope_base64)
        if file_bytes["responses/generation.bin"] != envelope:
            raise ContractError("accepted Ollama response file drift")
        generate_action = actions[4]
        if (
            run.envelope_sha256 != digest_bytes(envelope)
            or generate_action["response_sha256"] != digest_bytes(envelope)
            or generate_action["response_size_bytes"] != len(envelope)
        ):
            raise ContractError("Ollama action 5 does not bind the accepted envelope")
        regenerated = _parse_generate_response(
            package,
            TransportResponse(
                cast("int", generate_action["http_status"]),
                cast("str", generate_action["content_type"]),
                envelope,
                package.endpoint.host,
            ),
            synthetic=synthetic,
            declaration_id=package.declaration_id,
            invalid_reason=None,
        )
        if regenerated.to_dict() != run.to_dict():
            raise ContractError("accepted Ollama run projection does not replay")
    elif status == "invalid":
        if (
            len(actions) < _GENERATION_SEQUENCE + 1
            or actions[_GENERATION_SEQUENCE - 1]["operation"] != "generate"
            or generation_authorization is None
            or run is None
            or run.validity != "invalid"
            or "identity/pre.json" not in content_names
            or any(
                action["outcome"] != "response_received"
                for action in actions[:_IDENTITY_ACTION_COUNT]
            )
        ):
            raise ContractError("invalid Ollama execution lacks dispatched-run custody")
        post_actions = actions[_GENERATION_SEQUENCE:]
        if any(action["outcome"] != "response_received" for action in post_actions[:-1]):
            raise ContractError("invalid Ollama post schedule continued after a failure")
        if (
            len(post_actions) < _IDENTITY_ACTION_COUNT
            and post_actions[-1]["outcome"] != "transport_failure"
        ):
            raise ContractError("invalid Ollama post schedule stopped without a failure")
        terminal_reason = _sha256(terminal["reason_sha256"], "terminal.reason_sha256")
        if run.invalid_reason_sha256 != terminal_reason:
            raise ContractError("invalid Ollama run and terminal reason drift")
        _validate_identity_snapshot(
            _canonical_bundle_value(file_bytes, "identity/pre.json"),
            package,
            "pre",
            require_declared_load_state=True,
        )
        if "identity/post.json" in content_names:
            if len(actions) != _ACTION_COUNT or any(
                action["outcome"] != "response_received" for action in post_actions
            ):
                raise ContractError("post identity snapshot requires the complete post schedule")
            _validate_identity_snapshot(
                _canonical_bundle_value(file_bytes, "identity/post.json"),
                package,
                "post",
                require_declared_load_state=False,
            )
        generate_action = actions[_GENERATION_SEQUENCE - 1]
        if "responses/generation.bin" in content_names:
            envelope = file_bytes["responses/generation.bin"]
            if generate_action["response_sha256"] != digest_bytes(envelope) or generate_action[
                "response_size_bytes"
            ] != len(envelope):
                raise ContractError("invalid Ollama run envelope custody drift")
            if run.envelope_base64 is not None or run.envelope_sha256 is not None:
                raise ContractError("invalid Ollama run partially trusted response fields")
        elif (
            generate_action["outcome"] == "response_received"
            or generate_action["response_size_bytes"] != 0
        ):
            raise ContractError("invalid Ollama response bytes were not preserved")
    else:
        if (
            len(actions) > _IDENTITY_ACTION_COUNT
            or inference_requests != 0
            or generation_authorization is not None
            or run is not None
            or "identity/post.json" in content_names
            or "responses/generation.bin" in content_names
        ):
            raise ContractError("refused Ollama execution crossed the generation boundary")
        _sha256(terminal["reason_sha256"], "terminal.reason_sha256")
        if "identity/pre.json" in content_names:
            _validate_identity_snapshot(
                _canonical_bundle_value(file_bytes, "identity/pre.json"),
                package,
                "pre",
                require_declared_load_state=False,
            )
    if terminal["completed_runs"] != (0 if run is None else 1):
        raise ContractError("Ollama terminal completed-run accounting drift")
    return OllamaReplayResult(
        content_root,
        package.identity,
        cast("Literal['accepted', 'invalid', 'refused']", status),
        evidence_kind,
        len(actions),
        inference_requests,
        None if run is None else run.validity,
    )
