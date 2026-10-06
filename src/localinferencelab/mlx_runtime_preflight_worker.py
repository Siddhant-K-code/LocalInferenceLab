"""Sealed runtime-only MLX preflight worker."""

from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import importlib
import importlib.metadata
import json
import os
import socket
import stat
import struct
import sys
import sysconfig
import time
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

SCHEMA_VERSION = "1.0"
WORKER_FD = 3
INTERPRETER_IDENTITY_FD = 4
RUNTIME_ROOT_FD = 5
MAX_FRAME_BYTES = 1024 * 1024
MAX_IMPORTED_MODULES = 4_096
AUTHORIZATION_LIFETIME_NS = 30_000_000_000
RUNTIME_ROOT_DESCRIPTOR_PATH = f"/proc/self/fd/{RUNTIME_ROOT_FD}"
ALLOWED_PROBES = (
    "default_device",
    "default_stream",
    "distribution_versions",
    "import_mlx",
    "import_mlx_lm",
    "metal_is_available",
    "synchronize",
)
_EXPECTED_ENVIRONMENT = {
    "HF_HUB_OFFLINE": "1",
    "LC_ALL": "C",
    "MLXLM_USE_MODELSCOPE": "False",
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
    "TOKENIZERS_PARALLELISM": "false",
    "TRANSFORMERS_OFFLINE": "1",
    "TZ": "UTC",
}
_ENVIRONMENT_DESCRIPTOR = {
    "explicit": [
        {"name": name, "value": value} for name, value in sorted(_EXPECTED_ENVIRONMENT.items())
    ],
    "platform_injected": ("__CF_USER_TEXT_ENCODING=current_effective_uid_encoding_on_darwin_only"),
}
PROTOCOL_DESCRIPTOR = {
    "record_type": "mlx_runtime_preflight_protocol",
    "schema_version": SCHEMA_VERSION,
    "transport": "parent_created_inherited_private_af_unix_socketpair",
    "worker_fd": WORKER_FD,
    "transient_interpreter_identity_fd": INTERPRETER_IDENTITY_FD,
    "retained_runtime_root_fd": RUNTIME_ROOT_FD,
    "framing": "uint32_be_length_then_canonical_json",
    "max_frame_bytes": MAX_FRAME_BYTES,
    "sequence": [
        "parent_hello",
        "worker_identity",
        "authorize_once",
        "authorization_ack",
        "preflight_once",
        "preflight_result",
        "shutdown",
        "shutdown_ack",
    ],
    "action": "mlx_runtime_preflight_only",
    "allowed_probes": list(ALLOWED_PROBES),
    "attempts": 1,
    "retries": 0,
    "warmups": 0,
    "concurrency": 1,
}
WORKER_DESCRIPTOR = {
    "record_type": "mlx_runtime_preflight_worker_code",
    "schema_version": SCHEMA_VERSION,
    "protocol_id": "",
    "action": "mlx_runtime_preflight_only",
    "imports": ["mlx", "mlx_lm"],
    "allowed_probes": list(ALLOWED_PROBES),
    "model_load_surface": False,
    "tokenizer_load_surface": False,
    "generation_surface": False,
    "download_surface": False,
    "cache_mutation_surface": False,
    "benchmark_surface": False,
    "arbitrary_command_surface": False,
}
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_SURROGATE_START = 0xD800
_SURROGATE_END = 0xDFFF
_MAX_TEXT_BYTES = 4096
_NONCE_BYTES = 32
_READ_CHUNK = 1024 * 1024
_FORBIDDEN_ACTION_COUNT = 10
_AUDIT_OPEN_MODE_INDEX = 1
_AUDIT_OPEN_FLAGS_INDEX = 2
_MAX_REPRESENTATION_BYTES = 256
_SAFE_REPRESENTATION_CHARACTERS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_(), .=:-"
)


class WorkerProtocolError(ValueError):
    """Raised when the parent or runtime violates the sealed protocol."""


def _reject_float(_value: str) -> NoReturn:
    raise WorkerProtocolError("floating-point JSON numbers are forbidden")


def _reject_constant(value: str) -> NoReturn:
    raise WorkerProtocolError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_json(value: object, path: str = "$") -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if any(_SURROGATE_START <= ord(character) <= _SURROGATE_END for character in value):
            raise WorkerProtocolError(f"{path}: Unicode surrogate code points are forbidden")
        return value
    if isinstance(value, float):
        raise WorkerProtocolError(f"{path}: floating-point values are forbidden")
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise WorkerProtocolError(f"{path}: object keys must be strings")
            output[key] = _validate_json(item, f"{path}.{key}")
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_validate_json(item, f"{path}[{index}]") for index, item in enumerate(value)]
    raise WorkerProtocolError(f"{path}: unsupported JSON type {type(value).__name__}")


def _canonical_json(value: object) -> bytes:
    checked = _validate_json(value)
    return json.dumps(
        checked,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_identity(value: object) -> str:
    return _digest_bytes(_canonical_json(value))


PROTOCOL_ID = _canonical_identity(PROTOCOL_DESCRIPTOR)
WORKER_DESCRIPTOR["protocol_id"] = PROTOCOL_ID
WORKER_CODE_ID = _canonical_identity(WORKER_DESCRIPTOR)
ENVIRONMENT_ID = _canonical_identity(_ENVIRONMENT_DESCRIPTOR)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkerProtocolError(f"{label} must be an object")
    return value


def _keys(value: dict[str, object], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise WorkerProtocolError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise WorkerProtocolError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: object, label: str, *, maximum: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise WorkerProtocolError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise WorkerProtocolError(f"{label} exceeds its byte bound")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise WorkerProtocolError(f"{label} contains control characters")
    return value


def _integer(
    value: object,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise WorkerProtocolError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise WorkerProtocolError(f"{label} must be <= {maximum}")
    return value


def _sha256(value: object, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise WorkerProtocolError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _nonce(value: object, label: str) -> str:
    text = _text(value, label)
    padding = "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(text + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as error:
        raise WorkerProtocolError(f"{label} must be canonical URL-safe base64") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != text or len(decoded) != _NONCE_BYTES:
        raise WorkerProtocolError(f"{label} must encode exactly 32 bytes")
    return text


def _parse_canonical(data: bytes) -> dict[str, object]:
    try:
        text = data.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkerProtocolError("frame payload must be strict UTF-8 JSON") from error
    value = _mapping(_validate_json(parsed), "frame")
    if _canonical_json(value) != data:
        raise WorkerProtocolError("frame payload must use canonical JSON bytes")
    return value


class _Channel:
    def __init__(self, endpoint: socket.socket, deadline_ns: int) -> None:
        self.endpoint = endpoint
        self.deadline_ns = deadline_ns

    def remaining_seconds(self) -> float:
        remaining = self.deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            raise WorkerProtocolError("absolute protocol deadline expired")
        return remaining / 1_000_000_000

    def _read_exact(self, size: int, label: str) -> bytes:
        blocks = bytearray()
        while len(blocks) < size:
            self.endpoint.settimeout(self.remaining_seconds())
            try:
                block = self.endpoint.recv(size - len(blocks))
            except TimeoutError as error:
                raise WorkerProtocolError("absolute protocol deadline expired") from error
            if not block:
                if not blocks:
                    raise WorkerProtocolError(f"peer EOF before {label}")
                raise WorkerProtocolError(f"truncated {label}")
            blocks.extend(block)
        return bytes(blocks)

    def receive(self) -> dict[str, object]:
        header = self._read_exact(4, "frame header")
        length = struct.unpack(">I", header)[0]
        if length == 0 or length > MAX_FRAME_BYTES:
            raise WorkerProtocolError("frame length is outside its fixed bound")
        return _parse_canonical(self._read_exact(length, "frame payload"))

    def send(self, value: dict[str, object]) -> None:
        payload = _canonical_json(value)
        if not payload or len(payload) > MAX_FRAME_BYTES:
            raise WorkerProtocolError("outbound frame length is outside its fixed bound")
        self.endpoint.settimeout(self.remaining_seconds())
        try:
            self.endpoint.sendall(struct.pack(">I", len(payload)) + payload)
        except TimeoutError as error:
            raise WorkerProtocolError("absolute protocol deadline expired") from error


def _expect_message(
    value: dict[str, object],
    message_type: str,
    sequence: int,
    fields: set[str],
) -> None:
    _keys(value, fields | {"message_type", "sequence"}, message_type)
    if value["message_type"] != message_type:
        raise WorkerProtocolError(f"expected {message_type}")
    if _integer(value["sequence"], f"{message_type}.sequence", minimum=1) != sequence:
        raise WorkerProtocolError(f"{message_type} has wrong sequence")


def _hash_descriptor(
    descriptor: int,
    basename: str,
    *,
    executable: bool,
) -> dict[str, object]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise WorkerProtocolError("launch target must be a regular file")
    if executable and before.st_mode & 0o111 == 0:
        raise WorkerProtocolError("interpreter launch target must be executable")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while block := os.read(descriptor, _READ_CHUNK):
        digest.update(block)
        total += len(block)
    after = os.fstat(descriptor)
    stable_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    stable_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if total != before.st_size or stable_before != stable_after:
        raise WorkerProtocolError("launch target changed while it was hashed")
    return {
        "basename": basename,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "size_bytes": before.st_size,
        "sha256": f"sha256:{digest.hexdigest()}",
    }


def _runtime_root_identity() -> dict[str, object]:
    metadata = os.fstat(RUNTIME_ROOT_FD)
    if not stat.S_ISDIR(metadata.st_mode):
        raise WorkerProtocolError("runtime root descriptor must reference a directory")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


def _open_file_descriptors() -> list[int]:
    proc_fds = Path("/proc/self/fd")
    directory = proc_fds if proc_fds.is_dir() else Path("/dev/fd")
    try:
        candidates = [int(item.name) for item in directory.iterdir() if item.name.isdigit()]
    except OSError as error:
        raise WorkerProtocolError("worker cannot enumerate its descriptor table") from error
    result: list[int] = []
    for descriptor in sorted(set(candidates)):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        result.append(descriptor)
    return result


def _verify_hello(value: dict[str, object]) -> dict[str, object]:
    fields = {
        "protocol_id",
        "worker_code_id",
        "preflight_spec_id",
        "preflight_package_id",
        "preflight_package_sha256",
        "runtime_manifest_id",
        "runtime_manifest_sha256",
        "install_receipt_id",
        "interpreter_sha256",
        "worker_program_sha256",
        "parent_nonce",
        "output_root_id",
        "deadline_monotonic_ns",
    }
    _expect_message(value, "parent_hello", 1, fields)
    if _sha256(value["protocol_id"], "parent_hello.protocol_id") != PROTOCOL_ID:
        raise WorkerProtocolError("parent protocol identity mismatch")
    if _sha256(value["worker_code_id"], "parent_hello.worker_code_id") != WORKER_CODE_ID:
        raise WorkerProtocolError("parent worker-code identity mismatch")
    for field in fields - {"parent_nonce", "deadline_monotonic_ns"}:
        _sha256(value[field], f"parent_hello.{field}")
    _nonce(value["parent_nonce"], "parent_hello.parent_nonce")
    deadline = _integer(
        value["deadline_monotonic_ns"],
        "parent_hello.deadline_monotonic_ns",
        minimum=1,
    )
    if deadline <= time.monotonic_ns():
        raise WorkerProtocolError("parent hello deadline has expired")
    return value


def _verify_authorization(
    value: dict[str, object],
    hello: dict[str, object],
    worker_nonce: str,
) -> tuple[dict[str, object], str]:
    _expect_message(value, "authorize_once", 3, {"authorization"})
    authorization = _mapping(value["authorization"], "authorization")
    fields = {
        "record_type",
        "schema_version",
        "action",
        "allowed_probes",
        "forbidden_actions",
        "preflight_spec_id",
        "preflight_package_id",
        "preflight_package_sha256",
        "runtime_manifest_id",
        "runtime_manifest_sha256",
        "install_receipt_id",
        "interpreter_sha256",
        "worker_program_sha256",
        "protocol_id",
        "worker_code_id",
        "parent_nonce",
        "worker_nonce",
        "output_root_id",
        "created_at_unix_ns",
        "expires_at_unix_ns",
        "deadline_monotonic_ns",
        "authorization_id",
    }
    _keys(authorization, fields, "authorization")
    if (
        authorization["record_type"] != "mlx_runtime_preflight_one_shot_authorization"
        or authorization["schema_version"] != SCHEMA_VERSION
        or authorization["action"] != "mlx_runtime_preflight_only"
        or authorization["allowed_probes"] != list(ALLOWED_PROBES)
    ):
        raise WorkerProtocolError("unsupported runtime-preflight authorization")
    forbidden = authorization["forbidden_actions"]
    if (
        not isinstance(forbidden, list)
        or forbidden != sorted(forbidden)
        or len(forbidden) != _FORBIDDEN_ACTION_COUNT
    ):
        raise WorkerProtocolError("authorization forbidden-action set mismatch")
    expected = {
        "preflight_spec_id": hello["preflight_spec_id"],
        "preflight_package_id": hello["preflight_package_id"],
        "preflight_package_sha256": hello["preflight_package_sha256"],
        "runtime_manifest_id": hello["runtime_manifest_id"],
        "runtime_manifest_sha256": hello["runtime_manifest_sha256"],
        "install_receipt_id": hello["install_receipt_id"],
        "interpreter_sha256": hello["interpreter_sha256"],
        "worker_program_sha256": hello["worker_program_sha256"],
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": worker_nonce,
        "output_root_id": hello["output_root_id"],
        "deadline_monotonic_ns": hello["deadline_monotonic_ns"],
    }
    for field, expected_value in expected.items():
        if authorization[field] != expected_value:
            raise WorkerProtocolError(f"authorization {field} mismatch")
    for field in (
        "preflight_spec_id",
        "preflight_package_id",
        "preflight_package_sha256",
        "runtime_manifest_id",
        "runtime_manifest_sha256",
        "install_receipt_id",
        "interpreter_sha256",
        "worker_program_sha256",
        "protocol_id",
        "worker_code_id",
        "output_root_id",
    ):
        _sha256(authorization[field], f"authorization.{field}")
    _nonce(authorization["parent_nonce"], "authorization.parent_nonce")
    _nonce(authorization["worker_nonce"], "authorization.worker_nonce")
    created = _integer(
        authorization["created_at_unix_ns"],
        "authorization.created_at_unix_ns",
        minimum=1,
    )
    expires = _integer(
        authorization["expires_at_unix_ns"],
        "authorization.expires_at_unix_ns",
        minimum=1,
    )
    deadline = _integer(
        authorization["deadline_monotonic_ns"],
        "authorization.deadline_monotonic_ns",
        minimum=1,
    )
    if expires != created + AUTHORIZATION_LIFETIME_NS:
        raise WorkerProtocolError("authorization has an unexpected wall-clock lifetime")
    if time.time_ns() >= expires or time.monotonic_ns() >= deadline:
        raise WorkerProtocolError("authorization has expired")
    authorization_id = _sha256(
        authorization["authorization_id"],
        "authorization.authorization_id",
    )
    content = dict(authorization)
    del content["authorization_id"]
    if authorization_id != _canonical_identity(content):
        raise WorkerProtocolError("authorization identity mismatch")
    return authorization, authorization_id


def _verify_preflight(
    value: dict[str, object],
    hello: dict[str, object],
    worker_nonce: str,
    authorization_id: str,
) -> str:
    fields = {
        "action",
        "allowed_probes",
        "authorization_id",
        "preflight_package_id",
        "runtime_manifest_id",
        "output_root_id",
        "parent_nonce",
        "worker_nonce",
        "request_nonce",
    }
    _expect_message(value, "preflight_once", 5, fields)
    expected = {
        "action": "mlx_runtime_preflight_only",
        "allowed_probes": list(ALLOWED_PROBES),
        "authorization_id": authorization_id,
        "preflight_package_id": hello["preflight_package_id"],
        "runtime_manifest_id": hello["runtime_manifest_id"],
        "output_root_id": hello["output_root_id"],
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": worker_nonce,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise WorkerProtocolError(f"preflight_once {field} mismatch")
    _nonce(value["request_nonce"], "preflight_once.request_nonce")
    return str(value["request_nonce"])


def _verify_shutdown(
    value: dict[str, object],
    parent_nonce: object,
    worker_nonce: str,
    request_nonce: str,
) -> None:
    fields = {"parent_nonce", "worker_nonce", "request_nonce"}
    _expect_message(value, "shutdown", 7, fields)
    if (
        value["parent_nonce"] != parent_nonce
        or value["worker_nonce"] != worker_nonce
        or value["request_nonce"] != request_nonce
    ):
        raise WorkerProtocolError("shutdown nonce mismatch")


class _RuntimeGuard:
    def __init__(self) -> None:
        self.blocked_actions = 0
        self.write_attempts = 0
        self.network_attempts = 0
        self.process_attempts = 0

    def __call__(self, event: str, args: tuple[object, ...]) -> None:
        if event in {
            "socket.bind",
            "socket.connect",
            "socket.connect_ex",
            "socket.getaddrinfo",
            "socket.gethostbyaddr",
            "socket.gethostbyname",
            "socket.gethostbyname_ex",
        }:
            self.blocked_actions += 1
            self.network_attempts += 1
            raise WorkerProtocolError("network actions are forbidden")
        if event in {
            "os.exec",
            "os.posix_spawn",
            "os.spawn",
            "os.system",
            "subprocess.Popen",
        }:
            self.blocked_actions += 1
            self.process_attempts += 1
            raise WorkerProtocolError("process and command actions are forbidden")
        if event in {
            "os.mkdir",
            "os.remove",
            "os.rename",
            "os.rmdir",
            "os.symlink",
            "os.truncate",
            "shutil.copyfile",
            "shutil.rmtree",
        }:
            self.blocked_actions += 1
            self.write_attempts += 1
            raise WorkerProtocolError("filesystem mutation is forbidden")
        if event == "open" and len(args) > _AUDIT_OPEN_MODE_INDEX:
            mode = args[_AUDIT_OPEN_MODE_INDEX]
            flags = args[_AUDIT_OPEN_FLAGS_INDEX] if len(args) > _AUDIT_OPEN_FLAGS_INDEX else 0
            mutating_mode = isinstance(mode, str) and any(
                item in mode for item in ("w", "a", "x", "+")
            )
            mutating_flags = isinstance(flags, int) and bool(
                flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            )
            if mutating_mode or mutating_flags:
                self.blocked_actions += 1
                self.write_attempts += 1
                raise WorkerProtocolError("filesystem mutation is forbidden")


def _safe_representation(value: object, label: str) -> str:
    representation = repr(value)
    if (
        not representation
        or len(representation.encode("utf-8")) > _MAX_REPRESENTATION_BYTES
        or any(character not in _SAFE_REPRESENTATION_CHARACTERS for character in representation)
    ):
        raise WorkerProtocolError(f"{label} representation is outside the privacy-safe grammar")
    return representation


def _bound_runtime_import_path() -> str:
    if sys.platform == "darwin":
        if not hasattr(fcntl, "F_GETPATH"):
            raise WorkerProtocolError("macOS interpreter lacks descriptor path resolution")
        raw = fcntl.fcntl(RUNTIME_ROOT_FD, fcntl.F_GETPATH, b"\0" * 1024)
        if not isinstance(raw, bytes):
            raise WorkerProtocolError("macOS descriptor path resolution returned invalid bytes")
        path = raw.split(b"\0", 1)[0].decode("utf-8", errors="strict")
    else:
        path = RUNTIME_ROOT_DESCRIPTOR_PATH
    resolved = Path(path)
    if not path or not resolved.is_absolute():
        raise WorkerProtocolError("bound runtime import path is not absolute")
    descriptor_metadata = os.fstat(RUNTIME_ROOT_FD)
    path_metadata = resolved.stat(follow_symlinks=True)
    if (descriptor_metadata.st_dev, descriptor_metadata.st_ino) != (
        path_metadata.st_dev,
        path_metadata.st_ino,
    ):
        raise WorkerProtocolError("resolved runtime import path differs from inherited descriptor")
    return path


def _relative_runtime_path(path: str, runtime_import_path: str) -> str | None:
    prefix = runtime_import_path + "/"
    if not path.startswith(prefix):
        return None
    relative = path[len(prefix) :]
    candidate = PurePosixPath(relative)
    if (
        not candidate.parts
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or candidate.as_posix() != relative
    ):
        raise WorkerProtocolError("runtime module path is not canonical")
    return relative


def _stdlib_roots() -> list[tuple[str, Path]]:
    paths = sysconfig.get_paths()
    roots: list[tuple[str, Path]] = []
    for kind in ("stdlib", "platstdlib"):
        value = paths.get(kind)
        if value is None:
            continue
        root = Path(value)
        if not root.is_absolute():
            raise WorkerProtocolError("stdlib root must be absolute")
        if all(root != existing for _label, existing in roots):
            roots.append((kind, root))
    if not roots:
        raise WorkerProtocolError("interpreter exposes no stdlib root")
    return roots


def _classify_stdlib_file(path: Path, roots: list[tuple[str, Path]]) -> tuple[str, str] | None:
    for kind, root in roots:
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        text = relative.as_posix()
        if not text or any(part in {"", ".", ".."} for part in relative.parts):
            raise WorkerProtocolError("stdlib module path is not canonical")
        return kind, text
    return None


def _hash_file_descriptor(descriptor: int) -> tuple[os.stat_result, str]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise WorkerProtocolError("imported module must be a regular file")
    digest = hashlib.sha256()
    total = 0
    while block := os.read(descriptor, _READ_CHUNK):
        total += len(block)
        digest.update(block)
    after = os.fstat(descriptor)
    if total != before.st_size or (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise WorkerProtocolError("imported module changed while it was hashed")
    return before, f"sha256:{digest.hexdigest()}"


def _open_runtime_file(relative: str) -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(relative, flags, dir_fd=RUNTIME_ROOT_FD)


def _file_module_record(
    name: str,
    path: str,
    stdlib_roots: list[tuple[str, Path]],
    runtime_import_path: str,
) -> dict[str, object]:
    relative = _relative_runtime_path(path, runtime_import_path)
    root_kind: str
    if relative is not None:
        descriptor = _open_runtime_file(relative)
        root_kind = "bound_runtime_root"
    else:
        absolute = Path(path)
        if not absolute.is_absolute():
            raise WorkerProtocolError("imported module file is neither bound-root nor absolute")
        classification = _classify_stdlib_file(absolute, stdlib_roots)
        if classification is None:
            raise WorkerProtocolError("imported module file escaped bound runtime and stdlib roots")
        root_kind, relative = classification
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(absolute, flags)
    try:
        metadata, digest = _hash_file_descriptor(descriptor)
    finally:
        os.close(descriptor)
    return {
        "name": name,
        "origin_kind": "file",
        "root_kind": root_kind,
        "relative_path": relative,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "size_bytes": metadata.st_size,
        "sha256": digest,
    }


def _imported_module_closure(runtime_import_path: str) -> list[object]:
    roots = _stdlib_roots()
    records: list[object] = []
    for name in sorted(sys.modules):
        if len(records) >= MAX_IMPORTED_MODULES:
            raise WorkerProtocolError("imported module closure exceeds its fixed bound")
        module = cast("object", sys.modules.get(name))
        if module is None:
            continue
        path = getattr(module, "__file__", None)
        if isinstance(path, str) and path and path != "<stdin>":
            records.append(_file_module_record(name, path, roots, runtime_import_path))
            continue
        spec = getattr(module, "__spec__", None)
        origin = None if spec is None else getattr(spec, "origin", None)
        if origin in {"built-in", "frozen"}:
            records.append(
                {
                    "name": name,
                    "origin_kind": str(origin).replace("-", "_"),
                    "root_kind": None,
                    "relative_path": None,
                    "device": None,
                    "inode": None,
                    "mode": None,
                    "size_bytes": None,
                    "sha256": None,
                }
            )
        elif origin is None and getattr(module, "__path__", None) is not None:
            records.append(
                {
                    "name": name,
                    "origin_kind": "namespace",
                    "root_kind": None,
                    "relative_path": None,
                    "device": None,
                    "inode": None,
                    "mode": None,
                    "size_bytes": None,
                    "sha256": None,
                }
            )
        elif name == "__main__" and path == "<stdin>":
            records.append(
                {
                    "name": name,
                    "origin_kind": "sealed_stdin_worker",
                    "root_kind": None,
                    "relative_path": None,
                    "device": None,
                    "inode": None,
                    "mode": None,
                    "size_bytes": None,
                    "sha256": None,
                }
            )
        else:
            raise WorkerProtocolError(f"module {name} has an unsupported origin")
    return records


def _empty_actions() -> dict[str, object]:
    return {
        "mlx_imports": 0,
        "mlx_lm_imports": 0,
        "distribution_version_queries": 0,
        "default_device_queries": 0,
        "metal_availability_queries": 0,
        "default_stream_queries": 0,
        "synchronizations": 0,
    }


def _non_actions(guard: _RuntimeGuard) -> dict[str, object]:
    return {
        "model_discoveries": 0,
        "model_loads": 0,
        "tokenizer_discoveries": 0,
        "tokenizer_loads": 0,
        "prompt_actions": 0,
        "cache_actions": 0,
        "inference_requests": 0,
        "generation_requests": 0,
        "benchmark_actions": 0,
        "meaningful_tensor_allocations": 0,
        "physical_network_requests": guard.network_attempts,
        "package_index_requests": 0,
        "model_repository_requests": 0,
        "shell_actions": 0,
        "arbitrary_command_actions": guard.process_attempts,
        "filesystem_mutations": guard.write_attempts,
        "cloud_actions": 0,
        "spend_actions": 0,
    }


def _run_preflight(
    *,
    hello: dict[str, object],
    authorization_id: str,
    parent_nonce: str,
    worker_nonce: str,
    request_nonce: str,
) -> dict[str, object]:
    actions = _empty_actions()
    guard = _RuntimeGuard()
    import_observations: list[object] = []
    versions: object = None
    backend_facts: object = None
    synchronization: object = None
    imported_modules: list[object] = []
    status = "completed"
    error: object = None
    sys.addaudithook(guard)
    runtime_import_path = _bound_runtime_import_path()
    if runtime_import_path in sys.path:
        raise WorkerProtocolError("bound runtime root was present before authorization")
    sys.path.insert(0, runtime_import_path)
    phase = "import_mlx"
    try:
        started = time.monotonic_ns()
        mlx = importlib.import_module("mlx.core")
        actions["mlx_imports"] = 1
        import_observations.append(
            {
                "module": "mlx.core",
                "completed": True,
                "duration_ns": time.monotonic_ns() - started,
                "runtime_state_effect": "may_initialize_not_independently_observable",
                "explicit_probe_actions_during_import": 0,
            }
        )
        phase = "import_mlx_lm"
        started = time.monotonic_ns()
        mlx_lm = importlib.import_module("mlx_lm")
        actions["mlx_lm_imports"] = 1
        import_observations.append(
            {
                "module": "mlx_lm",
                "completed": True,
                "duration_ns": time.monotonic_ns() - started,
                "runtime_state_effect": (
                    "may_initialize_default_generation_stream_per_pinned_source"
                ),
                "explicit_probe_actions_during_import": 0,
            }
        )
        phase = "distribution_versions"
        mlx_version = importlib.metadata.version("mlx")
        mlx_lm_version = importlib.metadata.version("mlx-lm")
        actions["distribution_version_queries"] = 2
        versions = {"mlx": mlx_version, "mlx_lm": mlx_lm_version}
        if getattr(mlx, "__version__", mlx_version) != mlx_version:
            raise WorkerProtocolError("mlx module and distribution versions differ")
        if getattr(mlx_lm, "__version__", mlx_lm_version) != mlx_lm_version:
            raise WorkerProtocolError("mlx_lm module and distribution versions differ")
        phase = "default_device"
        device = mlx.default_device()
        actions["default_device_queries"] = 1
        device_representation = _safe_representation(device, "default device")
        phase = "metal_is_available"
        metal_available = mlx.metal.is_available()
        if not isinstance(metal_available, bool):
            raise WorkerProtocolError("mlx.metal.is_available() must return a boolean")
        actions["metal_availability_queries"] = 1
        phase = "default_stream"
        stream = mlx.default_stream(device)
        actions["default_stream_queries"] = 1
        stream_representation = _safe_representation(stream, "default stream")
        backend_facts = {
            "default_device_representation": device_representation,
            "metal_is_available": metal_available,
            "default_stream_representation": stream_representation,
            "per_kernel_metal_execution_proven": False,
        }
        phase = "synchronize"
        started = time.monotonic_ns()
        synchronize_result = mlx.synchronize()
        duration = time.monotonic_ns() - started
        if synchronize_result is not None:
            raise WorkerProtocolError("mlx.synchronize() must return None")
        actions["synchronizations"] = 1
        synchronization = {
            "completed": True,
            "duration_ns": duration,
            "scope": "mlx_default_streams",
            "kernel_execution_claim": "none",
        }
        phase = "imported_module_closure"
        imported_modules = _imported_module_closure(runtime_import_path)
    except (AttributeError, ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
        status = "terminal_error"
        error = {
            "phase": phase,
            "category": type(exc).__name__,
            "message_sha256": _digest_bytes(str(exc).encode("utf-8", errors="backslashreplace")),
        }
        with contextlib.suppress(OSError, WorkerProtocolError):
            imported_modules = _imported_module_closure(runtime_import_path)
    result: dict[str, object] = {
        "message_type": "preflight_result",
        "sequence": 6,
        "status": status,
        "error": error,
        "authorization_id": authorization_id,
        "preflight_package_id": hello["preflight_package_id"],
        "runtime_manifest_id": hello["runtime_manifest_id"],
        "output_root_id": hello["output_root_id"],
        "parent_nonce": parent_nonce,
        "worker_nonce": worker_nonce,
        "request_nonce": request_nonce,
        "package_versions": versions,
        "import_observations": import_observations,
        "imported_modules": imported_modules,
        "backend_facts": backend_facts,
        "synchronization": synchronization,
        "action_ledger": actions,
        "non_actions": _non_actions(guard),
        "runtime_root_import_path": "inherited_descriptor_only",
        "stdlib_closure_complete": False,
        "native_loader_closure_complete": False,
    }
    return result


def _worker_main() -> None:
    environment = dict(os.environ)
    if sys.platform == "darwin":
        expected = f"0x{os.geteuid():X}:0x0:0x0"
        if environment.pop("__CF_USER_TEXT_ENCODING", None) != expected:
            raise WorkerProtocolError("worker has invalid macOS system-injected environment")
    if environment != _EXPECTED_ENVIRONMENT:
        raise WorkerProtocolError("worker environment is not the exact closed allowlist")
    worker_program = _hash_descriptor(
        0,
        "mlx_runtime_preflight_worker.py",
        executable=False,
    )
    interpreter = _hash_descriptor(
        INTERPRETER_IDENTITY_FD,
        "python-interpreter",
        executable=True,
    )
    os.close(INTERPRETER_IDENTITY_FD)
    devnull = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(devnull, 0)
    finally:
        if devnull != 0:
            os.close(devnull)
    endpoint = socket.socket(fileno=WORKER_FD)
    try:
        initial_deadline = time.monotonic_ns() + 10_000_000_000
        channel = _Channel(endpoint, initial_deadline)
        hello = _verify_hello(channel.receive())
        channel.deadline_ns = _integer(
            hello["deadline_monotonic_ns"],
            "parent_hello.deadline_monotonic_ns",
            minimum=1,
        )
        parent_nonce = str(hello["parent_nonce"])
        worker_nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        open_descriptors = _open_file_descriptors()
        if open_descriptors != [0, 1, 2, WORKER_FD, RUNTIME_ROOT_FD]:
            raise WorkerProtocolError("worker inherited unrelated file descriptors")
        identity = {
            "message_type": "worker_identity",
            "sequence": 2,
            "protocol_id": PROTOCOL_ID,
            "worker_code_id": WORKER_CODE_ID,
            "preflight_spec_id": hello["preflight_spec_id"],
            "preflight_package_id": hello["preflight_package_id"],
            "runtime_manifest_id": hello["runtime_manifest_id"],
            "parent_nonce": parent_nonce,
            "worker_nonce": worker_nonce,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "worker_fd": WORKER_FD,
            "runtime_root_fd": RUNTIME_ROOT_FD,
            "open_file_descriptors": open_descriptors,
            "environment_id": ENVIRONMENT_ID,
            "interpreter": interpreter,
            "worker_program": worker_program,
            "runtime_root": _runtime_root_identity(),
            "mlx_imports_before_authorization": 0,
            "mlx_lm_imports_before_authorization": 0,
        }
        channel.send(identity)
        _authorization, authorization_id = _verify_authorization(
            channel.receive(),
            hello,
            worker_nonce,
        )
        channel.send(
            {
                "message_type": "authorization_ack",
                "sequence": 4,
                "authorization_id": authorization_id,
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "consumed": True,
                "mlx_imports_before_authorization": 0,
                "mlx_lm_imports_before_authorization": 0,
            }
        )
        request_nonce = _verify_preflight(
            channel.receive(),
            hello,
            worker_nonce,
            authorization_id,
        )
        channel.send(
            _run_preflight(
                hello=hello,
                authorization_id=authorization_id,
                parent_nonce=parent_nonce,
                worker_nonce=worker_nonce,
                request_nonce=request_nonce,
            )
        )
        _verify_shutdown(
            channel.receive(),
            parent_nonce,
            worker_nonce,
            request_nonce,
        )
        channel.send(
            {
                "message_type": "shutdown_ack",
                "sequence": 8,
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
                "terminal_state": "preflight_closed",
            }
        )
        endpoint.shutdown(socket.SHUT_WR)
        endpoint.settimeout(channel.remaining_seconds())
        if endpoint.recv(1) != b"":
            raise WorkerProtocolError("extra parent frame bytes after shutdown")
    finally:
        endpoint.close()
        os.close(RUNTIME_ROOT_FD)


def main() -> int:
    """Run the sealed worker and expose no command or argument surface."""
    if len(sys.argv) != 1:
        return 2
    try:
        _worker_main()
    except (OSError, WorkerProtocolError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
