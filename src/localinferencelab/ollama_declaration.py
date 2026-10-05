"""Canonical preflight-only Ollama repeatability-study declarations."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import cast

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
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.ollama import (
    VerifiedPackage,
    build_generate_request,
    verify_prospective_package,
)

SCHEMA_VERSION = "1.0"
FOUNDATION_COMMIT = "7f89682bdc50a944cf74e4729f5acffa48dc6f1a"
FOUNDATION_RELEASE = "0.1.0"
PROSPECTIVE_PACKAGE_SCHEMA = "1.0"
RUNNER_CONTRACT_SCHEMA = "1.0"
QWEN3_MANIFEST_DIGEST = "sha256:e56358ca25dd14db6853a9f68a92d717aaa6f0a94250a72d1a0f3d86a9f30130"
_DIGEST_LENGTH = 71
_MILLION = 1_000_000
_RUN_ACTION_COUNT = 9
_IDENTITY_REQUESTS_PER_RUN = 8
_PREFLIGHT_REQUESTS = 4
_CONTROL_CHARACTER_LIMIT = 32
_MAX_PORT = 65_535
_MAX_PROMPTS = 16
_MAX_REPEATS_PER_PROMPT = 100
_MAX_SCHEDULED_RUNS = 256
_ATTESTATION_GATES = (
    "listener_owner_attestation",
    "active_internal_runner_metal_attestation",
)


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str) -> list[JsonValue]:
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
    if any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _optional_text(value: JsonValue, label: str) -> str | None:
    return None if value is None else _text(value, label)


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
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _optional_sha256(value: JsonValue, label: str) -> str | None:
    return None if value is None else _sha256(value, label)


def _strict_canonical_file(path: Path, label: str) -> JsonValue:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
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
    finally:
        os.close(descriptor)
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def _canonical_bytes(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def _foundation_contract() -> dict[str, JsonValue]:
    descriptor: dict[str, JsonValue] = {
        "repository": "Siddhant-K-code/LocalInferenceLab",
        "foundation_release": FOUNDATION_RELEASE,
        "foundation_commit": FOUNDATION_COMMIT,
        "foundation_record_schema": "1.0",
        "ollama_runner_contract_schema": RUNNER_CONTRACT_SCHEMA,
        "ollama_prospective_package_schema": PROSPECTIVE_PACKAGE_SCHEMA,
        "ollama_repeatability_declaration_schema": SCHEMA_VERSION,
    }
    return {
        "descriptor": descriptor,
        "contract_id": canonical_identity(descriptor),
    }


def _parse_runtime(value: JsonValue) -> dict[str, JsonValue]:
    runtime = _mapping(value, "study_spec.known_identity.runtime")
    fields = {
        "evidence_source",
        "ollama_version",
        "artifact_sha256",
        "selected_internal_runner",
        "metal_state",
        "build_info",
    }
    _keys(runtime, fields, "study_spec.known_identity.runtime")
    if (
        _literal(
            runtime["evidence_source"],
            {"user_provided_prior_identity"},
            "study_spec.known_identity.runtime.evidence_source",
        )
        != "user_provided_prior_identity"
    ):
        raise ContractError("unsupported runtime evidence source")
    parsed_runtime: dict[str, JsonValue] = {
        "evidence_source": "user_provided_prior_identity",
        "ollama_version": _text(
            runtime["ollama_version"],
            "study_spec.known_identity.runtime.ollama_version",
        ),
        "artifact_sha256": _optional_sha256(
            runtime["artifact_sha256"],
            "study_spec.known_identity.runtime.artifact_sha256",
        ),
        "selected_internal_runner": _optional_text(
            runtime["selected_internal_runner"],
            "study_spec.known_identity.runtime.selected_internal_runner",
        ),
        "metal_state": _optional_text(
            runtime["metal_state"],
            "study_spec.known_identity.runtime.metal_state",
        ),
        "build_info": _optional_text(
            runtime["build_info"],
            "study_spec.known_identity.runtime.build_info",
        ),
    }
    return parsed_runtime


def _parse_model(value: JsonValue) -> dict[str, JsonValue]:
    model = _mapping(value, "study_spec.known_identity.model")
    fields = {
        "evidence_source",
        "request_model",
        "canonical_model_name",
        "representation",
        "quantization",
        "manifest_digest",
        "manifest_bytes_sha256",
        "config_sha256",
        "layer_digests",
        "artifact_closure_sha256",
    }
    _keys(model, fields, "study_spec.known_identity.model")
    if model["evidence_source"] != "user_provided_prior_identity":
        raise ContractError("model evidence must remain user_provided_prior_identity")
    if model["representation"] != "ollama_manifest":
        raise ContractError("Qwen3 study requires the ollama_manifest representation")
    request_model = _text(model["request_model"], "study_spec.known_identity.model.request_model")
    if not request_model.endswith(":local"):
        raise ContractError("request_model must retain the explicit :local suffix")
    local_name = request_model.removesuffix(":local")
    if (
        not local_name
        or local_name.endswith(":")
        or any(character.isspace() for character in local_name)
    ):
        raise ContractError("request_model is not canonical")
    final_component = local_name.rsplit("/", 1)[-1]
    canonical_name = local_name if ":" in final_component else f"{local_name}:latest"
    if model["canonical_model_name"] != canonical_name:
        raise ContractError("canonical model name must be derived from request_model")
    layers = _array(model["layer_digests"], "study_spec.known_identity.model.layer_digests")
    parsed_layers: list[JsonValue] = [
        _sha256(item, "study_spec.known_identity.model.layer_digests[]") for item in layers
    ]
    if len(parsed_layers) != len(set(parsed_layers)):
        raise ContractError("model layer digests must be unique")
    parsed_model: dict[str, JsonValue] = {
        "evidence_source": "user_provided_prior_identity",
        "request_model": request_model,
        "canonical_model_name": canonical_name,
        "representation": "ollama_manifest",
        "quantization": _text(
            model["quantization"],
            "study_spec.known_identity.model.quantization",
        ),
        "manifest_digest": _sha256(
            model["manifest_digest"],
            "study_spec.known_identity.model.manifest_digest",
        ),
        "manifest_bytes_sha256": _optional_sha256(
            model["manifest_bytes_sha256"],
            "study_spec.known_identity.model.manifest_bytes_sha256",
        ),
        "config_sha256": _optional_sha256(
            model["config_sha256"],
            "study_spec.known_identity.model.config_sha256",
        ),
        "layer_digests": parsed_layers,
        "artifact_closure_sha256": _optional_sha256(
            model["artifact_closure_sha256"],
            "study_spec.known_identity.model.artifact_closure_sha256",
        ),
    }
    return parsed_model


def _parse_host(value: JsonValue) -> dict[str, JsonValue]:
    host = _mapping(value, "study_spec.known_identity.host")
    fields = {
        "evidence_source",
        "observation_status",
        "chip",
        "architecture",
        "cpu_cores",
        "performance_cores",
        "efficiency_cores",
        "unified_memory_bytes",
        "os_name",
        "os_version",
        "os_build",
    }
    _keys(host, fields, "study_spec.known_identity.host")
    cpu_cores = _integer(host["cpu_cores"], "study_spec.known_identity.host.cpu_cores", minimum=1)
    performance = _integer(
        host["performance_cores"],
        "study_spec.known_identity.host.performance_cores",
        minimum=1,
    )
    efficiency = _integer(
        host["efficiency_cores"],
        "study_spec.known_identity.host.efficiency_cores",
        minimum=1,
    )
    if performance + efficiency != cpu_cores:
        raise ContractError("performance and efficiency cores must sum to cpu_cores")
    if host["evidence_source"] != "user_provided_prior_identity":
        raise ContractError("host evidence must remain user_provided_prior_identity")
    if host["observation_status"] != "not_reprobed_for_declaration":
        raise ContractError("declaration construction must not claim a fresh host observation")
    return {
        "evidence_source": "user_provided_prior_identity",
        "observation_status": "not_reprobed_for_declaration",
        "chip": _text(host["chip"], "study_spec.known_identity.host.chip"),
        "architecture": _text(
            host["architecture"],
            "study_spec.known_identity.host.architecture",
        ),
        "cpu_cores": cpu_cores,
        "performance_cores": performance,
        "efficiency_cores": efficiency,
        "unified_memory_bytes": _integer(
            host["unified_memory_bytes"],
            "study_spec.known_identity.host.unified_memory_bytes",
            minimum=1,
        ),
        "os_name": _text(host["os_name"], "study_spec.known_identity.host.os_name"),
        "os_version": _text(host["os_version"], "study_spec.known_identity.host.os_version"),
        "os_build": _text(host["os_build"], "study_spec.known_identity.host.os_build"),
    }


def _parse_known_identity(value: JsonValue) -> dict[str, JsonValue]:
    identity = _mapping(value, "study_spec.known_identity")
    _keys(identity, {"runtime", "model", "host"}, "study_spec.known_identity")
    return {
        "runtime": _parse_runtime(identity["runtime"]),
        "model": _parse_model(identity["model"]),
        "host": _parse_host(identity["host"]),
    }


def _parse_prompts(value: JsonValue) -> tuple[dict[str, JsonValue], ...]:
    prompts: list[dict[str, JsonValue]] = []
    for index, item in enumerate(_array(value, "study_spec.prompt_catalog")):
        prompt = _mapping(item, f"study_spec.prompt_catalog[{index}]")
        _keys(
            prompt,
            {"prompt_id", "prompt_base64", "prompt_sha256"},
            f"study_spec.prompt_catalog[{index}]",
        )
        prompt_id = _text(prompt["prompt_id"], f"study_spec.prompt_catalog[{index}].prompt_id")
        encoded = _text(
            prompt["prompt_base64"],
            f"study_spec.prompt_catalog[{index}].prompt_base64",
            empty=True,
        )
        prompt_bytes = decode_bytes(encoded)
        try:
            prompt_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ContractError("study prompts must be valid UTF-8") from error
        prompt_sha = _sha256(
            prompt["prompt_sha256"],
            f"study_spec.prompt_catalog[{index}].prompt_sha256",
        )
        if digest_bytes(prompt_bytes) != prompt_sha:
            raise ContractError("study prompt digest does not match its bytes")
        prompts.append(
            {
                "prompt_id": prompt_id,
                "prompt_base64": encoded,
                "prompt_sha256": prompt_sha,
            },
        )
    if not prompts:
        raise ContractError("study prompt catalog cannot be empty")
    if len(prompts) > _MAX_PROMPTS:
        raise ContractError(f"study prompt catalog cannot exceed {_MAX_PROMPTS} entries")
    prompt_ids = [cast("str", prompt["prompt_id"]) for prompt in prompts]
    if len(prompt_ids) != len(set(prompt_ids)):
        raise ContractError("study prompt IDs must be unique")
    return tuple(prompts)


def _parse_request_controls(value: JsonValue) -> dict[str, JsonValue]:
    controls = _mapping(value, "study_spec.request_controls")
    fields = {
        "raw",
        "think_mode",
        "stream",
        "shift",
        "truncate",
        "keep_alive_seconds",
        "seed",
        "temperature_millionths",
        "top_p_millionths",
        "top_k",
        "min_p_millionths",
        "repeat_penalty_millionths",
        "context_tokens",
        "max_output_tokens",
    }
    _keys(controls, fields, "study_spec.request_controls")
    fixed_booleans = {
        "raw": True,
        "stream": False,
        "shift": False,
        "truncate": False,
    }
    for field, expected in fixed_booleans.items():
        if _boolean(controls[field], f"study_spec.request_controls.{field}") is not expected:
            raise ContractError(f"request control {field} must be {str(expected).lower()}")
    if controls["think_mode"] not in {"false", "true"}:
        raise ContractError("think_mode must be explicitly true or false")
    keep_alive = _integer(
        controls["keep_alive_seconds"],
        "study_spec.request_controls.keep_alive_seconds",
    )
    if keep_alive != 0:
        raise ContractError("keep_alive_seconds must be zero")
    parsed: dict[str, JsonValue] = {
        "raw": True,
        "think_mode": cast("str", controls["think_mode"]),
        "stream": False,
        "shift": False,
        "truncate": False,
        "keep_alive_seconds": keep_alive,
        "seed": _integer(controls["seed"], "study_spec.request_controls.seed", minimum=-1),
        "temperature_millionths": _integer(
            controls["temperature_millionths"],
            "study_spec.request_controls.temperature_millionths",
        ),
        "top_p_millionths": _integer(
            controls["top_p_millionths"],
            "study_spec.request_controls.top_p_millionths",
        ),
        "top_k": _integer(controls["top_k"], "study_spec.request_controls.top_k"),
        "min_p_millionths": _integer(
            controls["min_p_millionths"],
            "study_spec.request_controls.min_p_millionths",
        ),
        "repeat_penalty_millionths": _integer(
            controls["repeat_penalty_millionths"],
            "study_spec.request_controls.repeat_penalty_millionths",
        ),
        "context_tokens": _integer(
            controls["context_tokens"],
            "study_spec.request_controls.context_tokens",
            minimum=1,
        ),
        "max_output_tokens": _integer(
            controls["max_output_tokens"],
            "study_spec.request_controls.max_output_tokens",
            minimum=1,
        ),
    }
    if (
        cast("int", parsed["top_p_millionths"]) > _MILLION
        or cast("int", parsed["min_p_millionths"]) > _MILLION
    ):
        raise ContractError("probability controls cannot exceed 1.0")
    return parsed


def _parse_transport(value: JsonValue) -> dict[str, JsonValue]:
    transport = _mapping(value, "study_spec.transport")
    fields = {
        "scheme",
        "host",
        "port",
        "version_path",
        "tags_path",
        "show_path",
        "ps_path",
        "generate_path",
        "absolute_request_deadline_ms",
        "max_identity_response_bytes",
        "max_generate_response_bytes",
        "redirects",
        "proxies",
        "retries",
    }
    _keys(transport, fields, "study_spec.transport")
    expected_text: dict[str, JsonValue] = {
        "scheme": "http",
        "host": "127.0.0.1",
        "version_path": "/api/version",
        "tags_path": "/api/tags",
        "show_path": "/api/show",
        "ps_path": "/api/ps",
        "generate_path": "/api/generate",
        "redirects": "forbidden",
        "proxies": "forbidden",
    }
    for field, expected in expected_text.items():
        if transport[field] != expected:
            raise ContractError(f"transport.{field} must be {expected}")
    retries = _integer(transport["retries"], "study_spec.transport.retries")
    if retries != 0:
        raise ContractError("transport retries must be zero")
    parsed: dict[str, JsonValue] = dict(expected_text)
    parsed.update(
        {
            "port": _integer(transport["port"], "study_spec.transport.port", minimum=1),
            "absolute_request_deadline_ms": _integer(
                transport["absolute_request_deadline_ms"],
                "study_spec.transport.absolute_request_deadline_ms",
                minimum=1,
            ),
            "max_identity_response_bytes": _integer(
                transport["max_identity_response_bytes"],
                "study_spec.transport.max_identity_response_bytes",
                minimum=1,
            ),
            "max_generate_response_bytes": _integer(
                transport["max_generate_response_bytes"],
                "study_spec.transport.max_generate_response_bytes",
                minimum=1,
            ),
            "retries": retries,
        },
    )
    if cast("int", parsed["port"]) > _MAX_PORT:
        raise ContractError("transport.port must be <= 65535")
    return parsed


def _parse_design(value: JsonValue) -> dict[str, JsonValue]:
    design = _mapping(value, "study_spec.study_design")
    fields = {
        "repeats_per_prompt",
        "run_order",
        "cache_cohorts",
        "concurrency",
        "attempts_per_run",
        "selective_reruns",
        "hidden_warmups",
    }
    _keys(design, fields, "study_spec.study_design")
    cohorts = _array(design["cache_cohorts"], "study_spec.study_design.cache_cohorts")
    if cohorts != ["cold_model_warm_process"]:
        raise ContractError("only cold_model_warm_process is supported")
    if design["run_order"] != "prompt_catalog_then_repeat_index":
        raise ContractError("study run order is not supported")
    concurrency = _integer(
        design["concurrency"],
        "study_spec.study_design.concurrency",
        minimum=1,
    )
    attempts = _integer(
        design["attempts_per_run"],
        "study_spec.study_design.attempts_per_run",
        minimum=1,
    )
    if concurrency != 1 or attempts != 1:
        raise ContractError("study requires concurrency=1 and one attempt per run")
    if design["selective_reruns"] != "forbidden" or design["hidden_warmups"] != "forbidden":
        raise ContractError("selective reruns and hidden warmups must be forbidden")
    repeats = _integer(
        design["repeats_per_prompt"],
        "study_spec.study_design.repeats_per_prompt",
        minimum=2,
    )
    if repeats > _MAX_REPEATS_PER_PROMPT:
        raise ContractError(f"study repeats_per_prompt cannot exceed {_MAX_REPEATS_PER_PROMPT}")
    return {
        "repeats_per_prompt": repeats,
        "run_order": "prompt_catalog_then_repeat_index",
        "cache_cohorts": ["cold_model_warm_process"],
        "concurrency": concurrency,
        "attempts_per_run": attempts,
        "selective_reruns": "forbidden",
        "hidden_warmups": "forbidden",
    }


def _parse_spec(value: JsonValue) -> dict[str, JsonValue]:
    spec = _mapping(value, "study_spec")
    fields = {
        "record_type",
        "schema_version",
        "study_name",
        "foundation_commit",
        "known_identity",
        "prompt_catalog",
        "request_controls",
        "transport",
        "study_design",
    }
    _keys(spec, fields, "study_spec")
    if (
        spec["record_type"] != "ollama_repeatability_study_spec"
        or spec["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported Ollama repeatability study specification")
    if spec["foundation_commit"] != FOUNDATION_COMMIT:
        raise ContractError("study must bind the reviewed foundation commit")
    return {
        "record_type": "ollama_repeatability_study_spec",
        "schema_version": SCHEMA_VERSION,
        "study_name": _text(spec["study_name"], "study_spec.study_name"),
        "foundation_commit": FOUNDATION_COMMIT,
        "known_identity": _parse_known_identity(spec["known_identity"]),
        "prompt_catalog": list(_parse_prompts(spec["prompt_catalog"])),
        "request_controls": _parse_request_controls(spec["request_controls"]),
        "transport": _parse_transport(spec["transport"]),
        "study_design": _parse_design(spec["study_design"]),
    }


def _request_catalog(spec: Mapping[str, JsonValue]) -> list[JsonValue]:
    identity = _mapping(spec["known_identity"], "known_identity")
    model = _mapping(identity["model"], "known_identity.model")
    controls = _mapping(spec["request_controls"], "request_controls")
    requests: list[JsonValue] = []
    for prompt_value in _array(spec["prompt_catalog"], "prompt_catalog"):
        prompt = _mapping(prompt_value, "prompt_catalog[]")
        prompt_bytes = decode_bytes(cast("str", prompt["prompt_base64"]))
        request = build_generate_request(
            model_name=cast("str", model["request_model"]),
            prompt=prompt_bytes,
            think_mode=cast("str", controls["think_mode"]),
            seed=cast("int", controls["seed"]),
            temperature_millionths=cast("int", controls["temperature_millionths"]),
            top_p_millionths=cast("int", controls["top_p_millionths"]),
            top_k=cast("int", controls["top_k"]),
            min_p_millionths=cast("int", controls["min_p_millionths"]),
            repeat_penalty_millionths=cast("int", controls["repeat_penalty_millionths"]),
            context_tokens=cast("int", controls["context_tokens"]),
            max_output_tokens=cast("int", controls["max_output_tokens"]),
            keep_alive_seconds=cast("int", controls["keep_alive_seconds"]),
        )
        requests.append(
            {
                "prompt_id": prompt["prompt_id"],
                "prompt_sha256": prompt["prompt_sha256"],
                "request_base64": encode_bytes(request),
                "request_sha256": digest_bytes(request),
                "request_size_bytes": len(request),
            },
        )
    return requests


def _action_template(
    request_sha256: str,
    request_size_bytes: int,
    transport: Mapping[str, JsonValue],
    model_name: str,
) -> list[JsonValue]:
    identity_limit = cast("int", transport["max_identity_response_bytes"])
    generate_limit = cast("int", transport["max_generate_response_bytes"])
    show_request = canonical_json({"model": model_name})
    identity_actions: tuple[tuple[str, str, str, bytes], ...] = (
        ("version", "GET", cast("str", transport["version_path"]), b""),
        ("tags", "GET", cast("str", transport["tags_path"]), b""),
        ("show", "POST", cast("str", transport["show_path"]), show_request),
        ("ps", "GET", cast("str", transport["ps_path"]), b""),
    )
    actions: list[JsonValue] = []
    sequence = 1
    for phase in ("pre_identity",):
        for operation, method, path, body in identity_actions:
            actions.append(
                {
                    "sequence": sequence,
                    "phase": phase,
                    "operation": operation,
                    "method": method,
                    "path": path,
                    "request_sha256": digest_bytes(body),
                    "request_size_bytes": len(body),
                    "max_response_bytes": identity_limit,
                    "response_read_budget_bytes": identity_limit + 1,
                },
            )
            sequence += 1
    actions.append(
        {
            "sequence": sequence,
            "phase": "generation",
            "operation": "generate",
            "method": "POST",
            "path": transport["generate_path"],
            "request_sha256": request_sha256,
            "request_size_bytes": request_size_bytes,
            "max_response_bytes": generate_limit,
            "response_read_budget_bytes": generate_limit + 1,
        },
    )
    sequence += 1
    for operation, method, path, body in identity_actions:
        actions.append(
            {
                "sequence": sequence,
                "phase": "post_identity",
                "operation": operation,
                "method": method,
                "path": path,
                "request_sha256": digest_bytes(body),
                "request_size_bytes": len(body),
                "max_response_bytes": identity_limit,
                "response_read_budget_bytes": identity_limit + 1,
            },
        )
        sequence += 1
    if len(actions) != _RUN_ACTION_COUNT:
        raise ContractError("trusted action schedule construction failed")
    return actions


def _verified_packages(
    values: Sequence[JsonValue],
) -> tuple[VerifiedPackage, ...]:
    return tuple(verify_prospective_package(value) for value in values)


def _schedule_and_packages(
    spec: Mapping[str, JsonValue],
    request_catalog: Sequence[JsonValue],
    package_values: Sequence[JsonValue],
) -> tuple[list[JsonValue], list[JsonValue]]:
    design = _mapping(spec["study_design"], "study_design")
    identity = _mapping(spec["known_identity"], "known_identity")
    known_runtime = _mapping(identity["runtime"], "known_identity.runtime")
    known_model = _mapping(identity["model"], "known_identity.model")
    known_host = _mapping(identity["host"], "known_identity.host")
    transport = _mapping(spec["transport"], "transport")
    prompt_count = len(request_catalog)
    repeat_count = cast("int", design["repeats_per_prompt"])
    if prompt_count * repeat_count > _MAX_SCHEDULED_RUNS:
        raise ContractError(f"study schedule cannot exceed {_MAX_SCHEDULED_RUNS} runs")
    run_inputs: list[tuple[str, dict[str, JsonValue]]] = []
    for request_value in request_catalog:
        request = _mapping(request_value, "request_catalog[]")
        for repeat in range(1, cast("int", design["repeats_per_prompt"]) + 1):
            prompt_id = cast("str", request["prompt_id"])
            run_inputs.append((f"{prompt_id}-repeat-{repeat:03d}", request))
    packages = _verified_packages(package_values)
    if packages and len(packages) != len(run_inputs):
        raise ContractError("prospective packages must cover every declared run or none")
    package_by_run: dict[str, VerifiedPackage] = {}
    for verified_package in packages:
        protocol = _mapping(verified_package.value["protocol"], "prospective.protocol")
        run_id = cast("str", protocol["run_id"])
        if run_id in package_by_run:
            raise ContractError("prospective package run IDs must be unique")
        package_by_run[run_id] = verified_package
    schedule: list[JsonValue] = []
    bindings: list[JsonValue] = []
    for sequence, (run_id, request) in enumerate(run_inputs, start=1):
        run_package = package_by_run.get(run_id)
        if packages and run_package is None:
            raise ContractError(f"missing prospective package for run {run_id}")
        action_template = _action_template(
            cast("str", request["request_sha256"]),
            cast("int", request["request_size_bytes"]),
            transport,
            cast("str", known_model["request_model"]),
        )
        binding: dict[str, JsonValue] = {
            "run_id": run_id,
            "binding_status": "missing_not_constructed",
            "package_id": None,
            "protocol_id": None,
            "execution_declaration_id": None,
            "runtime_id": None,
            "model_id": None,
            "host_id": None,
            "model_artifact_closure_sha256": None,
            "output_root_id": None,
            "preflight_nonce_sha256": None,
            "identity_guard_nonce_sha256": None,
            "generation_nonce_sha256": None,
        }
        if run_package is not None:
            protocol = _mapping(run_package.value["protocol"], "prospective.protocol")
            package_declaration = _mapping(
                run_package.value["declaration"],
                "prospective.declaration",
            )
            artifact = _mapping(
                run_package.value["model_artifact"],
                "prospective.model_artifact",
            )
            artifact_config = _mapping(artifact["config"], "prospective.model_artifact.config")
            artifact_layers = [
                _mapping(layer, "prospective.model_artifact.layers[]")
                for layer in _array(
                    artifact["layers"],
                    "prospective.model_artifact.layers",
                )
            ]
            package_cache = _mapping(
                run_package.value["cache_contract"],
                "prospective.cache_contract",
            )
            nonces = _mapping(
                package_declaration["authorization_nonce_sha256"],
                "prospective.authorization_nonce_sha256",
            )
            if protocol["request_sha256"] != request["request_sha256"]:
                raise ContractError(f"prospective package request drift for run {run_id}")
            if run_package.runtime.version != known_runtime["ollama_version"]:
                raise ContractError(f"prospective package runtime identity drift for run {run_id}")
            if run_package.canonical_model_name != known_model["canonical_model_name"]:
                raise ContractError(f"prospective package model name drift for run {run_id}")
            if artifact["manifest_digest"] != known_model["manifest_digest"]:
                raise ContractError(f"prospective package manifest identity drift for run {run_id}")
            declared_artifacts = (
                ("manifest_bytes_sha256", artifact["manifest_sha256"]),
                ("config_sha256", artifact_config["digest"]),
                ("artifact_closure_sha256", artifact["closure_sha256"]),
            )
            for field, actual in declared_artifacts:
                declared = known_model[field]
                if declared is not None and declared != actual:
                    raise ContractError(f"prospective package model {field} drift for run {run_id}")
            declared_layers = _array(
                known_model["layer_digests"],
                "known_identity.model.layer_digests",
            )
            actual_layers = [layer["digest"] for layer in artifact_layers]
            if declared_layers and declared_layers != actual_layers:
                raise ContractError(
                    f"prospective package model layer closure drift for run {run_id}"
                )
            runtime_facts = {fact.name: fact.value for fact in run_package.runtime.capability_facts}
            declared_runtime = (
                ("artifact_sha256", run_package.runtime.artifact_sha256),
                ("selected_internal_runner", runtime_facts.get("runner")),
                ("metal_state", runtime_facts.get("metal")),
                ("build_info", runtime_facts.get("build_info")),
            )
            for field, actual in declared_runtime:
                declared = known_runtime[field]
                if declared is not None and declared != actual:
                    raise ContractError(
                        f"prospective package runtime {field} drift for run {run_id}"
                    )
            if (
                run_package.host.chip != known_host["chip"]
                or run_package.host.architecture != known_host["architecture"]
                or run_package.host.logical_cores != known_host["cpu_cores"]
                or run_package.host.memory_bytes != known_host["unified_memory_bytes"]
                or run_package.host.os_name != known_host["os_name"]
                or run_package.host.os_version != known_host["os_version"]
                or run_package.host.os_build != known_host["os_build"]
            ):
                raise ContractError(f"prospective package host identity drift for run {run_id}")
            if (
                run_package.endpoint.scheme != transport["scheme"]
                or run_package.endpoint.host != transport["host"]
                or run_package.endpoint.port != transport["port"]
            ):
                raise ContractError(f"prospective package endpoint drift for run {run_id}")
            if protocol["timeout_ms"] != transport["absolute_request_deadline_ms"]:
                raise ContractError(f"prospective package request deadline drift for run {run_id}")
            if (
                package_cache["cache_cohort"] != "cold_model_warm_process"
                or package_cache["support_status"] != "supported"
            ):
                raise ContractError(f"prospective package cache cohort drift for run {run_id}")
            if package_declaration["disposition"] != "authorized":
                raise ContractError(f"prospective package is not authorized for run {run_id}")
            if list(run_package.actions) != action_template:
                raise ContractError(f"prospective package action schedule drift for run {run_id}")
            binding = {
                "run_id": run_id,
                "binding_status": "exact_verified_package",
                "package_id": run_package.identity,
                "protocol_id": run_package.protocol_id,
                "execution_declaration_id": run_package.declaration_id,
                "runtime_id": canonical_identity(run_package.runtime.to_dict()),
                "model_id": canonical_identity(run_package.model.to_dict()),
                "host_id": canonical_identity(run_package.host.to_dict()),
                "model_artifact_closure_sha256": artifact["closure_sha256"],
                "output_root_id": run_package.output_root_id,
                "preflight_nonce_sha256": nonces["preflight_only"],
                "identity_guard_nonce_sha256": nonces["identity_guard"],
                "generation_nonce_sha256": nonces["generation"],
            }
        bindings.append(binding)
        schedule.append(
            {
                "sequence": sequence,
                "run_id": run_id,
                "prompt_id": request["prompt_id"],
                "repeat_index": int(run_id.rsplit("-", 1)[1]),
                "request_sha256": request["request_sha256"],
                "package_id": binding["package_id"],
                "cache_cohort": "cold_model_warm_process",
                "concurrency": 1,
                "attempt_limit": 1,
                "retry_count": 0,
                "selective_rerun": "forbidden",
                "terminal_outcomes": ["accepted", "invalid", "refused", "interrupted"],
                "action_schedule": action_template,
            },
        )
    if packages and set(package_by_run) != {run_id for run_id, _request in run_inputs}:
        raise ContractError("prospective package run IDs do not match the exact schedule")
    return schedule, bindings


def _missing_fields(
    identity: Mapping[str, JsonValue],
    bindings: Sequence[JsonValue],
) -> list[JsonValue]:
    packages_complete = all(
        _mapping(binding, "prospective_package_bindings[]")["binding_status"]
        == "exact_verified_package"
        for binding in bindings
    )
    if packages_complete:
        return []
    runtime = _mapping(identity["runtime"], "known_identity.runtime")
    model = _mapping(identity["model"], "known_identity.model")
    missing: list[JsonValue] = [
        f"known_identity.runtime.{field}"
        for field in ("artifact_sha256", "selected_internal_runner", "metal_state", "build_info")
        if runtime[field] is None
    ]
    missing.extend(
        f"known_identity.model.{field}"
        for field in (
            "manifest_bytes_sha256",
            "config_sha256",
            "artifact_closure_sha256",
        )
        if model[field] is None
    )
    if not _array(model["layer_digests"], "known_identity.model.layer_digests"):
        missing.append("known_identity.model.layer_digests")
    for binding_value in bindings:
        binding = _mapping(binding_value, "prospective_package_bindings[]")
        if binding["binding_status"] != "exact_verified_package":
            missing.append(f"prospective_package_bindings.{binding['run_id']}")
    return missing


def _authorization_plan(
    bindings: Sequence[JsonValue],
    schedule: Sequence[JsonValue],
) -> dict[str, JsonValue]:
    package_bound = all(
        _mapping(binding, "prospective_package_bindings[]")["binding_status"]
        == "exact_verified_package"
        for binding in bindings
    )
    first_run = _mapping(schedule[0], "run_schedule[0]")
    preflight_actions: list[JsonValue] = []
    for sequence, action_value in enumerate(
        _array(first_run["action_schedule"], "run_schedule[0].action_schedule")[:4],
        start=1,
    ):
        action = dict(_mapping(action_value, "run_schedule[0].action_schedule[]"))
        action["sequence"] = sequence
        action["phase"] = "preflight_only"
        preflight_actions.append(action)
    return {
        "ambient_authorization": "forbidden",
        "metadata_preflight": {
            "phase": "preflight_only",
            "request_budget": _PREFLIGHT_REQUESTS,
            "action_schedule": preflight_actions,
            "separate_one_shot_authorization_required": True,
            "currently_authorized": False,
        },
        "per_run": [
            {
                "run_id": _mapping(binding, "binding")["run_id"],
                "identity_guard": {
                    "phase": "identity_guard",
                    "request_budget": _IDENTITY_REQUESTS_PER_RUN,
                    "nonce_sha256": _mapping(binding, "binding")["identity_guard_nonce_sha256"],
                },
                "generation": {
                    "phase": "generation",
                    "inference_request_budget": 1,
                    "nonce_sha256": _mapping(binding, "binding")["generation_nonce_sha256"],
                },
                "one_shot": True,
                "retry_count": 0,
            }
            for binding in bindings
        ],
        "all_nonce_commitments_content_bound": package_bound,
    }


def _analysis_policy() -> dict[str, JsonValue]:
    return {
        "scope": "within_backend_repeatability_only",
        "grouping_keys": [
            "runtime_id",
            "model_id",
            "host_id",
            "request_sha256",
            "cache_cohort",
            "concurrency",
        ],
        "per_run_provenance": ["package_id", "execution_declaration_id"],
        "valid_run_equality": {
            "raw_response": "byte_equality_by_sha256_and_size",
            "decoded_response_text": "utf8_text_byte_equality_by_sha256",
            "finish_reason": "exact_string_equality",
            "structured_envelope": "canonical_envelope_byte_equality",
        },
        "invalid_refused_interrupted": {
            "comparison": "not_equal_or_divergent",
            "accounting": "terminal_class_plus_reason_sha256",
            "partial_output_trust": "forbidden",
            "selective_rerun": "forbidden",
        },
        "native_metrics": [
            "total_duration_ns",
            "load_duration_ns",
            "prompt_eval_count",
            "prompt_eval_duration_ns",
            "eval_count",
            "eval_duration_ns",
        ],
        "derived_metrics": "none",
        "generated_token_ids": "unavailable_not_comparable",
        "ttft": "unavailable_not_comparable",
        "hardware_evidence": "requires_future_observed_attested_bundle",
        "contract_evidence": "declaration_and_synthetic_fixture_only",
        "control_non_claims": [
            "fixed seed is a control, not a determinism guarantee",
            "fixed temperature is a control, not a determinism guarantee",
            "contract evidence is not observed hardware evidence",
        ],
    }


def _custody_policy(bindings: Sequence[JsonValue]) -> dict[str, JsonValue]:
    roots = {
        cast("str", _mapping(binding, "binding")["output_root_id"])
        for binding in bindings
        if _mapping(binding, "binding")["output_root_id"] is not None
    }
    if len(roots) > 1:
        raise ContractError("all prospective packages must bind one exact output root")
    return {
        "output_root_id": next(iter(roots), None),
        "output_root_binding": (
            "declared_output_root_identity_unverified_instance"
            if roots
            else "missing_not_initialized"
        ),
        "declaration_construction_must_create_marker": False,
        "marker_required_before_authorization": True,
        "publication": "atomic_no_replace_receipt_last_v1",
        "evidence_bundle_must_bind": [
            "declaration_id",
            "package_id",
            "action_schedule",
            "authorization_consumption",
            "raw_bounded_responses",
            "terminal_outcome",
        ],
        "offline_replay": "strict_closed_set_recompute",
        "observed_generation_replay": "schema_ineligible_without_attestation",
    }


def build_study_declaration(
    spec_value: JsonValue,
    *,
    prospective_packages: Sequence[JsonValue] = (),
) -> dict[str, JsonValue]:
    """Build a declaration without socket, model, output-root, or authorization action."""
    spec = _parse_spec(spec_value)
    request_catalog = _request_catalog(spec)
    schedule, bindings = _schedule_and_packages(spec, request_catalog, prospective_packages)
    identity = _mapping(spec["known_identity"], "known_identity")
    missing = _missing_fields(identity, bindings)
    complete = not missing
    eligibility: dict[str, JsonValue] = {
        "declaration_completeness": {
            "status": "complete" if complete else "incomplete",
            "missing_fields": missing,
        },
        "metadata_preflight": {
            "decision": "separate_authorization_required",
            "currently_authorized": False,
            "may_generate": False,
        },
        "observed_generation": {
            "decision": "ineligible",
            "trust_gate_blockers": list(_ATTESTATION_GATES),
            "attestation_content_bound": False,
            "authorization_may_be_consumed": False,
            "socket_may_be_opened": False,
            "model_may_execute": False,
        },
        "observed_generation_replay": {
            "decision": "ineligible",
            "trust_gate_blockers": list(_ATTESTATION_GATES),
            "attestation_content_bound": False,
        },
    }
    declaration: dict[str, JsonValue] = {
        "record_type": "ollama_repeatability_study_declaration",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "prospective_declaration_only_not_observed_evidence",
        "study_spec": spec,
        "contract_binding": _foundation_contract(),
        "known_identity_id": canonical_identity(spec["known_identity"]),
        "request_catalog": request_catalog,
        "prospective_packages": [
            verify_prospective_package(value).value for value in prospective_packages
        ],
        "prospective_package_bindings": bindings,
        "run_schedule": schedule,
        "authorization_plan": _authorization_plan(bindings, schedule),
        "analysis_policy": _analysis_policy(),
        "custody_policy": _custody_policy(bindings),
        "attestation_gate": {
            "schema_status": "not_available_in_schema_1_0",
            "listener_owner_attestation_id": None,
            "active_internal_runner_metal_attestation_id": None,
            "gate_may_be_forged_by_caller": False,
        },
        "eligibility": eligibility,
        "terminal_policy": {
            "accepted": "retain_exact_response_and_native_metrics",
            "invalid": "digest_safe_reason_no_partial_output_trust",
            "refused": "terminal_no_generation_attempt",
            "interrupted": "terminal_attempt_consumed_no_selective_rerun",
        },
        "non_actions": {
            "physical_network_requests": 0,
            "socket_calls": 0,
            "model_inferences": 0,
            "model_process_starts": 0,
            "model_mutations": 0,
            "model_downloads": 0,
            "external_network_actions": 0,
            "cloud_actions": 0,
            "spend_actions": 0,
            "output_root_markers_created": 0,
        },
    }
    declaration["declaration_id"] = canonical_identity(declaration)
    return declaration


def verify_study_declaration(value: JsonValue) -> dict[str, JsonValue]:
    """Reject unknown fields, tampering, non-canonical derivations, and forged eligibility."""
    declaration = _mapping(value, "ollama_repeatability_study_declaration")
    fields = {
        "record_type",
        "schema_version",
        "evidence_status",
        "study_spec",
        "contract_binding",
        "known_identity_id",
        "request_catalog",
        "prospective_packages",
        "prospective_package_bindings",
        "run_schedule",
        "authorization_plan",
        "analysis_policy",
        "custody_policy",
        "attestation_gate",
        "eligibility",
        "terminal_policy",
        "non_actions",
        "declaration_id",
    }
    _keys(declaration, fields, "ollama_repeatability_study_declaration")
    if (
        declaration["record_type"] != "ollama_repeatability_study_declaration"
        or declaration["schema_version"] != SCHEMA_VERSION
        or declaration["evidence_status"] != "prospective_declaration_only_not_observed_evidence"
    ):
        raise ContractError("unsupported Ollama repeatability study declaration")
    package_values = _array(declaration["prospective_packages"], "prospective_packages")
    rebuilt = build_study_declaration(
        declaration["study_spec"],
        prospective_packages=package_values,
    )
    if canonical_json(rebuilt) != canonical_json(declaration):
        raise ContractError("Ollama repeatability declaration semantic or identity drift")
    return dict(declaration)


def write_study_declaration(path: Path, value: JsonValue) -> None:
    """Write one verified declaration without replacing an existing file."""
    declaration = verify_study_declaration(value)
    with path.open("xb") as output:
        output.write(canonical_json(declaration))
        output.flush()
        os.fsync(output.fileno())


def load_study_declaration(path: Path) -> dict[str, JsonValue]:
    """Load one strict canonical declaration without following a final symlink."""
    return verify_study_declaration(_strict_canonical_file(path, "study declaration"))


def qwen3_repeatability_study_spec() -> dict[str, JsonValue]:
    """Return the pinned Qwen3 study intent from repository and user-provided evidence."""
    prompt = b"Return exactly this ASCII text and nothing else: REPEATABILITY-ANCHOR-2026"
    return {
        "record_type": "ollama_repeatability_study_spec",
        "schema_version": SCHEMA_VERSION,
        "study_name": "qwen3-8b-q8-ollama-repeatability-2026",
        "foundation_commit": FOUNDATION_COMMIT,
        "known_identity": {
            "runtime": {
                "evidence_source": "user_provided_prior_identity",
                "ollama_version": "0.35.1",
                "artifact_sha256": None,
                "selected_internal_runner": None,
                "metal_state": None,
                "build_info": None,
            },
            "model": {
                "evidence_source": "user_provided_prior_identity",
                "request_model": "qwen3:8b:local",
                "canonical_model_name": "qwen3:8b",
                "representation": "ollama_manifest",
                "quantization": "Q8",
                "manifest_digest": QWEN3_MANIFEST_DIGEST,
                "manifest_bytes_sha256": None,
                "config_sha256": None,
                "layer_digests": [],
                "artifact_closure_sha256": None,
            },
            "host": {
                "evidence_source": "user_provided_prior_identity",
                "observation_status": "not_reprobed_for_declaration",
                "chip": "Apple M5 Pro",
                "architecture": "arm64",
                "cpu_cores": 18,
                "performance_cores": 6,
                "efficiency_cores": 12,
                "unified_memory_bytes": 25_769_803_776,
                "os_name": "macOS",
                "os_version": "27.0.1",
                "os_build": "26A434",
            },
        },
        "prompt_catalog": [
            {
                "prompt_id": "anchor",
                "prompt_base64": encode_bytes(prompt),
                "prompt_sha256": digest_bytes(prompt),
            },
        ],
        "request_controls": {
            "raw": True,
            "think_mode": "false",
            "stream": False,
            "shift": False,
            "truncate": False,
            "keep_alive_seconds": 0,
            "seed": 424_242,
            "temperature_millionths": 0,
            "top_p_millionths": 1_000_000,
            "top_k": 1,
            "min_p_millionths": 0,
            "repeat_penalty_millionths": 1_000_000,
            "context_tokens": 8_192,
            "max_output_tokens": 64,
        },
        "transport": {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 11_434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
            "absolute_request_deadline_ms": 120_000,
            "max_identity_response_bytes": 1_048_576,
            "max_generate_response_bytes": 8_388_608,
            "redirects": "forbidden",
            "proxies": "forbidden",
            "retries": 0,
        },
        "study_design": {
            "repeats_per_prompt": 5,
            "run_order": "prompt_catalog_then_repeat_index",
            "cache_cohorts": ["cold_model_warm_process"],
            "concurrency": 1,
            "attempts_per_run": 1,
            "selective_reruns": "forbidden",
            "hidden_warmups": "forbidden",
        },
    }


@dataclass(frozen=True, slots=True)
class DeclarationReplayResult:
    """Offline replay summary for a synthetic declaration fixture bundle."""

    bundle_root: str
    declaration_id: str
    declaration_complete: bool
    scheduled_runs: int
    physical_network_requests: int
    model_actions: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "declaration_id": self.declaration_id,
            "declaration_complete": self.declaration_complete,
            "scheduled_runs": self.scheduled_runs,
            "physical_network_requests": self.physical_network_requests,
            "model_actions": self.model_actions,
        }


def compile_declaration_fixture(output_root: Path) -> tuple[Path, DeclarationReplayResult]:
    """Publish deterministic non-observed declaration evidence with zero physical actions."""
    spec = qwen3_repeatability_study_spec()
    declaration = build_study_declaration(spec)
    source: dict[str, JsonValue] = {
        "record_type": "ollama_declaration_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_declaration_contract_evidence_only",
        "observed_hardware_evidence": False,
        "physical_network_requests": 0,
        "socket_calls": 0,
        "model_actions": 0,
        "external_network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }
    destination = publish_bundle(
        {
            "source/fixture.json": canonical_json(source),
            "source/study-spec.json": canonical_json(spec),
            "declaration.json": canonical_json(declaration),
        },
        output_root,
        name_prefix="localinferencelab-ollama-declaration-synthetic-v1",
    )
    return destination, replay_declaration_fixture(destination)


def replay_declaration_fixture(bundle: Path) -> DeclarationReplayResult:
    """Replay a declaration fixture bundle with no network, model, or host probe."""
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/fixture.json",
        "source/study-spec.json",
        "declaration.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("declaration fixture bundle has an invalid content set")
    source = _mapping(
        _canonical_bytes(
            files["source/fixture.json"],
            "ollama declaration fixture source",
        ),
        "ollama_declaration_fixture_source",
    )
    source_fields = {
        "record_type",
        "schema_version",
        "evidence_status",
        "observed_hardware_evidence",
        "physical_network_requests",
        "socket_calls",
        "model_actions",
        "external_network_actions",
        "cloud_actions",
        "spend_actions",
    }
    _keys(source, source_fields, "ollama_declaration_fixture_source")
    expected_source: dict[str, JsonValue] = {
        "record_type": "ollama_declaration_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_declaration_contract_evidence_only",
        "observed_hardware_evidence": False,
        "physical_network_requests": 0,
        "socket_calls": 0,
        "model_actions": 0,
        "external_network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }
    if files["source/fixture.json"] != canonical_json(expected_source):
        raise ContractError("declaration fixture source non-actions drift")
    spec = validate_json_value(
        _canonical_bytes(
            files["source/study-spec.json"],
            "Ollama declaration fixture study specification",
        ),
    )
    declaration = verify_study_declaration(
        _canonical_bytes(
            files["declaration.json"],
            "Ollama declaration fixture declaration",
        ),
    )
    if canonical_json(declaration) != canonical_json(build_study_declaration(spec)):
        raise ContractError("declaration fixture does not replay from its source spec")
    eligibility = _mapping(declaration["eligibility"], "eligibility")
    completeness = _mapping(
        eligibility["declaration_completeness"],
        "eligibility.declaration_completeness",
    )
    return DeclarationReplayResult(
        content_root,
        cast("str", declaration["declaration_id"]),
        completeness["status"] == "complete",
        len(_array(declaration["run_schedule"], "run_schedule")),
        0,
        0,
    )
