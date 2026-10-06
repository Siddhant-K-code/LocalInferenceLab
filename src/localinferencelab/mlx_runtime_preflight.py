"""Parent-owned custody, validation, and replay for MLX runtime-only preflight."""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import socket
import stat
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast
from urllib.parse import urlsplit

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_canonical_json_file,
)
from localinferencelab.custody import publish_bundle_at, read_closed_bundle
from localinferencelab.mlx_custody import (
    _canonical_value,
    _create_interpreter_snapshot_at,
    _create_worker_snapshot_at,
    _FrameChannel,
    _open_descriptors,
    _open_directory_no_follow,
    _open_private_output_root,
    _parent_process_evidence,
    _read_launch_target,
    _revalidate_output_root_launch_path,
    _revalidate_output_root_path,
    _terminate_and_wait,
    _verify_file_identity,
    _wait_child,
    _write_exclusive_at,
)
from localinferencelab.mlx_manifest import compile_runtime_manifest, verify_runtime_manifest
from localinferencelab.mlx_runner import build_mlx_prospective_package, mlx_study_spec
from localinferencelab.mlx_runtime_preflight_worker import (
    ALLOWED_PROBES,
    AUTHORIZATION_LIFETIME_NS,
    ENVIRONMENT_ID,
    INTERPRETER_IDENTITY_FD,
    PROTOCOL_DESCRIPTOR,
    PROTOCOL_ID,
    RUNTIME_ROOT_FD,
    SCHEMA_VERSION,
    WORKER_CODE_ID,
    WORKER_DESCRIPTOR,
    WORKER_FD,
)

MLX_VERSION = "0.29.3"
MLX_LM_VERSION = "0.30.6"
MLX_REVISION = "0e3ff3643b1c3719f78814b98e0d222afbad867c"
MLX_LM_REVISION = "5cfec4cb39deba54210b3ff4d86f2337c7bc10b5"
DEFAULT_DEADLINE_NS = AUTHORIZATION_LIFETIME_NS
MAX_BUNDLE_FILE_BYTES = 2 * 1024 * 1024
EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256 = (
    "sha256:78dadf2ac01cdaa29eaf2207f273726c0a22bbee0703849df812c65bda4bd927"
)
EXPECTED_OBSERVED_LOCK_ID = (
    "sha256:fd3dba6568f2efa9ac4f7f0b82998e97fda08013e1829b1c3a4bb62c6578e1ad"
)
OBSERVED_FAILURE_ID = "sha256:1cf37092ca3c503be4836b071c20c0ecc76b6bf180c54339e675a868c272a8f8"
OBSERVED_CONSUMPTION_ID = "sha256:201ea165a01eeb86d4c76b0a337b0ef4fe82ece7578e704d0093491fdd46dda8"
OBSERVED_AUTHORIZATION_ID = (
    "sha256:65dd8b73f5e879b76ab8d5501aedf56e6941a083f39d4add9bd04bde071456cc"
)
EXPECTED_OBSERVED_NEGATIVE_PROJECTION_ID = (
    "sha256:be758bfa5a4a3481cd04b87071498c233e36048368e81391825f4663796da99c"
)
_PRIVATE_DIRECTORY_MODE = 0o700
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_NONCE_BYTES = 32
_MAX_IMPORTED_MODULES = 4_096
_PREFLIGHT_RESULT_SEQUENCE = 6
_PUBLIC_PACKAGE_DOMAINS = {"files.pythonhosted.org", "pypi.org"}
_PREFLIGHT_LAUNCH_ENVIRONMENT = {
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
_PACKAGE_NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SAFE_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$")
_SAFE_ERROR_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SCHEMA_EXECUTION_BLOCKER = (
    "schema 1.0 runtime-preflight execution is disabled: mlx-lm==0.30.6 declares "
    "mlx>=0.30.4 on Darwin, but the reviewed selected runtime pins mlx==0.29.3; "
    "a compatible pair requires a separately reviewed schema and authorization"
)
_FORBIDDEN_ACTIONS = (
    "arbitrary_code_or_commands",
    "benchmarking",
    "cache_construction_or_mutation",
    "cloud_model_actions",
    "generation",
    "inference",
    "model_discovery_or_download",
    "model_load",
    "prompt_or_token_processing",
    "tokenizer_discovery_or_load",
)
_MESSAGE_SEQUENCE = cast("list[str]", PROTOCOL_DESCRIPTOR["sequence"])
_PARENT_MESSAGES = {"parent_hello", "authorize_once", "preflight_once", "shutdown"}
_WORKER_MESSAGES = {
    "worker_identity",
    "authorization_ack",
    "preflight_result",
    "shutdown_ack",
}
_PREFLIGHT_ACTION_LEDGER = {
    "attempts": 1,
    "retries": 0,
    "warmups": 0,
    "worker_process_starts": 1,
    "socketpair_creations": 1,
    "authorizations_consumed": 1,
    "parent_frames": 4,
    "worker_frames": 4,
    "preflight_once_commands": 1,
    "shutdowns": 1,
}
_SUCCESS_WORKER_ACTIONS = {
    "mlx_imports": 1,
    "mlx_lm_imports": 1,
    "distribution_version_queries": 2,
    "default_device_queries": 1,
    "metal_availability_queries": 1,
    "default_stream_queries": 1,
    "synchronizations": 1,
}
_ZERO_MODEL_NON_ACTIONS = {
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
    "package_index_requests": 0,
    "model_repository_requests": 0,
    "cloud_actions": 0,
    "spend_actions": 0,
}
_ZERO_GUARDED_ACTION_ATTEMPTS = {
    "network": 0,
    "process_or_command": 0,
    "filesystem_mutation": 0,
}
_GUARDED_ACTION_ATTEMPT_MAXIMA = dict.fromkeys(_ZERO_GUARDED_ACTION_ATTEMPTS, 1)
_ZERO_COMPLETED_FORBIDDEN_ACTIONS = dict(_ZERO_GUARDED_ACTION_ATTEMPTS)


@dataclass(frozen=True, slots=True)
class RuntimePreflightReplayResult:
    """Verified summary of one physical runtime-only preflight."""

    bundle_root: str
    preflight_record_id: str
    preflight_package_id: str
    runtime_manifest_id: str
    protocol_id: str
    terminal_state: str
    child_exit_code: int
    imported_module_count: int
    bound_runtime_module_count: int
    metal_is_available: bool | None
    default_device_representation: str | None
    synchronization_completed: bool
    authorization_consumptions: int
    python_audited_guarded_action_attempts: int
    worker_reported_completed_forbidden_actions: int
    completed_forbidden_actions_proven_by_parent: bool
    model_actions: int
    remaining_requirements: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "preflight_record_id": self.preflight_record_id,
            "preflight_package_id": self.preflight_package_id,
            "runtime_manifest_id": self.runtime_manifest_id,
            "protocol_id": self.protocol_id,
            "terminal_state": self.terminal_state,
            "child_exit_code": self.child_exit_code,
            "imported_module_count": self.imported_module_count,
            "bound_runtime_module_count": self.bound_runtime_module_count,
            "metal_is_available": self.metal_is_available,
            "default_device_representation": self.default_device_representation,
            "synchronization_completed": self.synchronization_completed,
            "authorization_consumptions": self.authorization_consumptions,
            "python_audited_guarded_action_attempts": (self.python_audited_guarded_action_attempts),
            "worker_reported_completed_forbidden_actions": (
                self.worker_reported_completed_forbidden_actions
            ),
            "completed_forbidden_actions_proven_by_parent": (
                self.completed_forbidden_actions_proven_by_parent
            ),
            "model_actions": self.model_actions,
            "remaining_requirements": self.remaining_requirements,
        }


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = 256) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum count {maximum}")
    return value


def _keys(value: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(
    value: JsonValue,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ContractError(f"{label} must be <= {maximum}")
    return value


def _boolean(value: JsonValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _sha256(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _nonce(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    try:
        decoded = decode_bytes(text)
    except ContractError as error:
        raise ContractError(f"{label} must be canonical URL-safe base64") from error
    if len(decoded) != _NONCE_BYTES:
        raise ContractError(f"{label} must encode exactly 32 bytes")
    return text


def _normalize_distribution_name(value: JsonValue, label: str) -> str:
    name = _text(value, label, maximum=128).lower().replace("_", "-").replace(".", "-")
    name = re.sub(r"-+", "-", name)
    if _PACKAGE_NAME_PATTERN.fullmatch(name) is None:
        raise ContractError(f"{label} is not a canonical distribution name")
    return name


def _relative_path(value: JsonValue, label: str) -> str:
    text = _text(value, label, maximum=1024)
    path = PurePosixPath(text)
    if (
        "\\" in text
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != text
    ):
        raise ContractError(f"{label} must be a canonical relative path")
    return text


def _require(*, condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def runtime_preflight_spec() -> dict[str, JsonValue]:
    """Return the exact additive runtime-only preflight specification."""
    return {
        "record_type": "mlx_runtime_preflight_spec",
        "schema_version": SCHEMA_VERSION,
        "action": "mlx_runtime_preflight_only",
        "reviewed_sources": [
            {
                "distribution": "mlx",
                "version": MLX_VERSION,
                "revision": MLX_REVISION,
            },
            {
                "distribution": "mlx-lm",
                "version": MLX_LM_VERSION,
                "revision": MLX_LM_REVISION,
            },
        ],
        "protocol": cast("dict[str, JsonValue]", PROTOCOL_DESCRIPTOR),
        "protocol_id": PROTOCOL_ID,
        "worker": cast("dict[str, JsonValue]", WORKER_DESCRIPTOR),
        "worker_code_id": WORKER_CODE_ID,
        "worker_program_sha256": EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256,
        "allowed_probes": list(ALLOWED_PROBES),
        "forbidden_actions": list(_FORBIDDEN_ACTIONS),
        "interpreter_flags": ["-I", "-S", "-E", "-s", "-B", "-"],
        "launch_environment": [
            {"name": name, "value": value}
            for name, value in sorted(_PREFLIGHT_LAUNCH_ENVIRONMENT.items())
        ],
        "environment_id": ENVIRONMENT_ID,
        "runtime_import_root": "retained_inherited_directory_descriptor_only",
        "imports_after_authorization_only": True,
        "result_validation": "strict_parent_schema_and_bound_root_module_closure",
        "execution_eligibility": "blocked_known_incompatible_dependency_pair",
        "public_execution_reachable": False,
        "compatible_pair_requires_new_schema_and_authorization": True,
        "python_audit_guard_scope": "python_audited_attempts_not_os_sandbox",
        "claim_scope": ("synthetic_protocol_contract_only_no_schema_1_0_observed_execution"),
        "explicit_blockers": [
            "known_incompatible_mlx_lm_declared_requirement",
            "applicable_dependency_distribution_semantic_closure",
            "complete_python_standard_library_closure",
            "complete_native_runtime_and_dynamic_loader_closure",
            "exact_cache_class_worker_evidence",
            "memory_limits",
            "model_action_authorization",
            "strict_model_parameter_key_shape_load_evidence",
        ],
    }


def runtime_preflight_capability_report() -> dict[str, JsonValue]:
    """Report the process-free description of the runtime-preflight surface."""
    return {
        "record_type": "mlx_runtime_preflight_capability_report",
        "schema_version": SCHEMA_VERSION,
        "action": "mlx_runtime_preflight_only",
        "execution_command": "mlx runtime-preflight",
        "execution_reachable": False,
        "execution_blocker": _SCHEMA_EXECUTION_BLOCKER,
        "compatible_pair_requires_new_schema_and_authorization": True,
        "pure_commands": [
            "mlx runtime-preflight-capability-report",
            "mlx runtime-preflight-failure-replay",
            "mlx runtime-preflight-inspect",
            "mlx runtime-preflight-negative-replay",
            "mlx runtime-preflight-replay",
            "mlx runtime-preflight-spec",
        ],
        "starts_one_local_child": False,
        "imports_exact_mlx_and_mlx_lm": False,
        "may_initialize_or_query_apple_runtime_or_metal": False,
        "synchronizes_mlx_default_streams": False,
        "synthetic_protocol_implementation_retained": True,
        "model_load": False,
        "tokenizer_load": False,
        "inference": False,
        "generation": False,
        "download": False,
        "cache_action": False,
        "benchmark": False,
        "cloud_action": False,
        "spend_action": False,
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "worker_program_sha256": EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256,
    }


def verify_runtime_lock(value: JsonValue, *, allow_synthetic: bool = False) -> dict[str, JsonValue]:
    """Verify one exact platform runtime artifact lock."""
    lock = _mapping(value, "mlx_runtime_preflight_lock")
    fields = {
        "record_type",
        "schema_version",
        "evidence_kind",
        "platform",
        "reviewed_sources",
        "requested",
        "artifacts",
        "lock_id",
    }
    _keys(lock, fields, "mlx_runtime_preflight_lock")
    evidence_kind = lock["evidence_kind"]
    if (
        lock["record_type"] != "mlx_runtime_preflight_lock"
        or lock["schema_version"] != SCHEMA_VERSION
        or evidence_kind not in {"observed_package_lock", "synthetic_fixture"}
        or (evidence_kind == "synthetic_fixture" and not allow_synthetic)
    ):
        raise ContractError("unsupported MLX runtime-preflight lock")
    platform = _mapping(lock["platform"], "runtime_lock.platform")
    _keys(platform, {"system", "machine", "python_abi"}, "runtime_lock.platform")
    for name in ("system", "machine", "python_abi"):
        _text(platform[name], f"runtime_lock.platform.{name}", maximum=64)
    reviewed = _array(lock["reviewed_sources"], "runtime_lock.reviewed_sources", maximum=2)
    expected_reviewed = cast("list[JsonValue]", runtime_preflight_spec()["reviewed_sources"])
    if reviewed != expected_reviewed:
        raise ContractError("runtime lock source revision claims differ from the reviewed sources")
    requested = [
        _text(item, "runtime_lock.requested[]", maximum=128)
        for item in _array(lock["requested"], "runtime_lock.requested", maximum=2)
    ]
    if requested != [f"mlx-lm=={MLX_LM_VERSION}", f"mlx=={MLX_VERSION}"]:
        raise ContractError("runtime lock request set must contain exact pinned MLX packages")
    artifacts: list[JsonValue] = []
    for index, item in enumerate(_array(lock["artifacts"], "runtime_lock.artifacts", maximum=256)):
        artifact = _mapping(item, f"runtime_lock.artifacts[{index}]")
        _keys(
            artifact,
            {"name", "version", "filename", "url", "size_bytes", "sha256"},
            f"runtime_lock.artifacts[{index}]",
        )
        name = _normalize_distribution_name(
            artifact["name"],
            f"runtime_lock.artifacts[{index}].name",
        )
        version = _text(
            artifact["version"],
            f"runtime_lock.artifacts[{index}].version",
            maximum=128,
        )
        filename = _text(
            artifact["filename"],
            f"runtime_lock.artifacts[{index}].filename",
            maximum=255,
        )
        if _SAFE_FILENAME_PATTERN.fullmatch(filename) is None:
            raise ContractError("runtime lock artifact filename is not privacy-safe")
        url = _text(artifact["url"], f"runtime_lock.artifacts[{index}].url", maximum=2048)
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname not in _PUBLIC_PACKAGE_DOMAINS
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ContractError("runtime lock artifacts must use credential-free public PyPI URLs")
        artifacts.append(
            {
                "name": name,
                "version": version,
                "filename": filename,
                "url": url,
                "size_bytes": _integer(
                    artifact["size_bytes"],
                    f"runtime_lock.artifacts[{index}].size_bytes",
                    minimum=1,
                ),
                "sha256": _sha256(
                    artifact["sha256"],
                    f"runtime_lock.artifacts[{index}].sha256",
                ),
            }
        )
    names = [cast("str", _mapping(item, "runtime artifact")["name"]) for item in artifacts]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ContractError("runtime lock artifact names must be unique and sorted")
    versions = {
        cast("str", _mapping(item, "runtime artifact")["name"]): cast(
            "str",
            _mapping(item, "runtime artifact")["version"],
        )
        for item in artifacts
    }
    if versions.get("mlx") != MLX_VERSION or versions.get("mlx-lm") != MLX_LM_VERSION:
        raise ContractError("runtime lock omits the exact reviewed MLX distributions")
    identity = _sha256(lock["lock_id"], "runtime_lock.lock_id")
    content = dict(lock)
    del content["lock_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime lock identity mismatch")
    if evidence_kind == "observed_package_lock" and identity != EXPECTED_OBSERVED_LOCK_ID:
        raise ContractError("runtime lock differs from the repository-pinned observed lock")
    return dict(lock)


def load_runtime_lock(path: Path, *, allow_synthetic: bool = False) -> dict[str, JsonValue]:
    """Load one canonical runtime lock."""
    return verify_runtime_lock(
        load_canonical_json_file(path, "MLX runtime-preflight lock"),
        allow_synthetic=allow_synthetic,
    )


def verify_install_receipt(
    value: JsonValue,
    *,
    runtime_lock: dict[str, JsonValue],
    runtime_manifest: dict[str, JsonValue],
    allow_synthetic: bool = False,
) -> dict[str, JsonValue]:
    """Verify package-network actions separately from the runtime preflight."""
    receipt = _mapping(value, "mlx_runtime_install_receipt")
    fields = {
        "record_type",
        "schema_version",
        "evidence_kind",
        "lock_id",
        "runtime_manifest_id",
        "runtime_root_closure_sha256",
        "installer",
        "preparation_actions",
        "dependency_semantic_closure",
        "package_network_actions",
        "installed_distributions",
        "artifacts",
        "receipt_id",
    }
    _keys(receipt, fields, "mlx_runtime_install_receipt")
    evidence_kind = receipt["evidence_kind"]
    if (
        receipt["record_type"] != "mlx_runtime_install_receipt"
        or receipt["schema_version"] != SCHEMA_VERSION
        or evidence_kind not in {"observed_package_install", "synthetic_fixture"}
        or (evidence_kind == "synthetic_fixture" and not allow_synthetic)
    ):
        raise ContractError("unsupported MLX runtime install receipt")
    if receipt["lock_id"] != runtime_lock["lock_id"]:
        raise ContractError("runtime install receipt lock substitution")
    if receipt["runtime_manifest_id"] != runtime_manifest["manifest_id"]:
        raise ContractError("runtime install receipt manifest substitution")
    package_root = _mapping(runtime_manifest["package_root"], "runtime_manifest.package_root")
    if receipt["runtime_root_closure_sha256"] != package_root["closure_sha256"]:
        raise ContractError("runtime install receipt package-root closure mismatch")
    installer = _mapping(receipt["installer"], "runtime_install_receipt.installer")
    _keys(installer, {"name", "version", "invocations"}, "runtime_install_receipt.installer")
    if installer["name"] != "uv":
        raise ContractError("runtime install receipt must identify uv")
    _text(installer["version"], "runtime_install_receipt.installer.version", maximum=64)
    invocation_count = _integer(
        installer["invocations"],
        "runtime_install_receipt.installer.invocations",
        minimum=1,
        maximum=16,
    )
    actions: list[dict[str, JsonValue]] = []
    allowed_operations = {
        "dependency_lock_compile",
        "dependency_resolution",
        "final_root_install",
        "top_level_artifact_acquisition",
        "top_level_lock_compile",
    }
    for index, item in enumerate(
        _array(
            receipt["preparation_actions"],
            "runtime_install_receipt.preparation_actions",
            maximum=16,
        )
    ):
        action = _mapping(item, f"preparation_actions[{index}]")
        _keys(
            action,
            {
                "sequence",
                "operation",
                "outcome",
                "physical_network_access",
                "index_domains",
                "artifact_fetches",
                "exact_http_request_count",
                "model_repository_requests",
                "arbitrary_url_requests",
                "credential_material_recorded",
            },
            f"preparation_actions[{index}]",
        )
        if _integer(action["sequence"], f"preparation_actions[{index}].sequence") != index + 1:
            raise ContractError("runtime preparation action sequence is not contiguous")
        operation = _text(
            action["operation"],
            f"preparation_actions[{index}].operation",
            maximum=64,
        )
        outcome = _text(
            action["outcome"],
            f"preparation_actions[{index}].outcome",
            maximum=64,
        )
        if operation not in allowed_operations or outcome not in {
            "completed",
            "failed_incompatible_requirement",
        }:
            raise ContractError("runtime preparation action is unsupported")
        if outcome == "failed_incompatible_requirement" and operation != "dependency_resolution":
            raise ContractError("only dependency resolution may record the reviewed conflict")
        physical_network = _boolean(
            action["physical_network_access"],
            f"preparation_actions[{index}].physical_network_access",
        )
        action_domains = [
            _text(domain, f"preparation_actions[{index}].index_domains[]", maximum=255)
            for domain in _array(
                action["index_domains"],
                f"preparation_actions[{index}].index_domains",
                maximum=4,
            )
        ]
        if action_domains != sorted(action_domains) or not set(action_domains).issubset(
            _PUBLIC_PACKAGE_DOMAINS
        ):
            raise ContractError("runtime preparation action domains are not allowlisted")
        fetches = _integer(
            action["artifact_fetches"],
            f"preparation_actions[{index}].artifact_fetches",
        )
        request_count_value = action["exact_http_request_count"]
        if request_count_value is not None:
            _integer(
                request_count_value,
                f"preparation_actions[{index}].exact_http_request_count",
            )
        if not physical_network and (action_domains or fetches != 0 or request_count_value != 0):
            raise ContractError("offline runtime preparation action reports network effects")
        if (
            _integer(
                action["model_repository_requests"],
                f"preparation_actions[{index}].model_repository_requests",
            )
            != 0
            or _integer(
                action["arbitrary_url_requests"],
                f"preparation_actions[{index}].arbitrary_url_requests",
            )
            != 0
            or _boolean(
                action["credential_material_recorded"],
                f"preparation_actions[{index}].credential_material_recorded",
            )
        ):
            raise ContractError("runtime preparation action exceeded package-index scope")
        actions.append(dict(action))
    if len(actions) != invocation_count:
        raise ContractError("runtime preparation action count differs from installer invocations")
    if evidence_kind == "observed_package_install":
        observed_operations = [cast("str", action["operation"]) for action in actions]
        observed_outcomes = [cast("str", action["outcome"]) for action in actions]
        if observed_operations != [
            "dependency_resolution",
            "top_level_artifact_acquisition",
            "top_level_lock_compile",
            "dependency_lock_compile",
            "final_root_install",
        ] or observed_outcomes != [
            "failed_incompatible_requirement",
            "completed",
            "completed",
            "completed",
            "completed",
        ]:
            raise ContractError("observed runtime preparation action history is incomplete")
    dependency_closure = _mapping(
        receipt["dependency_semantic_closure"],
        "runtime_install_receipt.dependency_semantic_closure",
    )
    _keys(
        dependency_closure,
        {
            "status",
            "requesting_distribution",
            "declared_requirement",
            "selected_distribution",
            "resolver_outcome",
            "substitution_performed",
        },
        "runtime_install_receipt.dependency_semantic_closure",
    )
    for field in (
        "status",
        "requesting_distribution",
        "declared_requirement",
        "selected_distribution",
        "resolver_outcome",
    ):
        _text(
            dependency_closure[field],
            f"runtime_install_receipt.dependency_semantic_closure.{field}",
            maximum=256,
        )
    if _boolean(
        dependency_closure["substitution_performed"],
        "runtime_install_receipt.dependency_semantic_closure.substitution_performed",
    ):
        raise ContractError("runtime preparation substituted an unreviewed distribution")
    if evidence_kind == "observed_package_install" and dependency_closure != {
        "status": "blocked_incompatible_declared_requirement",
        "requesting_distribution": "mlx-lm==0.30.6",
        "declared_requirement": 'mlx>=0.30.4; platform_system == "Darwin"',
        "selected_distribution": "mlx==0.29.3",
        "resolver_outcome": "unsatisfiable_without_substitution",
        "substitution_performed": False,
    }:
        raise ContractError("observed runtime dependency conflict evidence drift")
    network = _mapping(
        receipt["package_network_actions"],
        "runtime_install_receipt.package_network_actions",
    )
    _keys(
        network,
        {
            "scope",
            "index_domains",
            "artifact_fetches",
            "final_root_artifact_fetches",
            "exact_http_request_count",
            "model_repository_requests",
            "arbitrary_url_requests",
            "credential_material_recorded",
        },
        "runtime_install_receipt.package_network_actions",
    )
    if (
        network["scope"] != "exact_locked_pypi_runtime_artifacts_only"
        or network["exact_http_request_count"] is not None
        or network["model_repository_requests"] != 0
        or network["arbitrary_url_requests"] != 0
        or network["credential_material_recorded"] is not False
    ):
        raise ContractError("runtime install network scope is not fail-closed")
    domains = [
        _text(item, "package_network_actions.index_domains[]", maximum=255)
        for item in _array(
            network["index_domains"],
            "package_network_actions.index_domains",
            maximum=4,
        )
    ]
    if domains != sorted(domains) or not set(domains).issubset(_PUBLIC_PACKAGE_DOMAINS):
        raise ContractError("runtime install index domains are not the public PyPI allowlist")
    artifact_fetches = _integer(
        network["artifact_fetches"],
        "package_network_actions.artifact_fetches",
    )
    final_root_artifact_fetches = _integer(
        network["final_root_artifact_fetches"],
        "package_network_actions.final_root_artifact_fetches",
    )
    lock_artifacts = cast("list[JsonValue]", runtime_lock["artifacts"])
    if (
        artifact_fetches != sum(cast("int", action["artifact_fetches"]) for action in actions)
        or final_root_artifact_fetches != len(lock_artifacts)
        or final_root_artifact_fetches != cast("int", actions[-1]["artifact_fetches"])
    ):
        raise ContractError("runtime install artifact-fetch accounting differs from the exact lock")
    action_domain_union = sorted(
        {
            cast("str", domain)
            for action in actions
            for domain in cast("list[JsonValue]", action["index_domains"])
        }
    )
    if domains != action_domain_union:
        raise ContractError("runtime install domain summary differs from preparation actions")
    if receipt["artifacts"] != lock_artifacts:
        raise ContractError("runtime install artifacts differ from the exact lock")
    manifest_distributions = [
        {
            "name": _mapping(item, "runtime distribution")["name"],
            "version": _mapping(item, "runtime distribution")["version"],
            "metadata_sha256": _mapping(item, "runtime distribution")["metadata_sha256"],
        }
        for item in cast("list[JsonValue]", runtime_manifest["distributions"])
    ]
    if receipt["installed_distributions"] != manifest_distributions:
        raise ContractError("runtime install distribution metadata differs from the manifest")
    identity = _sha256(receipt["receipt_id"], "runtime_install_receipt.receipt_id")
    content = dict(receipt)
    del content["receipt_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime install receipt identity mismatch")
    return dict(receipt)


def load_install_receipt(
    path: Path,
    *,
    runtime_lock: dict[str, JsonValue],
    runtime_manifest: dict[str, JsonValue],
    allow_synthetic: bool = False,
) -> dict[str, JsonValue]:
    """Load one canonical package-install receipt."""
    return verify_install_receipt(
        load_canonical_json_file(path, "MLX runtime install receipt"),
        runtime_lock=runtime_lock,
        runtime_manifest=runtime_manifest,
        allow_synthetic=allow_synthetic,
    )


def _require_runtime_preflight_execution_eligible(
    receipt: dict[str, JsonValue],
    *,
    allow_synthetic: bool,
) -> None:
    dependency = _mapping(
        receipt["dependency_semantic_closure"],
        "runtime_install_receipt.dependency_semantic_closure",
    )
    if allow_synthetic:
        if (
            receipt["evidence_kind"] != "synthetic_fixture"
            or dependency["status"] != "satisfied_exact_fixture"
        ):
            raise ContractError("synthetic runtime-preflight path accepts only exact test fixtures")
        return
    raise ContractError(_SCHEMA_EXECUTION_BLOCKER)


def build_runtime_preflight_package(
    runtime_manifest_value: JsonValue,
    runtime_lock_value: JsonValue,
    install_receipt_value: JsonValue,
    *,
    allow_synthetic: bool = False,
) -> dict[str, JsonValue]:
    """Build the exact preflight package from static identities."""
    manifest = verify_runtime_manifest(runtime_manifest_value)
    runtime_lock = verify_runtime_lock(runtime_lock_value, allow_synthetic=allow_synthetic)
    receipt = verify_install_receipt(
        install_receipt_value,
        runtime_lock=runtime_lock,
        runtime_manifest=manifest,
        allow_synthetic=allow_synthetic,
    )
    _require_runtime_preflight_execution_eligible(
        receipt,
        allow_synthetic=allow_synthetic,
    )
    distributions = {
        cast("str", _mapping(item, "runtime distribution")["name"]): cast(
            "str",
            _mapping(item, "runtime distribution")["version"],
        )
        for item in cast("list[JsonValue]", manifest["distributions"])
    }
    if distributions.get("mlx") != MLX_VERSION or distributions.get("mlx-lm") != MLX_LM_VERSION:
        raise ContractError("runtime manifest does not contain the exact pinned MLX versions")
    worker = _mapping(manifest["worker_program"], "runtime_manifest.worker_program")
    if worker["sha256"] != EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256:
        raise ContractError("runtime manifest worker differs from the sealed preflight worker")
    spec = runtime_preflight_spec()
    package: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_package",
        "schema_version": SCHEMA_VERSION,
        "preflight_spec_id": canonical_identity(spec),
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "worker_program_sha256": EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256,
        "runtime_manifest_id": manifest["manifest_id"],
        "runtime_manifest_sha256": digest_bytes(canonical_json(manifest)),
        "runtime_lock_id": runtime_lock["lock_id"],
        "install_receipt_id": receipt["receipt_id"],
        "expected_versions": {"mlx": MLX_VERSION, "mlx_lm": MLX_LM_VERSION},
        "allowed_probes": list(ALLOWED_PROBES),
        "forbidden_actions": list(_FORBIDDEN_ACTIONS),
    }
    package["preflight_package_id"] = canonical_identity(package)
    return verify_runtime_preflight_package(package)


def verify_runtime_preflight_package(value: JsonValue) -> dict[str, JsonValue]:
    """Verify one exact runtime-preflight package."""
    package = _mapping(value, "mlx_runtime_preflight_package")
    fields = {
        "record_type",
        "schema_version",
        "preflight_spec_id",
        "protocol_id",
        "worker_code_id",
        "worker_program_sha256",
        "runtime_manifest_id",
        "runtime_manifest_sha256",
        "runtime_lock_id",
        "install_receipt_id",
        "expected_versions",
        "allowed_probes",
        "forbidden_actions",
        "preflight_package_id",
    }
    _keys(package, fields, "mlx_runtime_preflight_package")
    if (
        package["record_type"] != "mlx_runtime_preflight_package"
        or package["schema_version"] != SCHEMA_VERSION
        or package["preflight_spec_id"] != canonical_identity(runtime_preflight_spec())
        or package["protocol_id"] != PROTOCOL_ID
        or package["worker_code_id"] != WORKER_CODE_ID
        or package["worker_program_sha256"] != EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256
        or package["expected_versions"] != {"mlx": MLX_VERSION, "mlx_lm": MLX_LM_VERSION}
        or package["allowed_probes"] != list(ALLOWED_PROBES)
        or package["forbidden_actions"] != list(_FORBIDDEN_ACTIONS)
    ):
        raise ContractError("unsupported runtime-preflight package")
    for field in (
        "preflight_spec_id",
        "protocol_id",
        "worker_code_id",
        "worker_program_sha256",
        "runtime_manifest_id",
        "runtime_manifest_sha256",
        "runtime_lock_id",
        "install_receipt_id",
    ):
        _sha256(package[field], f"runtime_preflight_package.{field}")
    identity = _sha256(
        package["preflight_package_id"],
        "runtime_preflight_package.preflight_package_id",
    )
    content = dict(package)
    del content["preflight_package_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime-preflight package identity mismatch")
    return dict(package)


def _output_root_binding(descriptor: int, nonce: bytes) -> dict[str, JsonValue]:
    metadata = os.fstat(descriptor)
    binding: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_output_root_binding",
        "schema_version": SCHEMA_VERSION,
        "binding_mode": "physical_instance",
        "owner_scope": "current_effective_user",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "nonce_sha256": digest_bytes(nonce),
    }
    binding["output_root_id"] = canonical_identity(binding)
    return binding


def _verify_output_root_binding(value: JsonValue) -> dict[str, JsonValue]:
    binding = _mapping(value, "mlx_runtime_preflight_output_root_binding")
    fields = {
        "record_type",
        "schema_version",
        "binding_mode",
        "owner_scope",
        "device",
        "inode",
        "mode",
        "nonce_sha256",
        "output_root_id",
    }
    _keys(binding, fields, "mlx_runtime_preflight_output_root_binding")
    if (
        binding["record_type"] != "mlx_runtime_preflight_output_root_binding"
        or binding["schema_version"] != SCHEMA_VERSION
        or binding["binding_mode"] != "physical_instance"
        or binding["owner_scope"] != "current_effective_user"
    ):
        raise ContractError("unsupported runtime-preflight output-root binding")
    _integer(binding["device"], "output_root.device")
    _integer(binding["inode"], "output_root.inode", minimum=1)
    if _integer(binding["mode"], "output_root.mode") != _PRIVATE_DIRECTORY_MODE:
        raise ContractError("runtime-preflight output root must record mode 0700")
    _sha256(binding["nonce_sha256"], "output_root.nonce_sha256")
    identity = _sha256(binding["output_root_id"], "output_root.output_root_id")
    content = dict(binding)
    del content["output_root_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime-preflight output-root identity mismatch")
    return dict(binding)


def _runtime_scan_spec_from_manifest(manifest: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "record_type": "mlx_runtime_scan_spec",
        "schema_version": SCHEMA_VERSION,
        "python": manifest["python"],
        "expected_distributions": [
            {
                "name": _mapping(item, "runtime distribution")["name"],
                "version": _mapping(item, "runtime distribution")["version"],
            }
            for item in cast("list[JsonValue]", manifest["distributions"])
        ],
        "selected_module_files": manifest["selected_module_files"],
        "environment": manifest["environment"],
    }


def _open_bound_runtime_root(path: Path, manifest: dict[str, JsonValue]) -> int:
    descriptor = _open_directory_no_follow(path, "runtime root", trusted_launch_path=True)
    observed = os.fstat(descriptor)
    root = _mapping(manifest["package_root"], "runtime_manifest.package_root")
    if (
        observed.st_dev != root["device"]
        or observed.st_ino != root["inode"]
        or stat.S_IMODE(observed.st_mode) != root["mode"]
        or observed.st_uid != os.geteuid()
        or observed.st_mode & 0o022
    ):
        os.close(descriptor)
        raise ContractError("runtime-root physical identity differs from the manifest")
    return descriptor


def _spawn_runtime_worker(
    sealed_interpreter: Path,
    interpreter_argv0: Path,
    interpreter_identity_descriptor: int,
    worker_source_descriptor: int,
    runtime_root_descriptor: int,
    child_endpoint: socket.socket,
) -> int:
    descriptors = _open_descriptors()
    minimum = max(descriptors | {WORKER_FD, INTERPRETER_IDENTITY_FD, RUNTIME_ROOT_FD}) + 1
    duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD)
    sealed_source = fcntl.fcntl(worker_source_descriptor, duplicate_command, minimum)
    sealed_interpreter_identity: int | None = None
    sealed_runtime_root: int | None = None
    sealed_socket: int | None = None
    try:
        sealed_interpreter_identity = fcntl.fcntl(
            interpreter_identity_descriptor,
            duplicate_command,
            sealed_source + 1,
        )
        sealed_runtime_root = fcntl.fcntl(
            runtime_root_descriptor,
            duplicate_command,
            sealed_interpreter_identity + 1,
        )
        sealed_socket = fcntl.fcntl(
            child_endpoint.fileno(),
            duplicate_command,
            sealed_runtime_root + 1,
        )
        if duplicate_command == fcntl.F_DUPFD:
            for descriptor in (
                sealed_source,
                sealed_interpreter_identity,
                sealed_runtime_root,
                sealed_socket,
            ):
                os.set_inheritable(descriptor, False)
        descriptors = _open_descriptors()
        file_actions: list[tuple[int, ...] | tuple[int, int, str, int, int]] = [
            (os.POSIX_SPAWN_DUP2, sealed_source, 0),
            (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_DUP2, sealed_socket, WORKER_FD),
            (
                os.POSIX_SPAWN_DUP2,
                sealed_interpreter_identity,
                INTERPRETER_IDENTITY_FD,
            ),
            (os.POSIX_SPAWN_DUP2, sealed_runtime_root, RUNTIME_ROOT_FD),
        ]
        inherited = {WORKER_FD, INTERPRETER_IDENTITY_FD, RUNTIME_ROOT_FD}
        file_actions.extend(
            (os.POSIX_SPAWN_CLOSE, descriptor)
            for descriptor in sorted(descriptors)
            if descriptor >= WORKER_FD and descriptor not in inherited
        )
        argv = (str(interpreter_argv0), "-I", "-S", "-E", "-s", "-B", "-")
        try:
            return os.posix_spawn(
                str(sealed_interpreter),
                argv,
                _PREFLIGHT_LAUNCH_ENVIRONMENT,
                file_actions=file_actions,
            )
        except OSError as error:
            raise ContractError("sealed runtime-preflight worker launch failed") from error
    finally:
        if sealed_socket is not None:
            os.close(sealed_socket)
        if sealed_runtime_root is not None:
            os.close(sealed_runtime_root)
        if sealed_interpreter_identity is not None:
            os.close(sealed_interpreter_identity)
        os.close(sealed_source)


def _expect_message(
    value: dict[str, JsonValue],
    message_type: str,
    sequence: int,
    fields: set[str],
) -> None:
    _keys(value, fields | {"message_type", "sequence"}, message_type)
    if value["message_type"] != message_type:
        raise ContractError(f"expected {message_type}")
    if _integer(value["sequence"], f"{message_type}.sequence", minimum=1) != sequence:
        raise ContractError(f"{message_type} has wrong sequence")


def _verify_runtime_root_identity(
    value: JsonValue,
    manifest: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    identity = _mapping(value, "worker_identity.runtime_root")
    _keys(identity, {"device", "inode", "mode"}, "worker_identity.runtime_root")
    root = _mapping(manifest["package_root"], "runtime_manifest.package_root")
    for field in ("device", "inode", "mode"):
        _integer(identity[field], f"worker_identity.runtime_root.{field}")
        if identity[field] != root[field]:
            raise ContractError(f"worker runtime-root {field} mismatch")
    return dict(identity)


def _verify_worker_identity(
    value: dict[str, JsonValue],
    *,
    hello: dict[str, JsonValue],
    child_pid: int,
    parent_pid: int,
    interpreter: dict[str, JsonValue],
    worker_program: dict[str, JsonValue],
    runtime_manifest: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    fields = {
        "protocol_id",
        "worker_code_id",
        "preflight_spec_id",
        "preflight_package_id",
        "runtime_manifest_id",
        "parent_nonce",
        "worker_nonce",
        "pid",
        "ppid",
        "worker_fd",
        "runtime_root_fd",
        "open_file_descriptors",
        "environment_id",
        "interpreter",
        "worker_program",
        "runtime_root",
        "mlx_imports_before_authorization",
        "mlx_lm_imports_before_authorization",
    }
    _expect_message(value, "worker_identity", 2, fields)
    expected = {
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "preflight_spec_id": hello["preflight_spec_id"],
        "preflight_package_id": hello["preflight_package_id"],
        "runtime_manifest_id": hello["runtime_manifest_id"],
        "parent_nonce": hello["parent_nonce"],
        "pid": child_pid,
        "ppid": parent_pid,
        "worker_fd": WORKER_FD,
        "runtime_root_fd": RUNTIME_ROOT_FD,
        "environment_id": ENVIRONMENT_ID,
        "mlx_imports_before_authorization": 0,
        "mlx_lm_imports_before_authorization": 0,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise ContractError(f"worker identity {field} mismatch")
    _nonce(value["worker_nonce"], "worker_identity.worker_nonce")
    descriptors = _array(
        value["open_file_descriptors"],
        "worker_identity.open_file_descriptors",
        maximum=8,
    )
    if descriptors != [0, 1, 2, WORKER_FD, RUNTIME_ROOT_FD]:
        raise ContractError("runtime-preflight worker inherited unrelated descriptors")
    observed_interpreter = _verify_file_identity(
        value["interpreter"],
        "worker_identity.interpreter",
    )
    observed_program = _verify_file_identity(
        value["worker_program"],
        "worker_identity.worker_program",
    )
    if observed_interpreter != interpreter or observed_program != worker_program:
        raise ContractError("runtime-preflight worker launch-target identity mismatch")
    _verify_runtime_root_identity(value["runtime_root"], runtime_manifest)
    return dict(value)


def _build_authorization(
    hello: dict[str, JsonValue],
    worker_nonce: str,
    created_at_unix_ns: int,
) -> dict[str, JsonValue]:
    authorization: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_one_shot_authorization",
        "schema_version": SCHEMA_VERSION,
        "action": "mlx_runtime_preflight_only",
        "allowed_probes": list(ALLOWED_PROBES),
        "forbidden_actions": list(_FORBIDDEN_ACTIONS),
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
        "created_at_unix_ns": created_at_unix_ns,
        "expires_at_unix_ns": created_at_unix_ns + DEFAULT_DEADLINE_NS,
        "deadline_monotonic_ns": hello["deadline_monotonic_ns"],
    }
    authorization["authorization_id"] = canonical_identity(authorization)
    return authorization


def _verify_authorization(
    value: JsonValue,
    *,
    check_current_expiry: bool,
) -> dict[str, JsonValue]:
    authorization = _mapping(value, "mlx_runtime_preflight_one_shot_authorization")
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
    _keys(authorization, fields, "mlx_runtime_preflight_one_shot_authorization")
    if (
        authorization["record_type"] != "mlx_runtime_preflight_one_shot_authorization"
        or authorization["schema_version"] != SCHEMA_VERSION
        or authorization["action"] != "mlx_runtime_preflight_only"
        or authorization["allowed_probes"] != list(ALLOWED_PROBES)
        or authorization["forbidden_actions"] != list(_FORBIDDEN_ACTIONS)
        or authorization["protocol_id"] != PROTOCOL_ID
        or authorization["worker_code_id"] != WORKER_CODE_ID
    ):
        raise ContractError("unsupported runtime-preflight authorization")
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
        raise ContractError("authorization has an unexpected wall-clock lifetime")
    if check_current_expiry and (time.time_ns() >= expires or time.monotonic_ns() >= deadline):
        raise ContractError("runtime-preflight authorization has expired")
    identity = _sha256(authorization["authorization_id"], "authorization.authorization_id")
    content = dict(authorization)
    del content["authorization_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime-preflight authorization identity mismatch")
    return dict(authorization)


def _consume_authorization_at(
    output_root_descriptor: int,
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    verified_root = _verify_output_root_binding(output_root)
    verified = _verify_authorization(authorization, check_current_expiry=True)
    if verified["output_root_id"] != verified_root["output_root_id"]:
        raise ContractError("authorization output-root identity mismatch")
    consumed_at_unix_ns = time.time_ns()
    consumed_at_monotonic_ns = time.monotonic_ns()
    if consumed_at_unix_ns >= cast(
        "int",
        verified["expires_at_unix_ns"],
    ) or consumed_at_monotonic_ns >= cast("int", verified["deadline_monotonic_ns"]):
        raise ContractError("runtime-preflight authorization expired before consumption")
    consumption: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_authorization_consumption",
        "schema_version": SCHEMA_VERSION,
        "authorization_id": verified["authorization_id"],
        "action": "mlx_runtime_preflight_only",
        "preflight_package_id": verified["preflight_package_id"],
        "runtime_manifest_id": verified["runtime_manifest_id"],
        "output_root_id": verified["output_root_id"],
        "consumed_at_unix_ns": consumed_at_unix_ns,
        "consumed_at_monotonic_ns": consumed_at_monotonic_ns,
        "atomic_method": "exclusive_no_follow_output_root_marker",
    }
    consumption["consumption_id"] = canonical_identity(consumption)
    name = (
        ".localinferencelab-mlx-runtime-preflight-consumed-"
        f"{str(verified['authorization_id'])[7:]}.json"
    )
    try:
        _write_exclusive_at(output_root_descriptor, name, canonical_json(consumption))
    except FileExistsError as error:
        raise ContractError("runtime-preflight authorization was already consumed") from error
    return consumption


def _verify_consumption(
    value: JsonValue,
    authorization: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    consumption = _mapping(value, "mlx_runtime_preflight_authorization_consumption")
    fields = {
        "record_type",
        "schema_version",
        "authorization_id",
        "action",
        "preflight_package_id",
        "runtime_manifest_id",
        "output_root_id",
        "consumed_at_unix_ns",
        "consumed_at_monotonic_ns",
        "atomic_method",
        "consumption_id",
    }
    _keys(consumption, fields, "mlx_runtime_preflight_authorization_consumption")
    if (
        consumption["record_type"] != "mlx_runtime_preflight_authorization_consumption"
        or consumption["schema_version"] != SCHEMA_VERSION
        or consumption["action"] != "mlx_runtime_preflight_only"
        or consumption["atomic_method"] != "exclusive_no_follow_output_root_marker"
    ):
        raise ContractError("unsupported runtime-preflight authorization consumption")
    expected = {
        "authorization_id": authorization["authorization_id"],
        "preflight_package_id": authorization["preflight_package_id"],
        "runtime_manifest_id": authorization["runtime_manifest_id"],
        "output_root_id": output_root["output_root_id"],
    }
    for field, expected_value in expected.items():
        if consumption[field] != expected_value:
            raise ContractError(f"runtime-preflight consumption {field} mismatch")
    consumed_wall = _integer(
        consumption["consumed_at_unix_ns"],
        "consumption.consumed_at_unix_ns",
        minimum=1,
    )
    consumed_monotonic = _integer(
        consumption["consumed_at_monotonic_ns"],
        "consumption.consumed_at_monotonic_ns",
        minimum=1,
    )
    if not (
        cast("int", authorization["created_at_unix_ns"])
        <= consumed_wall
        < cast("int", authorization["expires_at_unix_ns"])
    ) or consumed_monotonic >= cast("int", authorization["deadline_monotonic_ns"]):
        raise ContractError("runtime-preflight consumption is outside authorization validity")
    identity = _sha256(consumption["consumption_id"], "consumption.consumption_id")
    content = dict(consumption)
    del content["consumption_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime-preflight consumption identity mismatch")
    return dict(consumption)


def _verify_authorization_ack(
    value: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
) -> None:
    fields = {
        "authorization_id",
        "parent_nonce",
        "worker_nonce",
        "consumed",
        "mlx_imports_before_authorization",
        "mlx_lm_imports_before_authorization",
    }
    _expect_message(value, "authorization_ack", 4, fields)
    expected = {
        "authorization_id": authorization["authorization_id"],
        "parent_nonce": authorization["parent_nonce"],
        "worker_nonce": authorization["worker_nonce"],
        "consumed": True,
        "mlx_imports_before_authorization": 0,
        "mlx_lm_imports_before_authorization": 0,
    }
    if value != {"message_type": "authorization_ack", "sequence": 4, **expected}:
        raise ContractError("runtime-preflight authorization acknowledgment mismatch")


def _verify_import_observations(
    value: JsonValue,
    *,
    completed: bool,
) -> list[JsonValue]:
    observations = _array(value, "preflight_result.import_observations", maximum=2)
    parsed: list[JsonValue] = []
    for index, item in enumerate(observations):
        observation = _mapping(item, f"import_observations[{index}]")
        _keys(
            observation,
            {
                "module",
                "completed",
                "duration_ns",
                "runtime_state_effect",
                "explicit_probe_actions_during_import",
            },
            f"import_observations[{index}]",
        )
        module = _text(observation["module"], f"import_observations[{index}].module")
        if module not in {"mlx.core", "mlx_lm"}:
            raise ContractError("runtime preflight reported an unauthorized import")
        if not _boolean(observation["completed"], f"import_observations[{index}].completed"):
            raise ContractError("recorded import observations must describe completed imports")
        _integer(
            observation["duration_ns"],
            f"import_observations[{index}].duration_ns",
            minimum=1,
        )
        effect = _text(
            observation["runtime_state_effect"],
            f"import_observations[{index}].runtime_state_effect",
            maximum=128,
        )
        expected_effect = {
            "mlx.core": "may_initialize_not_independently_observable",
            "mlx_lm": "may_initialize_default_generation_stream_per_pinned_source",
        }[module]
        if effect != expected_effect or observation["explicit_probe_actions_during_import"] != 0:
            raise ContractError("runtime import initialization accounting drift")
        parsed.append(dict(observation))
    modules = [cast("str", _mapping(item, "import observation")["module"]) for item in parsed]
    if modules != ["mlx.core", "mlx_lm"][: len(modules)]:
        raise ContractError("runtime import observations are missing, duplicate, or out of order")
    if completed and modules != ["mlx.core", "mlx_lm"]:
        raise ContractError("completed runtime preflight must import mlx and mlx_lm exactly once")
    return parsed


def _verify_module_record(
    value: JsonValue,
    index: int,
    runtime_files: dict[str, dict[str, JsonValue]],
) -> tuple[dict[str, JsonValue], bool]:
    record = _mapping(value, f"imported_modules[{index}]")
    fields = {
        "name",
        "origin_kind",
        "root_kind",
        "relative_path",
        "device",
        "inode",
        "mode",
        "size_bytes",
        "sha256",
    }
    _keys(record, fields, f"imported_modules[{index}]")
    name = _text(record["name"], f"imported_modules[{index}].name", maximum=512)
    if any(part in {"", ".", ".."} for part in name.split(".")):
        raise ContractError("imported module name is not canonical")
    origin_kind = _text(
        record["origin_kind"],
        f"imported_modules[{index}].origin_kind",
        maximum=64,
    )
    if origin_kind != "file":
        if origin_kind not in {
            "built_in",
            "frozen",
            "namespace",
            "sealed_stdin_worker",
            "stdlib_alias",
        }:
            raise ContractError("imported module has an unsupported origin kind")
        if origin_kind == "stdlib_alias" and name not in {"typing.io", "typing.re"}:
            raise ContractError("imported stdlib alias is not an exact supported alias")
        for field in (
            "root_kind",
            "relative_path",
            "device",
            "inode",
            "mode",
            "size_bytes",
            "sha256",
        ):
            if record[field] is not None:
                raise ContractError("fileless imported module contains file identity")
        return dict(record), False
    root_kind = _text(
        record["root_kind"],
        f"imported_modules[{index}].root_kind",
        maximum=64,
    )
    if root_kind not in {"bound_runtime_root", "stdlib", "platstdlib"}:
        raise ContractError("file-backed imported module escaped allowed roots")
    relative = _relative_path(
        record["relative_path"],
        f"imported_modules[{index}].relative_path",
    )
    normalized: dict[str, JsonValue] = {
        "name": name,
        "origin_kind": origin_kind,
        "root_kind": root_kind,
        "relative_path": relative,
        "device": _integer(record["device"], f"imported_modules[{index}].device"),
        "inode": _integer(
            record["inode"],
            f"imported_modules[{index}].inode",
            minimum=1,
        ),
        "mode": _integer(
            record["mode"],
            f"imported_modules[{index}].mode",
            maximum=0o7777,
        ),
        "size_bytes": _integer(
            record["size_bytes"],
            f"imported_modules[{index}].size_bytes",
        ),
        "sha256": _sha256(record["sha256"], f"imported_modules[{index}].sha256"),
    }
    if root_kind == "bound_runtime_root":
        expected = runtime_files.get(relative)
        if expected is None:
            raise ContractError("imported runtime module is outside the supplied-root closure")
        for field in ("device", "inode", "mode", "size_bytes", "sha256"):
            if normalized[field] != expected[field]:
                raise ContractError(f"imported runtime module {field} differs from manifest")
        return normalized, True
    if relative == "site-packages" or relative.startswith("site-packages/"):
        raise ContractError("stdlib-classified module cannot originate from site-packages")
    return normalized, False


def _verify_imported_modules(
    value: JsonValue,
    runtime_manifest: dict[str, JsonValue],
    *,
    completed: bool,
) -> tuple[list[JsonValue], int]:
    files = {
        cast("str", _mapping(item, "runtime file")["path"]): _mapping(item, "runtime file")
        for item in cast("list[JsonValue]", runtime_manifest["files"])
    }
    modules = _array(
        value,
        "preflight_result.imported_modules",
        maximum=_MAX_IMPORTED_MODULES,
    )
    parsed: list[JsonValue] = []
    bound_count = 0
    for index, item in enumerate(modules):
        module, bound = _verify_module_record(item, index, files)
        parsed.append(module)
        bound_count += int(bound)
    names = [cast("str", _mapping(item, "imported module")["name"]) for item in parsed]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ContractError("imported module names must be unique and sorted")
    if completed:
        required = {"mlx.core", "mlx_lm"}
        if not required.issubset(names):
            raise ContractError("completed runtime preflight omitted required imported modules")
        for required_name in required:
            module = _mapping(parsed[names.index(required_name)], "required imported module")
            if module["root_kind"] != "bound_runtime_root":
                raise ContractError("required MLX imports must originate from the bound root")
        if bound_count == 0:
            raise ContractError("completed runtime preflight has no bound-root module evidence")
    return parsed, bound_count


def _verify_worker_actions(value: JsonValue, *, completed: bool) -> dict[str, JsonValue]:
    actions = _mapping(value, "preflight_result.action_ledger")
    _keys(actions, set(_SUCCESS_WORKER_ACTIONS), "preflight_result.action_ledger")
    parsed = {
        name: _integer(actions[name], f"preflight_result.action_ledger.{name}", maximum=maximum)
        for name, maximum in _SUCCESS_WORKER_ACTIONS.items()
    }
    if completed and parsed != _SUCCESS_WORKER_ACTIONS:
        raise ContractError("completed runtime preflight action ledger drift")
    if parsed["mlx_lm_imports"] > parsed["mlx_imports"]:
        raise ContractError("mlx_lm import cannot precede a completed mlx import")
    if parsed["distribution_version_queries"] not in {0, 2}:
        raise ContractError("distribution version queries must complete as one exact pair")
    return cast("dict[str, JsonValue]", parsed)


def _verify_model_non_actions(value: JsonValue) -> dict[str, JsonValue]:
    non_actions = _mapping(value, "preflight_result.model_non_actions")
    _keys(non_actions, set(_ZERO_MODEL_NON_ACTIONS), "preflight_result.model_non_actions")
    parsed = {
        name: _integer(
            non_actions[name],
            f"preflight_result.model_non_actions.{name}",
            maximum=0,
        )
        for name in _ZERO_MODEL_NON_ACTIONS
    }
    return cast("dict[str, JsonValue]", parsed)


def _verify_guarded_action_attempts(value: JsonValue) -> dict[str, JsonValue]:
    attempts = _mapping(value, "preflight_result.guarded_action_attempts")
    _keys(
        attempts,
        set(_ZERO_GUARDED_ACTION_ATTEMPTS),
        "preflight_result.guarded_action_attempts",
    )
    parsed = {
        name: _integer(
            attempts[name],
            f"preflight_result.guarded_action_attempts.{name}",
            maximum=1,
        )
        for name in _ZERO_GUARDED_ACTION_ATTEMPTS
    }
    if sum(parsed.values()) > 1:
        raise ContractError("runtime preflight reported multiple guarded action attempts")
    if parsed != _ZERO_GUARDED_ACTION_ATTEMPTS:
        raise ContractError("runtime preflight reported a Python-audited forbidden action attempt")
    return cast("dict[str, JsonValue]", parsed)


def _verify_completed_forbidden_actions(value: JsonValue) -> dict[str, JsonValue]:
    completed = _mapping(value, "preflight_result.completed_forbidden_actions")
    _keys(
        completed,
        set(_ZERO_COMPLETED_FORBIDDEN_ACTIONS),
        "preflight_result.completed_forbidden_actions",
    )
    parsed = {
        name: _integer(
            completed[name],
            f"preflight_result.completed_forbidden_actions.{name}",
            maximum=0,
        )
        for name in _ZERO_COMPLETED_FORBIDDEN_ACTIONS
    }
    return cast("dict[str, JsonValue]", parsed)


def _verify_preflight_result(
    value: dict[str, JsonValue],
    *,
    authorization: dict[str, JsonValue],
    request_nonce: str,
    runtime_manifest: dict[str, JsonValue],
) -> tuple[dict[str, JsonValue], int]:
    fields = {
        "status",
        "error",
        "authorization_id",
        "preflight_package_id",
        "runtime_manifest_id",
        "output_root_id",
        "parent_nonce",
        "worker_nonce",
        "request_nonce",
        "package_versions",
        "import_observations",
        "imported_modules",
        "backend_facts",
        "synchronization",
        "action_ledger",
        "model_non_actions",
        "guarded_action_attempts",
        "completed_forbidden_actions",
        "runtime_root_import_path",
        "stdlib_closure_complete",
        "native_loader_closure_complete",
    }
    _expect_message(value, "preflight_result", 6, fields)
    expected = {
        "authorization_id": authorization["authorization_id"],
        "preflight_package_id": authorization["preflight_package_id"],
        "runtime_manifest_id": authorization["runtime_manifest_id"],
        "output_root_id": authorization["output_root_id"],
        "parent_nonce": authorization["parent_nonce"],
        "worker_nonce": authorization["worker_nonce"],
        "request_nonce": request_nonce,
        "runtime_root_import_path": "inherited_descriptor_only",
        "stdlib_closure_complete": False,
        "native_loader_closure_complete": False,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise ContractError(f"runtime preflight result {field} mismatch")
    status = _text(value["status"], "preflight_result.status", maximum=32)
    if status not in {"completed", "terminal_error"}:
        raise ContractError("runtime preflight result has an unsupported terminal status")
    completed = status == "completed"
    _verify_import_observations(value["import_observations"], completed=completed)
    modules, bound_count = _verify_imported_modules(
        value["imported_modules"],
        runtime_manifest,
        completed=completed,
    )
    value["imported_modules"] = modules
    _verify_worker_actions(value["action_ledger"], completed=completed)
    _verify_model_non_actions(value["model_non_actions"])
    _verify_completed_forbidden_actions(value["completed_forbidden_actions"])
    _verify_guarded_action_attempts(value["guarded_action_attempts"])
    if completed:
        if value["error"] is not None:
            raise ContractError("completed runtime preflight cannot contain an error")
        if value["package_versions"] != {"mlx": MLX_VERSION, "mlx_lm": MLX_LM_VERSION}:
            raise ContractError("imported MLX distribution versions differ from reviewed pins")
        backend = _mapping(value["backend_facts"], "preflight_result.backend_facts")
        _keys(
            backend,
            {
                "default_device_representation",
                "metal_is_available",
                "default_stream_representation",
                "per_kernel_metal_execution_proven",
            },
            "preflight_result.backend_facts",
        )
        for name in ("default_device_representation", "default_stream_representation"):
            representation = _text(backend[name], f"backend_facts.{name}", maximum=256)
            if "/" in representation or "\\" in representation or "0x" in representation:
                raise ContractError("backend representation is not privacy-safe")
        _boolean(backend["metal_is_available"], "backend_facts.metal_is_available")
        if backend["per_kernel_metal_execution_proven"] is not False:
            raise ContractError("runtime preflight cannot claim per-kernel Metal execution")
        synchronization = _mapping(
            value["synchronization"],
            "preflight_result.synchronization",
        )
        _keys(
            synchronization,
            {"completed", "duration_ns", "scope", "kernel_execution_claim"},
            "preflight_result.synchronization",
        )
        if (
            synchronization["completed"] is not True
            or synchronization["scope"] != "mlx_default_streams"
            or synchronization["kernel_execution_claim"] != "none"
        ):
            raise ContractError("runtime preflight synchronization evidence drift")
        _integer(
            synchronization["duration_ns"],
            "preflight_result.synchronization.duration_ns",
        )
    else:
        error = _mapping(value["error"], "preflight_result.error")
        _keys(error, {"phase", "category", "message_sha256"}, "preflight_result.error")
        _text(error["phase"], "preflight_result.error.phase", maximum=64)
        _text(error["category"], "preflight_result.error.category", maximum=128)
        _sha256(error["message_sha256"], "preflight_result.error.message_sha256")
        if (
            value["backend_facts"] is not None and not isinstance(value["backend_facts"], dict)
        ) or (
            value["synchronization"] is not None and not isinstance(value["synchronization"], dict)
        ):
            raise ContractError("terminal error contains malformed partial probe facts")
    return dict(value), bound_count


def _verify_shutdown_ack(
    value: dict[str, JsonValue],
    *,
    parent_nonce: str,
    worker_nonce: str,
    request_nonce: str,
) -> None:
    fields = {"parent_nonce", "worker_nonce", "request_nonce", "terminal_state"}
    _expect_message(value, "shutdown_ack", 8, fields)
    if (
        value["parent_nonce"] != parent_nonce
        or value["worker_nonce"] != worker_nonce
        or value["request_nonce"] != request_nonce
        or value["terminal_state"] != "preflight_closed"
    ):
        raise ContractError("runtime-preflight shutdown acknowledgment mismatch")


def _transcript(entries: list[JsonValue]) -> dict[str, JsonValue]:
    transcript: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_transcript",
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "frames": entries,
    }
    transcript["transcript_id"] = canonical_identity(transcript)
    return transcript


def _reconstruct_eligibility(*, completed: bool = True) -> dict[str, JsonValue]:
    legacy_package = build_mlx_prospective_package(mlx_study_spec())
    legacy = _mapping(legacy_package["eligibility"], "legacy eligibility")
    legacy_missing = cast("list[JsonValue]", legacy["missing_requirements"])
    remaining = {cast("str", item) for item in legacy_missing}
    if not completed:
        custody_closed = {
            "one_shot_authorization",
            "output_root_physical_binding",
            "production_worker_private_ipc_protocol_and_result_validation_implementation",
            "worker_process_birth_and_executable_binding",
        }
        remaining.difference_update(custody_closed)
        remaining.update(
            {
                "complete_python_standard_library_closure",
                "complete_native_runtime_and_dynamic_loader_closure",
                "generated_result_producer_and_validation_implementation",
                "mlx_model_action_one_shot_authorization",
                "parent_observed_running_executable_identity_on_all_supported_platforms",
            }
        )
        return {
            "record_type": "mlx_runtime_preflight_eligibility",
            "schema_version": SCHEMA_VERSION,
            "decision": "runtime_preflight_failed_closed_model_actions_ineligible",
            "runtime_preflight_observed": False,
            "observed_generation_reachable": False,
            "legacy_missing_requirements": legacy_missing,
            "closed_or_split_requirements": [
                {
                    "legacy": "one_shot_authorization",
                    "closed": "runtime_preflight_only_one_shot_authorization_consumed",
                    "remaining": "mlx_model_action_one_shot_authorization",
                },
                {
                    "legacy": "output_root_physical_binding",
                    "closed": "descriptor_retained_output_root_physical_binding",
                    "remaining": None,
                },
                {
                    "legacy": (
                        "production_worker_private_ipc_protocol_and_result_validation_implementation"
                    ),
                    "closed": "runtime_preflight_forbidden_result_rejection",
                    "remaining": "generated_result_producer_and_validation_implementation",
                },
                {
                    "legacy": "worker_process_birth_and_executable_binding",
                    "closed": "parent_owned_birth_wait_and_exact_launch_target_binding",
                    "remaining": (
                        "parent_observed_running_executable_identity_on_all_supported_platforms"
                    ),
                },
            ],
            "remaining_requirements": cast("list[JsonValue]", sorted(remaining)),
            "claim_limits": [
                "no_accepted_runtime_import_evidence",
                "no_accepted_backend_or_device_facts",
                "no_accepted_imported_module_closure",
                "no_accepted_synchronization_evidence",
                "no_model_or_tokenizer_action",
                "no_per_kernel_metal_execution_proof",
            ],
        }
    closed = {
        "active_backend_device_evidence",
        "exact_runtime_manifest",
        "final_stream_synchronization_evidence",
        "one_shot_authorization",
        "output_root_physical_binding",
        "production_worker_private_ipc_protocol_and_result_validation_implementation",
        "worker_process_birth_and_executable_binding",
        "worker_reported_imported_module_closure",
    }
    for blocker in closed:
        remaining.discard(blocker)
    remaining.update(
        {
            "complete_python_standard_library_closure",
            "complete_native_runtime_and_dynamic_loader_closure",
            "generated_result_producer_and_validation_implementation",
            "mlx_model_action_one_shot_authorization",
            "parent_observed_running_executable_identity_on_all_supported_platforms",
        }
    )
    return {
        "record_type": "mlx_runtime_preflight_eligibility",
        "schema_version": SCHEMA_VERSION,
        "decision": "runtime_preflight_observed_model_actions_ineligible",
        "runtime_preflight_observed": True,
        "observed_generation_reachable": False,
        "legacy_missing_requirements": legacy_missing,
        "closed_or_split_requirements": [
            {
                "legacy": "active_backend_device_evidence",
                "closed": "runtime_preflight_default_device_stream_and_metal_availability",
                "remaining": "per_kernel_metal_execution_unavailable",
            },
            {
                "legacy": "exact_runtime_manifest",
                "closed": "exact_imported_runtime_manifest_and_versions",
                "remaining": "applicable_dependency_distribution_semantic_closure",
            },
            {
                "legacy": "final_stream_synchronization_evidence",
                "closed": "model_free_mlx_default_stream_synchronization",
                "remaining": "generation_stream_synchronization_after_model_action",
            },
            {
                "legacy": "one_shot_authorization",
                "closed": "runtime_preflight_only_one_shot_authorization",
                "remaining": "mlx_model_action_one_shot_authorization",
            },
            {
                "legacy": "output_root_physical_binding",
                "closed": "descriptor_retained_output_root_physical_binding",
                "remaining": None,
            },
            {
                "legacy": (
                    "production_worker_private_ipc_protocol_and_result_validation_implementation"
                ),
                "closed": "runtime_preflight_private_ipc_and_strict_result_validation",
                "remaining": "generated_result_producer_and_validation_implementation",
            },
            {
                "legacy": "worker_process_birth_and_executable_binding",
                "closed": "parent_owned_birth_wait_and_exact_launch_target_binding",
                "remaining": (
                    "parent_observed_running_executable_identity_on_all_supported_platforms"
                ),
            },
            {
                "legacy": "worker_reported_imported_module_closure",
                "closed": "preflight_imported_bound_root_module_file_closure",
                "remaining": ("complete_python_standard_library_and_native_dynamic_loader_closure"),
            },
        ],
        "remaining_requirements": cast("list[JsonValue]", sorted(remaining)),
        "claim_limits": [
            "no_model_or_tokenizer_identity",
            "no_model_or_tokenizer_load",
            "no_prompt_cache_inference_or_generation",
            "no_benchmark_or_meaningful_tensor_allocation",
            "no_per_kernel_metal_execution_proof",
            "requires_dist_semantics_not_proven",
            "stdlib_native_and_dynamic_loader_closure_incomplete",
        ],
    }


def _decode_transcript_entry(
    value: JsonValue,
    expected_direction: str,
    expected_message_type: str,
    expected_sequence: int,
) -> dict[str, JsonValue]:
    entry = _mapping(value, "transcript.frames[]")
    fields = {
        "direction",
        "message_type",
        "sequence",
        "size_bytes",
        "payload_base64",
        "payload_sha256",
        "frame_sha256",
    }
    _keys(entry, fields, "transcript.frames[]")
    if (
        entry["direction"] != expected_direction
        or entry["message_type"] != expected_message_type
        or entry["sequence"] != expected_sequence
    ):
        raise ContractError("runtime-preflight transcript frame order or direction mismatch")
    payload = decode_bytes(
        _text(
            entry["payload_base64"],
            "frame.payload_base64",
            maximum=MAX_BUNDLE_FILE_BYTES * 2,
        )
    )
    size = _integer(
        entry["size_bytes"],
        "frame.size_bytes",
        minimum=1,
        maximum=MAX_BUNDLE_FILE_BYTES,
    )
    if len(payload) != size or digest_bytes(payload) != _sha256(
        entry["payload_sha256"],
        "frame.payload_sha256",
    ):
        raise ContractError("runtime-preflight transcript payload size or digest mismatch")
    framed = len(payload).to_bytes(4, byteorder="big") + payload
    if digest_bytes(framed) != _sha256(entry["frame_sha256"], "frame.frame_sha256"):
        raise ContractError("runtime-preflight transcript frame digest mismatch")
    message = _mapping(_canonical_value(payload, "runtime-preflight frame"), "frame")
    if (
        message.get("message_type") != expected_message_type
        or message.get("sequence") != expected_sequence
    ):
        raise ContractError("runtime-preflight transcript payload label mismatch")
    return message


def _verify_transcript(
    value: JsonValue,
    *,
    package: dict[str, JsonValue],
    runtime_manifest: dict[str, JsonValue],
    install_receipt: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
    interpreter: dict[str, JsonValue],
    worker_program: dict[str, JsonValue],
    child_pid: int,
    parent_pid: int,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue], int]:
    transcript = _mapping(value, "mlx_runtime_preflight_transcript")
    fields = {"record_type", "schema_version", "protocol_id", "frames", "transcript_id"}
    _keys(transcript, fields, "mlx_runtime_preflight_transcript")
    if (
        transcript["record_type"] != "mlx_runtime_preflight_transcript"
        or transcript["schema_version"] != SCHEMA_VERSION
        or transcript["protocol_id"] != PROTOCOL_ID
    ):
        raise ContractError("unsupported runtime-preflight transcript")
    frames = _array(transcript["frames"], "transcript.frames", maximum=8)
    if len(frames) != len(_MESSAGE_SEQUENCE):
        raise ContractError("runtime-preflight transcript must contain exactly eight frames")
    messages: list[dict[str, JsonValue]] = []
    for index, message_type in enumerate(_MESSAGE_SEQUENCE):
        direction = "parent_to_worker" if message_type in _PARENT_MESSAGES else "worker_to_parent"
        if message_type not in _PARENT_MESSAGES | _WORKER_MESSAGES:
            raise ContractError("runtime-preflight protocol contains an unknown message")
        messages.append(
            _decode_transcript_entry(
                frames[index],
                direction,
                message_type,
                index + 1,
            )
        )
    hello, identity, authorize, ack, preflight, result, shutdown, shutdown_ack = messages
    hello_fields = {
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
    _expect_message(hello, "parent_hello", 1, hello_fields)
    expected_hello = {
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "preflight_spec_id": package["preflight_spec_id"],
        "preflight_package_id": package["preflight_package_id"],
        "preflight_package_sha256": digest_bytes(canonical_json(package)),
        "runtime_manifest_id": runtime_manifest["manifest_id"],
        "runtime_manifest_sha256": digest_bytes(canonical_json(runtime_manifest)),
        "install_receipt_id": install_receipt["receipt_id"],
        "interpreter_sha256": interpreter["sha256"],
        "worker_program_sha256": worker_program["sha256"],
        "output_root_id": output_root["output_root_id"],
    }
    for field, expected_value in expected_hello.items():
        if hello[field] != expected_value:
            raise ContractError(f"runtime-preflight hello {field} mismatch")
    _nonce(hello["parent_nonce"], "parent_hello.parent_nonce")
    _integer(hello["deadline_monotonic_ns"], "parent_hello.deadline", minimum=1)
    verified_identity = _verify_worker_identity(
        identity,
        hello=hello,
        child_pid=child_pid,
        parent_pid=parent_pid,
        interpreter=interpreter,
        worker_program=worker_program,
        runtime_manifest=runtime_manifest,
    )
    _expect_message(authorize, "authorize_once", 3, {"authorization"})
    if authorize["authorization"] != authorization:
        raise ContractError("transcript authorization differs from its bundle artifact")
    bindings = {
        "preflight_spec_id": hello["preflight_spec_id"],
        "preflight_package_id": hello["preflight_package_id"],
        "preflight_package_sha256": hello["preflight_package_sha256"],
        "runtime_manifest_id": hello["runtime_manifest_id"],
        "runtime_manifest_sha256": hello["runtime_manifest_sha256"],
        "install_receipt_id": hello["install_receipt_id"],
        "interpreter_sha256": hello["interpreter_sha256"],
        "worker_program_sha256": hello["worker_program_sha256"],
        "protocol_id": hello["protocol_id"],
        "worker_code_id": hello["worker_code_id"],
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": verified_identity["worker_nonce"],
        "output_root_id": hello["output_root_id"],
        "deadline_monotonic_ns": hello["deadline_monotonic_ns"],
    }
    for field, expected_value in bindings.items():
        if authorization[field] != expected_value:
            raise ContractError(f"authorization {field} session binding mismatch")
    _verify_authorization_ack(ack, authorization)
    preflight_fields = {
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
    _expect_message(preflight, "preflight_once", 5, preflight_fields)
    expected_preflight: dict[str, JsonValue] = {
        "action": "mlx_runtime_preflight_only",
        "allowed_probes": list(ALLOWED_PROBES),
        "authorization_id": authorization["authorization_id"],
        "preflight_package_id": package["preflight_package_id"],
        "runtime_manifest_id": runtime_manifest["manifest_id"],
        "output_root_id": output_root["output_root_id"],
        "parent_nonce": authorization["parent_nonce"],
        "worker_nonce": authorization["worker_nonce"],
    }
    for field, expected_value in expected_preflight.items():
        if preflight[field] != expected_value:
            raise ContractError(f"runtime-preflight request {field} mismatch")
    request_nonce = _nonce(preflight["request_nonce"], "preflight_once.request_nonce")
    verified_result, bound_count = _verify_preflight_result(
        result,
        authorization=authorization,
        request_nonce=request_nonce,
        runtime_manifest=runtime_manifest,
    )
    shutdown_fields = {"parent_nonce", "worker_nonce", "request_nonce"}
    _expect_message(shutdown, "shutdown", 7, shutdown_fields)
    if (
        shutdown["parent_nonce"] != authorization["parent_nonce"]
        or shutdown["worker_nonce"] != authorization["worker_nonce"]
        or shutdown["request_nonce"] != request_nonce
    ):
        raise ContractError("runtime-preflight shutdown binding mismatch")
    _verify_shutdown_ack(
        shutdown_ack,
        parent_nonce=cast("str", authorization["parent_nonce"]),
        worker_nonce=cast("str", authorization["worker_nonce"]),
        request_nonce=request_nonce,
    )
    identity_value = _sha256(transcript["transcript_id"], "transcript.transcript_id")
    content = dict(transcript)
    del content["transcript_id"]
    if identity_value != canonical_identity(content):
        raise ContractError("runtime-preflight transcript identity mismatch")
    return dict(transcript), verified_result, bound_count


def _preflight_record(
    *,
    package: dict[str, JsonValue],
    runtime_manifest: dict[str, JsonValue],
    runtime_lock: dict[str, JsonValue],
    install_receipt: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
    consumption: dict[str, JsonValue],
    transcript: dict[str, JsonValue],
    result: dict[str, JsonValue],
    bound_module_count: int,
    interpreter: dict[str, JsonValue],
    worker_program: dict[str, JsonValue],
    process_evidence: dict[str, JsonValue],
    child_wait: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    terminal_state = (
        "completed_and_closed" if result["status"] == "completed" else "terminal_error_and_closed"
    )
    modules = cast("list[JsonValue]", result["imported_modules"])
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_record",
        "schema_version": SCHEMA_VERSION,
        "preflight_spec_id": package["preflight_spec_id"],
        "preflight_package_id": package["preflight_package_id"],
        "runtime_manifest_id": runtime_manifest["manifest_id"],
        "runtime_lock_id": runtime_lock["lock_id"],
        "install_receipt_id": install_receipt["receipt_id"],
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "interpreter": interpreter,
        "worker_program": worker_program,
        "output_root_id": output_root["output_root_id"],
        "authorization_id": authorization["authorization_id"],
        "consumption_id": consumption["consumption_id"],
        "transcript_id": transcript["transcript_id"],
        "result_sha256": digest_bytes(canonical_json(result)),
        "imported_module_closure_id": canonical_identity(modules),
        "imported_module_count": len(modules),
        "bound_runtime_module_count": bound_module_count,
        "terminal_state": terminal_state,
        "parent_process_evidence": process_evidence,
        "child_wait": child_wait,
        "preflight_action_ledger": dict(_PREFLIGHT_ACTION_LEDGER),
        "worker_action_ledger": result["action_ledger"],
        "model_non_actions": result["model_non_actions"],
        "guarded_action_attempts": result["guarded_action_attempts"],
        "completed_forbidden_actions": result["completed_forbidden_actions"],
        "package_network_actions": install_receipt["package_network_actions"],
        "backend_facts": result["backend_facts"],
        "synchronization": result["synchronization"],
        "eligibility": _reconstruct_eligibility(completed=result["status"] == "completed"),
    }
    record["preflight_record_id"] = canonical_identity(record)
    return record


def _verify_process_evidence(
    value: JsonValue,
) -> tuple[dict[str, JsonValue], int, int]:
    evidence = _mapping(value, "parent_process_evidence")
    _keys(
        evidence,
        {"method", "available", "matched", "parent_pid", "child_pid"},
        "parent_process_evidence",
    )
    method = _text(evidence["method"], "parent_process_evidence.method")
    available = _boolean(evidence["available"], "parent_process_evidence.available")
    parent_pid = _integer(evidence["parent_pid"], "parent_process_evidence.parent_pid", minimum=1)
    child_pid = _integer(evidence["child_pid"], "parent_process_evidence.child_pid", minimum=1)
    if method == "linux_proc_exe_device_inode":
        if not available or evidence["matched"] is not True:
            raise ContractError("Linux runtime-preflight process evidence must match")
    elif method == "unavailable_on_platform":
        if available or evidence["matched"] is not None:
            raise ContractError("unavailable runtime-preflight process evidence cannot match")
    else:
        raise ContractError("unsupported runtime-preflight process evidence method")
    return dict(evidence), parent_pid, child_pid


def _verify_child_wait(value: JsonValue, child_pid: int) -> dict[str, JsonValue]:
    child_wait = _mapping(value, "child_wait")
    _keys(child_wait, {"pid", "wait_owned", "exited", "exit_code", "signal"}, "child_wait")
    if (
        child_wait["pid"] != child_pid
        or child_wait["wait_owned"] is not True
        or child_wait["exited"] is not True
        or child_wait["exit_code"] != 0
        or child_wait["signal"] is not None
    ):
        raise ContractError("runtime-preflight child wait is not one clean parent-owned exit")
    return dict(child_wait)


def _verify_preflight_record(
    value: JsonValue,
    *,
    package: dict[str, JsonValue],
    runtime_manifest: dict[str, JsonValue],
    runtime_lock: dict[str, JsonValue],
    install_receipt: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
    consumption: dict[str, JsonValue],
    transcript: dict[str, JsonValue],
    worker_bytes: bytes,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue], int]:
    record = _mapping(value, "mlx_runtime_preflight_record")
    fields = {
        "record_type",
        "schema_version",
        "preflight_spec_id",
        "preflight_package_id",
        "runtime_manifest_id",
        "runtime_lock_id",
        "install_receipt_id",
        "protocol_id",
        "worker_code_id",
        "interpreter",
        "worker_program",
        "output_root_id",
        "authorization_id",
        "consumption_id",
        "transcript_id",
        "result_sha256",
        "imported_module_closure_id",
        "imported_module_count",
        "bound_runtime_module_count",
        "terminal_state",
        "parent_process_evidence",
        "child_wait",
        "preflight_action_ledger",
        "worker_action_ledger",
        "model_non_actions",
        "guarded_action_attempts",
        "completed_forbidden_actions",
        "package_network_actions",
        "backend_facts",
        "synchronization",
        "eligibility",
        "preflight_record_id",
    }
    _keys(record, fields, "mlx_runtime_preflight_record")
    if (
        record["record_type"] != "mlx_runtime_preflight_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["protocol_id"] != PROTOCOL_ID
        or record["worker_code_id"] != WORKER_CODE_ID
        or record["terminal_state"] not in {"completed_and_closed", "terminal_error_and_closed"}
    ):
        raise ContractError("unsupported runtime-preflight terminal record")
    interpreter = _verify_file_identity(record["interpreter"], "preflight.interpreter")
    worker_program = _verify_file_identity(record["worker_program"], "preflight.worker_program")
    if (
        worker_program["sha256"] != digest_bytes(worker_bytes)
        or worker_program["sha256"] != EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256
    ):
        raise ContractError("published runtime-preflight worker differs from sealed bytes")
    expected = {
        "preflight_spec_id": package["preflight_spec_id"],
        "preflight_package_id": package["preflight_package_id"],
        "runtime_manifest_id": runtime_manifest["manifest_id"],
        "runtime_lock_id": runtime_lock["lock_id"],
        "install_receipt_id": install_receipt["receipt_id"],
        "output_root_id": output_root["output_root_id"],
        "authorization_id": authorization["authorization_id"],
        "consumption_id": consumption["consumption_id"],
        "transcript_id": transcript["transcript_id"],
    }
    for field, expected_value in expected.items():
        if record[field] != expected_value:
            raise ContractError(f"runtime-preflight record {field} mismatch")
    if (
        authorization["interpreter_sha256"] != interpreter["sha256"]
        or authorization["worker_program_sha256"] != worker_program["sha256"]
    ):
        raise ContractError("runtime-preflight launch digest authorization mismatch")
    _process, parent_pid, child_pid = _verify_process_evidence(
        record["parent_process_evidence"],
    )
    _verify_child_wait(record["child_wait"], child_pid)
    if record["preflight_action_ledger"] != _PREFLIGHT_ACTION_LEDGER:
        raise ContractError("runtime-preflight physical action ledger drift")
    verified_transcript, result, bound_count = _verify_transcript(
        transcript,
        package=package,
        runtime_manifest=runtime_manifest,
        install_receipt=install_receipt,
        output_root=output_root,
        authorization=authorization,
        interpreter=interpreter,
        worker_program=worker_program,
        child_pid=child_pid,
        parent_pid=parent_pid,
    )
    modules = cast("list[JsonValue]", result["imported_modules"])
    if (
        record["result_sha256"] != digest_bytes(canonical_json(result))
        or record["imported_module_closure_id"] != canonical_identity(modules)
        or record["imported_module_count"] != len(modules)
        or record["bound_runtime_module_count"] != bound_count
        or record["worker_action_ledger"] != result["action_ledger"]
        or record["model_non_actions"] != result["model_non_actions"]
        or record["guarded_action_attempts"] != result["guarded_action_attempts"]
        or record["completed_forbidden_actions"] != result["completed_forbidden_actions"]
        or record["package_network_actions"] != install_receipt["package_network_actions"]
        or record["backend_facts"] != result["backend_facts"]
        or record["synchronization"] != result["synchronization"]
        or record["eligibility"]
        != _reconstruct_eligibility(completed=result["status"] == "completed")
        or verified_transcript["transcript_id"] != record["transcript_id"]
    ):
        raise ContractError("runtime-preflight record reconstruction mismatch")
    expected_terminal = (
        "completed_and_closed" if result["status"] == "completed" else "terminal_error_and_closed"
    )
    if record["terminal_state"] != expected_terminal:
        raise ContractError("runtime-preflight result and terminal-state mismatch")
    identity = _sha256(record["preflight_record_id"], "preflight.preflight_record_id")
    content = dict(record)
    del content["preflight_record_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime-preflight record identity mismatch")
    return dict(record), result, bound_count


def _replay_runtime_preflight_snapshot(
    bundle: Path,
    *,
    allow_synthetic: bool = False,
) -> tuple[RuntimePreflightReplayResult, dict[str, JsonValue]]:
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/runtime-preflight-spec.json",
        "source/worker-program.py",
        "runtime-lock.json",
        "runtime-install-receipt.json",
        "runtime-manifest.json",
        "runtime-preflight-package.json",
        "output-root-binding.json",
        "authorization.json",
        "authorization-consumption.json",
        "transcript.json",
        "preflight-record.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("runtime-preflight bundle has an invalid content set")
    for name, data in files.items():
        if len(data) > MAX_BUNDLE_FILE_BYTES:
            raise ContractError(f"runtime-preflight artifact exceeds its bound: {name}")
    spec = _canonical_value(
        files["source/runtime-preflight-spec.json"],
        "runtime-preflight spec",
    )
    if canonical_json(spec) != canonical_json(runtime_preflight_spec()):
        raise ContractError("runtime-preflight specification drift")
    worker_bytes = files["source/worker-program.py"]
    if digest_bytes(worker_bytes) != EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256:
        raise ContractError("runtime-preflight bundle worker differs from sealed bytes")
    runtime_manifest = verify_runtime_manifest(
        _canonical_value(files["runtime-manifest.json"], "runtime manifest")
    )
    runtime_lock = verify_runtime_lock(
        _canonical_value(files["runtime-lock.json"], "runtime lock"),
        allow_synthetic=allow_synthetic,
    )
    install_receipt = verify_install_receipt(
        _canonical_value(files["runtime-install-receipt.json"], "runtime install receipt"),
        runtime_lock=runtime_lock,
        runtime_manifest=runtime_manifest,
        allow_synthetic=allow_synthetic,
    )
    package = verify_runtime_preflight_package(
        _canonical_value(
            files["runtime-preflight-package.json"],
            "runtime-preflight package",
        )
    )
    rebuilt_package = build_runtime_preflight_package(
        runtime_manifest,
        runtime_lock,
        install_receipt,
        allow_synthetic=allow_synthetic,
    )
    if canonical_json(package) != canonical_json(rebuilt_package):
        raise ContractError("runtime-preflight package reconstruction mismatch")
    output_root = _verify_output_root_binding(
        _canonical_value(files["output-root-binding.json"], "output-root binding")
    )
    authorization = _verify_authorization(
        _canonical_value(files["authorization.json"], "authorization"),
        check_current_expiry=False,
    )
    expected_authorization = {
        "preflight_spec_id": package["preflight_spec_id"],
        "preflight_package_id": package["preflight_package_id"],
        "preflight_package_sha256": digest_bytes(canonical_json(package)),
        "runtime_manifest_id": runtime_manifest["manifest_id"],
        "runtime_manifest_sha256": digest_bytes(canonical_json(runtime_manifest)),
        "install_receipt_id": install_receipt["receipt_id"],
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "output_root_id": output_root["output_root_id"],
    }
    for field, expected_value in expected_authorization.items():
        if authorization[field] != expected_value:
            raise ContractError(f"runtime-preflight authorization {field} substitution")
    consumption = _verify_consumption(
        _canonical_value(
            files["authorization-consumption.json"],
            "authorization consumption",
        ),
        authorization,
        output_root,
    )
    transcript = _mapping(
        _canonical_value(files["transcript.json"], "runtime-preflight transcript"),
        "runtime-preflight transcript",
    )
    record, result, bound_count = _verify_preflight_record(
        _canonical_value(files["preflight-record.json"], "runtime-preflight record"),
        package=package,
        runtime_manifest=runtime_manifest,
        runtime_lock=runtime_lock,
        install_receipt=install_receipt,
        output_root=output_root,
        authorization=authorization,
        consumption=consumption,
        transcript=transcript,
        worker_bytes=worker_bytes,
    )
    modules = cast("list[JsonValue]", result["imported_modules"])
    backend_value = result["backend_facts"]
    backend = None if backend_value is None else _mapping(backend_value, "backend facts")
    synchronization_value = result["synchronization"]
    synchronization = (
        None
        if synchronization_value is None
        else _mapping(synchronization_value, "synchronization")
    )
    eligibility = _mapping(record["eligibility"], "runtime-preflight eligibility")
    remaining = _array(
        eligibility["remaining_requirements"],
        "eligibility.remaining_requirements",
    )
    replay = RuntimePreflightReplayResult(
        bundle_root=content_root,
        preflight_record_id=cast("str", record["preflight_record_id"]),
        preflight_package_id=cast("str", package["preflight_package_id"]),
        runtime_manifest_id=cast("str", runtime_manifest["manifest_id"]),
        protocol_id=PROTOCOL_ID,
        terminal_state=cast("str", record["terminal_state"]),
        child_exit_code=0,
        imported_module_count=len(modules),
        bound_runtime_module_count=bound_count,
        metal_is_available=(
            None if backend is None else cast("bool", backend["metal_is_available"])
        ),
        default_device_representation=(
            None if backend is None else cast("str", backend["default_device_representation"])
        ),
        synchronization_completed=(
            False if synchronization is None else cast("bool", synchronization["completed"])
        ),
        authorization_consumptions=1,
        python_audited_guarded_action_attempts=sum(
            cast("int", count)
            for count in _mapping(
                result["guarded_action_attempts"],
                "preflight_result.guarded_action_attempts",
            ).values()
        ),
        worker_reported_completed_forbidden_actions=sum(
            cast("int", count)
            for count in _mapping(
                result["completed_forbidden_actions"],
                "preflight_result.completed_forbidden_actions",
            ).values()
        ),
        completed_forbidden_actions_proven_by_parent=False,
        model_actions=0,
        remaining_requirements=len(remaining),
    )
    return replay, dict(eligibility)


def replay_runtime_preflight_bundle(bundle: Path) -> RuntimePreflightReplayResult:
    """Replay one observed runtime preflight without imports, processes, or sockets."""
    replay, _eligibility = _replay_runtime_preflight_snapshot(bundle)
    return replay


def inspect_runtime_preflight_bundle(bundle: Path) -> dict[str, JsonValue]:
    """Return the reconstructed blocker split after process-free replay."""
    replay, eligibility = _replay_runtime_preflight_snapshot(bundle)
    return {
        **replay.to_dict(),
        "decision": eligibility["decision"],
        "runtime_preflight_observed": eligibility["runtime_preflight_observed"],
        "observed_generation_reachable": eligibility["observed_generation_reachable"],
        "closed_or_split_requirements": eligibility["closed_or_split_requirements"],
        "remaining_requirements": eligibility["remaining_requirements"],
        "claim_limits": eligibility["claim_limits"],
    }


def _project_integer_ledger(
    value: JsonValue,
    maxima: dict[str, int],
) -> dict[str, JsonValue] | None:
    if not isinstance(value, dict) or set(value) != set(maxima):
        return None
    projection: dict[str, JsonValue] = {}
    for name, maximum in sorted(maxima.items()):
        count = value[name]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > maximum:
            return None
        projection[name] = count
    return projection


def _rejected_result_projection(value: dict[str, JsonValue] | None) -> dict[str, JsonValue] | None:
    if value is None:
        return None
    status = value.get("status")
    worker_status: JsonValue = status if status in {"completed", "terminal_error"} else None
    error_phase: JsonValue = None
    error_category: JsonValue = None
    error_message_sha256: JsonValue = None
    error = value.get("error")
    if isinstance(error, dict):
        phase = error.get("phase")
        category = error.get("category")
        message_sha256 = error.get("message_sha256")
        if isinstance(phase, str) and _SAFE_ERROR_TOKEN_PATTERN.fullmatch(phase):
            error_phase = phase
        if isinstance(category, str) and _SAFE_ERROR_TOKEN_PATTERN.fullmatch(category):
            error_category = category
        if (
            isinstance(message_sha256, str)
            and len(message_sha256) == _DIGEST_LENGTH
            and message_sha256.startswith("sha256:")
            and all(character in "0123456789abcdef" for character in message_sha256[7:])
        ):
            error_message_sha256 = message_sha256
    worker_actions = _project_integer_ledger(
        value.get("action_ledger"),
        _SUCCESS_WORKER_ACTIONS,
    )
    worker_model_non_actions = _project_integer_ledger(
        value.get("model_non_actions"),
        dict.fromkeys(_ZERO_MODEL_NON_ACTIONS, 1),
    )
    worker_guarded_attempts = _project_integer_ledger(
        value.get("guarded_action_attempts"),
        _GUARDED_ACTION_ATTEMPT_MAXIMA,
    )
    worker_reported_completed = _project_integer_ledger(
        value.get("completed_forbidden_actions"),
        dict.fromkeys(_ZERO_COMPLETED_FORBIDDEN_ACTIONS, 1),
    )
    attempt_count: JsonValue = (
        None
        if worker_guarded_attempts is None
        else sum(cast("int", count) for count in worker_guarded_attempts.values())
    )
    modules = value.get("imported_modules")
    imported_module_count: JsonValue = (
        len(modules)
        if isinstance(modules, list) and len(modules) <= _MAX_IMPORTED_MODULES
        else None
    )
    return {
        "observed_preflight_accepted": False,
        "worker_status": worker_status,
        "worker_error_phase": error_phase,
        "worker_error_category": error_category,
        "worker_error_message_sha256": error_message_sha256,
        "worker_action_ledger": worker_actions,
        "worker_model_non_action_ledger": worker_model_non_actions,
        "worker_guarded_action_attempt_ledger": worker_guarded_attempts,
        "worker_reported_completed_forbidden_action_ledger": worker_reported_completed,
        "guarded_action_attempt_count_untrusted": attempt_count,
        "completed_forbidden_actions_accepted": False,
        "imported_module_count_untrusted": imported_module_count,
        "backend_facts_accepted": False,
        "synchronization_accepted": False,
    }


def _rejected_frame_projection(entries: list[JsonValue]) -> dict[str, JsonValue] | None:
    if not entries:
        return None
    entry = _mapping(entries[-1], "failure frame")
    if (
        entry.get("direction") != "worker_to_parent"
        or entry.get("message_type") != "preflight_result"
        or entry.get("sequence") != _PREFLIGHT_RESULT_SEQUENCE
    ):
        return None
    return {
        "direction": "worker_to_parent",
        "message_type": "preflight_result",
        "sequence": _PREFLIGHT_RESULT_SEQUENCE,
        "size_bytes": entry["size_bytes"],
        "payload_sha256": entry["payload_sha256"],
        "frame_sha256": entry["frame_sha256"],
        "payload_retained_in_projection": False,
    }


def _write_terminal_failure_at(
    output_root_descriptor: int,
    *,
    phase: str,
    output_root_id: JsonValue,
    package_id: JsonValue,
    authorization_id: JsonValue,
    consumption_id: JsonValue,
    actions: dict[str, JsonValue],
    child_spawned: bool,
    child_wait: dict[str, JsonValue] | None,
    entries: list[JsonValue],
    rejected_result: dict[str, JsonValue] | None,
    validation_error: Exception,
) -> None:
    _keys(actions, set(_PREFLIGHT_ACTION_LEDGER), "failure action_ledger")
    for name, maximum in _PREFLIGHT_ACTION_LEDGER.items():
        _integer(actions[name], f"failure action_ledger.{name}", maximum=maximum)
    if actions["attempts"] != 1:
        raise ContractError("runtime-preflight failure must describe one commenced attempt")
    if child_spawned:
        if actions["worker_process_starts"] != 1 or child_wait is None:
            raise ContractError("spawned runtime-preflight failure lacks terminal custody")
        child_reaped: JsonValue = True
    else:
        if actions["worker_process_starts"] != 0 or child_wait is not None:
            raise ContractError("pre-spawn runtime-preflight failure contains child evidence")
        child_reaped = None
    failure: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_terminal_failure",
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "phase": phase,
        "terminal_state": "failed_closed",
        "reason": "runtime_preflight_protocol_or_process_failure",
        "output_root_id": output_root_id,
        "preflight_package_id": package_id,
        "authorization_id": authorization_id,
        "consumption_id": consumption_id,
        "child_spawned": child_spawned,
        "child_reaped": child_reaped,
        "child_reaped_or_never_spawned": True,
        "child_wait": child_wait,
        "action_ledger": actions,
        "recorded_frame_counts": {
            "parent_to_worker": sum(
                1
                for entry in entries
                if _mapping(entry, "failure frame")["direction"] == "parent_to_worker"
            ),
            "worker_to_parent": sum(
                1
                for entry in entries
                if _mapping(entry, "failure frame")["direction"] == "worker_to_parent"
            ),
        },
        "rejected_worker_frame": _rejected_frame_projection(entries),
        "rejected_result_projection": _rejected_result_projection(rejected_result),
        "validation_error": {
            "category": type(validation_error).__name__,
            "message_sha256": digest_bytes(str(validation_error).encode("utf-8")),
        },
        "failure_nonce_sha256": digest_bytes(os.urandom(32)),
    }
    failure["failure_id"] = canonical_identity(failure)
    name = (
        f".localinferencelab-mlx-runtime-preflight-terminal-{str(failure['failure_id'])[7:]}.json"
    )
    _write_exclusive_at(output_root_descriptor, name, canonical_json(failure))


def verify_runtime_preflight_terminal_failure(
    value: JsonValue,
    *,
    expected_authorization_id: str | None = None,
    expected_consumption_id: str | None = None,
) -> dict[str, JsonValue]:
    """Verify a privacy-safe terminal failure projection without starting a process."""
    failure = _mapping(value, "mlx_runtime_preflight_terminal_failure")
    fields = {
        "record_type",
        "schema_version",
        "protocol_id",
        "worker_code_id",
        "phase",
        "terminal_state",
        "reason",
        "output_root_id",
        "preflight_package_id",
        "authorization_id",
        "consumption_id",
        "child_spawned",
        "child_reaped",
        "child_reaped_or_never_spawned",
        "child_wait",
        "action_ledger",
        "recorded_frame_counts",
        "rejected_worker_frame",
        "rejected_result_projection",
        "validation_error",
        "failure_nonce_sha256",
        "failure_id",
    }
    _keys(failure, fields, "mlx_runtime_preflight_terminal_failure")
    if (
        failure["record_type"] != "mlx_runtime_preflight_terminal_failure"
        or failure["schema_version"] != SCHEMA_VERSION
        or failure["protocol_id"] != PROTOCOL_ID
        or failure["worker_code_id"] != WORKER_CODE_ID
        or failure["terminal_state"] != "failed_closed"
        or failure["reason"] != "runtime_preflight_protocol_or_process_failure"
        or failure["child_reaped_or_never_spawned"] is not True
    ):
        raise ContractError("unsupported runtime-preflight terminal failure")
    _text(failure["phase"], "terminal_failure.phase", maximum=64)
    for field in ("output_root_id", "preflight_package_id", "authorization_id", "consumption_id"):
        if failure[field] is not None:
            _sha256(failure[field], f"terminal_failure.{field}")
    if expected_authorization_id is not None and failure["authorization_id"] != (
        expected_authorization_id
    ):
        raise ContractError("terminal failure authorization binding mismatch")
    if expected_consumption_id is not None and failure["consumption_id"] != expected_consumption_id:
        raise ContractError("terminal failure consumption binding mismatch")
    actions = _mapping(failure["action_ledger"], "terminal_failure.action_ledger")
    _keys(actions, set(_PREFLIGHT_ACTION_LEDGER), "terminal_failure.action_ledger")
    for name, maximum in _PREFLIGHT_ACTION_LEDGER.items():
        _integer(actions[name], f"terminal_failure.action_ledger.{name}", maximum=maximum)
    if actions["attempts"] != 1 or actions["retries"] != 0 or actions["warmups"] != 0:
        raise ContractError("terminal failure attempt accounting drift")
    consumed = actions["authorizations_consumed"] == 1
    if consumed != (
        failure["authorization_id"] is not None and failure["consumption_id"] is not None
    ):
        raise ContractError("terminal failure authorization consumption accounting drift")
    frames = _mapping(failure["recorded_frame_counts"], "terminal_failure.recorded_frame_counts")
    _keys(frames, {"parent_to_worker", "worker_to_parent"}, "recorded_frame_counts")
    if (
        _integer(frames["parent_to_worker"], "recorded_frame_counts.parent_to_worker", maximum=4)
        != actions["parent_frames"]
        or _integer(
            frames["worker_to_parent"],
            "recorded_frame_counts.worker_to_parent",
            maximum=4,
        )
        != actions["worker_frames"]
    ):
        raise ContractError("terminal failure frame counts differ from completed actions")
    child_spawned = _boolean(failure["child_spawned"], "terminal_failure.child_spawned")
    if child_spawned:
        if failure["child_reaped"] is not True or failure["child_wait"] is None:
            raise ContractError("spawned terminal failure lacks parent-owned wait custody")
        wait = _mapping(failure["child_wait"], "terminal_failure.child_wait")
        _keys(wait, {"pid", "wait_owned", "exited", "exit_code", "signal"}, "child_wait")
        _integer(wait["pid"], "child_wait.pid", minimum=1)
        if (
            wait["wait_owned"] is not True
            or (wait["exited"] is not False and wait["exited"] is not True)
            or (wait["exit_code"] is None) == (wait["signal"] is None)
        ):
            raise ContractError("terminal failure child wait is not terminal")
        if wait["exit_code"] is not None:
            _integer(wait["exit_code"], "child_wait.exit_code", maximum=255)
        if wait["signal"] is not None:
            _integer(wait["signal"], "child_wait.signal", minimum=1, maximum=255)
    elif (
        failure["child_reaped"] is not None
        or failure["child_wait"] is not None
        or actions["worker_process_starts"] != 0
    ):
        raise ContractError("pre-spawn terminal failure contains child evidence")
    validation = _mapping(failure["validation_error"], "terminal_failure.validation_error")
    _keys(validation, {"category", "message_sha256"}, "terminal_failure.validation_error")
    category = _text(
        validation["category"],
        "terminal_failure.validation_error.category",
        maximum=64,
    )
    if _SAFE_ERROR_TOKEN_PATTERN.fullmatch(category) is None:
        raise ContractError("terminal failure validation category is not privacy-safe")
    _sha256(
        validation["message_sha256"],
        "terminal_failure.validation_error.message_sha256",
    )
    if failure["rejected_worker_frame"] is not None:
        rejected_frame = _mapping(
            failure["rejected_worker_frame"],
            "terminal_failure.rejected_worker_frame",
        )
        _keys(
            rejected_frame,
            {
                "direction",
                "message_type",
                "sequence",
                "size_bytes",
                "payload_sha256",
                "frame_sha256",
                "payload_retained_in_projection",
            },
            "terminal_failure.rejected_worker_frame",
        )
        if (
            rejected_frame["direction"] != "worker_to_parent"
            or rejected_frame["message_type"] != "preflight_result"
            or rejected_frame["sequence"] != _PREFLIGHT_RESULT_SEQUENCE
            or rejected_frame["payload_retained_in_projection"] is not False
        ):
            raise ContractError("terminal failure rejected-frame projection drift")
        _integer(rejected_frame["size_bytes"], "rejected_worker_frame.size_bytes", minimum=1)
        _sha256(rejected_frame["payload_sha256"], "rejected_worker_frame.payload_sha256")
        _sha256(rejected_frame["frame_sha256"], "rejected_worker_frame.frame_sha256")
    projection = failure["rejected_result_projection"]
    if (projection is None) != (failure["rejected_worker_frame"] is None):
        raise ContractError("terminal failure rejected frame and result projection differ")
    if projection is not None:
        result = _mapping(projection, "terminal_failure.rejected_result_projection")
        _keys(
            result,
            {
                "observed_preflight_accepted",
                "worker_status",
                "worker_error_phase",
                "worker_error_category",
                "worker_error_message_sha256",
                "worker_action_ledger",
                "worker_model_non_action_ledger",
                "worker_guarded_action_attempt_ledger",
                "worker_reported_completed_forbidden_action_ledger",
                "guarded_action_attempt_count_untrusted",
                "completed_forbidden_actions_accepted",
                "imported_module_count_untrusted",
                "backend_facts_accepted",
                "synchronization_accepted",
            },
            "terminal_failure.rejected_result_projection",
        )
        if (
            result["observed_preflight_accepted"] is not False
            or result["backend_facts_accepted"] is not False
            or result["synchronization_accepted"] is not False
            or result["completed_forbidden_actions_accepted"] is not False
            or result["worker_status"] not in {None, "completed", "terminal_error"}
        ):
            raise ContractError("terminal failure rejected-result projection drift")
        for field in ("worker_error_phase", "worker_error_category"):
            token = result[field]
            if token is not None and (
                not isinstance(token, str) or _SAFE_ERROR_TOKEN_PATTERN.fullmatch(token) is None
            ):
                raise ContractError("terminal failure contains unsafe worker error metadata")
        if result["worker_error_message_sha256"] is not None:
            _sha256(
                result["worker_error_message_sha256"],
                "rejected_result_projection.worker_error_message_sha256",
            )
        worker_actions = _project_integer_ledger(
            result["worker_action_ledger"],
            _SUCCESS_WORKER_ACTIONS,
        )
        worker_model_non_actions = _project_integer_ledger(
            result["worker_model_non_action_ledger"],
            dict.fromkeys(_ZERO_MODEL_NON_ACTIONS, 1),
        )
        worker_guarded_attempts = _project_integer_ledger(
            result["worker_guarded_action_attempt_ledger"],
            _GUARDED_ACTION_ATTEMPT_MAXIMA,
        )
        worker_reported_completed = _project_integer_ledger(
            result["worker_reported_completed_forbidden_action_ledger"],
            dict.fromkeys(_ZERO_COMPLETED_FORBIDDEN_ACTIONS, 1),
        )
        if (
            (result["worker_action_ledger"] is not None and worker_actions is None)
            or (
                result["worker_model_non_action_ledger"] is not None
                and worker_model_non_actions is None
            )
            or (
                result["worker_guarded_action_attempt_ledger"] is not None
                and worker_guarded_attempts is None
            )
            or (
                result["worker_reported_completed_forbidden_action_ledger"] is not None
                and worker_reported_completed is None
            )
        ):
            raise ContractError("terminal failure contains malformed worker ledgers")
        attempt_count = result["guarded_action_attempt_count_untrusted"]
        if worker_guarded_attempts is None:
            if attempt_count is not None:
                raise ContractError("terminal failure inferred an unavailable attempt count")
        elif attempt_count != sum(cast("int", count) for count in worker_guarded_attempts.values()):
            raise ContractError("terminal failure guarded-attempt accounting drift")
        imported_count = result["imported_module_count_untrusted"]
        if imported_count is not None:
            _integer(
                imported_count,
                "rejected_result_projection.imported_module_count_untrusted",
                maximum=_MAX_IMPORTED_MODULES,
            )
    _sha256(failure["failure_nonce_sha256"], "terminal_failure.failure_nonce_sha256")
    identity = _sha256(failure["failure_id"], "terminal_failure.failure_id")
    content = dict(failure)
    del content["failure_id"]
    if identity != canonical_identity(content):
        raise ContractError("runtime-preflight terminal failure identity mismatch")
    return dict(failure)


def replay_runtime_preflight_terminal_failure(path: Path) -> dict[str, JsonValue]:
    """Replay one terminal failure record without imports, processes, or sockets."""
    return verify_runtime_preflight_terminal_failure(
        load_canonical_json_file(path, "MLX runtime-preflight terminal failure")
    )


def _observed_negative_projection_content() -> dict[str, JsonValue]:
    return {
        "record_type": "mlx_runtime_preflight_observed_negative_projection",
        "schema_version": SCHEMA_VERSION,
        "outcome": "failed_closed",
        "observed_preflight_accepted": False,
        "retry_count": 0,
        "authorized_attempt_count": 1,
        "pre_spawn_refusal_count": 1,
        "platform": {"system": "Darwin", "machine": "arm64", "python_abi": "cp313"},
        "runtime_lock_id": EXPECTED_OBSERVED_LOCK_ID,
        "runtime_manifest_id": (
            "sha256:6021032a1300dfd7855d9c3bfac855f81437380daa8f764fe01c01bdfc1493b5"
        ),
        "preflight_package_id": (
            "sha256:26589aa951a4f2499a4fcc2714c5f2dbc6efca7bb67a813cdddc2fc398b58c0c"
        ),
        "historical_protocol_id": (
            "sha256:c3df6f0eb9a67a00e1f1f180b0e34fd9b5ac5dd662b430f86ec29c87dd30727a"
        ),
        "historical_worker_code_id": (
            "sha256:bfd840635879dfae9a57fb11cae0e6ddef4f3f5f3b9b81f39e8e1cec51539fe3"
        ),
        "historical_worker_program_sha256": (
            "sha256:472932ab2db8ed336af8ce60ee76be04b1f6c14eb5d77bade39169ca91367c71"
        ),
        "raw_bindings": {
            "terminal_failure_id": OBSERVED_FAILURE_ID,
            "consumption_id": OBSERVED_CONSUMPTION_ID,
            "authorization_id": OBSERVED_AUTHORIZATION_ID,
            "terminal_file_sha256": (
                "sha256:00b4f0ede631d482ac741b757db33c78b6ff88847b6f5129fd55f977721fa0e0"
            ),
            "consumption_file_sha256": (
                "sha256:88462d3f3182a75e2dac36fcb9c10f75dfb9b69a62939442dc47038cdf9732ff"
            ),
            "raw_local_artifacts_committed": False,
        },
        "failure": {
            "parent_phase": "preflight_result",
            "worker_result_frame_received": True,
            "worker_result_frame_retained": False,
            "worker_internal_phase": None,
            "worker_action_ledger_retained": False,
            "worker_model_non_action_ledger_retained": False,
            "worker_guarded_action_attempt_ledger_retained": False,
            "worker_completed_forbidden_action_ledger_retained": False,
            "stable_category": "worker_reported_forbidden_action_attempt",
            "exact_forbidden_event": None,
            "exact_attempt_category": None,
            "exact_event_unavailable_reason": (
                "rejected_worker_frame_omitted_by_original_failure_custody"
            ),
            "attempted": True,
            "completed": None,
            "completed_status": "not_accepted_or_proven",
            "guard_scope": "python_audit_events_not_os_sandbox",
            "validation_error_category": "ContractError",
            "validation_error_message_sha256": (
                "sha256:f861a1f6b47815a1497f9ae1004f183d54f25f1c28d048f72c36cb5d095e7104"
            ),
        },
        "custody": {
            "authorization_consumed": True,
            "child_spawned": True,
            "child_reaped": True,
            "child_exit_kind": "terminated_by_parent",
            "child_signal": 15,
            "parent_frames_sent": 3,
            "worker_frames_validated": 2,
            "worker_result_frames_received_but_rejected": 1,
            "preflight_once_commands": 1,
        },
        "accepted_physical_actions": {
            "attempts": 1,
            "retries": 0,
            "warmups": 0,
            "worker_process_starts": 1,
            "socketpair_creations": 1,
            "authorizations_consumed": 1,
            "preflight_once_commands": 1,
            "shutdowns": 0,
        },
        "accepted_non_actions": {
            "model_discoveries": 0,
            "model_loads": 0,
            "tokenizer_discoveries": 0,
            "tokenizer_loads": 0,
            "prompt_actions": 0,
            "model_cache_actions": 0,
            "inference_requests": 0,
            "generation_requests": 0,
            "benchmark_actions": 0,
            "cloud_actions": 0,
            "spend_actions": 0,
        },
        "eligibility": {
            "decision": "runtime_preflight_failed_closed_model_actions_ineligible",
            "observed_requirements_closed": [],
            "custody_requirements_proven": [
                "forbidden_action_rejection",
                "one_shot_authorization_consumption",
                "parent_owned_worker_birth_and_reaping",
            ],
            "observed_requirements_remaining": [
                "active_backend_device_evidence",
                "final_stream_synchronization_evidence",
                "worker_reported_imported_module_closure",
            ],
            "claim_limits": [
                "no_accepted_runtime_import_evidence",
                "no_accepted_backend_or_device_facts",
                "no_accepted_synchronization_evidence",
                "no_accepted_completed_forbidden_action_ledger",
                "python_audit_guard_is_not_an_os_sandbox",
                "no_model_or_tokenizer_action",
                "no_per_kernel_metal_execution_proof",
            ],
        },
    }


def verify_observed_negative_projection(value: JsonValue) -> dict[str, JsonValue]:
    """Verify the repository-pinned privacy-safe projection of the failed observed attempt."""
    projection = _mapping(value, "mlx_runtime_preflight_observed_negative_projection")
    _keys(
        projection,
        set(_observed_negative_projection_content()) | {"projection_id"},
        "mlx_runtime_preflight_observed_negative_projection",
    )
    content = dict(projection)
    identity = _sha256(content.pop("projection_id"), "negative_projection.projection_id")
    if content != _observed_negative_projection_content():
        raise ContractError("observed negative projection content drift")
    if identity != canonical_identity(content):
        raise ContractError("observed negative projection identity mismatch")
    if identity != EXPECTED_OBSERVED_NEGATIVE_PROJECTION_ID:
        raise ContractError("observed negative projection differs from the repository pin")
    return dict(projection)


def replay_observed_negative_projection(path: Path) -> dict[str, JsonValue]:
    """Replay the failed observed-attempt projection without imports, processes, or sockets."""
    return verify_observed_negative_projection(
        load_canonical_json_file(path, "MLX observed negative projection")
    )


def _require_successful_child(
    child_wait: dict[str, JsonValue],
    actions: dict[str, JsonValue],
) -> None:
    if child_wait["exit_code"] != 0:
        raise ContractError("sealed runtime-preflight worker did not exit successfully")
    if actions != _PREFLIGHT_ACTION_LEDGER:
        raise ContractError("runtime-preflight completed-action ledger drift")


def run_runtime_preflight(
    runtime_manifest_value: JsonValue,
    runtime_lock_value: JsonValue,
    install_receipt_value: JsonValue,
    runtime_root: Path,
    interpreter_path: Path,
    output_root: Path,
    *,
    allow_synthetic: bool = False,
) -> tuple[Path, RuntimePreflightReplayResult]:
    """Execute exactly one authorized runtime-only preflight and publish its bundle."""
    runtime_manifest = verify_runtime_manifest(runtime_manifest_value)
    runtime_lock = verify_runtime_lock(runtime_lock_value, allow_synthetic=allow_synthetic)
    install_receipt = verify_install_receipt(
        install_receipt_value,
        runtime_lock=runtime_lock,
        runtime_manifest=runtime_manifest,
        allow_synthetic=allow_synthetic,
    )
    package = build_runtime_preflight_package(
        runtime_manifest,
        runtime_lock,
        install_receipt,
        allow_synthetic=allow_synthetic,
    )
    root_descriptor = _open_private_output_root(output_root)
    runtime_root_descriptor: int | None = None
    parent_endpoint: socket.socket | None = None
    child_endpoint: socket.socket | None = None
    child_pid: int | None = None
    interpreter_snapshot_descriptor: int | None = None
    interpreter_snapshot_name: str | None = None
    worker_source_descriptor: int | None = None
    root_binding: dict[str, JsonValue] | None = None
    authorization: dict[str, JsonValue] | None = None
    consumption: dict[str, JsonValue] | None = None
    entries: list[JsonValue] = []
    received_preflight_result: dict[str, JsonValue] | None = None
    child_spawned = False
    child_wait: dict[str, JsonValue] | None = None
    phase = "initialization"
    actions: dict[str, JsonValue] = {
        "attempts": 1,
        "retries": 0,
        "warmups": 0,
        "worker_process_starts": 0,
        "socketpair_creations": 0,
        "authorizations_consumed": 0,
        "parent_frames": 0,
        "worker_frames": 0,
        "preflight_once_commands": 0,
        "shutdowns": 0,
    }
    try:
        resolved_output_root = output_root.resolve(strict=True)
        worker_program_path = (
            Path(__file__).with_name("mlx_runtime_preflight_worker.py").resolve(strict=True)
        )
        source_worker, worker_bytes = _read_launch_target(
            worker_program_path,
            "runtime-preflight worker program",
            executable=False,
        )
        _require(
            condition=source_worker["sha256"] == EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256,
            message="runtime-preflight worker differs from its sealed digest",
        )
        source_interpreter, interpreter_bytes = _read_launch_target(
            interpreter_path,
            "Python interpreter",
            executable=True,
            trusted_ancestors=False,
            trusted_source=False,
        )
        rescanned = compile_runtime_manifest(
            _runtime_scan_spec_from_manifest(runtime_manifest),
            runtime_root,
            interpreter_path,
            worker_program_path,
        )
        _require(
            condition=canonical_json(rescanned) == canonical_json(runtime_manifest),
            message="live runtime root, interpreter, or worker differs from manifest",
        )
        _require(
            condition=source_interpreter["sha256"]
            == _mapping(
                runtime_manifest["interpreter"],
                "runtime_manifest.interpreter",
            )["sha256"],
            message="selected interpreter bytes differ from runtime manifest",
        )
        runtime_root_descriptor = _open_bound_runtime_root(runtime_root, runtime_manifest)
        root_binding = _output_root_binding(root_descriptor, os.urandom(32))
        worker_source_descriptor, worker_program = _create_worker_snapshot_at(
            root_descriptor,
            worker_bytes,
            worker_program_path.name,
        )
        _require(
            condition=worker_program["sha256"] == EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256,
            message="sealed runtime-preflight worker snapshot digest mismatch",
        )
        (
            interpreter_snapshot_descriptor,
            interpreter,
            interpreter_snapshot_name,
        ) = _create_interpreter_snapshot_at(root_descriptor, interpreter_bytes)
        sealed_interpreter_path = resolved_output_root / interpreter_snapshot_name
        parent_pid = os.getpid()
        parent_nonce = encode_bytes(os.urandom(32))
        deadline_ns = time.monotonic_ns() + DEFAULT_DEADLINE_NS
        hello: dict[str, JsonValue] = {
            "message_type": "parent_hello",
            "sequence": 1,
            "protocol_id": PROTOCOL_ID,
            "worker_code_id": WORKER_CODE_ID,
            "preflight_spec_id": package["preflight_spec_id"],
            "preflight_package_id": package["preflight_package_id"],
            "preflight_package_sha256": digest_bytes(canonical_json(package)),
            "runtime_manifest_id": runtime_manifest["manifest_id"],
            "runtime_manifest_sha256": digest_bytes(canonical_json(runtime_manifest)),
            "install_receipt_id": install_receipt["receipt_id"],
            "interpreter_sha256": interpreter["sha256"],
            "worker_program_sha256": worker_program["sha256"],
            "parent_nonce": parent_nonce,
            "output_root_id": root_binding["output_root_id"],
            "deadline_monotonic_ns": deadline_ns,
        }
        phase = "socketpair_creation"
        parent_endpoint, child_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        actions["socketpair_creations"] = 1
        phase = "worker_process_start"
        _revalidate_output_root_launch_path(resolved_output_root, root_descriptor)
        child_pid = _spawn_runtime_worker(
            sealed_interpreter_path,
            interpreter_path,
            interpreter_snapshot_descriptor,
            worker_source_descriptor,
            runtime_root_descriptor,
            child_endpoint,
        )
        child_spawned = True
        actions["worker_process_starts"] = 1
        os.close(interpreter_snapshot_descriptor)
        interpreter_snapshot_descriptor = None
        os.close(worker_source_descriptor)
        worker_source_descriptor = None
        os.close(runtime_root_descriptor)
        runtime_root_descriptor = None
        child_endpoint.close()
        child_endpoint = None
        channel = _FrameChannel(parent_endpoint, deadline_ns, entries)
        phase = "parent_hello"
        channel.send(hello)
        actions["parent_frames"] = 1
        phase = "worker_identity"
        identity_frame = channel.receive()
        actions["worker_frames"] = 1
        identity = _verify_worker_identity(
            identity_frame,
            hello=hello,
            child_pid=child_pid,
            parent_pid=parent_pid,
            interpreter=interpreter,
            worker_program=worker_program,
            runtime_manifest=runtime_manifest,
        )
        process_evidence = _parent_process_evidence(child_pid, parent_pid, interpreter)
        worker_nonce = cast("str", identity["worker_nonce"])
        authorization = _build_authorization(hello, worker_nonce, time.time_ns())
        _verify_authorization(authorization, check_current_expiry=True)
        phase = "authorization_consumption"
        consumption = _consume_authorization_at(root_descriptor, root_binding, authorization)
        actions["authorizations_consumed"] = 1
        phase = "authorize_once"
        channel.send(
            {
                "message_type": "authorize_once",
                "sequence": 3,
                "authorization": authorization,
            }
        )
        actions["parent_frames"] = 2
        phase = "authorization_ack"
        authorization_ack = channel.receive()
        actions["worker_frames"] = 2
        _verify_authorization_ack(authorization_ack, authorization)
        request_nonce = encode_bytes(os.urandom(32))
        phase = "preflight_once"
        channel.send(
            {
                "message_type": "preflight_once",
                "sequence": 5,
                "action": "mlx_runtime_preflight_only",
                "allowed_probes": list(ALLOWED_PROBES),
                "authorization_id": authorization["authorization_id"],
                "preflight_package_id": package["preflight_package_id"],
                "runtime_manifest_id": runtime_manifest["manifest_id"],
                "output_root_id": root_binding["output_root_id"],
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
            }
        )
        actions["preflight_once_commands"] = 1
        actions["parent_frames"] = 3
        phase = "preflight_result"
        received_preflight_result = channel.receive()
        actions["worker_frames"] = 3
        result, bound_module_count = _verify_preflight_result(
            received_preflight_result,
            authorization=authorization,
            request_nonce=request_nonce,
            runtime_manifest=runtime_manifest,
        )
        phase = "shutdown"
        channel.send(
            {
                "message_type": "shutdown",
                "sequence": 7,
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
            }
        )
        actions["shutdowns"] = 1
        actions["parent_frames"] = 4
        parent_endpoint.shutdown(socket.SHUT_WR)
        phase = "shutdown_ack"
        shutdown_ack = channel.receive()
        actions["worker_frames"] = 4
        _verify_shutdown_ack(
            shutdown_ack,
            parent_nonce=parent_nonce,
            worker_nonce=worker_nonce,
            request_nonce=request_nonce,
        )
        channel.expect_eof()
        phase = "child_wait"
        child_wait = _wait_child(child_pid, deadline_ns)
        child_pid = None
        os.unlink(interpreter_snapshot_name, dir_fd=root_descriptor)
        interpreter_snapshot_name = None
        os.fsync(root_descriptor)
        _require_successful_child(child_wait, actions)
        transcript = _transcript(entries)
        record = _preflight_record(
            package=package,
            runtime_manifest=runtime_manifest,
            runtime_lock=runtime_lock,
            install_receipt=install_receipt,
            output_root=root_binding,
            authorization=authorization,
            consumption=consumption,
            transcript=transcript,
            result=result,
            bound_module_count=bound_module_count,
            interpreter=interpreter,
            worker_program=worker_program,
            process_evidence=process_evidence,
            child_wait=child_wait,
        )
        phase = "publication"
        _revalidate_output_root_path(output_root, root_descriptor)
        content_files = {
            "source/runtime-preflight-spec.json": canonical_json(runtime_preflight_spec()),
            "source/worker-program.py": worker_bytes,
            "runtime-lock.json": canonical_json(runtime_lock),
            "runtime-install-receipt.json": canonical_json(install_receipt),
            "runtime-manifest.json": canonical_json(runtime_manifest),
            "runtime-preflight-package.json": canonical_json(package),
            "output-root-binding.json": canonical_json(root_binding),
            "authorization.json": canonical_json(authorization),
            "authorization-consumption.json": canonical_json(consumption),
            "transcript.json": canonical_json(transcript),
            "preflight-record.json": canonical_json(record),
        }
        _require(
            condition=not any(len(data) > MAX_BUNDLE_FILE_BYTES for data in content_files.values()),
            message="runtime-preflight artifact exceeds its byte bound",
        )
        destination = publish_bundle_at(
            content_files,
            output_root,
            root_descriptor,
            name_prefix="localinferencelab-mlx-runtime-preflight-v1",
        )
        _revalidate_output_root_path(output_root, root_descriptor)
        if allow_synthetic:
            replay, _eligibility = _replay_runtime_preflight_snapshot(
                destination,
                allow_synthetic=True,
            )
            return destination, replay
        return destination, replay_runtime_preflight_bundle(destination)
    except (ContractError, OSError) as error:
        if child_pid is not None:
            child_wait = _terminate_and_wait(child_pid)
            child_pid = None
        _write_terminal_failure_at(
            root_descriptor,
            phase=phase,
            output_root_id=None if root_binding is None else root_binding["output_root_id"],
            package_id=package["preflight_package_id"],
            authorization_id=(None if authorization is None else authorization["authorization_id"]),
            consumption_id=(None if consumption is None else consumption["consumption_id"]),
            actions=actions,
            child_spawned=child_spawned,
            child_wait=child_wait,
            entries=entries,
            rejected_result=received_preflight_result,
            validation_error=error,
        )
        raise
    finally:
        if child_endpoint is not None:
            child_endpoint.close()
        if parent_endpoint is not None:
            parent_endpoint.close()
        if child_pid is not None:
            _terminate_and_wait(child_pid)
        if runtime_root_descriptor is not None:
            os.close(runtime_root_descriptor)
        if worker_source_descriptor is not None:
            os.close(worker_source_descriptor)
        if interpreter_snapshot_descriptor is not None:
            os.close(interpreter_snapshot_descriptor)
        if interpreter_snapshot_name is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(interpreter_snapshot_name, dir_fd=root_descriptor)
        os.close(root_descriptor)
