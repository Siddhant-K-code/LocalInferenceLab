"""Exact prospective MLX runtime target identity and process-free replay."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_canonical_json_file,
)

SCHEMA_VERSION = "1.0"
EXPECTED_RUNTIME_TARGET_ANCHOR_ID = (
    "sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0"
)
_CONTROL_LIMIT = 32
_DIGEST_LENGTH = 71
_ZERO_ACTION_COUNTERS: dict[str, int] = {
    "backend_queries": 0,
    "device_queries": 0,
    "metal_queries": 0,
    "model_actions": 0,
    "package_installations": 0,
    "package_network_requests": 0,
    "process_starts": 0,
    "runtime_imports": 0,
    "socket_creations": 0,
    "synchronizations": 0,
}
RUNTIME_TARGET_OBSERVATION_CLAIM_BLOCKERS = (
    "authoritative_observer_identity_unavailable",
    "caller_supplied_provenance_is_self_asserted",
    "custody_bound_executable_measurement_unavailable",
    "custody_bound_platform_measurement_unavailable",
    "runtime_observation_acceptance_unimplemented",
)
_INTERPRETER_IDENTITY: dict[str, JsonValue] = {
    "abi_flags": "",
    "cache_tag": "cpython-313",
    "executable_realpath": ("cpython-3.13.15-macos-aarch64-none/bin/python3.13"),
    "code_signature": {
        "cdhash_sha256": ("09a976c9f1b4632fdb567ef2ab14ee4eb93aba159dd99c1096ffcdd0b2ca6673"),
        "identifier": "-",
        "signature_kind": "adhoc_linker_signed",
    },
    "executable_name": "python3.13",
    "executable_sha256": (
        "sha256:4e1dfb03f82c5f7f253bbc3c04a79bb9f09a5cd0528829c32d6984ef309ebb2f"
    ),
    "implementation_name": "cpython",
    "implementation_version": "3.13.15",
    "python_abi": "cp313",
    "python_full_version": "3.13.15",
    "python_version": "3.13",
    "realpath_kind": "installation_root_relative",
    "soabi": "cpython-313-darwin",
}
_PLATFORM_IDENTITY: dict[str, JsonValue] = {
    "architecture": "arm64",
    "macos_build_version": "26A434",
    "macos_product_version": "27.0.1",
    "platform_system": "Darwin",
    "python_interpreter_deployment_target": "11.0",
    "python_platform_tag": "macosx-11.0-arm64",
    "runtime_wheel_deployment_target": "15.0",
}


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _keys(value: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(
    value: JsonValue,
    label: str,
    *,
    allow_empty: bool = False,
    maximum: int = 4096,
) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        requirement = "a string" if allow_empty else "a non-empty string"
        raise ContractError(f"{label} must be {requirement}")
    if len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(value: JsonValue, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be an integer >= 0")
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


def _verify_zero_actions(value: JsonValue, label: str) -> None:
    counters = _mapping(value, label)
    _keys(counters, set(_ZERO_ACTION_COUNTERS), label)
    for name in sorted(_ZERO_ACTION_COUNTERS):
        if _integer(counters[name], f"{label}.{name}") != 0:
            raise ContractError(f"{label}.{name} must remain zero")


def _development_host_observation() -> dict[str, JsonValue]:
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_development_host_observation",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "development_host_observation_not_runtime_evidence",
        "observed_at_utc_date": "2026-10-07",
        "collection_scope": "bounded_os_commands_and_python_standard_library_only",
        "interpreter": dict(_INTERPRETER_IDENTITY),
        "platform": {
            **_PLATFORM_IDENTITY,
            "darwin_kernel_release": "27.0.0",
        },
        "absolute_private_path_committed": False,
        "can_satisfy_future_runtime_evidence": False,
        "mlx_or_mlx_lm_imported": False,
        "metal_or_backend_queried": False,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    content["observation_id"] = canonical_identity(content)
    return content


def _runtime_target_anchor_content() -> dict[str, JsonValue]:
    development_observation = _development_host_observation()
    return {
        "record_type": "mlx_runtime_target_anchor",
        "schema_version": SCHEMA_VERSION,
        "action": "prospective_runtime_target_binding_only",
        "selection": {
            "development_host_observation_id": development_observation["observation_id"],
            "historical_failed_receipt_accepted_as_target_evidence": False,
            "historical_failed_receipt_python_full_version": "3.13.15",
            "prior_candidate_python_full_version": "3.13.0",
            "promotion_authority": "committed_human_reviewed_target",
            "selected_python_full_version": "3.13.15",
            "selection_basis": "available_local_interpreter_and_host_envelope",
            "self_attested_runtime_evidence_accepted": False,
        },
        "development_host_observation": development_observation,
        "prospective_target": {
            "evidence_status": "prospective_target_not_observed_runtime_evidence",
            "interpreter": dict(_INTERPRETER_IDENTITY),
            "platform": dict(_PLATFORM_IDENTITY),
            "requires_python_evaluation": "exact_python_full_version",
            "wheel_abi_compatibility": "cp313_scoped",
        },
        "future_observation_policy": {
            "ambiguous_host_promotion_accepted": False,
            "development_observation_accepted_as_runtime_evidence": False,
            "independent_observer_required": True,
            "self_attested_observation_accepted": False,
            "target_drift_accepted": False,
        },
        "claims": {
            "mlx_installed": False,
            "mlx_imported": False,
            "mlx_lm_imported": False,
            "backend_available": False,
            "device_available": False,
            "metal_available": False,
            "model_action_performed": False,
            "runtime_authorized": False,
        },
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }


def runtime_target_anchor() -> dict[str, JsonValue]:
    """Return the exact committed prospective target anchor."""
    content = _runtime_target_anchor_content()
    identity = canonical_identity(content)
    if identity != EXPECTED_RUNTIME_TARGET_ANCHOR_ID:
        raise ContractError("hardcoded runtime target anchor identity drift")
    content["anchor_id"] = identity
    return content


def verify_runtime_target_anchor(value: JsonValue) -> dict[str, JsonValue]:
    """Reject malformed anchors, target drift, and coordinated rehashing."""
    anchor = _mapping(value, "mlx_runtime_target_anchor")
    expected = runtime_target_anchor()
    _keys(anchor, set(expected), "mlx_runtime_target_anchor")
    identity = _sha256(anchor["anchor_id"], "mlx_runtime_target_anchor.anchor_id")
    if identity != EXPECTED_RUNTIME_TARGET_ANCHOR_ID:
        raise ContractError("runtime target anchor is not the committed trust root")
    _verify_zero_actions(
        anchor["static_action_counters"],
        "mlx_runtime_target_anchor.static_action_counters",
    )
    observation = _mapping(
        anchor["development_host_observation"],
        "mlx_runtime_target_anchor.development_host_observation",
    )
    _verify_zero_actions(
        observation["static_action_counters"],
        "development_host_observation.static_action_counters",
    )
    content = dict(anchor)
    del content["anchor_id"]
    if canonical_identity(content) != identity:
        raise ContractError("runtime target anchor identity mismatch")
    if canonical_json(anchor) != canonical_json(expected):
        raise ContractError("runtime target anchor content drift")
    return dict(anchor)


def load_runtime_target_anchor(path: Path) -> dict[str, JsonValue]:
    """Load the canonical target anchor without host or runtime action."""
    return verify_runtime_target_anchor(load_canonical_json_file(path, "MLX runtime target anchor"))


def _validate_runtime_target_observation_claim(
    anchor_value: JsonValue,
    claim_value: JsonValue,
) -> dict[str, JsonValue]:
    """Validate a caller-supplied structure that can never become runtime evidence."""
    anchor = verify_runtime_target_anchor(anchor_value)
    claim = _mapping(claim_value, "mlx_runtime_target_observation_claim")
    fields = {
        "claim_id",
        "claimed_ambiguous_host_promotion",
        "claimed_observer_relationship",
        "claimed_self_attested",
        "evidence_kind",
        "interpreter",
        "platform",
        "record_type",
        "schema_version",
        "static_action_counters",
        "target_anchor_id",
    }
    _keys(claim, fields, "mlx_runtime_target_observation_claim")
    if (
        claim["record_type"] != "mlx_runtime_target_observation_claim"
        or claim["schema_version"] != SCHEMA_VERSION
        or claim["evidence_kind"] != "caller_supplied_structure_only"
        or claim["claimed_observer_relationship"] != "independent_from_candidate"
    ):
        raise ContractError("unsupported runtime target observation claim")
    if _boolean(
        claim["claimed_self_attested"],
        "runtime_target_observation_claim.claimed_self_attested",
    ):
        raise ContractError("self-attested runtime target observation claims are forbidden")
    if _boolean(
        claim["claimed_ambiguous_host_promotion"],
        "runtime_target_observation_claim.claimed_ambiguous_host_promotion",
    ):
        raise ContractError("ambiguous host promotion is forbidden")
    if claim["target_anchor_id"] != anchor["anchor_id"]:
        raise ContractError("runtime target observation claim anchor identity mismatch")
    target = _mapping(anchor["prospective_target"], "prospective target")
    interpreter = _mapping(
        claim["interpreter"],
        "runtime_target_observation_claim.interpreter",
    )
    platform = _mapping(
        claim["platform"],
        "runtime_target_observation_claim.platform",
    )
    if canonical_json(interpreter) != canonical_json(target["interpreter"]):
        raise ContractError("runtime target observation claim interpreter identity drift")
    if canonical_json(platform) != canonical_json(target["platform"]):
        raise ContractError("runtime target observation claim platform identity drift")
    _verify_zero_actions(
        claim["static_action_counters"],
        "runtime_target_observation_claim.static_action_counters",
    )
    identity = _sha256(
        claim["claim_id"],
        "runtime_target_observation_claim.claim_id",
    )
    content = dict(claim)
    del content["claim_id"]
    if canonical_identity(content) != identity:
        raise ContractError("runtime target observation claim identity mismatch")
    return dict(claim)


def verify_runtime_target_observation_claim(
    anchor_value: JsonValue,
    claim_value: JsonValue,
) -> dict[str, JsonValue]:
    """Validate one structure-only claim and return only its refusal projection."""
    anchor = verify_runtime_target_anchor(anchor_value)
    claim = _validate_runtime_target_observation_claim(anchor, claim_value)
    return {
        "claim_id": claim["claim_id"],
        "target_anchor_id": anchor["anchor_id"],
        "evidence_kind": "caller_supplied_structure_only",
        "claimed_identity_fields_match_target": True,
        "runtime_evidence_accepted": False,
        "independent_provenance_proven": False,
        "custody_bound_measurement_proven": False,
        "can_satisfy_qualification_or_preflight": False,
        "blockers": list(RUNTIME_TARGET_OBSERVATION_CLAIM_BLOCKERS),
        "runtime_authorized": False,
        "mlx_or_metal_actions": 0,
    }


def runtime_target_replay(value: JsonValue) -> dict[str, JsonValue]:
    """Return a bounded process-free projection of the committed target."""
    anchor = verify_runtime_target_anchor(value)
    target = _mapping(anchor["prospective_target"], "prospective target")
    interpreter = _mapping(target["interpreter"], "prospective target interpreter")
    platform = _mapping(target["platform"], "prospective target platform")
    observation = _mapping(
        anchor["development_host_observation"],
        "development host observation",
    )
    return {
        "anchor_id": anchor["anchor_id"],
        "development_host_observation_id": observation["observation_id"],
        "python_full_version": interpreter["python_full_version"],
        "python_abi": interpreter["python_abi"],
        "executable_sha256": interpreter["executable_sha256"],
        "macos_product_version": platform["macos_product_version"],
        "macos_build_version": platform["macos_build_version"],
        "runtime_wheel_deployment_target": platform["runtime_wheel_deployment_target"],
        "architecture": platform["architecture"],
        "development_observation_is_runtime_evidence": False,
        "runtime_observation_committed": False,
        "runtime_authorized": False,
        "mlx_or_metal_actions": 0,
    }


def target_environment_binding() -> dict[str, JsonValue]:
    """Return the qualification fields bound by the target anchor."""
    anchor = runtime_target_anchor()
    target = cast("dict[str, JsonValue]", anchor["prospective_target"])
    interpreter = cast("dict[str, JsonValue]", target["interpreter"])
    platform = cast("dict[str, JsonValue]", target["platform"])
    return {
        "implementation_name": interpreter["implementation_name"],
        "macos_version": platform["macos_product_version"],
        "os_name": "posix",
        "platform_machine": platform["architecture"],
        "platform_system": platform["platform_system"],
        "python_abi": interpreter["python_abi"],
        "python_full_version": interpreter["python_full_version"],
        "python_version": interpreter["python_version"],
        "runtime_target_anchor_id": anchor["anchor_id"],
        "sys_platform": "darwin",
    }
