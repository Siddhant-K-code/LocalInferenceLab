"""Pinned independent review policy for static MLX evidence."""

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
EXPECTED_REVIEW_REGISTRY_ID = (
    "sha256:dd1a6f0710a38cdb5757a81c749a2b9005b2c0371e5c1f4900bf6d6c41c7d9ff"
)
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_REGISTRY_FILENAME = "mlx-static-evidence-review-registry-v1.json"
_SOURCE_REGISTRY_PATH = Path(__file__).resolve().parents[2] / "evidence" / _REGISTRY_FILENAME
_PACKAGED_REGISTRY_PATH = Path(__file__).resolve().parent / "evidence" / _REGISTRY_FILENAME
COMMITTED_REVIEW_REGISTRY_PATH = (
    _PACKAGED_REGISTRY_PATH if _PACKAGED_REGISTRY_PATH.exists() else _SOURCE_REGISTRY_PATH
)
_EVIDENCE_FIELDS = {
    "candidate_package_id",
    "candidate_review_anchor_id",
    "predecessor_manifest_anchor_spec_id",
    "qualification_spec_id",
    "runtime_target_anchor_id",
    "wheel_evidence_manifest_id",
    "wheel_evidence_pack_receipt_id",
    "wheel_evidence_pack_spec_id",
    "worker_api_evidence_anchor_id",
}
_CANDIDATE_BINDING_FIELDS = {
    "candidate_package_id",
    "candidate_review_anchor_id",
    "qualification_spec_id",
    "runtime_target_anchor_id",
    "worker_api_evidence_anchor_id",
}
_REVIEW_SCOPE: list[JsonValue] = [
    "candidate_static_source_wheel_and_metadata_evidence",
    "supplied_wheel_closure_manifest_static_evidence",
]
_LIMITS: dict[str, JsonValue] = {
    "backend_or_device_availability_proven": False,
    "candidate_or_manifest_mutation_authorized": False,
    "installation_or_import_success_proven": False,
    "metal_availability_proven": False,
    "model_or_tokenizer_support_proven": False,
    "runtime_executability_proven": False,
    "static_evidence_only": True,
    "stream_synchronization_proven": False,
}
_PROMOTION: dict[str, JsonValue] = {
    "final_qualification_record_publication": "separate_later_change_required",
    "independent_review_event": "repository_commit_and_pull_request_review",
    "reviewed_artifact_mutation_allowed": False,
}
_ZERO_ACTION_COUNTERS: dict[str, int] = {
    "backend_queries": 0,
    "benchmark_actions": 0,
    "cloud_actions": 0,
    "device_queries": 0,
    "inference_requests": 0,
    "metal_queries": 0,
    "model_loads": 0,
    "package_installations": 0,
    "package_network_requests": 0,
    "process_starts": 0,
    "runtime_imports": 0,
    "spend_actions": 0,
    "synchronizations": 0,
    "tokenizer_loads": 0,
}


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int) -> list[JsonValue]:
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


def _text(value: JsonValue, label: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(value: JsonValue, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
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


def review_registry_spec() -> dict[str, JsonValue]:
    """Return the immutable schema for independent static-evidence approvals."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_static_evidence_review_registry_spec",
        "schema_version": SCHEMA_VERSION,
        "approval_identity_rule": "canonical_approval_content_without_approval_id",
        "registry_identity_rule": "canonical_registry_content_without_registry_id",
        "eligibility_registry_source": "repository_committed_exact_pinned_registry_only",
        "generic_verification_expected_id_source": "caller_supplied_content_address",
        "approval_evidence_fields": cast("list[JsonValue]", sorted(_EVIDENCE_FIELDS)),
        "review_scope": list(_REVIEW_SCOPE),
        "limits": dict(_LIMITS),
        "promotion": dict(_PROMOTION),
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def _verify_zero_actions(value: JsonValue, label: str) -> None:
    counters = _mapping(value, label)
    _keys(counters, set(_ZERO_ACTION_COUNTERS), label)
    for name in sorted(_ZERO_ACTION_COUNTERS):
        if _integer(counters[name], f"{label}.{name}") != 0:
            raise ContractError(f"{label}.{name} must remain zero")


def _verify_approval(value: JsonValue, index: int) -> dict[str, JsonValue]:
    label = f"review_registry.approvals[{index}]"
    approval = _mapping(value, label)
    fields = {
        "approval_id",
        "evidence",
        "limits",
        "promotion",
        "record_type",
        "review_scope",
        "schema_version",
        "static_action_counters",
    }
    _keys(approval, fields, label)
    if (
        approval["record_type"] != "mlx_static_evidence_review_approval"
        or approval["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported MLX static evidence review approval")
    evidence = _mapping(approval["evidence"], f"{label}.evidence")
    _keys(evidence, _EVIDENCE_FIELDS, f"{label}.evidence")
    for name in sorted(_EVIDENCE_FIELDS):
        _sha256(evidence[name], f"{label}.evidence.{name}")
    if canonical_json(approval["review_scope"]) != canonical_json(_REVIEW_SCOPE):
        raise ContractError("review approval scope drift")
    if canonical_json(approval["limits"]) != canonical_json(_LIMITS):
        raise ContractError("review approval limits drift")
    if canonical_json(approval["promotion"]) != canonical_json(_PROMOTION):
        raise ContractError("review approval promotion policy drift")
    _verify_zero_actions(approval["static_action_counters"], f"{label}.static_action_counters")
    identity = _sha256(approval["approval_id"], f"{label}.approval_id")
    content = dict(approval)
    del content["approval_id"]
    if canonical_identity(content) != identity:
        raise ContractError("review approval identity mismatch")
    return dict(approval)


def verify_review_registry(
    value: JsonValue,
    expected_registry_id: str,
) -> dict[str, JsonValue]:
    """Verify any registry against an explicit caller-supplied content address."""
    registry = _mapping(value, "mlx_static_evidence_review_registry")
    fields = {
        "approvals",
        "record_type",
        "registry_id",
        "registry_spec_id",
        "registry_version",
        "schema_version",
    }
    _keys(registry, fields, "mlx_static_evidence_review_registry")
    if (
        registry["record_type"] != "mlx_static_evidence_review_registry"
        or registry["schema_version"] != SCHEMA_VERSION
        or registry["registry_spec_id"] != review_registry_spec()["spec_id"]
        or _integer(registry["registry_version"], "review_registry.registry_version", minimum=1)
        != 1
    ):
        raise ContractError("unsupported MLX static evidence review registry")
    trusted_identity = _sha256(expected_registry_id, "expected_registry_id")
    identity = _sha256(registry["registry_id"], "review_registry.registry_id")
    if identity != trusted_identity:
        raise ContractError("review registry differs from expected content address")
    content = dict(registry)
    del content["registry_id"]
    if canonical_identity(content) != identity:
        raise ContractError("review registry identity mismatch")
    approvals = [
        _verify_approval(item, index)
        for index, item in enumerate(
            _array(registry["approvals"], "review_registry.approvals", maximum=128)
        )
    ]
    if not approvals:
        raise ContractError("review registry must contain at least one approval")
    approval_ids = [cast("str", approval["approval_id"]) for approval in approvals]
    if approval_ids != sorted(set(approval_ids)):
        raise ContractError("review approvals must be unique and sorted by approval identity")
    candidate_anchors: set[str] = set()
    manifest_ids: set[str] = set()
    for approval in approvals:
        evidence = _mapping(approval["evidence"], "review approval evidence")
        candidate_anchor = cast("str", evidence["candidate_review_anchor_id"])
        manifest_id = cast("str", evidence["wheel_evidence_manifest_id"])
        if candidate_anchor in candidate_anchors:
            raise ContractError("review registry contains duplicate candidate approvals")
        if manifest_id in manifest_ids:
            raise ContractError("review registry contains duplicate manifest approvals")
        candidate_anchors.add(candidate_anchor)
        manifest_ids.add(manifest_id)
        if identity in evidence.values() or approval["approval_id"] == identity:
            raise ContractError("review registry must not refer to its own identity")
    return dict(registry)


def load_committed_review_registry() -> dict[str, JsonValue]:
    """Load only the repository-pinned registry used by eligibility decisions."""
    try:
        value = load_canonical_json_file(
            COMMITTED_REVIEW_REGISTRY_PATH,
            "committed MLX static evidence review registry",
        )
    except OSError as error:
        raise ContractError(
            "committed MLX static evidence review registry is unavailable"
        ) from error
    return verify_review_registry(value, EXPECTED_REVIEW_REGISTRY_ID)


def _matching_approval(
    registry: dict[str, JsonValue],
    required_evidence: dict[str, str],
) -> dict[str, JsonValue] | None:
    matches: list[dict[str, JsonValue]] = []
    for item in cast("list[JsonValue]", registry["approvals"]):
        approval = _mapping(item, "review approval")
        evidence = _mapping(approval["evidence"], "review approval evidence")
        if all(evidence[name] == value for name, value in required_evidence.items()):
            matches.append(approval)
    if len(matches) > 1:
        raise ContractError("review registry approval match is ambiguous")
    return None if not matches else dict(matches[0])


def committed_candidate_review_approval(
    *,
    candidate_package_id: str,
    candidate_review_anchor_id: str,
    qualification_spec_id: str,
    runtime_target_anchor_id: str,
    worker_api_evidence_anchor_id: str,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue] | None]:
    """Match candidate review only against the committed pinned registry."""
    registry = load_committed_review_registry()
    required = {
        "candidate_package_id": candidate_package_id,
        "candidate_review_anchor_id": candidate_review_anchor_id,
        "qualification_spec_id": qualification_spec_id,
        "runtime_target_anchor_id": runtime_target_anchor_id,
        "worker_api_evidence_anchor_id": worker_api_evidence_anchor_id,
    }
    if set(required) != _CANDIDATE_BINDING_FIELDS:
        raise ContractError("candidate review binding fields drift")
    return registry, _matching_approval(registry, required)


def committed_pack_review_approval(
    *,
    candidate_package_id: str,
    candidate_review_anchor_id: str,
    predecessor_manifest_anchor_spec_id: str,
    qualification_spec_id: str,
    runtime_target_anchor_id: str,
    wheel_evidence_manifest_id: str,
    wheel_evidence_pack_receipt_id: str,
    wheel_evidence_pack_spec_id: str,
    worker_api_evidence_anchor_id: str,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue] | None]:
    """Match full candidate and pack review only against the pinned registry."""
    registry = load_committed_review_registry()
    required = {
        "candidate_package_id": candidate_package_id,
        "candidate_review_anchor_id": candidate_review_anchor_id,
        "predecessor_manifest_anchor_spec_id": predecessor_manifest_anchor_spec_id,
        "qualification_spec_id": qualification_spec_id,
        "runtime_target_anchor_id": runtime_target_anchor_id,
        "wheel_evidence_manifest_id": wheel_evidence_manifest_id,
        "wheel_evidence_pack_receipt_id": wheel_evidence_pack_receipt_id,
        "wheel_evidence_pack_spec_id": wheel_evidence_pack_spec_id,
        "worker_api_evidence_anchor_id": worker_api_evidence_anchor_id,
    }
    if set(required) != _EVIDENCE_FIELDS:
        raise ContractError("pack review binding fields drift")
    return registry, _matching_approval(registry, required)


def committed_review_registry_inspection() -> dict[str, JsonValue]:
    """Return the bounded zero-action projection of the pinned registry."""
    registry = load_committed_review_registry()
    approvals = cast("list[JsonValue]", registry["approvals"])
    return {
        "registry_id": registry["registry_id"],
        "registry_spec_id": registry["registry_spec_id"],
        "registry_version": registry["registry_version"],
        "approval_ids": [_mapping(item, "review approval")["approval_id"] for item in approvals],
        "final_qualification_record_publication": ("separate_later_change_required"),
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
