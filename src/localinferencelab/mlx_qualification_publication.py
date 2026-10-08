"""Canonical publication and offline replay of the reviewed MLX qualification."""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_canonical_json_file,
)
from localinferencelab.mlx_qualification import ELIGIBLE, INELIGIBLE
from localinferencelab.mlx_review_registry import (
    EXPECTED_REVIEW_REGISTRY_ID,
    review_registry_spec,
)
from localinferencelab.mlx_wheel_custody import (
    build_reviewed_pack_qualification_assessment,
    verify_reviewed_pack_receipt,
)

SCHEMA_VERSION = "1.0"
EXPECTED_CANDIDATE_PACKAGE_ID = (
    "sha256:4f87b4678c31c0cd08534c58485e2b242c74936737b8f9c6c96319454ada358d"
)
EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID = (
    "sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f"
)
EXPECTED_QUALIFICATION_SPEC_ID = (
    "sha256:17d2f62fd4832a224f3bf61c7aa5b9668d05077ed36d56d1bf873fd63f2ac826"
)
EXPECTED_RUNTIME_TARGET_ANCHOR_ID = (
    "sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0"
)
EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID = (
    "sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd"
)
EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID = (
    "sha256:0c28cc713fe9baabdda8c075f148f23b4d2ebd4525160212d0f538cc907db6b4"
)
EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID = (
    "sha256:969783ae80daffae5451d0009e77d3618ba92756d8adbfdf0cf6aa9c13453761"
)
EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID = (
    "sha256:6eb636208a880f49b7ece6571dd20a5b3465996692683bfa9b8e873a0f68b07c"
)
EXPECTED_REVIEW_REGISTRY_SPEC_ID = (
    "sha256:41b3586faa73ddc1d739d300bfd8ff82bfb7219f83e0c24660ed645d59bd9da0"
)
EXPECTED_REVIEW_APPROVAL_ID = (
    "sha256:03897777a7460b2000b808504268f7654176793181467d2b391468a432837f42"
)
EXPECTED_QUALIFICATION_RECORD_ID = (
    "sha256:419c6db9924a1da7ef815b445cc1412e3a0c19b9040cae3a26ef583f81eb8a21"
)

_CANDIDATE_FILENAME = "mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json"
_MANIFEST_FILENAME = "mlx-wheel-closure-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json"
_RECORD_FILENAME = "mlx-runtime-qualification-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json"
_SOURCE_EVIDENCE_ROOT = Path(__file__).resolve().parents[2] / "evidence"
_PACKAGED_EVIDENCE_ROOT = Path(__file__).resolve().parent / "evidence"


def _evidence_path(filename: str) -> Path:
    packaged = _PACKAGED_EVIDENCE_ROOT / filename
    return packaged if packaged.exists() else _SOURCE_EVIDENCE_ROOT / filename


COMMITTED_CANDIDATE_PATH = _evidence_path(_CANDIDATE_FILENAME)
COMMITTED_MANIFEST_PATH = _evidence_path(_MANIFEST_FILENAME)
COMMITTED_QUALIFICATION_RECORD_PATH = _evidence_path(_RECORD_FILENAME)

_RECORD_FIELDS = {
    "assessment",
    "blockers",
    "decision",
    "eligibility_meaning",
    "evidence_bindings",
    "limitations",
    "pack_verification",
    "receipt_evidence_scope",
    "record_id",
    "record_type",
    "schema_1_0_remains_permanently_disabled",
    "schema_version",
    "static_action_counters",
}
_EVIDENCE_BINDING_FIELDS = {
    "candidate_package_id",
    "candidate_review_anchor_id",
    "qualification_spec_id",
    "review_approval_id",
    "review_registry_id",
    "review_registry_spec_id",
    "runtime_target_anchor_id",
    "wheel_evidence_manifest_id",
    "wheel_evidence_pack_receipt_id",
    "wheel_evidence_pack_spec_id",
    "worker_api_evidence_anchor_id",
}
_ZERO_ACTION_COUNTERS: dict[str, int] = {
    "authorization_consumptions": 0,
    "authorization_creations": 0,
    "backend_queries": 0,
    "benchmark_actions": 0,
    "cache_actions": 0,
    "cloud_actions": 0,
    "device_queries": 0,
    "generation_requests": 0,
    "inference_requests": 0,
    "metal_queries": 0,
    "model_discoveries": 0,
    "model_loads": 0,
    "package_installations": 0,
    "package_network_requests": 0,
    "process_starts": 0,
    "prompt_actions": 0,
    "runtime_imports": 0,
    "socket_creations": 0,
    "spend_actions": 0,
    "synchronizations": 0,
    "tokenizer_discoveries": 0,
    "tokenizer_loads": 0,
}
_LIMITATIONS: dict[str, JsonValue] = {
    "authorization_created": False,
    "backend_or_device_availability_proven": False,
    "installation_or_import_success_proven": False,
    "metal_availability_proven": False,
    "model_or_tokenizer_support_proven": False,
    "permission_to_run": False,
    "runtime_executability_proven": False,
    "static_coherence_only": True,
    "stream_synchronization_proven": False,
}
_RECEIPT_EVIDENCE_SCOPE: dict[str, JsonValue] = {
    "fresh_pack_verification_requires_exact_supplied_pack": True,
    "offline_record_replay_requires_supplied_pack": False,
    "record_or_manifest_proves_current_wheel_bytes_present": False,
    "reviewed_receipt_reproduced_from_canonical_manifest_aggregates": True,
    "wheel_bytes_embedded_in_record": False,
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


def _verify_zero_actions(value: JsonValue) -> None:
    counters = _mapping(value, "qualification publication static_action_counters")
    _keys(counters, set(_ZERO_ACTION_COUNTERS), "qualification publication static_action_counters")
    for name in sorted(_ZERO_ACTION_COUNTERS):
        counter = counters[name]
        if isinstance(counter, bool) or not isinstance(counter, int) or counter != 0:
            raise ContractError(f"static_action_counters.{name} must be integer zero")


def _load_committed_evidence() -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    candidate = _mapping(
        load_canonical_json_file(COMMITTED_CANDIDATE_PATH, "committed MLX candidate"),
        "committed MLX candidate",
    )
    manifest = _mapping(
        load_canonical_json_file(COMMITTED_MANIFEST_PATH, "committed wheel closure manifest"),
        "committed wheel closure manifest",
    )
    return candidate, manifest


def build_qualification_publication_record() -> dict[str, JsonValue]:
    """Build the sole current qualification publication from pinned committed evidence."""
    candidate, manifest = _load_committed_evidence()
    derived = build_reviewed_pack_qualification_assessment(
        candidate,
        manifest,
        EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
    )
    verified_candidate = _mapping(derived["candidate"], "verified candidate")
    candidate_anchor = _mapping(derived["candidate_anchor"], "verified candidate anchor")
    candidate_assessment = _mapping(
        derived["candidate_assessment"],
        "verified candidate assessment",
    )
    verified_manifest = _mapping(derived["manifest"], "verified manifest")
    receipt = verify_reviewed_pack_receipt(
        derived["pack_verification"],
        verified_manifest,
        EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
    )
    target = _mapping(verified_candidate["target_environment"], "verified candidate target")
    registry_spec_id = cast("str", review_registry_spec()["spec_id"])
    bindings: dict[str, JsonValue] = {
        "candidate_package_id": verified_candidate["package_id"],
        "candidate_review_anchor_id": candidate_assessment["review_anchor_id"],
        "qualification_spec_id": verified_candidate["qualification_spec_id"],
        "review_approval_id": derived["review_approval_id"],
        "review_registry_id": derived["review_registry_id"],
        "review_registry_spec_id": registry_spec_id,
        "runtime_target_anchor_id": target["runtime_target_anchor_id"],
        "wheel_evidence_manifest_id": verified_manifest["manifest_id"],
        "wheel_evidence_pack_receipt_id": receipt["receipt_id"],
        "wheel_evidence_pack_spec_id": verified_manifest["pack_spec_id"],
        "worker_api_evidence_anchor_id": verified_candidate["worker_api_evidence_anchor_id"],
    }
    expected_bindings: dict[str, JsonValue] = {
        "candidate_package_id": EXPECTED_CANDIDATE_PACKAGE_ID,
        "candidate_review_anchor_id": EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID,
        "qualification_spec_id": EXPECTED_QUALIFICATION_SPEC_ID,
        "review_approval_id": EXPECTED_REVIEW_APPROVAL_ID,
        "review_registry_id": EXPECTED_REVIEW_REGISTRY_ID,
        "review_registry_spec_id": EXPECTED_REVIEW_REGISTRY_SPEC_ID,
        "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        "wheel_evidence_manifest_id": EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        "wheel_evidence_pack_receipt_id": EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
        "wheel_evidence_pack_spec_id": EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID,
        "worker_api_evidence_anchor_id": EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
    }
    if canonical_json(bindings) != canonical_json(expected_bindings):
        raise ContractError("qualification publication evidence binding drift")
    if candidate_anchor["package_id"] != bindings["candidate_package_id"]:
        raise ContractError("qualification publication candidate package binding drift")
    blockers = cast("list[JsonValue]", derived["blockers"])
    if blockers != sorted(set(cast("list[str]", blockers))):
        raise ContractError("qualification publication blockers must be unique and sorted")
    decision = derived["decision"]
    if decision not in {ELIGIBLE, INELIGIBLE} or (decision == ELIGIBLE) != (not blockers):
        raise ContractError("qualification publication decision does not match blockers")
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_qualification_publication_record",
        "schema_version": SCHEMA_VERSION,
        "evidence_bindings": bindings,
        "pack_verification": receipt,
        "assessment": {
            "blockers": blockers,
            "closure": derived["closure"],
            "decision": decision,
            "eligibility_scope": (
                "human_review_for_possible_fresh_explicit_authorization_only"
                if decision == ELIGIBLE
                else "not_eligible_for_new_observed_authorization"
            ),
            "next_required_step": (
                "human_review_and_possible_fresh_explicit_authorization_in_a_separate_change"
            ),
        },
        "decision": decision,
        "blockers": blockers,
        "eligibility_meaning": (
            "eligible_only_for_human_review_and_possible_fresh_explicit_authorization"
        ),
        "limitations": dict(_LIMITATIONS),
        "receipt_evidence_scope": dict(_RECEIPT_EVIDENCE_SCOPE),
        "schema_1_0_remains_permanently_disabled": True,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    record["record_id"] = canonical_identity(record)
    return record


def verify_qualification_publication_record(value: JsonValue) -> dict[str, JsonValue]:
    """Replay the current publication offline against only pinned committed evidence."""
    record = _mapping(value, "MLX qualification publication record")
    _keys(record, _RECORD_FIELDS, "MLX qualification publication record")
    if (
        record["record_type"] != "mlx_runtime_qualification_publication_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["decision"] not in {ELIGIBLE, INELIGIBLE}
        or record["schema_1_0_remains_permanently_disabled"] is not True
        or canonical_json(record["limitations"]) != canonical_json(_LIMITATIONS)
        or canonical_json(record["receipt_evidence_scope"])
        != canonical_json(_RECEIPT_EVIDENCE_SCOPE)
    ):
        raise ContractError("unsupported MLX qualification publication record")
    bindings = _mapping(record["evidence_bindings"], "qualification evidence bindings")
    _keys(bindings, _EVIDENCE_BINDING_FIELDS, "qualification evidence bindings")
    _verify_zero_actions(record["static_action_counters"])
    content = dict(record)
    identity = content.pop("record_id", None)
    if not isinstance(identity, str) or canonical_identity(content) != identity:
        raise ContractError("qualification publication record identity mismatch")
    rebuilt = build_qualification_publication_record()
    if canonical_json(record) != canonical_json(rebuilt):
        raise ContractError("qualification publication semantic reconstruction mismatch")
    if identity != EXPECTED_QUALIFICATION_RECORD_ID:
        raise ContractError("qualification publication differs from expected record identity")
    return dict(record)


def load_qualification_publication_record(path: Path) -> dict[str, JsonValue]:
    """Load and replay one canonical qualification publication record offline."""
    return verify_qualification_publication_record(
        load_canonical_json_file(path, "MLX qualification publication record")
    )


def compile_qualification_publication_record(path: Path) -> dict[str, JsonValue]:
    """Write one deterministic publication record without replacing an existing file."""
    record = build_qualification_publication_record()
    with path.open("xb") as output:
        output.write(canonical_json(record))
        output.flush()
        os.fsync(output.fileno())
    return record


def committed_qualification_publication_record() -> dict[str, JsonValue]:
    """Load the exact committed qualification publication record."""
    return load_qualification_publication_record(COMMITTED_QUALIFICATION_RECORD_PATH)


def qualification_publication_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Return an explicit bounded projection of the replayed static result."""
    record = verify_qualification_publication_record(value)
    assessment = _mapping(record["assessment"], "qualification publication assessment")
    return {
        "record_id": record["record_id"],
        "decision": record["decision"],
        "blockers": record["blockers"],
        "evidence_bindings": record["evidence_bindings"],
        "eligibility_scope": assessment["eligibility_scope"],
        "next_required_step": assessment["next_required_step"],
        "limitations": record["limitations"],
        "receipt_evidence_scope": record["receipt_evidence_scope"],
        "schema_1_0_remains_permanently_disabled": True,
        "static_action_counters": record["static_action_counters"],
        "verification_scope": "current_pinned_registry_bound_static_coherence_only",
    }
