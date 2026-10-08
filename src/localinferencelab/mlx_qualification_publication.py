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
from localinferencelab.mlx_qualification import (
    ELIGIBLE,
    INELIGIBLE,
    verify_qualification_package,
)
from localinferencelab.mlx_review_registry import (
    EXPECTED_REVIEW_REGISTRY_ID,
    committed_pack_review_approval,
    review_registry_spec,
)
from localinferencelab.mlx_wheel_custody import (
    build_supplied_pack_qualification_record,
    verify_wheel_evidence_manifest,
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
EXPECTED_WHEEL_EVIDENCE_MANIFEST_ANCHOR_SPEC_ID = (
    "sha256:099dbdf8190330224262ccd352066d49341c30b9a18d1dc0936a7f44c2161386"
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
    "sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df"
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
    "pack_bytes_not_reverified_during_offline_replay": True,
    "publication_compilation_requires_exact_supplied_pack": True,
    "record_or_manifest_proves_current_wheel_bytes_present": False,
    "wheel_bytes_embedded_in_record": False,
}
_EXPECTED_PRIOR_PACK_RECEIPT: dict[str, JsonValue] = {
    "artifact_count": 34,
    "committed_manifest_alone_proves_supplied_bytes_present": False,
    "manifest_id": EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
    "network_actions": 0,
    "pack_spec_id": EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID,
    "package_installations": 0,
    "process_starts": 0,
    "receipt_id": EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
    "record_type": "mlx_wheel_evidence_pack_verification_receipt",
    "runtime_imports": 0,
    "schema_version": SCHEMA_VERSION,
    "supplied_pack_verified": True,
    "total_size_bytes": 70_700_189,
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


def _expected_bindings() -> dict[str, JsonValue]:
    return {
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


def _verify_prior_pack_receipt(value: JsonValue) -> dict[str, JsonValue]:
    receipt = _mapping(value, "qualification publication prior pack receipt")
    if canonical_json(receipt) != canonical_json(_EXPECTED_PRIOR_PACK_RECEIPT):
        raise ContractError("qualification publication prior pack receipt differs from approval")
    content = dict(receipt)
    identity = content.pop("receipt_id")
    if identity != canonical_identity(content):
        raise ContractError("qualification publication prior pack receipt identity mismatch")
    return dict(receipt)


def _publication_record(
    *,
    closure: JsonValue,
    receipt: dict[str, JsonValue],
    blockers: list[JsonValue],
    decision: JsonValue,
) -> dict[str, JsonValue]:
    if blockers != sorted(set(cast("list[str]", blockers))):
        raise ContractError("qualification publication blockers must be unique and sorted")
    if decision not in {ELIGIBLE, INELIGIBLE} or (decision == ELIGIBLE) != (not blockers):
        raise ContractError("qualification publication decision does not match blockers")
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_qualification_publication_record",
        "schema_version": SCHEMA_VERSION,
        "evidence_bindings": _expected_bindings(),
        "pack_verification": receipt,
        "assessment": {
            "blockers": blockers,
            "closure": closure,
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


def build_qualification_publication_record(pack_root: Path) -> dict[str, JsonValue]:
    """Build the publication only after direct exact supplied-pack verification."""
    candidate, manifest = _load_committed_evidence()
    supplied_pack_record = build_supplied_pack_qualification_record(
        candidate,
        manifest,
        pack_root,
        EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
    )
    receipt = _verify_prior_pack_receipt(supplied_pack_record["pack_verification"])
    assessment = _mapping(supplied_pack_record["assessment"], "supplied pack assessment")
    bindings = {
        "candidate_package_id": _mapping(
            supplied_pack_record["candidate_anchor"],
            "supplied pack candidate anchor",
        )["package_id"],
        "candidate_review_anchor_id": assessment["review_anchor_id"],
        "qualification_spec_id": supplied_pack_record["qualification_spec_id"],
        "review_approval_id": supplied_pack_record["review_approval_id"],
        "review_registry_id": supplied_pack_record["review_registry_id"],
        "review_registry_spec_id": review_registry_spec()["spec_id"],
        "runtime_target_anchor_id": _mapping(
            candidate["target_environment"],
            "candidate target",
        )["runtime_target_anchor_id"],
        "wheel_evidence_manifest_id": supplied_pack_record["wheel_evidence_manifest_id"],
        "wheel_evidence_pack_receipt_id": receipt["receipt_id"],
        "wheel_evidence_pack_spec_id": supplied_pack_record["wheel_evidence_pack_spec_id"],
        "worker_api_evidence_anchor_id": candidate["worker_api_evidence_anchor_id"],
    }
    if canonical_json(bindings) != canonical_json(_expected_bindings()):
        raise ContractError("qualification publication evidence binding drift")
    record = _publication_record(
        closure=assessment["closure"],
        receipt=receipt,
        blockers=cast("list[JsonValue]", supplied_pack_record["blockers"]),
        decision=supplied_pack_record["decision"],
    )
    if record["record_id"] != EXPECTED_QUALIFICATION_RECORD_ID:
        raise ContractError("compiled qualification publication identity drift")
    return record


def verify_qualification_publication_record(value: JsonValue) -> dict[str, JsonValue]:
    """Replay the immutable publication offline without claiming pack reverification."""
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
    if canonical_json(bindings) != canonical_json(_expected_bindings()):
        raise ContractError("qualification publication evidence binding drift")
    receipt = _verify_prior_pack_receipt(record["pack_verification"])
    if bindings["wheel_evidence_pack_receipt_id"] != receipt["receipt_id"]:
        raise ContractError("qualification publication receipt binding drift")
    _verify_zero_actions(record["static_action_counters"])
    content = dict(record)
    identity = content.pop("record_id", None)
    if not isinstance(identity, str) or canonical_identity(content) != identity:
        raise ContractError("qualification publication record identity mismatch")
    if identity != EXPECTED_QUALIFICATION_RECORD_ID:
        raise ContractError("qualification publication differs from expected record identity")

    candidate_value, manifest_value = _load_committed_evidence()
    candidate = verify_qualification_package(candidate_value)
    manifest = verify_wheel_evidence_manifest(
        manifest_value,
        EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
    )
    target = _mapping(candidate["target_environment"], "candidate target")
    manifest_candidate = _mapping(manifest["candidate_anchor"], "manifest candidate anchor")
    if (
        candidate["package_id"] != EXPECTED_CANDIDATE_PACKAGE_ID
        or candidate["qualification_spec_id"] != EXPECTED_QUALIFICATION_SPEC_ID
        or candidate["worker_api_evidence_anchor_id"] != EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID
        or target["runtime_target_anchor_id"] != EXPECTED_RUNTIME_TARGET_ANCHOR_ID
        or manifest_candidate["review_anchor_id"] != EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID
        or manifest_candidate["package_id"] != EXPECTED_CANDIDATE_PACKAGE_ID
    ):
        raise ContractError("qualification publication committed evidence drift")
    registry, approval = committed_pack_review_approval(
        candidate_package_id=EXPECTED_CANDIDATE_PACKAGE_ID,
        candidate_review_anchor_id=EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID,
        predecessor_manifest_anchor_spec_id=EXPECTED_WHEEL_EVIDENCE_MANIFEST_ANCHOR_SPEC_ID,
        qualification_spec_id=EXPECTED_QUALIFICATION_SPEC_ID,
        runtime_target_anchor_id=EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        wheel_evidence_manifest_id=EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        wheel_evidence_pack_receipt_id=EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
        wheel_evidence_pack_spec_id=EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID,
        worker_api_evidence_anchor_id=EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
    )
    if (
        registry["registry_id"] != EXPECTED_REVIEW_REGISTRY_ID
        or approval is None
        or approval["approval_id"] != EXPECTED_REVIEW_APPROVAL_ID
    ):
        raise ContractError("qualification publication pinned approval is unavailable")
    assessment = _mapping(record["assessment"], "qualification publication assessment")
    if (
        canonical_json(assessment["closure"]) != canonical_json(manifest["closure"])
        or assessment["decision"] != record["decision"]
        or assessment["blockers"] != record["blockers"]
        or record["decision"] != ELIGIBLE
        or record["blockers"] != []
    ):
        raise ContractError("qualification publication assessment drift")
    return dict(record)


def load_qualification_publication_record(path: Path) -> dict[str, JsonValue]:
    """Load and replay one canonical qualification publication record offline."""
    return verify_qualification_publication_record(
        load_canonical_json_file(path, "MLX qualification publication record")
    )


def compile_qualification_publication_record(
    pack_root: Path,
    path: Path,
) -> dict[str, JsonValue]:
    """Verify the exact supplied pack and write one deterministic publication."""
    record = build_qualification_publication_record(pack_root)
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
        "verification_scope": "current_pinned_publication_prior_pack_attestation_offline",
    }
