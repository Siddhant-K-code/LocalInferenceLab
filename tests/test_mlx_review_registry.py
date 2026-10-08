"""Independent MLX static-evidence review registry tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_qualification as qualification_module
import localinferencelab.mlx_review_registry as registry_module
import localinferencelab.mlx_wheel_custody as wheel_custody_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_canonical_json_file,
)
from localinferencelab.mlx_preflight_contract import (
    build_runtime_preflight_record_1_1,
    inspect_runtime_preflight_record_1_1,
)
from localinferencelab.mlx_qualification import (
    ELIGIBLE,
    INELIGIBLE,
    build_qualification_record,
    historical_incompatible_qualification_package,
    qualification_inspection,
    synthetic_eligible_qualification_package,
    verify_qualification_record,
)
from localinferencelab.mlx_review_registry import (
    EXPECTED_REVIEW_REGISTRY_ID,
    committed_candidate_review_approval,
    committed_pack_review_approval,
    committed_review_registry_inspection,
    load_committed_review_registry,
    review_registry_spec,
    verify_review_registry,
)
from localinferencelab.mlx_wheel_custody import verify_wheel_evidence_manifest

_APPROVAL_ID = "sha256:03897777a7460b2000b808504268f7654176793181467d2b391468a432837f42"
_SPEC_ID = "sha256:41b3586faa73ddc1d739d300bfd8ff82bfb7219f83e0c24660ed645d59bd9da0"
_EVIDENCE = {
    "candidate_package_id": (
        "sha256:4f87b4678c31c0cd08534c58485e2b242c74936737b8f9c6c96319454ada358d"
    ),
    "candidate_review_anchor_id": (
        "sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f"
    ),
    "predecessor_manifest_anchor_spec_id": (
        "sha256:099dbdf8190330224262ccd352066d49341c30b9a18d1dc0936a7f44c2161386"
    ),
    "qualification_spec_id": (
        "sha256:17d2f62fd4832a224f3bf61c7aa5b9668d05077ed36d56d1bf873fd63f2ac826"
    ),
    "runtime_target_anchor_id": (
        "sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0"
    ),
    "wheel_evidence_manifest_id": (
        "sha256:0c28cc713fe9baabdda8c075f148f23b4d2ebd4525160212d0f538cc907db6b4"
    ),
    "wheel_evidence_pack_receipt_id": (
        "sha256:6eb636208a880f49b7ece6571dd20a5b3465996692683bfa9b8e873a0f68b07c"
    ),
    "wheel_evidence_pack_spec_id": (
        "sha256:969783ae80daffae5451d0009e77d3618ba92756d8adbfdf0cf6aa9c13453761"
    ),
    "worker_api_evidence_anchor_id": (
        "sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd"
    ),
}


def _dict(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    copied = json.loads(canonical_json(value))
    assert isinstance(copied, dict)
    return cast("dict[str, JsonValue]", copied)


def _candidate() -> dict[str, JsonValue]:
    path = Path("evidence/mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json")
    return _dict(load_canonical_json_file(path, "reviewed candidate"))


def _rehash_approval(approval: dict[str, JsonValue]) -> None:
    content = dict(approval)
    content.pop("approval_id", None)
    approval["approval_id"] = canonical_identity(content)


def _rehash_registry(registry: dict[str, JsonValue]) -> None:
    content = dict(registry)
    content.pop("registry_id", None)
    registry["registry_id"] = canonical_identity(content)


def _write_registry(path: Path, registry: dict[str, JsonValue]) -> None:
    path.write_bytes(canonical_json(registry))


def _candidate_binding() -> dict[str, str]:
    return {
        name: value
        for name, value in _EVIDENCE.items()
        if name
        in {
            "candidate_package_id",
            "candidate_review_anchor_id",
            "qualification_spec_id",
            "runtime_target_anchor_id",
            "worker_api_evidence_anchor_id",
        }
    }


def test_committed_registry_binds_every_exact_identity_and_separation() -> None:
    assert review_registry_spec()["spec_id"] == _SPEC_ID
    registry = load_committed_review_registry()
    assert registry["registry_id"] == EXPECTED_REVIEW_REGISTRY_ID
    assert registry["registry_spec_id"] == _SPEC_ID
    approvals = _list(registry["approvals"])
    assert len(approvals) == 1
    approval = _dict(approvals[0])
    assert approval["approval_id"] == _APPROVAL_ID
    assert _dict(approval["evidence"]) == _EVIDENCE
    assert _dict(approval["limits"]) == {
        "backend_or_device_availability_proven": False,
        "candidate_or_manifest_mutation_authorized": False,
        "installation_or_import_success_proven": False,
        "metal_availability_proven": False,
        "model_or_tokenizer_support_proven": False,
        "runtime_executability_proven": False,
        "static_evidence_only": True,
        "stream_synchronization_proven": False,
    }
    assert _dict(approval["promotion"])["final_qualification_record_publication"] == (
        "separate_later_change_required"
    )
    verify_review_registry(registry, EXPECTED_REVIEW_REGISTRY_ID)

    candidate_registry, candidate_approval = committed_candidate_review_approval(
        **_candidate_binding()
    )
    assert candidate_registry["registry_id"] == EXPECTED_REVIEW_REGISTRY_ID
    assert candidate_approval is not None
    assert candidate_approval["approval_id"] == _APPROVAL_ID
    pack_registry, pack_approval = committed_pack_review_approval(**_EVIDENCE)
    assert pack_registry["registry_id"] == EXPECTED_REVIEW_REGISTRY_ID
    assert pack_approval is not None
    assert pack_approval["approval_id"] == _APPROVAL_ID
    inspection = committed_review_registry_inspection()
    assert inspection["final_qualification_record_publication"] == (
        "separate_later_change_required"
    )


def test_exact_registry_clears_both_review_blockers_without_publishing_record() -> None:
    candidate = _candidate()
    candidate_record = build_qualification_record(candidate)
    manifest_value = _dict(
        load_canonical_json_file(
            Path("evidence/mlx-wheel-closure-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json"),
            "wheel closure manifest",
        )
    )
    manifest = verify_wheel_evidence_manifest(
        manifest_value,
        cast("str", manifest_value["manifest_id"]),
    )
    blockers, registry_id, approval_id = wheel_custody_module._pack_record_blockers(  # noqa: SLF001
        candidate,
        candidate_record,
        manifest,
        {"receipt_id": _EVIDENCE["wheel_evidence_pack_receipt_id"]},
    )
    assert blockers == []
    assert registry_id == EXPECTED_REVIEW_REGISTRY_ID
    assert approval_id == _APPROVAL_ID

    wrong_receipt = {"receipt_id": "sha256:" + ("f" * 64)}
    blockers, _registry_id, approval_id = wheel_custody_module._pack_record_blockers(  # noqa: SLF001
        candidate,
        candidate_record,
        manifest,
        wrong_receipt,
    )
    assert blockers == [
        "wheel_evidence_manifest_anchor_not_independently_reviewed:"
        + _EVIDENCE["wheel_evidence_manifest_id"]
    ]
    assert approval_id is None


@pytest.mark.parametrize("field", sorted(_EVIDENCE))
def test_any_wrong_evidence_identity_prevents_registry_approval(field: str) -> None:
    values = dict(_EVIDENCE)
    values[field] = "sha256:" + ("f" * 64)
    _registry, approval = committed_pack_review_approval(**values)
    assert approval is None
    if field in _candidate_binding():
        candidate_values = _candidate_binding()
        candidate_values[field] = values[field]
        _candidate_registry, candidate_approval = committed_candidate_review_approval(
            **candidate_values
        )
        assert candidate_approval is None


def test_caller_supplied_rehashed_registry_cannot_influence_eligibility() -> None:
    forged = _copy(load_committed_review_registry())
    approval = _dict(_list(forged["approvals"])[0])
    _dict(approval["evidence"])["candidate_package_id"] = "sha256:" + ("c" * 64)
    _rehash_approval(approval)
    _rehash_registry(forged)
    forged_id = cast("str", forged["registry_id"])
    verify_review_registry(forged, forged_id)

    record = build_qualification_record(_candidate())
    assert record["review_registry_id"] == EXPECTED_REVIEW_REGISTRY_ID
    assert record["review_approval_id"] == _APPROVAL_ID

    mutated_candidate = _candidate()
    mutated_candidate["candidate_name"] = "same-change-mutated-candidate"
    candidate_content = dict(mutated_candidate)
    candidate_content.pop("package_id")
    mutated_candidate["package_id"] = canonical_identity(candidate_content)
    mutated_record = build_qualification_record(mutated_candidate)
    mutated_assessment = _dict(mutated_record["assessment"])
    assert mutated_record["review_approval_id"] is None
    assert (
        f"reviewed_candidate_not_approved_by_registry:{mutated_assessment['review_anchor_id']}"
    ) in _list(mutated_record["blockers"])


def test_rehashed_manifest_and_coordinated_registry_remain_unapproved() -> None:
    manifest = _dict(
        load_canonical_json_file(
            Path("evidence/mlx-wheel-closure-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json"),
            "wheel closure manifest",
        )
    )
    forged_manifest = _copy(manifest)
    _dict(forged_manifest["selection_policy"])["acquired_at_utc"] = "2026-10-07T00:00:01Z"
    manifest_content = dict(forged_manifest)
    manifest_content.pop("manifest_id")
    forged_manifest["manifest_id"] = canonical_identity(manifest_content)
    forged_manifest_id = cast("str", forged_manifest["manifest_id"])
    verify_wheel_evidence_manifest(forged_manifest, forged_manifest_id)

    values = dict(_EVIDENCE)
    values["wheel_evidence_manifest_id"] = forged_manifest_id
    _registry, approval = committed_pack_review_approval(**values)
    assert approval is None

    coordinated = _copy(load_committed_review_registry())
    coordinated_approval = _dict(_list(coordinated["approvals"])[0])
    _dict(coordinated_approval["evidence"])["wheel_evidence_manifest_id"] = forged_manifest_id
    _rehash_approval(coordinated_approval)
    _rehash_registry(coordinated)
    verify_review_registry(coordinated, cast("str", coordinated["registry_id"]))
    _registry, approval = committed_pack_review_approval(**values)
    assert approval is None


def test_registry_absence_substitution_and_rollback_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing = tmp_path / "missing.json"
    monkeypatch.setattr(registry_module, "COMMITTED_REVIEW_REGISTRY_PATH", missing)
    with pytest.raises(ContractError, match="unavailable"):
        load_committed_review_registry()

    committed = _copy(
        load_canonical_json_file(
            Path("evidence/mlx-static-evidence-review-registry-v1.json"),
            "committed review registry",
        )
    )
    with pytest.raises(ContractError, match="differs from expected"):
        verify_review_registry(committed, "sha256:" + ("0" * 64))

    substituted = _copy(committed)
    substituted["registry_version"] = 2
    _rehash_registry(substituted)
    substituted_path = tmp_path / "substituted.json"
    _write_registry(substituted_path, substituted)
    monkeypatch.setattr(registry_module, "COMMITTED_REVIEW_REGISTRY_PATH", substituted_path)
    with pytest.raises(ContractError, match=r"unsupported|differs from expected"):
        load_committed_review_registry()


def test_registry_rejects_duplicate_self_referential_and_malformed_entries() -> None:
    duplicate = _copy(load_committed_review_registry())
    duplicate["approvals"] = [
        _copy(_list(duplicate["approvals"])[0]),
        _copy(_list(duplicate["approvals"])[0]),
    ]
    _rehash_registry(duplicate)
    with pytest.raises(ContractError, match="unique and sorted"):
        verify_review_registry(duplicate, cast("str", duplicate["registry_id"]))

    self_referential = _copy(load_committed_review_registry())
    approval = _dict(_list(self_referential["approvals"])[0])
    _dict(approval["evidence"])["registry_id"] = self_referential["registry_id"]
    _rehash_approval(approval)
    _rehash_registry(self_referential)
    with pytest.raises(ContractError, match="unknown keys"):
        verify_review_registry(
            self_referential,
            cast("str", self_referential["registry_id"]),
        )

    boolean_version = _copy(load_committed_review_registry())
    boolean_version["registry_version"] = True
    _rehash_registry(boolean_version)
    with pytest.raises(ContractError, match="must be an integer"):
        verify_review_registry(boolean_version, cast("str", boolean_version["registry_id"]))

    boolean_counter = _copy(load_committed_review_registry())
    approval = _dict(_list(boolean_counter["approvals"])[0])
    _dict(approval["static_action_counters"])["package_installations"] = False
    _rehash_approval(approval)
    _rehash_registry(boolean_counter)
    with pytest.raises(ContractError, match="must be an integer"):
        verify_review_registry(boolean_counter, cast("str", boolean_counter["registry_id"]))


def test_registry_change_after_record_construction_invalidates_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = build_qualification_record(_candidate())
    future = _copy(load_committed_review_registry())
    second = _copy(_list(future["approvals"])[0])
    second_evidence = _dict(second["evidence"])
    for index, name in enumerate(sorted(second_evidence), start=1):
        second_evidence[name] = f"sha256:{index:064x}"
    _rehash_approval(second)
    approvals = [_dict(_list(future["approvals"])[0]), second]
    future["approvals"] = cast(
        "list[JsonValue]",
        sorted(approvals, key=lambda item: cast("str", item["approval_id"])),
    )
    _rehash_registry(future)
    future_path = tmp_path / "future.json"
    _write_registry(future_path, future)
    monkeypatch.setattr(registry_module, "COMMITTED_REVIEW_REGISTRY_PATH", future_path)
    monkeypatch.setattr(
        registry_module,
        "EXPECTED_REVIEW_REGISTRY_ID",
        cast("str", future["registry_id"]),
    )
    verify_review_registry(future, cast("str", future["registry_id"]))
    with pytest.raises(ContractError, match="semantic reconstruction mismatch"):
        verify_qualification_record(record)


def test_exact_base_reviewed_record_replays_but_is_nonpromotable() -> None:
    reviewed = qualification_module._build_legacy_qualification_record(  # noqa: SLF001
        _candidate()
    )
    assert reviewed["record_id"] == (
        "sha256:968f4bf20c15f97503ad5f7d3a95025bc40f0f787bf63b4c59d16e0d7d25ded3"
    )
    assert digest_bytes(canonical_json(reviewed)) == (
        "sha256:a6c92d3005dfe9f92cf17ae8f0eddbab0bb680b92938d6dc59bd206ad323bc8b"
    )
    assert verify_qualification_record(reviewed) == reviewed
    inspection = qualification_inspection(reviewed)
    assert inspection["verification_scope"] == "verified_historical_replay_non_promotable"
    assert inspection["current_registry_policy_bound"] is False
    assert inspection["review_registry_id"] is None
    assert inspection["review_approval_id"] is None
    assert reviewed["decision"] == INELIGIBLE
    assert (
        "reviewed_candidate_not_committed_in_spec:"
        "sha256:1382dfd5e9f5d19bfa74c8f3a7ad4db5b30d10caddfed3cd62c130242003f45f"
    ) in _list(reviewed["blockers"])

    current_preflight = inspect_runtime_preflight_record_1_1(
        build_runtime_preflight_record_1_1(reviewed)
    )
    assert current_preflight["verification_scope"] == "current_registry_policy"
    assert current_preflight["prerequisites_satisfied"] is False
    assert "qualification_review_registry_is_not_exact" in _list(current_preflight["blockers"])


def test_qualification_record_version_confusion_and_fallback_fail_closed() -> None:
    current = build_qualification_record(_candidate())

    stripped = _copy(current)
    stripped.pop("review_registry_id")
    _rehash_record_content = dict(stripped)
    _rehash_record_content.pop("record_id")
    stripped["record_id"] = canonical_identity(_rehash_record_content)
    with pytest.raises(ContractError, match="missing keys"):
        verify_qualification_record(stripped)

    malformed_legacy = _copy(current)
    malformed_legacy.pop("review_registry_id")
    malformed_legacy.pop("review_approval_id")
    assessment = _dict(malformed_legacy["assessment"])
    assessment.pop("review_registry_id")
    assessment.pop("review_approval_id")
    content = dict(malformed_legacy)
    content.pop("record_id")
    malformed_legacy["record_id"] = canonical_identity(content)
    with pytest.raises(ContractError, match="semantic reconstruction mismatch"):
        verify_qualification_record(malformed_legacy)

    legacy = qualification_module._build_legacy_qualification_record(  # noqa: SLF001
        _candidate()
    )
    extra = _copy(legacy)
    extra["legacy_policy_version"] = "deb58ee"
    content = dict(extra)
    content.pop("record_id")
    extra["record_id"] = canonical_identity(content)
    with pytest.raises(ContractError, match="unknown keys"):
        verify_qualification_record(extra)

    coordinated = _copy(legacy)
    coordinated["decision"] = ELIGIBLE
    coordinated["blockers"] = []
    _dict(coordinated["assessment"])["decision"] = ELIGIBLE
    _dict(coordinated["assessment"])["blockers"] = []
    content = dict(coordinated)
    content.pop("record_id")
    coordinated["record_id"] = canonical_identity(content)
    with pytest.raises(ContractError, match="semantic reconstruction mismatch"):
        verify_qualification_record(coordinated)

    historical = build_qualification_record(historical_incompatible_qualification_package())
    synthetic = build_qualification_record(synthetic_eligible_qualification_package())
    assert verify_qualification_record(historical)["decision"] == INELIGIBLE
    assert verify_qualification_record(synthetic)["decision"] == ELIGIBLE
    assert "review_registry_id" not in historical
    assert "review_registry_id" not in synthetic

    synthetic_preflight = inspect_runtime_preflight_record_1_1(
        build_runtime_preflight_record_1_1(synthetic)
    )
    assert synthetic_preflight["prerequisites_satisfied"] is False
    assert "qualification_candidate_is_not_reviewed_real_candidate" in _list(
        synthetic_preflight["blockers"]
    )
    assert "qualification_review_registry_is_not_exact" in _list(synthetic_preflight["blockers"])


def test_no_final_eligible_qualification_record_is_published_with_registry() -> None:
    candidate_record = build_qualification_record(_candidate())
    assert candidate_record["decision"] == INELIGIBLE
    assert not any(
        path.name.endswith("-qualification-record.json") for path in Path("evidence").iterdir()
    )
