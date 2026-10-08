"""Final registry-bound MLX qualification publication tests."""

from __future__ import annotations

import inspect
import json
import socket
import subprocess
import urllib.request
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_qualification_publication as publication_module
import localinferencelab.mlx_review_registry as registry_module
import localinferencelab.mlx_wheel_custody as wheel_custody_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_canonical_json_file,
)
from localinferencelab.cli import run
from localinferencelab.mlx_qualification import (
    build_qualification_record,
    historical_incompatible_qualification_package,
)
from localinferencelab.mlx_qualification_publication import (
    EXPECTED_QUALIFICATION_RECORD_ID,
    EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
    build_qualification_publication_record,
    committed_qualification_publication_record,
    compile_qualification_publication_record,
    qualification_publication_inspection,
    verify_qualification_publication_record,
)
from localinferencelab.mlx_wheel_custody import build_supplied_pack_qualification_record

_RECORD_PATH = Path(
    "evidence/mlx-runtime-qualification-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json"
)
_CANDIDATE_PATH = Path("evidence/mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json")
_MANIFEST_PATH = Path(
    "evidence/mlx-wheel-closure-mlx-0.30.4-mlx-lm-0.30.6-macos-arm64-py313-v1.json"
)


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


def _rehash(value: dict[str, JsonValue], identity_field: str) -> None:
    content = dict(value)
    content.pop(identity_field, None)
    value[identity_field] = canonical_identity(content)


def test_exact_committed_record_bytes_identity_decision_and_bindings() -> None:
    raw = _RECORD_PATH.read_bytes()
    record = committed_qualification_publication_record()
    assert raw == canonical_json(record)
    assert record["record_id"] == EXPECTED_QUALIFICATION_RECORD_ID
    assert record["decision"] == "eligible_for_new_observed_authorization"
    assert record["blockers"] == []
    inspection = qualification_publication_inspection(record)
    assert inspection["verification_scope"] == (
        "current_pinned_publication_prior_pack_attestation_offline"
    )
    scope = _dict(inspection["receipt_evidence_scope"])
    assert scope["pack_bytes_not_reverified_during_offline_replay"] is True
    assert scope["publication_compilation_requires_exact_supplied_pack"] is True
    assert scope["record_or_manifest_proves_current_wheel_bytes_present"] is False
    assert inspection["limitations"] == {
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


def test_aggregate_only_receipt_constructors_are_absent() -> None:
    assert not hasattr(wheel_custody_module, "reconstruct_reviewed_pack_receipt")
    assert not hasattr(wheel_custody_module, "verify_reviewed_pack_receipt")
    assert not hasattr(wheel_custody_module, "_wheel_evidence_pack_receipt")
    assert not hasattr(wheel_custody_module, "build_reviewed_pack_qualification_assessment")


def test_real_publication_compiler_requires_explicit_pack_root() -> None:
    assert tuple(inspect.signature(build_qualification_publication_record).parameters) == (
        "pack_root",
    )
    assert tuple(inspect.signature(compile_qualification_publication_record).parameters) == (
        "pack_root",
        "path",
    )
    assert tuple(inspect.signature(verify_qualification_publication_record).parameters) == (
        "value",
    )


def test_missing_or_empty_pack_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="supplied wheel pack root"):
        build_qualification_publication_record(tmp_path / "missing-pack")
    with pytest.raises(ContractError, match="supplied wheel pack root"):
        run(
            [
                "mlx",
                "runtime-qualification-publication-compile",
                str(tmp_path / "missing-pack"),
                str(tmp_path / "record.json"),
            ]
        )
    empty_pack = tmp_path / "empty-pack"
    empty_pack.mkdir()
    with pytest.raises(ContractError, match="member set mismatch"):
        build_qualification_publication_record(empty_pack)


def test_exact_manifest_aggregates_with_substituted_files_fail_closed(tmp_path: Path) -> None:
    manifest = _dict(load_canonical_json_file(_MANIFEST_PATH, "manifest"))
    pack = tmp_path / "pack"
    pack.mkdir()
    for item in _list(manifest["distributions"]):
        distribution = _dict(item)
        artifact = _dict(distribution["artifact"])
        (pack / cast("str", artifact["filename"])).write_bytes(b"substituted")
    with pytest.raises(ContractError, match=r"size mismatch|digest mismatch"):
        build_qualification_publication_record(pack)


def test_real_compiler_calls_physical_pack_verifier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class VerifierReachedError(RuntimeError):
        pass

    def reached(*_args: object, **_kwargs: object) -> None:
        raise VerifierReachedError

    monkeypatch.setattr(wheel_custody_module, "verify_supplied_wheel_pack", reached)
    with pytest.raises(VerifierReachedError):
        build_qualification_publication_record(tmp_path)


@pytest.mark.parametrize(
    "field",
    [
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
    ],
)
def test_any_record_evidence_binding_drift_fails_closed(field: str) -> None:
    record = _copy(committed_qualification_publication_record())
    _dict(record["evidence_bindings"])[field] = "sha256:" + ("f" * 64)
    _rehash(record, "record_id")
    with pytest.raises(ContractError, match=r"evidence binding drift|expected record identity"):
        verify_qualification_publication_record(record)


def test_fabricated_success_receipt_and_caller_boolean_fail_closed() -> None:
    record = _copy(committed_qualification_publication_record())
    receipt = _dict(record["pack_verification"])
    receipt["total_size_bytes"] = 70_700_188
    receipt["supplied_pack_verified"] = True
    receipt_content = dict(receipt)
    receipt_content.pop("receipt_id")
    receipt["receipt_id"] = canonical_identity(receipt_content)
    _rehash(record, "record_id")
    with pytest.raises(ContractError, match="prior pack receipt differs from approval"):
        verify_qualification_publication_record(record)

    boolean_counter = _copy(committed_qualification_publication_record())
    _dict(boolean_counter["static_action_counters"])["process_starts"] = False
    _rehash(boolean_counter, "record_id")
    with pytest.raises(ContractError, match="integer zero"):
        verify_qualification_publication_record(boolean_counter)


def test_coordinated_record_rehash_and_legacy_promotion_fail_closed() -> None:
    coordinated = _copy(committed_qualification_publication_record())
    coordinated["decision"] = "ineligible"
    coordinated["blockers"] = ["caller_selected_blocker"]
    assessment = _dict(coordinated["assessment"])
    assessment["decision"] = "ineligible"
    assessment["blockers"] = ["caller_selected_blocker"]
    _rehash(coordinated, "record_id")
    with pytest.raises(ContractError, match="expected record identity"):
        verify_qualification_publication_record(coordinated)

    legacy = build_qualification_record(historical_incompatible_qualification_package())
    with pytest.raises(ContractError, match=r"missing keys|unknown keys"):
        verify_qualification_publication_record(legacy)


def test_stale_or_coordinated_registry_cannot_replace_pinned_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = _copy(registry_module.load_committed_review_registry())
    registry["registry_version"] = 2
    _rehash(registry, "registry_id")
    path = tmp_path / "stale-registry.json"
    path.write_bytes(canonical_json(registry))
    monkeypatch.setattr(registry_module, "COMMITTED_REVIEW_REGISTRY_PATH", path)
    monkeypatch.setattr(
        registry_module,
        "EXPECTED_REVIEW_REGISTRY_ID",
        cast("str", registry["registry_id"]),
    )
    with pytest.raises(ContractError, match="unsupported"):
        verify_qualification_publication_record(
            load_canonical_json_file(_RECORD_PATH, "publication record")
        )


def test_candidate_and_manifest_artifact_drift_fail_against_fixed_identities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _copy(load_canonical_json_file(_CANDIDATE_PATH, "candidate"))
    candidate["candidate_name"] = "coordinated-rehash"
    _rehash(candidate, "package_id")
    candidate_path = tmp_path / "candidate.json"
    candidate_path.write_bytes(canonical_json(candidate))
    monkeypatch.setattr(publication_module, "COMMITTED_CANDIDATE_PATH", candidate_path)
    with pytest.raises(ContractError):
        verify_qualification_publication_record(
            load_canonical_json_file(_RECORD_PATH, "publication record")
        )

    monkeypatch.setattr(publication_module, "COMMITTED_CANDIDATE_PATH", _CANDIDATE_PATH)
    manifest = _copy(load_canonical_json_file(_MANIFEST_PATH, "manifest"))
    _dict(manifest["selection_policy"])["acquired_at_utc"] = "2026-10-07T00:00:01Z"
    _rehash(manifest, "manifest_id")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    monkeypatch.setattr(publication_module, "COMMITTED_MANIFEST_PATH", manifest_path)
    with pytest.raises(ContractError, match="expected content address"):
        verify_qualification_publication_record(
            load_canonical_json_file(_RECORD_PATH, "publication record")
        )


def test_offline_replay_cannot_compile_mint_or_touch_physical_surfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("physical or compilation action attempted")

    monkeypatch.setattr(wheel_custody_module, "verify_supplied_wheel_pack", forbidden)
    monkeypatch.setattr(publication_module, "build_supplied_pack_qualification_record", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    record = verify_qualification_publication_record(
        load_canonical_json_file(_RECORD_PATH, "qualification publication")
    )
    scope = _dict(record["receipt_evidence_scope"])
    assert scope["pack_bytes_not_reverified_during_offline_replay"] is True
    assert scope["offline_record_replay_requires_supplied_pack"] is False


def test_cli_replays_committed_record_offline(
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert run(["mlx", "runtime-qualification-publication-replay", str(_RECORD_PATH)]) == 0
    output = json.loads(capfd.readouterr().out)
    assert output["status"] == "replayed"
    assert output["decision"] == "eligible_for_new_observed_authorization"
    assert output["blockers"] == []
    assert output["receipt_evidence_scope"]["pack_bytes_not_reverified_during_offline_replay"]


def test_generic_supplied_pack_builder_still_requires_pack(tmp_path: Path) -> None:
    candidate = load_canonical_json_file(_CANDIDATE_PATH, "candidate")
    manifest = load_canonical_json_file(_MANIFEST_PATH, "manifest")
    with pytest.raises(ContractError, match="supplied wheel pack root"):
        build_supplied_pack_qualification_record(
            candidate,
            manifest,
            tmp_path / "missing-pack",
            EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        )
