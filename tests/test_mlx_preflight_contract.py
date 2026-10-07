"""Schema-1.1 model-free runtime-preflight contract tests."""

from __future__ import annotations

import ast
import importlib
import json
import os
import socket
import subprocess
import urllib.request
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_custody as custody_module
import localinferencelab.mlx_preflight_contract as contract_module
import localinferencelab.mlx_runtime_preflight as preflight_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_json_bytes,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_preflight_contract import (
    ACTION,
    AUTHORIZATION_LIFETIME_NS,
    build_runtime_preflight_record_1_1,
    compile_runtime_preflight_fixture_1_1,
    inspect_runtime_preflight_record_1_1,
    load_runtime_preflight_record_1_1,
    replay_runtime_preflight_fixture_1_1,
    runtime_preflight_capability_report_1_1,
    runtime_preflight_protocol_1_1,
    runtime_preflight_spec_1_1,
    verify_observed_authorization_1_1,
    verify_runtime_preflight_record_1_1,
    write_runtime_preflight_record_1_1,
)
from localinferencelab.mlx_qualification import (
    ELIGIBLE,
    build_qualification_record,
    historical_incompatible_qualification_package,
    qualification_spec,
    synthetic_eligible_qualification_package,
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


def _qualification(candidate: str = "synthetic") -> dict[str, JsonValue]:
    package = (
        synthetic_eligible_qualification_package()
        if candidate == "synthetic"
        else historical_incompatible_qualification_package()
    )
    return build_qualification_record(package)


def _authorization(
    qualification: dict[str, JsonValue],
    *,
    issued_at: int = 1_000_000_000,
) -> dict[str, JsonValue]:
    assessment = _dict(qualification["assessment"])
    spec = runtime_preflight_spec_1_1()
    value: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_observed_authorization",
        "schema_version": "1.1",
        "evidence_kind": "observed_explicit_authorization",
        "action": ACTION,
        "explicit_decision": "authorize_once",
        "one_shot": True,
        "consumption_state": "fresh_unconsumed",
        "qualification_record_id": qualification["record_id"],
        "qualification_review_anchor_id": assessment["review_anchor_id"],
        "nonce_sha256": "sha256:" + ("1" * 64),
        "output_root_id": "sha256:" + ("2" * 64),
        "spec_id": spec["spec_id"],
        "protocol_id": spec["protocol_id"],
        "issued_at_unix_ns": issued_at,
        "observed_at_unix_ns": issued_at + 1,
        "expires_at_unix_ns": issued_at + AUTHORIZATION_LIFETIME_NS,
        "synchronization_canary_authorized": False,
    }
    value["authorization_id"] = canonical_identity(value)
    return value


def _rehash(value: dict[str, JsonValue], identity_field: str) -> None:
    content = dict(value)
    content.pop(identity_field, None)
    value[identity_field] = canonical_identity(content)


def test_spec_protocol_and_capability_keep_execution_unreachable() -> None:
    protocol = runtime_preflight_protocol_1_1()
    spec = runtime_preflight_spec_1_1()
    report = runtime_preflight_capability_report_1_1()
    assert protocol["schema_version"] == "1.1"
    assert spec["schema_version"] == "1.1"
    assert spec["protocol_id"] == protocol["protocol_id"]
    assert spec["qualification_spec_id"] == qualification_spec()["spec_id"]
    assert _dict(spec["execution"]) == {
        "authorization_consumer_present": False,
        "authorization_creator_present": False,
        "becomes_reachable_when_prerequisites_satisfied": False,
        "implementation_present": False,
        "package_retrieval_or_installation_present": False,
        "public_or_internal_execute_entrypoint_present": False,
        "reachable": False,
        "worker_present": False,
    }
    assert protocol["worker_implementation_present"] is False
    assert protocol["execution_command_present"] is False
    assert report["execution_reachable"] is False
    assert report["execute_command_present"] is False
    assert report["physical_actions"] == 0
    assert not any("execute" in cast("str", item) for item in _list(report["pure_commands"]))


def test_future_action_contract_is_narrow_and_truthful() -> None:
    protocol = runtime_preflight_protocol_1_1()
    allowed = _list(protocol["base_allowed_physical_actions"])
    assert allowed == sorted(allowed)
    assert allowed == [
        "default_device_metadata_query",
        "default_stream_metadata_query",
        "distribution_version_query",
        "isolated_runtime_closure_verification",
        "metal_availability_metadata_query",
        "mlx_core_import",
        "mlx_lm_import",
    ]
    conditional = _dict(protocol["conditional_physical_action"])
    assert conditional["action"] == "single_default_stream_synchronization_canary"
    assert conditional["maximum"] == 1
    assert conditional["requires_distinct_explicit_one_shot_authorization"] is True
    imports = _dict(protocol["imports"])
    assert imports["allowed"] == ["mlx.core", "mlx_lm"]
    assert imports["import_before_authorization"] is False
    assert _dict(protocol["metadata_bounds"]) == {
        "distribution_records": 2,
        "imported_module_records": 4096,
        "representation_utf8_bytes_each": 256,
        "values": "canonical_json_only",
    }
    forbidden = _list(protocol["forbidden_actions"])
    assert "model_load" in forbidden
    assert "tensor_allocation_or_operation" in forbidden
    ledgers = _dict(protocol["result_ledgers"])
    assert set(ledgers) == {
        "accepted_evidence",
        "attempted_actions",
        "completed_actions",
        "ledgers_are_disjoint_claim_scopes",
    }
    audit = _dict(protocol["audit_hooks"])
    assert audit["os_sandbox"] is False
    assert audit["proof_of_non_occurrence"] is False


def test_module_has_no_physical_runtime_surface() -> None:
    module_path = Path(contract_module.__file__).resolve(strict=True)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported_roots & {
        "importlib",
        "mlx",
        "mlx_lm",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called_names & {"exec", "eval"}
    assert not called_attributes & {
        "default_device",
        "default_stream",
        "import_module",
        "metal",
        "posix_spawn",
        "socketpair",
        "synchronize",
    }


def test_synthetic_positive_and_historical_records_cannot_satisfy_prerequisites() -> None:
    synthetic = _qualification()
    assert synthetic["decision"] == ELIGIBLE
    synthetic_record = build_runtime_preflight_record_1_1(
        synthetic,
        _authorization(synthetic),
    )
    synthetic_inspection = inspect_runtime_preflight_record_1_1(synthetic_record)
    assert synthetic_inspection["prerequisites_satisfied"] is False
    assert "qualification_candidate_is_not_reviewed_real_candidate" in _list(
        synthetic_inspection["blockers"]
    )
    assert any(
        cast("str", blocker).startswith("qualification_review_anchor_not_committed:")
        for blocker in _list(synthetic_inspection["blockers"])
    )

    historical = _qualification("historical")
    historical_record = build_runtime_preflight_record_1_1(
        historical,
        _authorization(historical),
    )
    historical_inspection = inspect_runtime_preflight_record_1_1(historical_record)
    assert historical_inspection["prerequisites_satisfied"] is False
    assert "qualification_candidate_is_not_reviewed_real_candidate" in _list(
        historical_inspection["blockers"]
    )
    assert "qualification_decision_is_not_eligible" in _list(historical_inspection["blockers"])
    assert qualification_spec()["reviewed_candidate_anchors"] == []


def test_missing_authorization_refuses_without_creating_or_consuming_one() -> None:
    record = build_runtime_preflight_record_1_1(_qualification())
    inspection = inspect_runtime_preflight_record_1_1(record)
    assert inspection["authorization_id"] is None
    assert "fresh_observed_one_shot_authorization_missing" in _list(inspection["blockers"])
    assert inspection["execution_state"] == "disabled_unreachable_contract_only"
    assert inspection["schema_1_0_state"] == "permanently_disabled"
    assert inspection["attempted_actions"] == []
    assert inspection["completed_actions"] == []
    assert inspection["accepted_evidence"] == []
    assert set(_dict(inspection["static_action_counters"]).values()) == {0}


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("evidence_kind", "synthetic_fixture", "unsupported"),
        ("one_shot", 1, "unsupported"),
        ("consumption_state", "consumed", "unsupported"),
        ("synchronization_canary_authorized", True, "unsupported"),
        ("observed_at_unix_ns", True, "integer"),
    ],
)
def test_authorization_validation_fails_closed(
    field: str,
    value: JsonValue,
    message: str,
) -> None:
    qualification = _qualification()
    authorization = _authorization(qualification)
    authorization[field] = value
    _rehash(authorization, "authorization_id")
    with pytest.raises(ContractError, match=message):
        verify_observed_authorization_1_1(authorization)


def test_authorization_rejects_excess_lifetime_and_binding_mismatch() -> None:
    qualification = _qualification()
    excessive = _authorization(qualification)
    excessive["expires_at_unix_ns"] = cast("int", excessive["issued_at_unix_ns"]) + (
        AUTHORIZATION_LIFETIME_NS + 1
    )
    _rehash(excessive, "authorization_id")
    with pytest.raises(ContractError, match="lifetime bound"):
        verify_observed_authorization_1_1(excessive)

    mismatched = _authorization(qualification)
    mismatched["qualification_record_id"] = "sha256:" + ("0" * 64)
    _rehash(mismatched, "authorization_id")
    record = build_runtime_preflight_record_1_1(qualification, mismatched)
    assert "authorization_qualification_record_mismatch" in _list(
        _dict(record["prerequisite_assessment"])["blockers"]
    )


def test_record_rejects_forged_readiness_ledgers_and_coordinated_rehashing() -> None:
    record = build_runtime_preflight_record_1_1(_qualification())

    forged = _copy(record)
    _dict(forged["prerequisite_assessment"])["prerequisites_satisfied"] = True
    _rehash(forged, "record_id")
    with pytest.raises(ContractError, match="reconstruction mismatch"):
        verify_runtime_preflight_record_1_1(forged)

    attempted = _copy(record)
    _dict(attempted["evidence_ledgers"])["attempted_actions"] = ["mlx_core_import"]
    _rehash(attempted, "record_id")
    with pytest.raises(ContractError, match="must remain empty"):
        verify_runtime_preflight_record_1_1(attempted)

    physical = _copy(record)
    _dict(physical["static_action_counters"])["runtime_imports"] = 1
    _rehash(physical, "record_id")
    with pytest.raises(ContractError, match="must remain zero"):
        verify_runtime_preflight_record_1_1(physical)


def test_record_io_is_exclusive_and_no_follow(tmp_path: Path) -> None:
    record = build_runtime_preflight_record_1_1(_qualification())
    target = tmp_path / "record.json"
    write_runtime_preflight_record_1_1(target, record)
    assert load_runtime_preflight_record_1_1(target) == record

    input_link = tmp_path / "input-link.json"
    input_link.symlink_to(target)
    with pytest.raises(OSError, match="Too many levels"):
        load_runtime_preflight_record_1_1(input_link)

    output_link = tmp_path / "output-link.json"
    output_link.symlink_to(tmp_path / "missing.json")
    with pytest.raises(FileExistsError):
        write_runtime_preflight_record_1_1(output_link, record)


def test_fixture_is_deterministic_process_free_and_contains_no_private_path(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_replay = compile_runtime_preflight_fixture_1_1(first_root)
    second, second_replay = compile_runtime_preflight_fixture_1_1(second_root)
    assert first.name == second.name
    assert first_replay.to_dict() == second_replay.to_dict() | {
        "bundle_root": first_replay.bundle_root
    }
    assert first_replay.synthetic_prerequisites_satisfied is False
    assert first_replay.historical_prerequisites_satisfied is False
    assert first_replay.fixture_id.startswith("sha256:")
    assert first_replay.physical_actions == 0
    assert first_replay.authorization_creations == 0
    assert "/Users/" not in b"".join(read_closed_bundle(first)[1].values()).decode(
        "utf-8",
        errors="ignore",
    )


def test_validation_and_replay_touch_no_physical_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "fixture"
    output.mkdir()
    bundle, _result = compile_runtime_preflight_fixture_1_1(output)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("physical boundary touched")

    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(socket, "socketpair", forbidden)
    monkeypatch.setattr(importlib, "import_module", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(preflight_module, "run_runtime_preflight", forbidden)
    monkeypatch.setattr(custody_module, "run_inert_custody_self_test", forbidden)

    qualification = _qualification()
    record = build_runtime_preflight_record_1_1(qualification, _authorization(qualification))
    verify_runtime_preflight_record_1_1(record)
    replay = replay_runtime_preflight_fixture_1_1(bundle)
    assert replay.physical_actions == 0


def test_fixture_replay_rejects_extra_content(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    bundle, _result = compile_runtime_preflight_fixture_1_1(source_root)
    _root, files = read_closed_bundle(bundle)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    content["private/raw-evidence.json"] = canonical_json({"forbidden": True})
    tampered_root = tmp_path / "tampered"
    tampered_root.mkdir()
    tampered = publish_bundle(content, tampered_root, name_prefix="tampered-schema-1-1")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_runtime_preflight_fixture_1_1(tampered)


def test_cli_contract_record_and_fixture_commands_are_pure(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    qualification_path = tmp_path / "qualification.json"
    qualification_path.write_bytes(canonical_json(_qualification()))
    record_path = tmp_path / "record.json"
    assert (
        run(
            [
                "mlx",
                "runtime-preflight-1-1-record-create",
                str(qualification_path),
                str(record_path),
            ]
        )
        == 0
    )
    created = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert created["status"] == "created"
    assert created["prerequisites_satisfied"] is False
    assert run(["mlx", "runtime-preflight-1-1-record-verify", str(record_path)]) == 0
    assert (
        _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))["status"] == "valid"
    )
    assert run(["mlx", "runtime-preflight-1-1-record-inspect", str(record_path)]) == 0
    assert (
        _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))["status"]
        == "inspected"
    )
    assert run(["mlx", "runtime-preflight-1-1-protocol"]) == 0
    assert (
        _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))["protocol_id"]
        == runtime_preflight_protocol_1_1()["protocol_id"]
    )
    assert run(["mlx", "runtime-preflight-1-1-spec"]) == 0
    assert (
        _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))["spec_id"]
        == runtime_preflight_spec_1_1()["spec_id"]
    )
    assert run(["mlx", "runtime-preflight-1-1-capability-report"]) == 0
    assert (
        _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))["physical_actions"]
        == 0
    )

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    assert run(["mlx", "runtime-preflight-1-1-fixture-compile", str(fixture_root)]) == 0
    compiled = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert compiled["physical_actions"] == 0
    bundle = fixture_root / cast("str", compiled["path"])
    assert run(["mlx", "runtime-preflight-1-1-fixture-replay", str(bundle)]) == 0
    replayed = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert replayed["status"] == "replayed"
    assert replayed["physical_actions"] == 0
