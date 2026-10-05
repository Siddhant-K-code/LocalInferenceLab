"""Adversarial tests for the offline Ollama attestation feasibility contract."""

from __future__ import annotations

import http.client
import json
import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_json,
    decode_bytes,
    digest_bytes,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.ollama_attestation import (
    DECLARATION_COMMIT,
    DECLARATION_ID,
    FOUNDATION_COMMIT,
    GENERATION_REQUEST_SHA256,
    OLLAMA_REVISION,
    SECURITY_REVISION,
    XNU_REVISION,
    attestation_feasibility_spec,
    attestation_inspection,
    build_attestation_assessment,
    compile_attestation_fixture,
    load_attestation_assessment,
    replay_attestation_fixture,
    verify_attestation_assessment,
    verify_attestation_spec,
)
from localinferencelab.ollama_declaration import (
    build_study_declaration,
    qwen3_repeatability_study_spec,
)


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    copied = json.loads(canonical_json(value))
    assert isinstance(copied, dict)
    return cast("dict[str, JsonValue]", copied)


def _dict(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _output(capfd: pytest.CaptureFixture[str]) -> dict[str, JsonValue]:
    captured = capfd.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert isinstance(value, dict)
    return cast("dict[str, JsonValue]", value)


def _candidate(spec: dict[str, JsonValue], candidate_id: str) -> dict[str, JsonValue]:
    for value in _list(spec["candidate_mechanisms"]):
        candidate = _dict(value)
        if candidate["candidate_id"] == candidate_id:
            return candidate
    raise AssertionError(f"missing candidate {candidate_id}")


def _scenario(spec: dict[str, JsonValue], scenario_id: str) -> dict[str, JsonValue]:
    for value in _list(spec["threat_scenarios"]):
        scenario = _dict(value)
        if scenario["scenario_id"] == scenario_id:
            return scenario
    raise AssertionError(f"missing scenario {scenario_id}")


def test_pinned_spec_separates_requirements_candidates_and_verdict() -> None:
    spec = verify_attestation_spec(attestation_feasibility_spec())
    binding = _dict(spec["contract_binding"])
    assert binding["declaration_contract_commit"] == DECLARATION_COMMIT
    assert binding["declaration_id"] == DECLARATION_ID
    assert binding["ollama_revision"] == OLLAMA_REVISION
    assert binding["generation_request_sha256"] == GENERATION_REQUEST_SHA256
    scope = _dict(spec["platform_scope"])
    endpoint = _dict(scope["endpoint"])
    assert scope["architecture"] == "arm64"
    assert scope["privilege_scope"] == "non_root_no_special_entitlements"
    assert endpoint == {
        "scheme": "http",
        "address_family": "AF_INET",
        "host": "127.0.0.1",
        "port": 11_434,
        "dns": "forbidden",
        "proxy": "forbidden",
        "redirect": "forbidden",
        "unix_forwarding": "forbidden",
    }

    libproc = _candidate(spec, "darwin_process_fd_socket_snapshot")
    assert libproc["source_revision"] == XNU_REVISION
    assert libproc["status"] == "insufficient_snapshot"
    signing = _candidate(spec, "darwin_dynamic_code_identity")
    assert signing["source_revision"] == SECURITY_REVISION
    assert signing["status"] == "insufficient_semantics"
    public_ps = _candidate(spec, "ollama_public_ps")
    assert public_ps["status"] == "unsupported_public_api"
    assert "runner PID" in cast("str", public_ps["reason"])

    assessment = verify_attestation_assessment(build_attestation_assessment(spec))
    verdict = _dict(assessment["verdict"])
    assert verdict["decision"] == "insufficient"
    assert verdict["satisfied_requirement_ids"] == []
    assert verdict["missing_requirement_ids"] == verdict["required_requirement_ids"]
    assert verdict["listener_owner_attestation_id"] is None
    assert verdict["active_internal_runner_metal_attestation_id"] is None
    assert verdict["observed_generation_eligible"] is False
    assert verdict["observed_generation_replay_eligible"] is False
    assert verdict["metadata_preflight"] == "separately_authorized_generation_free"
    assert all(value == 0 for value in _dict(assessment["non_actions"]).values())


def test_separate_verdict_explains_unchanged_declaration_ineligibility() -> None:
    assessment = build_attestation_assessment()
    declaration = build_study_declaration(qwen3_repeatability_study_spec())
    gate = _dict(declaration["attestation_gate"])
    assert gate == {
        "schema_status": "not_available_in_schema_1_0",
        "listener_owner_attestation_id": None,
        "active_internal_runner_metal_attestation_id": None,
        "gate_may_be_forged_by_caller": False,
    }
    eligibility = _dict(declaration["eligibility"])
    for key in ("observed_generation", "observed_generation_replay"):
        observed = _dict(eligibility[key])
        assert observed["decision"] == "ineligible"
        assert observed["attestation_content_bound"] is False
    verdict = _dict(assessment["verdict"])
    assert verdict["decision"] == "insufficient"
    assert verdict["observed_generation_eligible"] is False
    assert verdict["observed_generation_replay_eligible"] is False


def test_attestation_binding_matches_the_declared_study_contract() -> None:
    spec = attestation_feasibility_spec()
    binding = _dict(spec["contract_binding"])
    scope = _dict(spec["platform_scope"])
    endpoint = _dict(scope["endpoint"])
    study = qwen3_repeatability_study_spec()
    declaration = build_study_declaration(study)
    request = _dict(_list(declaration["request_catalog"])[0])
    identity = _dict(study["known_identity"])
    host = _dict(identity["host"])
    controls = _dict(study["request_controls"])
    transport = _dict(study["transport"])

    assert binding["foundation_commit"] == FOUNDATION_COMMIT
    assert binding["declaration_id"] == DECLARATION_ID
    assert declaration["declaration_id"] == DECLARATION_ID
    assert binding["generation_request_sha256"] == request["request_sha256"]
    assert (
        digest_bytes(decode_bytes(cast("str", request["request_base64"])))
        == binding["generation_request_sha256"]
    )
    assert binding["declaration_record_type"] == declaration["record_type"]
    assert binding["declaration_schema_version"] == declaration["schema_version"]
    assert (
        scope["operating_system"],
        scope["os_version"],
        scope["os_build"],
        scope["architecture"],
    ) == (
        host["os_name"],
        host["os_version"],
        host["os_build"],
        host["architecture"],
    )
    assert (endpoint["scheme"], endpoint["host"], endpoint["port"]) == (
        transport["scheme"],
        transport["host"],
        transport["port"],
    )
    assert controls == {
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
    }


def _top_unknown(value: dict[str, JsonValue]) -> None:
    value["unexpected"] = True


def _nested_unknown(value: dict[str, JsonValue]) -> None:
    _dict(value["feasibility"])["unexpected"] = True


def _forged_positive_decision(value: dict[str, JsonValue]) -> None:
    _dict(value["verdict"])["decision"] = "sufficient"


def _forged_generation_eligibility(value: dict[str, JsonValue]) -> None:
    _dict(value["verdict"])["observed_generation_eligible"] = True


def _forged_replay_eligibility(value: dict[str, JsonValue]) -> None:
    _dict(value["verdict"])["observed_generation_replay_eligible"] = True


def _forged_listener_attestation(value: dict[str, JsonValue]) -> None:
    _dict(value["verdict"])["listener_owner_attestation_id"] = GENERATION_REQUEST_SHA256


def _forged_satisfied_requirement(value: dict[str, JsonValue]) -> None:
    verdict = _dict(value["verdict"])
    verdict["satisfied_requirement_ids"] = ["accepted_connection_owner"]


def _bool_integer_ambiguity(value: dict[str, JsonValue]) -> None:
    _dict(value["non_actions"])["socket_calls"] = False


def _malformed_digest(value: dict[str, JsonValue]) -> None:
    value["feasibility_id"] = "sha256:" + ("A" * 64)


@pytest.mark.parametrize(
    "mutate",
    [
        _top_unknown,
        _nested_unknown,
        _forged_positive_decision,
        _forged_generation_eligibility,
        _forged_replay_eligibility,
        _forged_listener_attestation,
        _forged_satisfied_requirement,
        _bool_integer_ambiguity,
        _malformed_digest,
    ],
)
def test_assessment_rejects_forgery_and_type_ambiguity(
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    assessment = _copy(build_attestation_assessment())
    mutate(assessment)
    with pytest.raises(ContractError):
        verify_attestation_assessment(assessment)


def test_spec_rejects_missing_duplicate_and_unbounded_structures() -> None:
    missing_requirement = _copy(attestation_feasibility_spec())
    _list(missing_requirement["normative_requirements"]).pop()
    with pytest.raises(ContractError):
        verify_attestation_spec(missing_requirement)

    missing_candidate = _copy(attestation_feasibility_spec())
    _list(missing_candidate["candidate_mechanisms"]).pop()
    with pytest.raises(ContractError):
        verify_attestation_spec(missing_candidate)

    duplicate_requirement = _copy(attestation_feasibility_spec())
    requirements = _list(duplicate_requirement["normative_requirements"])
    requirements.append(_copy(requirements[0]))
    with pytest.raises(ContractError, match=r"duplicate IDs|sorted"):
        verify_attestation_spec(duplicate_requirement)

    duplicate_candidate = _copy(attestation_feasibility_spec())
    candidates = _list(duplicate_candidate["candidate_mechanisms"])
    candidates.append(_copy(candidates[0]))
    with pytest.raises(ContractError, match=r"duplicate IDs|sorted"):
        verify_attestation_spec(duplicate_candidate)

    bool_port = _copy(attestation_feasibility_spec())
    _dict(_dict(bool_port["platform_scope"])["endpoint"])["port"] = True
    with pytest.raises(ContractError, match="integer"):
        verify_attestation_spec(bool_port)

    malformed_request_digest = _copy(attestation_feasibility_spec())
    _dict(malformed_request_digest["contract_binding"])["generation_request_sha256"] = "sha256:" + (
        "F" * 64
    )
    with pytest.raises(ContractError, match="lowercase"):
        verify_attestation_spec(malformed_request_digest)

    excessive_candidates = _copy(attestation_feasibility_spec())
    candidates = _list(excessive_candidates["candidate_mechanisms"])
    candidates.extend(_copy(candidates[0]) for _ in range(32))
    with pytest.raises(ContractError, match="maximum count"):
        verify_attestation_spec(excessive_candidates)

    excessive_reason = _copy(attestation_feasibility_spec())
    _dict(_list(excessive_reason["candidate_mechanisms"])[0])["reason"] = "x" * 1_025
    with pytest.raises(ContractError, match="maximum length"):
        verify_attestation_spec(excessive_reason)


@pytest.mark.parametrize(
    "scenario_id",
    [
        "pid_reuse",
        "process_birth_drift",
        "listener_owner_uid_mismatch",
        "executable_socket_mismatch",
        "socket_endpoint_mismatch",
        "listener_rebind_race",
        "runner_replacement",
        "model_closure_drift",
        "metal_claim_from_weak_evidence",
        "privilege_mismatch",
        "coordinated_record_receipt_tampering",
    ],
)
def test_every_named_threat_stays_not_attested(scenario_id: str) -> None:
    spec = attestation_feasibility_spec()
    scenario = _scenario(spec, scenario_id)
    assert scenario["required_outcome"] == "not_attested"
    forged = _copy(spec)
    _scenario(forged, scenario_id)["required_outcome"] = "attested"
    with pytest.raises(ContractError):
        verify_attestation_spec(forged)


def test_fixture_is_byte_identical_and_replays_from_closed_bundle(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_result = compile_attestation_fixture(first_root)
    second, second_result = compile_attestation_fixture(second_root)
    assert first.name == second.name
    first_content_root, first_files = read_closed_bundle(first)
    second_content_root, second_files = read_closed_bundle(second)
    assert first_content_root == second_content_root
    assert first_files == second_files
    assert first_result == second_result
    assert first_result.decision == "insufficient"
    assert first_result.physical_network_requests == 0
    assert first_result.model_actions == 0
    assert replay_attestation_fixture(first) == first_result


def test_replay_rejects_coordinated_tampering_extra_missing_and_noncanonical(
    tmp_path: Path,
) -> None:
    original_root = tmp_path / "original"
    original_root.mkdir()
    original, _result = compile_attestation_fixture(original_root)
    _content_root, files = read_closed_bundle(original)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }

    tampered = dict(content)
    assessment = _copy(json.loads(tampered["attestation-assessment.json"]))
    _dict(assessment["verdict"])["observed_generation_eligible"] = True
    tampered["attestation-assessment.json"] = canonical_json(assessment)
    tampered_root = tmp_path / "tampered"
    tampered_root.mkdir()
    coordinated = publish_bundle(tampered, tampered_root, name_prefix="coordinated")
    with pytest.raises(ContractError):
        replay_attestation_fixture(coordinated)

    extra = dict(content)
    extra["extra.json"] = b"{}"
    extra_bundle = publish_bundle(extra, tampered_root, name_prefix="extra")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_attestation_fixture(extra_bundle)

    missing = dict(content)
    missing.pop("source/attestation-spec.json")
    missing_bundle = publish_bundle(missing, tampered_root, name_prefix="missing")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_attestation_fixture(missing_bundle)

    noncanonical = dict(content)
    noncanonical["source/attestation-spec.json"] = json.dumps(
        json.loads(noncanonical["source/attestation-spec.json"]),
        indent=2,
    ).encode()
    noncanonical_bundle = publish_bundle(
        noncanonical,
        tampered_root,
        name_prefix="noncanonical",
    )
    with pytest.raises(ContractError, match="canonical JSON bytes"):
        replay_attestation_fixture(noncanonical_bundle)


def test_contract_paths_make_no_socket_subprocess_or_process_probe_calls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline attestation contract crossed a physical-action boundary")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(http.client, "HTTPConnection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "kill", forbidden)

    assessment = build_attestation_assessment()
    verify_attestation_assessment(assessment)
    inspection = attestation_inspection(assessment)
    assert inspection["declaration_id"] == DECLARATION_ID
    assert inspection["physical_network_requests"] == 0
    assert inspection["model_actions"] == 0
    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    bundle, _result = compile_attestation_fixture(bundle_root)
    replay_attestation_fixture(bundle)


def test_attestation_cli_create_verify_inspect_compile_and_replay(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assessment_path = tmp_path / "assessment.json"
    assert run(["ollama", "attestation-create", str(assessment_path)]) == 0
    created = _output(capfd)
    assert created["status"] == "created"
    assert created["decision"] == "insufficient"
    assert created["declaration_id"] == DECLARATION_ID
    assert created["observed_generation_eligible"] is False
    load_attestation_assessment(assessment_path)

    spec_path = tmp_path / "attestation-spec.json"
    spec_path.write_bytes(canonical_json(attestation_feasibility_spec()))
    explicit_assessment = tmp_path / "explicit-assessment.json"
    assert (
        run(
            [
                "ollama",
                "attestation-create",
                str(explicit_assessment),
                "--spec",
                str(spec_path),
            ]
        )
        == 0
    )
    explicit = _output(capfd)
    assert explicit["assessment_id"] == created["assessment_id"]
    assert explicit_assessment.read_bytes() == assessment_path.read_bytes()

    assert run(["ollama", "attestation-verify", str(assessment_path)]) == 0
    assert _output(capfd)["status"] == "valid"
    assert run(["ollama", "attestation-inspect", str(assessment_path)]) == 0
    inspected = _output(capfd)
    assert inspected["status"] == "inspected"
    assert inspected["missing_requirement_ids"]

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    assert run(["ollama", "attestation-fixture-compile", str(fixture_root)]) == 0
    compiled = _output(capfd)
    assert compiled["status"] == "compiled"
    bundle = fixture_root / cast("str", compiled["path"])
    assert run(["ollama", "attestation-replay", str(bundle)]) == 0
    replayed = _output(capfd)
    assert replayed["status"] == "replayed"
    assert replayed["decision"] == "insufficient"
    assert replayed["external_network_actions"] == 0
