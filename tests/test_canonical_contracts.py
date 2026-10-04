"""Canonical encoding and strict contract tests."""

from __future__ import annotations

import json
import os as os_module
import platform as platform_module
from pathlib import Path

import pytest

import localinferencelab.host as host_module
from localinferencelab.analysis import analyze_runs
from localinferencelab.backends import backend_plan, probe_runtime_artifact
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_json_bytes,
)
from localinferencelab.contracts import (
    ActionBudget,
    Backend,
    ExecutionDeclaration,
    Fact,
    HostIdentity,
    ModelIdentity,
    RunRecord,
    RuntimeFact,
    RuntimeIdentity,
    parse_record,
    record_id,
)
from localinferencelab.fixture import fixture_content
from localinferencelab.host import probe_host


def _complete_runtime_data(backend: Backend) -> dict[str, JsonValue]:
    common: dict[str, JsonValue] = {
        "record_type": "runtime_identity",
        "schema_version": "1.0",
        "backend": backend,
        "evidence_kind": "observed_execution",
        "executable_name": None,
        "package_name": None,
        "version": "1.0",
        "commit": "fixture-commit",
        "artifact_sha256": None,
        "install_manifest_sha256": None,
        "capability_facts": [],
        "identity_complete": True,
    }
    if backend == "mlx-lm":
        common["package_name"] = "mlx-lm"
        common["install_manifest_sha256"] = digest_bytes(b"mlx-manifest")
        common["capability_facts"] = [
            {"name": "runner", "value": "mlx"},
            {"name": "metal", "value": "enabled"},
            {"name": "mlx_version", "value": "1.0"},
            {"name": "mlx_lm_version", "value": "1.0"},
        ]
    elif backend == "llama.cpp":
        common["executable_name"] = "llama-server"
        common["artifact_sha256"] = digest_bytes(b"llama")
        common["capability_facts"] = [
            {"name": "runner", "value": "llama.cpp"},
            {"name": "metal", "value": "enabled"},
            {"name": "build_info", "value": "fixture-build"},
        ]
    else:
        common["executable_name"] = "ollama"
        common["artifact_sha256"] = digest_bytes(b"ollama")
        common["capability_facts"] = [
            {"name": "runner", "value": "mlx"},
            {"name": "metal", "value": "enabled"},
            {"name": "build_info", "value": "fixture-build"},
        ]
    return common


def test_canonical_json_is_sorted_and_rejects_floats() -> None:
    assert canonical_json({"z": 1, "a": ["é", True]}) == b'{"a":["\xc3\xa9",true],"z":1}'
    with pytest.raises(ContractError, match="floating-point"):
        canonical_json({"value": 0.1})
    with pytest.raises(ContractError, match="floating-point"):
        load_json_bytes(b'{"value":0.1}')


def test_strict_json_rejects_duplicates_and_noncanonical_base64() -> None:
    with pytest.raises(ContractError, match="duplicate"):
        load_json_bytes(b'{"value":1,"value":2}')
    assert decode_bytes(encode_bytes(b"\x00fixture")) == b"\x00fixture"
    with pytest.raises(ContractError, match="canonical"):
        decode_bytes("YQ==")


def test_all_fixture_contract_records_round_trip() -> None:
    content = fixture_content()
    parsed = 0
    for name, data in content.items():
        if name == "analysis.json":
            continue
        value = load_json_bytes(data)
        record = parse_record(value)
        assert canonical_json(record.to_dict()) == data
        assert record_id(record).startswith("sha256:")
        parsed += 1
    assert parsed == 24


def test_unknown_record_keys_are_rejected() -> None:
    content = fixture_content()
    value = load_json_bytes(content["protocol.json"])
    assert isinstance(value, dict)
    value["surprise"] = True
    with pytest.raises(ContractError, match="unknown keys"):
        parse_record(value)


def test_private_host_facts_are_rejected() -> None:
    with pytest.raises(ContractError, match="allowed public fact"):
        HostIdentity(
            "host_identity",
            "1.0",
            "safe_host_probe",
            "non_apple_ci",
            "x86_64",
            digest_bytes(b"fixture-output-root"),
            1,
            1,
            1,
            "Linux",
            "1",
            "1",
            (Fact.from_value({"name": "username", "value": "person"}, "fact"),),
        )
    with pytest.raises(ContractError, match="private or path-like"):
        Fact.from_value(
            {"name": "device_serial_number", "value": "SECRET-SERIAL"},
            "fact",
        )


def test_observed_runtime_requires_complete_identity() -> None:
    data: dict[str, JsonValue] = {
        "record_type": "runtime_identity",
        "schema_version": "1.0",
        "backend": "ollama",
        "evidence_kind": "observed_execution",
        "executable_name": "ollama",
        "package_name": None,
        "version": "1.0",
        "commit": None,
        "artifact_sha256": None,
        "install_manifest_sha256": None,
        "capability_facts": [
            {"name": "runner", "value": "unobserved"},
            {"name": "metal", "value": "unobserved"},
        ],
        "identity_complete": False,
    }
    with pytest.raises(ContractError, match="observed execution"):
        RuntimeIdentity.from_dict(data)


def test_forbidden_declaration_requires_zero_budget() -> None:
    content = fixture_content()
    protocol = parse_record(load_json_bytes(content["protocol.json"]))
    runtime = parse_record(load_json_bytes(content["identities/runtime-mlx-lm.json"]))
    model = parse_record(load_json_bytes(content["identities/model-mlx-lm.json"]))
    host = parse_record(load_json_bytes(content["identities/host.json"]))
    declaration = ExecutionDeclaration(
        "execution_declaration",
        "1.0",
        "model_execution_forbidden",
        record_id(protocol),
        "mlx-lm",
        record_id(runtime),
        record_id(model),
        "exact_identity",
        record_id(host),
        "non_apple_ci",
        "fixture",
        ActionBudget(1, 0, 0, 0),
    )
    with pytest.raises(ContractError, match="zero action budget"):
        ExecutionDeclaration.from_dict(declaration.to_dict())


def test_authorized_declaration_requires_an_inference_budget() -> None:
    content = fixture_content()
    declaration = load_json_bytes(content["authorizations/mlx-lm.json"])
    assert isinstance(declaration, dict)
    declaration["disposition"] = "authorized"
    with pytest.raises(ContractError, match="positive inference budget"):
        ExecutionDeclaration.from_dict(declaration)


def test_protocol_identity_sets_are_lowercase_unique_and_sorted() -> None:
    content = fixture_content()
    protocol = load_json_bytes(content["protocol.json"])
    assert isinstance(protocol, dict)
    runtime_ids = protocol["allowed_runtime_ids"]
    assert isinstance(runtime_ids, list)
    runtime_ids.append(runtime_ids[0])
    with pytest.raises(ContractError, match="unique, and sorted"):
        parse_record(protocol)

    protocol = load_json_bytes(content["protocol.json"])
    assert isinstance(protocol, dict)
    protocol["chat_template_sha256"] = "sha256:" + ("A" * 64)
    with pytest.raises(ContractError, match="lowercase"):
        parse_record(protocol)

    protocol = load_json_bytes(content["protocol.json"])
    assert isinstance(protocol, dict)
    protocol["ordering"] = "round_robin"
    with pytest.raises(ContractError, match="must be one of"):
        parse_record(protocol)


def test_eligibility_actions_use_a_closed_vocabulary() -> None:
    eligibility = load_json_bytes(fixture_content()["eligibility/mlx-lm.json"])
    assert isinstance(eligibility, dict)
    eligibility["decision"] = "eligible"
    eligibility["allowed_actions"] = ["network_request"]
    with pytest.raises(ContractError, match="must be one of"):
        parse_record(eligibility)


def test_canonical_json_rejects_surrogates() -> None:
    with pytest.raises(ContractError, match="surrogate"):
        load_json_bytes(b'{"value":"\\ud800"}')
    with pytest.raises(ContractError, match="surrogate"):
        load_json_bytes(b'{"\\ud800":"value"}')
    with pytest.raises(ContractError, match="surrogate"):
        canonical_json({"\ud800": "value"})


@pytest.mark.parametrize(
    "facts",
    [
        [
            {"name": "runner", "value": "mlx"},
            {"name": "runner", "value": "llama.cpp"},
            {"name": "metal", "value": "enabled"},
            {"name": "build_info", "value": "fixture-build"},
        ],
        [
            {"name": "runner", "value": "mlx"},
            {"name": "metal", "value": "enabled"},
            {"name": "metal", "value": "disabled"},
            {"name": "build_info", "value": "fixture-build"},
        ],
        [
            {"name": "runner", "value": "unsupported"},
            {"name": "metal", "value": "enabled"},
            {"name": "build_info", "value": "fixture-build"},
        ],
        [
            {"name": "runner", "value": "mlx"},
            {"name": "metal", "value": "unknown"},
            {"name": "build_info", "value": "fixture-build"},
        ],
        [
            {"name": "runner", "value": "mlx"},
            {"name": "metal", "value": "enabled"},
            {"name": "mlx_version", "value": "unexpected-for-ollama"},
        ],
        [
            {"name": "runner", "value": "mlx"},
            {"name": "metal", "value": "enabled"},
            {"name": "unknown", "value": "unexpected"},
        ],
    ],
)
def test_runtime_capability_contradictions_are_rejected(
    facts: list[JsonValue],
) -> None:
    data: dict[str, JsonValue] = {
        "record_type": "runtime_identity",
        "schema_version": "1.0",
        "backend": "ollama",
        "evidence_kind": "observed_execution",
        "executable_name": "ollama",
        "package_name": None,
        "version": "1.0",
        "commit": "fixture-commit",
        "artifact_sha256": digest_bytes(b"ollama"),
        "install_manifest_sha256": None,
        "capability_facts": facts,
        "identity_complete": True,
    }
    with pytest.raises(ContractError):
        RuntimeIdentity.from_dict(data)


def test_runtime_direct_construction_rejects_contradictory_facts() -> None:
    with pytest.raises(ContractError, match="unique"):
        RuntimeIdentity(
            "runtime_identity",
            "1.0",
            "ollama",
            "observed_execution",
            "ollama",
            None,
            "1.0",
            "fixture-commit",
            digest_bytes(b"ollama"),
            None,
            (
                RuntimeFact("runner", "mlx"),
                RuntimeFact("runner", "llama.cpp"),
                RuntimeFact("metal", "enabled"),
                RuntimeFact("build_info", "fixture-build"),
            ),
            True,
        )


@pytest.mark.parametrize(
    "data",
    [
        {
            "record_type": "runtime_identity",
            "schema_version": "1.0",
            "backend": "mlx-lm",
            "evidence_kind": "observed_execution",
            "executable_name": None,
            "package_name": "mlx-lm",
            "version": "1.0",
            "commit": "fixture-commit",
            "artifact_sha256": None,
            "install_manifest_sha256": digest_bytes(b"mlx-manifest"),
            "capability_facts": [
                {"name": "runner", "value": "mlx"},
                {"name": "metal", "value": "enabled"},
                {"name": "mlx_version", "value": "1.0"},
            ],
            "identity_complete": True,
        },
        {
            "record_type": "runtime_identity",
            "schema_version": "1.0",
            "backend": "llama.cpp",
            "evidence_kind": "observed_execution",
            "executable_name": "llama-server",
            "package_name": None,
            "version": "1.0",
            "commit": "fixture-commit",
            "artifact_sha256": digest_bytes(b"llama"),
            "install_manifest_sha256": None,
            "capability_facts": [
                {"name": "runner", "value": "llama.cpp"},
                {"name": "metal", "value": "unobserved"},
                {"name": "build_info", "value": "fixture-build"},
            ],
            "identity_complete": True,
        },
        {
            "record_type": "runtime_identity",
            "schema_version": "1.0",
            "backend": "ollama",
            "evidence_kind": "observed_execution",
            "executable_name": "ollama",
            "package_name": None,
            "version": "1.0",
            "commit": "fixture-commit",
            "artifact_sha256": digest_bytes(b"ollama"),
            "install_manifest_sha256": None,
            "capability_facts": [
                {"name": "runner", "value": "unobserved"},
                {"name": "metal", "value": "enabled"},
                {"name": "build_info", "value": "fixture-build"},
            ],
            "identity_complete": True,
        },
    ],
)
def test_each_observed_backend_rejects_incomplete_structured_identity(
    data: dict[str, JsonValue],
) -> None:
    with pytest.raises(ContractError, match="does not match supplied evidence"):
        RuntimeIdentity.from_dict(data)


@pytest.mark.parametrize("backend", ["mlx-lm", "llama.cpp", "ollama"])
def test_complete_observed_runtime_facts_are_accepted(backend: Backend) -> None:
    assert RuntimeIdentity.from_dict(_complete_runtime_data(backend)).identity_complete


@pytest.mark.parametrize(
    ("backend", "field", "fact_name", "absence_value"),
    [
        ("mlx-lm", "version", None, "unobserved"),
        ("mlx-lm", None, "mlx_version", "unknown"),
        ("mlx-lm", None, "mlx_lm_version", "unavailable"),
        ("llama.cpp", "commit", None, "unobserved"),
        ("llama.cpp", None, "build_info", "unknown"),
        ("ollama", "version", None, "unavailable"),
        ("ollama", None, "build_info", "not_observed"),
    ],
)
def test_observed_runtime_rejects_explicitly_unobserved_required_facts(
    backend: Backend,
    field: str | None,
    fact_name: str | None,
    absence_value: str,
) -> None:
    data = _complete_runtime_data(backend)
    if field is not None:
        data[field] = absence_value
    else:
        facts = data["capability_facts"]
        assert isinstance(facts, list)
        for fact in facts:
            assert isinstance(fact, dict)
            if fact["name"] == fact_name:
                fact["value"] = absence_value
    with pytest.raises(ContractError, match="does not match supplied evidence"):
        RuntimeIdentity.from_dict(data)


def test_cross_representation_mapping_is_mechanically_unavailable() -> None:
    content = fixture_content()
    for name in (
        "identities/model-mlx-lm.json",
        "identities/model-llama-cpp.json",
    ):
        value = load_json_bytes(content[name])
        assert isinstance(value, dict)
        value["cross_representation_equivalence"] = "mapped"
        value["mapping_artifact_sha256"] = digest_bytes(b"coordinated-forgery")
        with pytest.raises(ContractError):
            parse_record(value)
    model = parse_record(load_json_bytes(content["identities/model-mlx-lm.json"]))
    assert isinstance(model, ModelIdentity)
    values = list(model.to_dict().values())
    assert "mapped" not in values
    assert digest_bytes(b"coordinated-forgery") not in values


def test_run_output_projection_semantics_are_strict() -> None:
    content = fixture_content()
    valid = load_json_bytes(content["runs/0001-mlx-warm-model-001.json"])
    assert isinstance(valid, dict)
    valid["finish_reason"] = None
    with pytest.raises(ContractError, match="finish reason"):
        parse_record(valid)

    invalid = load_json_bytes(content["runs/0001-mlx-warm-model-001.json"])
    assert isinstance(invalid, dict)
    invalid["validity"] = "invalid"
    invalid["invalid_reason_sha256"] = digest_bytes(b"invalid")
    for field in (
        "raw_response_base64",
        "raw_response_sha256",
        "text_utf8",
        "text_sha256",
        "token_ids",
        "token_ids_sha256",
        "envelope_base64",
        "envelope_sha256",
    ):
        invalid[field] = None
    with pytest.raises(ContractError, match="digest-safe"):
        parse_record(invalid)


def test_tokenless_valid_outputs_are_not_comparable() -> None:
    content = fixture_content()
    runs: list[RunRecord] = []
    for name in (
        "runs/0001-mlx-warm-model-001.json",
        "runs/0002-mlx-warm-model-002.json",
    ):
        value = load_json_bytes(content[name])
        assert isinstance(value, dict)
        value["token_ids"] = None
        value["token_ids_sha256"] = None
        record = parse_record(value)
        assert isinstance(record, RunRecord)
        runs.append(record)
    model = parse_record(load_json_bytes(content["identities/model-mlx-lm.json"]))
    assert isinstance(model, ModelIdentity)
    analysis = analyze_runs(runs, {record_id(model): model})
    groups = analysis["groups"]
    assert isinstance(groups, list)
    group = groups[0]
    assert isinstance(group, dict)
    assert group["group_classification"] == "not_comparable"
    projections = group["exact_repeatability"]
    assert isinstance(projections, dict)
    assert projections["token_ids"] == "not_comparable"


def test_synthetic_metric_evidence_and_throughput_units_are_enforced() -> None:
    content = fixture_content()
    run_value = load_json_bytes(content["runs/0001-mlx-warm-model-001.json"])
    assert isinstance(run_value, dict)
    metrics = run_value["native_metrics"]
    assert isinstance(metrics, list)
    first_metric = metrics[0]
    assert isinstance(first_metric, dict)
    first_metric["availability"] = "observed"
    with pytest.raises(ContractError, match="metric evidence"):
        parse_record(run_value)

    runs: list[RunRecord] = []
    for name in (
        "runs/0001-mlx-warm-model-001.json",
        "runs/0002-mlx-warm-model-002.json",
    ):
        value = load_json_bytes(content[name])
        assert isinstance(value, dict)
        native_metrics = value["native_metrics"]
        assert isinstance(native_metrics, list)
        for metric in native_metrics:
            assert isinstance(metric, dict)
            if metric["name"] == "generation_count":
                metric["unit"] = "bytes"
        record = parse_record(value)
        assert isinstance(record, RunRecord)
        runs.append(record)
    model = parse_record(load_json_bytes(content["identities/model-mlx-lm.json"]))
    assert isinstance(model, ModelIdentity)
    analysis = analyze_runs(runs, {record_id(model): model})
    groups = analysis["groups"]
    assert isinstance(groups, list)
    group = groups[0]
    assert isinstance(group, dict)
    throughput = group["derived_throughput"]
    assert isinstance(throughput, dict)
    assert throughput["availability"] == "unavailable"


def test_backend_plan_is_fail_closed() -> None:
    plan = backend_plan("ollama")
    assert plan["allowed_to_execute"] is False
    assert plan["automatic_runtime_start"] is False
    assert plan["automatic_model_download"] is False
    assert plan["network_access"] is False


def test_static_backend_probe_hashes_without_path_custody(tmp_path: Path) -> None:
    artifact = tmp_path / "llama-server"
    artifact.write_bytes(b"not an executable fixture")
    identity = probe_runtime_artifact(
        "llama.cpp",
        artifact,
        version="fixture",
        commit="abc123",
    )
    assert identity.executable_name == "llama-server"
    assert str(tmp_path) not in json.dumps(identity.to_dict())
    assert identity.identity_complete is False
    reparsed = parse_record(load_json_bytes(canonical_json(identity.to_dict())))
    assert reparsed == identity


@pytest.mark.parametrize(
    "version",
    [
        "/Users/person/private-runtime",
        "username=person",
        "bad\ud800version",
        "Users/person/private-runtime",
        "home/person/private-runtime",
        "~/private-runtime",
        "~\\private-runtime",
    ],
)
def test_static_backend_probe_rejects_private_or_invalid_versions(
    tmp_path: Path,
    version: str,
) -> None:
    artifact = tmp_path / "runtime"
    artifact.write_bytes(b"fixture")
    with pytest.raises(ContractError):
        probe_runtime_artifact("ollama", artifact, version=version, commit=None)


@pytest.mark.parametrize("backend", ["mlx-lm", "llama.cpp", "ollama"])
def test_static_backend_probe_round_trips_for_every_backend(
    tmp_path: Path,
    backend: Backend,
) -> None:
    artifact = tmp_path / backend.replace(".", "-")
    artifact.write_bytes(b"fixture")
    identity = probe_runtime_artifact(
        backend,
        artifact,
        version="fixture",
        commit="fixture-commit",
    )
    assert parse_record(load_json_bytes(canonical_json(identity.to_dict()))) == identity


def test_static_backend_probe_rejects_symlink(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"fixture")
    link = tmp_path / "link"
    link.symlink_to(artifact)
    with pytest.raises(ContractError, match="symlink"):
        probe_runtime_artifact("mlx-lm", link, version="fixture", commit=None)


def test_host_probe_contains_only_public_facts() -> None:
    host = probe_host()
    payload = canonical_json(host.to_dict())
    assert b"/Users/" not in payload
    assert b"/home/" not in payload
    assert b"username" not in payload.lower()
    if host.os_name != "Darwin":
        assert host.host_class == "non_apple_ci"


def test_linux_host_probe_is_explicitly_non_apple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(platform_module, "system", lambda: "Linux")
    monkeypatch.setattr(platform_module, "machine", lambda: "x86_64")
    monkeypatch.setattr(os_module, "cpu_count", lambda: 8)
    monkeypatch.setattr(host_module, "_linux_chip", lambda: "fixture-linux-chip")
    monkeypatch.setattr(host_module, "_linux_physical_cores", lambda: 4)
    monkeypatch.setattr(host_module, "_linux_memory", lambda: 16_000_000_000)
    monkeypatch.setattr(host_module, "_linux_os_identity", lambda: ("24.04", "noble"))
    host = host_module.probe_host()
    assert host.host_class == "non_apple_ci"
    assert host.physical_cores == 4
    assert host.logical_cores == 8
    assert Fact("apple_silicon_eligible", "false") in host.device_facts
