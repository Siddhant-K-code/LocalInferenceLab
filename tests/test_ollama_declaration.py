"""Adversarial tests for the preflight-only Ollama study declaration."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_json,
    digest_bytes,
)
from localinferencelab.cli import run
from localinferencelab.contracts import (
    Fact,
    HostIdentity,
    ModelIdentity,
    RuntimeFact,
    RuntimeIdentity,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.ollama import (
    build_prospective_package,
    initialize_output_root,
    inspect_model_artifacts,
)
from localinferencelab.ollama_declaration import (
    FOUNDATION_COMMIT,
    QWEN3_MANIFEST_DIGEST,
    build_study_declaration,
    compile_declaration_fixture,
    load_study_declaration,
    qwen3_repeatability_study_spec,
    replay_declaration_fixture,
    verify_study_declaration,
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
    parsed = json.loads(captured.out)
    assert isinstance(parsed, dict)
    return cast("dict[str, JsonValue]", parsed)


def _bound_study(
    root: Path,
    *,
    cache_cohort: str = "cold_model_warm_process",
    cache_support: str = "supported",
    disposition: str = "authorized",
    package_deadline_ms: int = 120_000,
    mixed_identity: str | None = None,
) -> tuple[dict[str, JsonValue], list[dict[str, JsonValue]]]:
    root.mkdir()
    runtime_path = root / "ollama"
    runtime_path.write_bytes(b"synthetic preinstalled Ollama runtime for package binding")
    blobs = root / "blobs"
    blobs.mkdir()
    config = canonical_json({"architecture": "fixture", "context_length": 8192})
    layer = b"synthetic Qwen3 package-binding layer"
    config_digest = digest_bytes(config)
    layer_digest = digest_bytes(layer)
    (blobs / config_digest.replace(":", "-", 1)).write_bytes(config)
    (blobs / layer_digest.replace(":", "-", 1)).write_bytes(layer)
    manifest = canonical_json(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.ollama.image.config",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.ollama.image.model",
                    "digest": layer_digest,
                    "size": len(layer),
                },
            ],
        },
    )
    manifest_path = root / "manifest"
    manifest_path.write_bytes(manifest)
    artifact = inspect_model_artifacts(manifest_path, blobs)
    output_root = root / "output"
    output_root.mkdir()
    output_root_id = initialize_output_root(
        output_root,
        "synthetic-bound-declaration-output",
        synthetic_fixture=True,
    )
    runtime = RuntimeIdentity(
        "runtime_identity",
        "1.0",
        "ollama",
        "observed_execution",
        "ollama",
        None,
        "0.35.1",
        "fixture-source-commit",
        digest_bytes(runtime_path.read_bytes()),
        None,
        (
            RuntimeFact("runner", "llama.cpp"),
            RuntimeFact("metal", "enabled"),
            RuntimeFact("build_info", "fixture-build"),
        ),
        True,
    )
    alternate_runtime_path = root / "ollama-alternate"
    alternate_runtime_path.write_bytes(
        b"alternate synthetic preinstalled Ollama runtime for package binding"
    )
    alternate_runtime = RuntimeIdentity(
        "runtime_identity",
        "1.0",
        "ollama",
        "observed_execution",
        "ollama-alternate",
        None,
        "0.35.1",
        "alternate-fixture-source-commit",
        digest_bytes(alternate_runtime_path.read_bytes()),
        None,
        (
            RuntimeFact("runner", "mlx"),
            RuntimeFact("metal", "enabled"),
            RuntimeFact("build_info", "alternate-fixture-build"),
        ),
        True,
    )
    model = ModelIdentity(
        "model_identity",
        "1.0",
        "ollama",
        "ollama_manifest",
        "observed_execution",
        "synthetic-qwen3-binding-representation",
        None,
        artifact.manifest_sha256,
        artifact.config.digest,
        None,
        artifact.closure_sha256,
        "unproven",
    )
    alternate_model = ModelIdentity(
        "model_identity",
        "1.0",
        "ollama",
        "ollama_manifest",
        "observed_execution",
        "alternate-synthetic-qwen3-binding-representation",
        None,
        artifact.manifest_sha256,
        artifact.config.digest,
        None,
        artifact.closure_sha256,
        "unproven",
    )
    host = HostIdentity(
        "host_identity",
        "1.0",
        "safe_host_probe",
        "apple_silicon",
        "arm64",
        "Apple M5 Pro",
        18,
        18,
        25_769_803_776,
        "macOS",
        "27.0.1",
        "26A434",
        (),
    )
    alternate_host = HostIdentity(
        "host_identity",
        "1.0",
        "safe_host_probe",
        "apple_silicon",
        "arm64",
        "Apple M5 Pro",
        18,
        18,
        25_769_803_776,
        "macOS",
        "27.0.1",
        "26A434",
        (Fact("probe_method", "alternate-synthetic-package-binding"),),
    )
    spec = _copy(qwen3_repeatability_study_spec())
    _dict(spec["study_design"])["repeats_per_prompt"] = 2
    known = _dict(spec["known_identity"])
    known_runtime = _dict(known["runtime"])
    if mixed_identity != "runtime":
        known_runtime.update(
            {
                "artifact_sha256": runtime.artifact_sha256,
                "selected_internal_runner": "llama.cpp",
                "metal_state": "enabled",
                "build_info": "fixture-build",
            },
        )
    known_model = _dict(known["model"])
    known_model.update(
        {
            "manifest_digest": artifact.manifest_digest,
            "manifest_bytes_sha256": artifact.manifest_sha256,
            "config_sha256": artifact.config.digest,
            "layer_digests": [blob.digest for blob in artifact.layers],
            "artifact_closure_sha256": artifact.closure_sha256,
        },
    )
    prompt = _dict(_list(spec["prompt_catalog"])[0])
    controls = _dict(spec["request_controls"])
    transport = _dict(spec["transport"])
    show_projection = {
        name: digest_bytes(name.encode())
        for name in (
            "modelfile_sha256",
            "parameters_sha256",
            "template_sha256",
            "details_sha256",
            "model_info_sha256",
            "thinking_sha256",
        )
    }
    packages: list[dict[str, JsonValue]] = []
    for repeat in range(1, 3):
        run_id = f"anchor-repeat-{repeat:03d}"
        selected_runtime = (
            alternate_runtime if mixed_identity == "runtime" and repeat == 2 else runtime
        )
        selected_runtime_path = (
            alternate_runtime_path if mixed_identity == "runtime" and repeat == 2 else runtime_path
        )
        selected_model = alternate_model if mixed_identity == "model" and repeat == 2 else model
        selected_host = alternate_host if mixed_identity == "host" and repeat == 2 else host
        package_spec: dict[str, JsonValue] = {
            "record_type": "ollama_study_spec",
            "schema_version": "1.0",
            "study_name": spec["study_name"],
            "run_id": run_id,
            "endpoint": {
                "scheme": transport["scheme"],
                "host": transport["host"],
                "port": transport["port"],
                "version_path": transport["version_path"],
                "tags_path": transport["tags_path"],
                "show_path": transport["show_path"],
                "ps_path": transport["ps_path"],
                "generate_path": transport["generate_path"],
            },
            "runtime": selected_runtime.to_dict(),
            "model": selected_model.to_dict(),
            "host": selected_host.to_dict(),
            "model_name": known_model["request_model"],
            "prompt_base64": prompt["prompt_base64"],
            "prompt_sha256": prompt["prompt_sha256"],
            "template_sha256": digest_bytes(b"raw-mode-no-template"),
            "raw_mode": True,
            "think_mode": controls["think_mode"],
            "sampler": {
                "seed": controls["seed"],
                "temperature_millionths": controls["temperature_millionths"],
                "top_p_millionths": controls["top_p_millionths"],
                "top_k": controls["top_k"],
                "min_p_millionths": controls["min_p_millionths"],
                "repeat_penalty_millionths": controls["repeat_penalty_millionths"],
            },
            "context_tokens": controls["context_tokens"],
            "max_output_tokens": controls["max_output_tokens"],
            "keep_alive_seconds": controls["keep_alive_seconds"],
            "cache_cohort": cache_cohort,
            "cache_support": cache_support,
            "cache_evidence_sha256": digest_bytes(
                f"synthetic-cache-evidence-{repeat}".encode(),
            ),
            "show_projection": show_projection,
            "process_instance_label": "preexisting-loopback-runtime-1",
            "model_instance_label": f"cold-load-{repeat}",
            "timeout_ms": package_deadline_ms,
            "max_identity_response_bytes": transport["max_identity_response_bytes"],
            "max_generate_response_bytes": transport["max_generate_response_bytes"],
            "output_root_id": output_root_id,
            "authorization_nonce_sha256": {
                "preflight_only": digest_bytes(f"preflight-{repeat}".encode()),
                "identity_guard": digest_bytes(f"identity-{repeat}".encode()),
                "generation": digest_bytes(f"generation-{repeat}".encode()),
            },
            "disposition": disposition,
        }
        packages.append(
            build_prospective_package(
                package_spec,
                runtime_artifact=selected_runtime_path,
                model_manifest=manifest_path,
                blob_root=blobs,
            ),
        )
    return spec, packages


def test_qwen3_declaration_is_exact_incomplete_and_fail_closed() -> None:
    declaration = build_study_declaration(qwen3_repeatability_study_spec())
    assert verify_study_declaration(declaration) == declaration
    assert declaration["evidence_status"] == "prospective_declaration_only_not_observed_evidence"

    contract = _dict(declaration["contract_binding"])
    descriptor = _dict(contract["descriptor"])
    assert descriptor["foundation_commit"] == FOUNDATION_COMMIT
    assert descriptor["ollama_runner_contract_schema"] == "1.0"
    assert descriptor["ollama_prospective_package_schema"] == "1.0"
    assert descriptor["ollama_repeatability_declaration_schema"] == "1.0"

    identity = _dict(_dict(declaration["study_spec"])["known_identity"])
    runtime = _dict(identity["runtime"])
    model = _dict(identity["model"])
    host = _dict(identity["host"])
    assert runtime["ollama_version"] == "0.35.1"
    assert runtime["artifact_sha256"] is None
    assert runtime["selected_internal_runner"] is None
    assert runtime["metal_state"] is None
    assert model["manifest_digest"] == QWEN3_MANIFEST_DIGEST
    assert model["artifact_closure_sha256"] is None
    assert model["layer_digests"] == []
    assert host == {
        "evidence_source": "user_provided_prior_identity",
        "observation_status": "not_reprobed_for_declaration",
        "chip": "Apple M5 Pro",
        "architecture": "arm64",
        "cpu_cores": 18,
        "performance_cores": 6,
        "efficiency_cores": 12,
        "unified_memory_bytes": 25_769_803_776,
        "os_name": "macOS",
        "os_version": "27.0.1",
        "os_build": "26A434",
    }

    eligibility = _dict(declaration["eligibility"])
    completeness = _dict(eligibility["declaration_completeness"])
    observed = _dict(eligibility["observed_generation"])
    observed_replay = _dict(eligibility["observed_generation_replay"])
    assert completeness["status"] == "incomplete"
    assert "known_identity.model.artifact_closure_sha256" in _list(completeness["missing_fields"])
    assert _dict(eligibility["metadata_preflight"]) == {
        "decision": "separate_authorization_required",
        "currently_authorized": False,
        "may_generate": False,
    }
    expected_gates = [
        "listener_owner_attestation",
        "active_internal_runner_metal_attestation",
    ]
    assert observed["decision"] == "ineligible"
    assert observed["trust_gate_blockers"] == expected_gates
    assert observed_replay["decision"] == "ineligible"
    assert observed_replay["trust_gate_blockers"] == expected_gates
    metadata_preflight = _dict(_dict(declaration["authorization_plan"])["metadata_preflight"])
    assert metadata_preflight["run_id"] == "anchor-repeat-001"
    assert metadata_preflight["package_id"] is None
    assert metadata_preflight["nonce_sha256"] is None
    assert metadata_preflight["currently_authorized"] is False
    assert _dict(declaration["non_actions"]) == {
        "physical_network_requests": 0,
        "socket_calls": 0,
        "model_inferences": 0,
        "model_process_starts": 0,
        "model_mutations": 0,
        "model_downloads": 0,
        "external_network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
        "output_root_markers_created": 0,
    }


def test_request_bytes_schedule_and_study_controls_are_frozen() -> None:
    declaration = build_study_declaration(qwen3_repeatability_study_spec())
    requests = _list(declaration["request_catalog"])
    assert len(requests) == 1
    request = _dict(requests[0])
    request_bytes = json.loads(
        __import__("base64").urlsafe_b64decode(cast("str", request["request_base64"]) + "==")
    )
    assert request["request_sha256"] == digest_bytes(
        __import__("base64").urlsafe_b64decode(cast("str", request["request_base64"]) + "==")
    )
    assert request_bytes == {
        "keep_alive": 0,
        "model": "qwen3:8b:local",
        "options": {
            "min_p": 0,
            "num_ctx": 8192,
            "num_predict": 64,
            "repeat_penalty": 1,
            "seed": 424242,
            "temperature": 0,
            "top_k": 1,
            "top_p": 1,
        },
        "prompt": ("Return exactly this ASCII text and nothing else: REPEATABILITY-ANCHOR-2026"),
        "raw": True,
        "shift": False,
        "stream": False,
        "think": False,
        "truncate": False,
    }
    schedule = _list(declaration["run_schedule"])
    assert [cast("dict[str, JsonValue]", item)["sequence"] for item in schedule] == [
        1,
        2,
        3,
        4,
        5,
    ]
    assert [cast("dict[str, JsonValue]", item)["run_id"] for item in schedule] == [
        f"anchor-repeat-{index:03d}" for index in range(1, 6)
    ]
    for run_value in schedule:
        scheduled_run = _dict(run_value)
        assert scheduled_run["cache_cohort"] == "cold_model_warm_process"
        assert scheduled_run["concurrency"] == 1
        assert scheduled_run["attempt_limit"] == 1
        assert scheduled_run["retry_count"] == 0
        assert scheduled_run["selective_rerun"] == "forbidden"
        actions = _list(scheduled_run["action_schedule"])
        assert len(actions) == 9
        assert _dict(actions[4])["operation"] == "generate"
        assert _dict(actions[4])["request_sha256"] == request["request_sha256"]


def test_exact_packages_are_embedded_content_bound_and_complete(tmp_path: Path) -> None:
    spec, packages = _bound_study(tmp_path / "bound")
    declaration = build_study_declaration(spec, prospective_packages=packages)
    assert verify_study_declaration(declaration) == declaration
    assert declaration["prospective_packages"] == packages
    bindings = [_dict(item) for item in _list(declaration["prospective_package_bindings"])]
    assert [binding["binding_status"] for binding in bindings] == [
        "exact_verified_package",
        "exact_verified_package",
    ]
    assert all(binding["package_id"] is not None for binding in bindings)
    completeness = _dict(_dict(declaration["eligibility"])["declaration_completeness"])
    assert completeness == {"status": "complete", "missing_fields": []}
    authorization = _dict(declaration["authorization_plan"])
    assert authorization["all_nonce_commitments_content_bound"] is True
    metadata_preflight = _dict(authorization["metadata_preflight"])
    assert metadata_preflight["run_id"] == bindings[0]["run_id"]
    assert metadata_preflight["package_id"] == bindings[0]["package_id"]
    assert metadata_preflight["nonce_sha256"] == bindings[0]["preflight_nonce_sha256"]
    assert metadata_preflight["currently_authorized"] is False
    custody = _dict(declaration["custody_policy"])
    assert custody["output_root_binding"] == "declared_output_root_identity_unverified_instance"
    analysis = _dict(declaration["analysis_policy"])
    assert "package_id" not in _list(analysis["grouping_keys"])
    assert analysis["per_run_provenance"] == [
        "package_id",
        "execution_declaration_id",
    ]


@pytest.mark.parametrize(
    ("section", "field", "value"),
    [
        ("runtime", "artifact_sha256", digest_bytes(b"wrong-runtime")),
        ("runtime", "selected_internal_runner", "wrong-runner"),
        ("runtime", "metal_state", "disabled"),
        ("runtime", "build_info", "wrong-build"),
        ("model", "manifest_bytes_sha256", digest_bytes(b"wrong-manifest")),
        ("model", "config_sha256", digest_bytes(b"wrong-config")),
        ("model", "layer_digests", [digest_bytes(b"wrong-layer")]),
        ("model", "artifact_closure_sha256", digest_bytes(b"wrong-closure")),
    ],
)
def test_exact_packages_reject_declared_identity_contradictions(
    tmp_path: Path,
    section: str,
    field: str,
    value: JsonValue,
) -> None:
    spec, packages = _bound_study(tmp_path / f"identity-{section}-{field}")
    known = _dict(_dict(spec["known_identity"])[section])
    known[field] = value
    with pytest.raises(ContractError, match="drift"):
        build_study_declaration(spec, prospective_packages=packages)


def test_exact_packages_reject_partial_duplicate_and_policy_drift(tmp_path: Path) -> None:
    spec, packages = _bound_study(tmp_path / "coverage")
    with pytest.raises(ContractError, match="cover every declared run"):
        build_study_declaration(spec, prospective_packages=packages[:1])
    with pytest.raises(ContractError, match="run IDs must be unique"):
        build_study_declaration(spec, prospective_packages=[packages[0], packages[0]])

    warm_spec, warm_packages = _bound_study(
        tmp_path / "warm",
        cache_cohort="warm_prompt_kv_cache",
        cache_support="unsupported",
        disposition="model_execution_forbidden",
    )
    with pytest.raises(ContractError, match="cache cohort drift"):
        build_study_declaration(warm_spec, prospective_packages=warm_packages)

    timeout_spec, timeout_packages = _bound_study(
        tmp_path / "timeout",
        package_deadline_ms=1,
    )
    with pytest.raises(ContractError, match="deadline drift"):
        build_study_declaration(timeout_spec, prospective_packages=timeout_packages)


@pytest.mark.parametrize(
    ("mixed_identity", "field"),
    [
        ("runtime", "runtime_id"),
        ("model", "model_id"),
        ("host", "host_id"),
    ],
)
def test_exact_packages_require_singleton_repeatability_identities(
    tmp_path: Path,
    mixed_identity: str,
    field: str,
) -> None:
    spec, packages = _bound_study(
        tmp_path / f"mixed-{mixed_identity}",
        mixed_identity=mixed_identity,
    )
    with pytest.raises(ContractError, match=rf"must share one {field}"):
        build_study_declaration(spec, prospective_packages=packages)


def _top_unknown(value: dict[str, JsonValue]) -> None:
    value["unknown"] = True


def _nested_unknown(value: dict[str, JsonValue]) -> None:
    _dict(value["study_spec"])["runtime_path"] = "mutable-runtime-alias"


def _foundation_drift(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["contract_binding"])["descriptor"])["foundation_commit"] = "0" * 40


def _request_drift(value: dict[str, JsonValue]) -> None:
    _dict(_list(value["request_catalog"])[0])["request_sha256"] = digest_bytes(b"drift")


def _schedule_order_drift(value: dict[str, JsonValue]) -> None:
    schedule = _list(value["run_schedule"])
    schedule[0], schedule[1] = schedule[1], schedule[0]


def _retry_drift(value: dict[str, JsonValue]) -> None:
    _dict(_list(value["run_schedule"])[0])["retry_count"] = 1


def _cache_drift(value: dict[str, JsonValue]) -> None:
    _dict(_list(value["run_schedule"])[0])["cache_cohort"] = "warm_prompt_kv_cache"


def _analysis_claim_drift(value: dict[str, JsonValue]) -> None:
    _dict(value["analysis_policy"])["ttft"] = "available"


def _authorization_forgery(value: dict[str, JsonValue]) -> None:
    metadata = _dict(_dict(value["authorization_plan"])["metadata_preflight"])
    metadata["currently_authorized"] = True


def _metadata_preflight_run_drift(value: dict[str, JsonValue]) -> None:
    metadata = _dict(_dict(value["authorization_plan"])["metadata_preflight"])
    metadata["run_id"] = "anchor-repeat-002"


def _metadata_preflight_package_forgery(value: dict[str, JsonValue]) -> None:
    metadata = _dict(_dict(value["authorization_plan"])["metadata_preflight"])
    metadata["package_id"] = digest_bytes(b"forged-package")


def _metadata_preflight_nonce_forgery(value: dict[str, JsonValue]) -> None:
    metadata = _dict(_dict(value["authorization_plan"])["metadata_preflight"])
    metadata["nonce_sha256"] = digest_bytes(b"forged-preflight-nonce")


def _output_root_forgery(value: dict[str, JsonValue]) -> None:
    _dict(value["custody_policy"])["output_root_id"] = digest_bytes(b"forged")


def _eligibility_forgery(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["eligibility"])["observed_generation"])["decision"] = "eligible"


def _attestation_forgery(value: dict[str, JsonValue]) -> None:
    gate = _dict(value["attestation_gate"])
    gate["schema_status"] = "available"
    gate["listener_owner_attestation_id"] = digest_bytes(b"forged-listener")


def _bool_integer_identity_ambiguity(value: dict[str, JsonValue]) -> None:
    _dict(value["non_actions"])["socket_calls"] = False


@pytest.mark.parametrize(
    "mutate",
    [
        _top_unknown,
        _nested_unknown,
        _foundation_drift,
        _request_drift,
        _schedule_order_drift,
        _retry_drift,
        _cache_drift,
        _analysis_claim_drift,
        _authorization_forgery,
        _metadata_preflight_run_drift,
        _metadata_preflight_package_forgery,
        _metadata_preflight_nonce_forgery,
        _output_root_forgery,
        _eligibility_forgery,
        _attestation_forgery,
        _bool_integer_identity_ambiguity,
    ],
)
def test_declaration_rejects_tampering(
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    tampered = _copy(build_study_declaration(qwen3_repeatability_study_spec()))
    mutate(tampered)
    with pytest.raises(ContractError):
        verify_study_declaration(tampered)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("study_design", "cache_cohorts"), ["warm_prompt_kv_cache"]),
        (("study_design", "concurrency"), 2),
        (("study_design", "attempts_per_run"), 2),
        (("study_design", "selective_reruns"), "allowed"),
        (("study_design", "hidden_warmups"), "allowed"),
        (("transport", "retries"), 1),
        (("transport", "redirects"), "allowed"),
        (("transport", "proxies"), "environment"),
        (("request_controls", "raw"), False),
        (("request_controls", "stream"), True),
        (("request_controls", "shift"), True),
        (("request_controls", "truncate"), True),
        (("request_controls", "keep_alive_seconds"), 1),
        (("request_controls", "keep_alive_seconds"), False),
        (("request_controls", "think_mode"), []),
        (("request_controls", "think_mode"), {}),
        (("request_controls", "think_mode"), False),
        (("transport", "retries"), False),
        (("study_design", "concurrency"), True),
        (("study_design", "attempts_per_run"), True),
    ],
)
def test_study_spec_rejects_policy_weakening(
    path: tuple[str, str],
    value: JsonValue,
) -> None:
    spec = _copy(qwen3_repeatability_study_spec())
    _dict(spec[path[0]])[path[1]] = value
    with pytest.raises(ContractError):
        build_study_declaration(spec)


def test_study_spec_rejects_noncanonical_digest_and_schedule_expansion() -> None:
    invalid_digest = _copy(qwen3_repeatability_study_spec())
    _dict(_dict(invalid_digest["known_identity"])["model"])["manifest_digest"] = "sha256:+" + (
        "a" * 63
    )
    with pytest.raises(ContractError, match="lowercase prefixed SHA-256"):
        build_study_declaration(invalid_digest)

    excessive_repeats = _copy(qwen3_repeatability_study_spec())
    _dict(excessive_repeats["study_design"])["repeats_per_prompt"] = 101
    with pytest.raises(ContractError, match="cannot exceed 100"):
        build_study_declaration(excessive_repeats)

    excessive_prompts = _copy(qwen3_repeatability_study_spec())
    original = _dict(_list(excessive_prompts["prompt_catalog"])[0])
    excessive_prompts["prompt_catalog"] = [
        {**original, "prompt_id": f"prompt-{index:02d}"} for index in range(17)
    ]
    with pytest.raises(ContractError, match="cannot exceed 16"):
        build_study_declaration(excessive_prompts)


def test_declaration_construction_and_replay_never_create_a_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_socket(*_args: object, **_kwargs: object) -> socket.socket:
        raise AssertionError("declaration construction must not create a socket")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    first_path, first_result = compile_declaration_fixture(first)
    second_path, second_result = compile_declaration_fixture(second)
    assert first_path.name == second_path.name
    assert first_result == second_result
    assert first_result.declaration_complete is False
    assert first_result.physical_network_requests == 0
    assert first_result.model_actions == 0
    assert replay_declaration_fixture(first_path) == first_result
    first_files = read_closed_bundle(first_path)[1]
    second_files = read_closed_bundle(second_path)[1]
    assert first_files == second_files


def test_replay_rejects_coordinated_fixture_tampering(tmp_path: Path) -> None:
    original_root = tmp_path / "original"
    tampered_root = tmp_path / "tampered"
    original_root.mkdir()
    tampered_root.mkdir()
    original, _result = compile_declaration_fixture(original_root)
    _content_root, files = read_closed_bundle(original)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    declaration = _copy(json.loads(content["declaration.json"]))
    _dict(_dict(declaration["eligibility"])["observed_generation"])[
        "authorization_may_be_consumed"
    ] = True
    content["declaration.json"] = canonical_json(declaration)
    republished = publish_bundle(content, tampered_root, name_prefix="tampered-declaration")
    with pytest.raises(ContractError):
        replay_declaration_fixture(republished)


def test_replay_rejects_noncanonical_and_type_ambiguous_fixture_bytes(
    tmp_path: Path,
) -> None:
    original_root = tmp_path / "original"
    tampered_root = tmp_path / "tampered"
    original_root.mkdir()
    tampered_root.mkdir()
    original, _result = compile_declaration_fixture(original_root)
    _content_root, files = read_closed_bundle(original)
    base_content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }

    wrong_type = dict(base_content)
    source = _copy(json.loads(wrong_type["source/fixture.json"]))
    source["observed_hardware_evidence"] = 0
    source["socket_calls"] = False
    wrong_type["source/fixture.json"] = canonical_json(source)
    wrong_type_bundle = publish_bundle(
        wrong_type,
        tampered_root,
        name_prefix="wrong-type-declaration",
    )
    with pytest.raises(ContractError, match="non-actions drift"):
        replay_declaration_fixture(wrong_type_bundle)

    noncanonical = dict(base_content)
    spec = json.loads(noncanonical["source/study-spec.json"])
    noncanonical["source/study-spec.json"] = json.dumps(
        spec,
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    ).encode()
    noncanonical_bundle = publish_bundle(
        noncanonical,
        tampered_root,
        name_prefix="noncanonical-declaration",
    )
    with pytest.raises(ContractError, match="canonical JSON bytes"):
        replay_declaration_fixture(noncanonical_bundle)


def test_declaration_cli_create_verify_inspect_and_replay(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    spec = tmp_path / "spec.json"
    declaration = tmp_path / "declaration.json"
    assert run(["ollama", "declaration-spec"]) == 0
    emitted_spec = _output(capfd)
    assert emitted_spec == qwen3_repeatability_study_spec()
    spec.write_bytes(canonical_json(emitted_spec))

    assert run(["ollama", "declaration-create", str(spec), str(declaration)]) == 0
    created = _output(capfd)
    assert created["status"] == "created"
    assert created["declaration_complete"] is False
    assert created["physical_network_requests"] == 0
    assert created["model_actions"] == 0
    assert load_study_declaration(declaration)["declaration_id"] == created["declaration_id"]

    assert run(["ollama", "declaration-verify", str(declaration)]) == 0
    verified = _output(capfd)
    assert verified["status"] == "valid"
    assert verified["scheduled_runs"] == 5

    assert run(["ollama", "declaration-inspect", str(declaration)]) == 0
    inspected = _output(capfd)
    assert inspected["status"] == "inspected"
    assert _dict(inspected["observed_generation"])["decision"] == "ineligible"

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    assert run(["ollama", "declaration-fixture-compile", str(fixture_root)]) == 0
    compiled = _output(capfd)
    bundle = fixture_root / cast("str", compiled["path"])
    assert compiled["evidence_status"] == "synthetic_declaration_contract_evidence_only"
    assert run(["ollama", "declaration-replay", str(bundle)]) == 0
    replayed = _output(capfd)
    assert replayed["status"] == "replayed"
    assert replayed["bundle_root"] == compiled["bundle_root"]
    assert replayed["external_network_actions"] == 0
