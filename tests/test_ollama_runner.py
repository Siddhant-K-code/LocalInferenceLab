"""Adversarial tests for the fail-closed Ollama runner and fake transport."""

from __future__ import annotations

import http.client
import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.ollama as ollama_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
)
from localinferencelab.cli import run
from localinferencelab.contracts import (
    Fact,
    HostIdentity,
    ModelIdentity,
    RuntimeFact,
    RuntimeIdentity,
)
from localinferencelab.custody import publish_bundle
from localinferencelab.ollama import (
    EndpointIdentity,
    FakeTransport,
    LoopbackHTTPTransport,
    TransportFailureError,
    TransportRequest,
    TransportResponse,
    build_generate_request,
    build_prospective_package,
    execute_observed,
    execute_synthetic,
    initialize_output_root,
    inspect_model_artifacts,
    make_authorization,
    output_root_identity,
    preflight_synthetic,
    read_authorization_nonce,
    replay_ollama_bundle,
    verify_prospective_package,
    write_authorization,
    write_prospective_package,
)
from localinferencelab.ollama_fixture import compile_ollama_contract_fixtures

_JSON_CONTENT_TYPE = "application/json"
_PREFLIGHT_NONCE = "test-preflight-authorization-nonce-000001"
_IDENTITY_NONCE = "test-identity-authorization-nonce-0000001"
_GENERATION_NONCE = "test-generation-authorization-nonce-00001"


def _write_artifacts(root: Path) -> tuple[Path, Path, Path]:
    runtime = root / "ollama"
    runtime.write_bytes(b"synthetic preinstalled ollama runtime")
    blob_root = root / "blobs"
    blob_root.mkdir()
    config = canonical_json({"architecture": "fixture", "context_length": 256})
    layer = b"synthetic preinstalled model layer"
    config_digest = digest_bytes(config)
    layer_digest = digest_bytes(layer)
    (blob_root / config_digest.replace(":", "-", 1)).write_bytes(config)
    (blob_root / layer_digest.replace(":", "-", 1)).write_bytes(layer)
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
    return runtime, manifest_path, blob_root


def _show_body() -> dict[str, JsonValue]:
    return {
        "modelfile": "FROM fixture",
        "parameters": "temperature 0",
        "template": "{{ .Prompt }}",
        "details": {
            "family": "fixture",
            "parameter_size": "tiny",
            "quantization_level": "synthetic",
        },
        "model_info": {
            "fixture.context_length": 256,
            "fixture.embedding_length": 8,
        },
        "thinking": {"values": [False], "default": False},
    }


def _show_projection() -> dict[str, JsonValue]:
    body = _show_body()
    return {
        "modelfile_sha256": digest_bytes(cast("str", body["modelfile"]).encode()),
        "parameters_sha256": digest_bytes(cast("str", body["parameters"]).encode()),
        "template_sha256": digest_bytes(cast("str", body["template"]).encode()),
        "details_sha256": canonical_identity(body["details"]),
        "model_info_sha256": canonical_identity(body["model_info"]),
        "thinking_sha256": canonical_identity(body["thinking"]),
    }


def _make_package(
    root: Path,
    *,
    output_nonce: str = "fixture-output-root",
    synthetic_output_root: bool = False,
) -> tuple[
    ollama_module.VerifiedPackage,
    Path,
    Path,
    Path,
    Path,
]:
    root.mkdir()
    runtime_path, manifest_path, blob_root = _write_artifacts(root)
    output_root = root / "output"
    output_root.mkdir(mode=0o700)
    output_root_id = initialize_output_root(
        output_root,
        output_nonce,
        synthetic_fixture=synthetic_output_root,
    )
    artifact = inspect_model_artifacts(manifest_path, blob_root)
    runtime = RuntimeIdentity(
        "runtime_identity",
        "1.0",
        "ollama",
        "observed_execution",
        "ollama",
        None,
        "0.12.0",
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
    model = ModelIdentity(
        "model_identity",
        "1.0",
        "ollama",
        "ollama_manifest",
        "observed_execution",
        "fixture-model-representation",
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
        "non_apple_ci",
        "fixture-architecture",
        "fixture-chip",
        4,
        8,
        16_000_000_000,
        "fixture-os",
        "1.0",
        "fixture-build",
        (
            Fact("probe_method", "synthetic-test-input"),
            Fact("apple_silicon_eligible", "false"),
        ),
    )
    prompt = b"Return one synthetic fixture response."
    spec: dict[str, JsonValue] = {
        "record_type": "ollama_study_spec",
        "schema_version": "1.0",
        "study_name": "synthetic-ollama-contract-study",
        "run_id": "ollama-synthetic-001",
        "endpoint": {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 11434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        },
        "runtime": runtime.to_dict(),
        "model": model.to_dict(),
        "host": host.to_dict(),
        "model_name": "fixture-model:local",
        "prompt_base64": encode_bytes(prompt),
        "prompt_sha256": digest_bytes(prompt),
        "template_sha256": digest_bytes(b"raw-mode-no-template"),
        "raw_mode": True,
        "think_mode": "false",
        "sampler": {
            "seed": 4242,
            "temperature_millionths": 0,
            "top_p_millionths": 1_000_000,
            "top_k": 1,
            "min_p_millionths": 0,
            "repeat_penalty_millionths": 1_000_000,
        },
        "context_tokens": 256,
        "max_output_tokens": 8,
        "keep_alive_seconds": 0,
        "cache_cohort": "cold_model_warm_process",
        "cache_support": "supported",
        "cache_evidence_sha256": digest_bytes(b"model absent from exact ps projection"),
        "show_projection": _show_projection(),
        "process_instance_label": "preexisting-loopback-runtime-1",
        "model_instance_label": "one-cold-load-1",
        "timeout_ms": 1_000,
        "max_identity_response_bytes": 32_768,
        "max_generate_response_bytes": 65_536,
        "output_root_id": output_root_id,
        "authorization_nonce_sha256": {
            "preflight_only": digest_bytes(_PREFLIGHT_NONCE.encode()),
            "identity_guard": digest_bytes(_IDENTITY_NONCE.encode()),
            "generation": digest_bytes(_GENERATION_NONCE.encode()),
        },
        "disposition": "authorized",
    }
    value = build_prospective_package(
        spec,
        runtime_artifact=runtime_path,
        model_manifest=manifest_path,
        blob_root=blob_root,
    )
    return (
        verify_prospective_package(value),
        runtime_path,
        manifest_path,
        blob_root,
        output_root,
    )


def _response(
    value: JsonValue, *, status: int = 200, content_type: str = _JSON_CONTENT_TYPE
) -> TransportResponse:
    return TransportResponse(status, content_type, canonical_json(value), "127.0.0.1")


def _identity_responses(
    package: ollama_module.VerifiedPackage,
    *,
    version: str | None = None,
    loaded: bool = False,
) -> list[TransportResponse]:
    ps_models: list[JsonValue] = []
    if loaded:
        ps_models.append(
            {
                "name": package.canonical_model_name,
                "digest": package.model_artifact.manifest_digest,
            },
        )
    return [
        _response({"version": version or package.runtime.version}),
        _response(
            {
                "models": [
                    {
                        "name": package.canonical_model_name,
                        "digest": package.model_artifact.manifest_digest,
                    },
                ],
            },
        ),
        _response(_show_body()),
        _response({"models": ps_models}),
    ]


def _generate_response(package: ollama_module.VerifiedPackage) -> TransportResponse:
    return _response(
        {
            "model": package.canonical_model_name,
            "created_at": "2026-01-01T00:00:00Z",
            "response": "synthetic response",
            "done": True,
            "done_reason": "length",
            "total_duration": 100,
            "load_duration": 10,
            "prompt_eval_count": 7,
            "prompt_eval_duration": 20,
            "eval_count": 4,
            "eval_duration": 70,
        },
    )


def _accepted_transport(package: ollama_module.VerifiedPackage) -> FakeTransport:
    return FakeTransport(
        [
            *_identity_responses(package),
            _generate_response(package),
            *_identity_responses(package),
        ],
    )


def _execute_fixture(
    package: ollama_module.VerifiedPackage,
    runtime: Path,
    manifest: Path,
    blobs: Path,
    output: Path,
    transport: FakeTransport,
    *,
    prefix: str,
) -> ollama_module.ExecutionResult:
    return execute_synthetic(
        package=package,
        identity_authorization=make_authorization(package, "identity_guard", _IDENTITY_NONCE),
        generation_authorization=make_authorization(package, "generation", _GENERATION_NONCE),
        output_root=output,
        runtime_artifact=runtime,
        model_manifest=manifest,
        blob_root=blobs,
        transport=transport,
        bundle_prefix=prefix,
    )


def _bundle_files(path: Path) -> dict[str, bytes]:
    return {
        item.relative_to(path).as_posix(): item.read_bytes()
        for item in path.rglob("*")
        if item.is_file()
    }


def _repack_with_json_change(
    source: Path,
    destination_root: Path,
    file_name: str,
    change: Callable[[dict[str, object]], None],
) -> Path:
    evidence = {
        name: data
        for name, data in _bundle_files(source).items()
        if name not in {"index.json", "receipt.json"}
    }
    value = json.loads(evidence[file_name])
    change(value)
    evidence[file_name] = canonical_json(value)
    destination_root.mkdir(mode=0o700)
    return publish_bundle(evidence, destination_root, name_prefix="tampered")


def _repack_with_file_change(
    source: Path,
    destination_root: Path,
    change: Callable[[dict[str, bytes]], None],
) -> Path:
    evidence = {
        name: data
        for name, data in _bundle_files(source).items()
        if name not in {"index.json", "receipt.json"}
    }
    change(evidence)
    destination_root.mkdir(mode=0o700)
    return publish_bundle(evidence, destination_root, name_prefix="tampered")


def test_request_builder_has_an_exact_closed_contract() -> None:
    request = build_generate_request(
        model_name="fixture-model:local",
        prompt=b"hello",
        think_mode="false",
        seed=7,
        temperature_millionths=0,
        top_p_millionths=1_000_000,
        top_k=1,
        min_p_millionths=0,
        repeat_penalty_millionths=1_000_000,
        context_tokens=256,
        max_output_tokens=8,
        keep_alive_seconds=0,
    )
    assert request == (
        b'{"keep_alive":0,"model":"fixture-model:local",'
        b'"options":{"min_p":0,"num_ctx":256,"num_predict":8,"repeat_penalty":1,'
        b'"seed":7,"temperature":0,"top_k":1,"top_p":1},'
        b'"prompt":"hello","raw":true,"shift":false,"stream":false,"think":false,'
        b'"truncate":false}'
    )
    assert json.loads(request)["options"] == {
        "min_p": 0,
        "num_ctx": 256,
        "num_predict": 8,
        "repeat_penalty": 1,
        "seed": 7,
        "temperature": 0,
        "top_k": 1,
        "top_p": 1,
    }


@pytest.mark.parametrize(
    "endpoint",
    [
        {
            "scheme": "http",
            "host": "localhost",
            "port": 11434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        },
        {
            "scheme": "https",
            "host": "127.0.0.1",
            "port": 11434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        },
        {
            "scheme": "http",
            "host": "user@127.0.0.1",
            "port": 11434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        },
    ],
)
def test_endpoint_rejects_dns_tls_and_credentials(endpoint: dict[str, JsonValue]) -> None:
    with pytest.raises(ContractError):
        EndpointIdentity.from_value(endpoint)


def test_direct_transport_ignores_proxy_environment_and_rejects_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, int]] = []

    class FakeSocket:
        def getpeername(self) -> tuple[str, int]:
            return ("127.0.0.1", 11434)

    class FakeHeaders:
        def get_all(self, _name: str) -> list[str]:
            return []

    class FakeResponse:
        headers = FakeHeaders()
        status = 302

        def getheader(self, name: str) -> str | None:
            return "http://example.invalid/" if name == "Location" else None

    class FakeConnection:
        def __init__(self, host: str, port: int, *, timeout: float) -> None:
            del timeout
            calls.append((host, port))
            self.sock: FakeSocket | None = None

        def connect(self) -> None:
            self.sock = FakeSocket()

        def request(
            self,
            _method: str,
            _path: str,
            *,
            body: bytes,
            headers: dict[str, str],
        ) -> None:
            del body, headers

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setenv("HTTP_PROXY", "http://example.invalid:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://example.invalid:8080")
    monkeypatch.setattr(http.client, "HTTPConnection", FakeConnection)
    endpoint = EndpointIdentity.from_value(
        {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 11434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        },
    )
    with pytest.raises(TransportFailureError, match="redirect"):
        LoopbackHTTPTransport(endpoint).request(
            TransportRequest("version", "GET", "/api/version", b"", 100, 100, 101),
        )
    assert calls == [("127.0.0.1", 11434)]


def test_direct_transport_rejects_connected_peer_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_called = False

    class DriftSocket:
        def getpeername(self) -> tuple[str, int]:
            return ("192.0.2.1", 11434)

    class DriftConnection:
        def __init__(self, _host: str, _port: int, *, timeout: float) -> None:
            del timeout
            self.sock: DriftSocket | None = None

        def connect(self) -> None:
            self.sock = DriftSocket()

        def request(self, *_args: object, **_kwargs: object) -> None:
            nonlocal request_called
            request_called = True

        def close(self) -> None:
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", DriftConnection)
    endpoint = EndpointIdentity.from_value(
        {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 11434,
            "version_path": "/api/version",
            "tags_path": "/api/tags",
            "show_path": "/api/show",
            "ps_path": "/api/ps",
            "generate_path": "/api/generate",
        },
    )
    with pytest.raises(TransportFailureError, match="exact pinned loopback"):
        LoopbackHTTPTransport(endpoint).request(
            TransportRequest("version", "GET", "/api/version", b"", 100, 100, 101),
        )
    assert request_called is False


def test_package_freezes_artifacts_schedule_and_request_bytes(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, _output = _make_package(tmp_path / "package")
    assert package.request == decode_request(package)
    assert package.actions[4]["request_sha256"] == digest_bytes(package.request)
    assert package.actions[4]["path"] == "/api/generate"
    assert len(package.actions) == 9
    assert package.runtime.artifact_sha256 == digest_bytes(runtime.read_bytes())
    assert inspect_model_artifacts(manifest, blobs) == package.model_artifact
    assert package.value["evidence_status"] == "prospective_not_execution_evidence"


def test_model_artifact_inspection_rejects_remote_backing(tmp_path: Path) -> None:
    _runtime, manifest_path, blob_root = _write_artifacts(tmp_path)
    manifest = json.loads(manifest_path.read_bytes())
    remote_config = canonical_json(
        {
            "architecture": "fixture",
            "remote_host": "ollama.com",
            "remote_model": "private-model",
        },
    )
    remote_digest = digest_bytes(remote_config)
    (blob_root / remote_digest.replace(":", "-", 1)).write_bytes(remote_config)
    manifest["config"]["digest"] = remote_digest
    manifest["config"]["size"] = len(remote_config)
    manifest_path.write_bytes(canonical_json(manifest))
    with pytest.raises(ContractError, match="remote-backed"):
        inspect_model_artifacts(manifest_path, blob_root)


def decode_request(package: ollama_module.VerifiedPackage) -> bytes:
    protocol = cast("dict[str, JsonValue]", package.value["protocol"])
    return decode_bytes(cast("str", protocol["request_base64"]))


def test_mismatched_authorization_refuses_before_transport_or_output_write(
    tmp_path: Path,
) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "refuse")
    good_guard = make_authorization(package, "identity_guard", _IDENTITY_NONCE)
    bad_guard = replace(good_guard, package_id=digest_bytes(b"other-package"))
    transport = _accepted_transport(package)
    with pytest.raises(ContractError, match="authorization does not match"):
        execute_synthetic(
            package=package,
            identity_authorization=bad_guard,
            generation_authorization=make_authorization(
                package,
                "generation",
                _GENERATION_NONCE,
            ),
            output_root=output,
            runtime_artifact=runtime,
            model_manifest=manifest,
            blob_root=blobs,
            transport=transport,
            bundle_prefix="must-not-exist",
        )
    assert transport.requests == []
    assert not list(output.glob(".localinferencelab-consumed-*"))
    assert not list(output.glob("must-not-exist-*"))


def test_authorization_nonce_must_match_the_prospective_commitment(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "nonce-commitment")
    with pytest.raises(ContractError, match="prospective commitment"):
        make_authorization(
            package,
            "generation",
            "different-generation-authorization-nonce",
        )
    authorization = make_authorization(package, "generation", _GENERATION_NONCE)
    altered = replace(authorization, nonce_sha256=digest_bytes(b"different"))
    transport = _accepted_transport(package)
    with pytest.raises(ContractError, match="authorization does not match"):
        execute_synthetic(
            package=package,
            identity_authorization=make_authorization(package, "identity_guard", _IDENTITY_NONCE),
            generation_authorization=altered,
            output_root=output,
            runtime_artifact=runtime,
            model_manifest=manifest,
            blob_root=blobs,
            transport=transport,
            bundle_prefix="must-not-exist",
        )
    assert transport.requests == []
    altered_preimage = replace(authorization, nonce_base64=encode_bytes(b"different"))
    with pytest.raises(ContractError, match="authorization does not match"):
        execute_synthetic(
            package=package,
            identity_authorization=make_authorization(package, "identity_guard", _IDENTITY_NONCE),
            generation_authorization=altered_preimage,
            output_root=output,
            runtime_artifact=runtime,
            model_manifest=manifest,
            blob_root=blobs,
            transport=transport,
            bundle_prefix="must-not-exist",
        )
    duplicated = json.loads(canonical_json(package.value))
    commitments = duplicated["declaration"]["authorization_nonce_sha256"]
    commitments["generation"] = commitments["identity_guard"]
    with pytest.raises(ContractError, match="pairwise distinct"):
        verify_prospective_package(duplicated)


def test_authorization_nonce_file_must_be_owner_only_and_not_a_symlink(
    tmp_path: Path,
) -> None:
    nonce = tmp_path / "nonce"
    nonce.write_bytes(_GENERATION_NONCE.encode())
    nonce.chmod(0o644)
    with pytest.raises(ContractError, match="owner-only"):
        read_authorization_nonce(nonce)
    nonce.chmod(0o600)
    link = tmp_path / "nonce-link"
    link.symlink_to(nonce)
    with pytest.raises(ContractError, match="must not be a symlink"):
        read_authorization_nonce(link)


def test_output_root_marker_cannot_be_copied_to_another_directory(tmp_path: Path) -> None:
    original = tmp_path / "original"
    clone = tmp_path / "clone"
    original.mkdir(mode=0o700)
    clone.mkdir(mode=0o700)
    second = tmp_path / "second"
    second.mkdir(mode=0o700)
    output_id = initialize_output_root(original, "copy-resistant-output-root")
    assert initialize_output_root(second, "copy-resistant-output-root") != output_id
    (clone / ollama_module.OUTPUT_ROOT_MARKER).write_bytes(
        (original / ollama_module.OUTPUT_ROOT_MARKER).read_bytes()
    )
    assert output_root_identity(original) == output_id
    with pytest.raises(ContractError, match="directory instance"):
        output_root_identity(clone)


def test_accepted_fake_execution_is_exact_deterministic_and_replayable(
    tmp_path: Path,
) -> None:
    first = _make_package(
        tmp_path / "first",
        output_nonce="shared-output",
        synthetic_output_root=True,
    )
    second = _make_package(
        tmp_path / "second",
        output_nonce="shared-output",
        synthetic_output_root=True,
    )
    first_result = _execute_fixture(*first, _accepted_transport(first[0]), prefix="accepted")
    second_result = _execute_fixture(*second, _accepted_transport(second[0]), prefix="accepted")
    assert first_result.status == "accepted"
    assert first_result.run_validity == "valid"
    assert first_result.path.name == second_result.path.name
    assert _bundle_files(first_result.path) == _bundle_files(second_result.path)
    replay = replay_ollama_bundle(first_result.path)
    assert replay.status == "accepted"
    assert replay.evidence_kind == "synthetic_transport_contract_evidence"
    assert replay.action_count == 9
    assert replay.inference_request_count == 1
    assert replay.run_validity == "valid"


def test_authorization_consumption_is_durable_and_one_shot(tmp_path: Path) -> None:
    package_data = _make_package(tmp_path / "one-shot")
    _execute_fixture(
        *package_data,
        _accepted_transport(package_data[0]),
        prefix="first",
    )
    second_transport = _accepted_transport(package_data[0])
    with pytest.raises(FileExistsError):
        _execute_fixture(
            *package_data,
            second_transport,
            prefix="second",
        )
    assert second_transport.requests == []


@pytest.mark.parametrize("target", ["action", "snapshot", "run"])
def test_replay_rejects_semantically_repacked_execution_tampering(
    tmp_path: Path,
    target: str,
) -> None:
    package_data = _make_package(tmp_path / f"semantic-{target}")
    result = _execute_fixture(
        *package_data,
        _accepted_transport(package_data[0]),
        prefix="accepted",
    )
    if target == "action":
        file_name = "actions.json"

        def change(value: dict[str, object]) -> None:
            actions = cast("list[dict[str, object]]", value["actions"])
            actions[4]["response_sha256"] = digest_bytes(b"different")

    elif target == "snapshot":
        file_name = "identity/pre.json"

        def change(value: dict[str, object]) -> None:
            projection = cast("dict[str, object]", value["projection"])
            projection["runtime_version"] = "different"

    else:
        file_name = "runs/0001.json"

        def change(value: dict[str, object]) -> None:
            value["runtime_id"] = digest_bytes(b"different")

    repacked = _repack_with_json_change(
        result.path,
        tmp_path / f"repacked-{target}",
        file_name,
        change,
    )
    with pytest.raises(ContractError):
        replay_ollama_bundle(repacked)


def test_replay_rejects_observed_execution_without_attestation_schema(
    tmp_path: Path,
) -> None:
    package_data = _make_package(tmp_path / "observed-replay")
    result = _execute_fixture(
        *package_data,
        _accepted_transport(package_data[0]),
        prefix="accepted",
    )

    def change(source: dict[str, object]) -> None:
        source["evidence_kind"] = "observed_execution"
        source["implementation_evidence_only"] = False

    repacked = _repack_with_json_change(
        result.path,
        tmp_path / "observed-repacked",
        "source/ollama.json",
        change,
    )
    with pytest.raises(ContractError, match="observed execution replay is disabled"):
        replay_ollama_bundle(repacked)


@pytest.mark.parametrize("target", ["pre_snapshot", "response_bytes", "reason"])
def test_invalid_replay_requires_complete_producer_custody(
    tmp_path: Path,
    target: str,
) -> None:
    package_data = _make_package(tmp_path / f"invalid-custody-{target}")
    package = package_data[0]
    result = _execute_fixture(
        *package_data,
        FakeTransport(
            [
                *_identity_responses(package),
                TransportResponse(200, _JSON_CONTENT_TYPE, b"{", "127.0.0.1"),
                *_identity_responses(package),
            ]
        ),
        prefix="invalid",
    )
    if target in {"pre_snapshot", "response_bytes"}:
        missing_name = (
            "identity/pre.json" if target == "pre_snapshot" else "responses/generation.bin"
        )

        def remove_file(files: dict[str, bytes]) -> None:
            files.pop(missing_name)

        repacked = _repack_with_file_change(
            result.path,
            tmp_path / f"invalid-repacked-{target}",
            remove_file,
        )
    else:

        def change_reason(run: dict[str, object]) -> None:
            run["invalid_reason_sha256"] = digest_bytes(b"different")

        repacked = _repack_with_json_change(
            result.path,
            tmp_path / "invalid-repacked-reason",
            "runs/0001.json",
            change_reason,
        )
    with pytest.raises(ContractError):
        replay_ollama_bundle(repacked)


def test_invalid_replay_rejects_successful_truncated_post_prefix(
    tmp_path: Path,
) -> None:
    package_data = _make_package(tmp_path / "invalid-truncated-post")
    package = package_data[0]
    result = _execute_fixture(
        *package_data,
        FakeTransport(
            [
                *_identity_responses(package),
                TransportResponse(200, _JSON_CONTENT_TYPE, b"{", "127.0.0.1"),
                *_identity_responses(package),
            ]
        ),
        prefix="invalid",
    )

    def truncate(files: dict[str, bytes]) -> None:
        action_log = json.loads(files["actions.json"])
        actions = action_log["actions"][:6]
        action_log["actions"] = actions
        action_log["request_bytes_consumed"] = sum(
            action["request_size_bytes"] for action in actions
        )
        action_log["response_bytes_consumed"] = sum(
            action["response_size_bytes"] for action in actions
        )
        action_log["response_budget_reserved"] = sum(
            cast("int", action["response_read_budget_bytes"]) for action in package.actions[:6]
        )
        action_log["network_requests_consumed"] = 6
        action_log["identity_requests_consumed"] = 5
        action_log["inference_requests_consumed"] = 1
        files["actions.json"] = canonical_json(action_log)
        terminal = json.loads(files["terminal.json"])
        terminal["logical_identity_requests"] = 5
        files["terminal.json"] = canonical_json(terminal)
        files.pop("identity/post.json")

    repacked = _repack_with_file_change(
        result.path,
        tmp_path / "invalid-truncated-repacked",
        truncate,
    )
    with pytest.raises(ContractError, match="stopped without a failure"):
        replay_ollama_bundle(repacked)


def test_observed_generation_refuses_without_listener_attestation_before_socket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "attestation")

    def forbidden_connection(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("socket construction is forbidden")

    monkeypatch.setattr(http.client, "HTTPConnection", forbidden_connection)
    with pytest.raises(ContractError, match="mechanically attested"):
        execute_observed(
            package=package,
            identity_authorization=make_authorization(package, "identity_guard", _IDENTITY_NONCE),
            generation_authorization=make_authorization(package, "generation", _GENERATION_NONCE),
            output_root=output,
            runtime_artifact=runtime,
            model_manifest=manifest,
            blob_root=blobs,
        )
    assert not list(output.glob(".localinferencelab-consumed-*"))


def test_identity_drift_refuses_before_generation(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "drift")
    transport = FakeTransport(_identity_responses(package, version="different"))
    result = _execute_fixture(
        package,
        runtime,
        manifest,
        blobs,
        output,
        transport,
        prefix="refused",
    )
    assert result.status == "refused"
    assert [request.operation for request in transport.requests] == [
        "version",
        "tags",
        "show",
        "ps",
    ]
    replay = replay_ollama_bundle(result.path)
    assert replay.status == "refused"
    assert replay.inference_request_count == 0
    assert replay.run_validity is None
    assert not list(output.glob(".localinferencelab-consumed-*" + ".generation"))


@pytest.mark.parametrize(
    "generation_outcome",
    [
        TransportResponse(500, _JSON_CONTENT_TYPE, b"{}", "127.0.0.1"),
        TransportResponse(200, "text/plain", b"{}", "127.0.0.1"),
        TransportResponse(200, _JSON_CONTENT_TYPE, b"{", "127.0.0.1"),
        _response({"model": "fixture-model:local", "done": True}),
        TransportFailureError("synthetic timeout"),
    ],
)
def test_generation_failures_close_as_digest_safe_invalid_records(
    tmp_path: Path,
    generation_outcome: TransportResponse | Exception,
) -> None:
    package, runtime, manifest, blobs, output = _make_package(
        tmp_path / f"invalid-{digest_bytes(repr(generation_outcome).encode())[7:15]}",
    )
    transport = FakeTransport(
        [
            *_identity_responses(package),
            generation_outcome,
            *_identity_responses(package),
        ],
    )
    result = _execute_fixture(
        package,
        runtime,
        manifest,
        blobs,
        output,
        transport,
        prefix="invalid",
    )
    assert result.status == "invalid"
    assert result.run_validity == "invalid"
    replay = replay_ollama_bundle(result.path)
    assert replay.status == "invalid"
    run = json.loads((result.path / "runs/0001.json").read_bytes())
    assert run["validity"] == "invalid"
    assert run["envelope_base64"] is None
    assert run["text_utf8"] is None
    assert run["token_ids"] is None


def test_oversized_response_is_bounded_and_post_identity_still_runs(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "oversized")
    transport = FakeTransport(
        [
            *_identity_responses(package),
            TransportResponse(200, _JSON_CONTENT_TYPE, b"x" * 65_537, "127.0.0.1"),
            *_identity_responses(package),
        ],
    )
    result = _execute_fixture(
        package,
        runtime,
        manifest,
        blobs,
        output,
        transport,
        prefix="oversized",
    )
    assert result.status == "invalid"
    assert len(transport.requests) == 9
    assert [request.operation for request in transport.requests[5:]] == [
        "version",
        "tags",
        "show",
        "ps",
    ]
    actions = json.loads((result.path / "actions.json").read_bytes())
    generate = actions["actions"][4]
    assert generate["response_size_bytes"] == 65_537
    assert generate["response_complete"] is True
    assert actions["response_budget_reserved"] == sum(
        cast("int", action["response_read_budget_bytes"]) for action in package.actions
    )


def test_post_request_identity_drift_invalidates_an_otherwise_valid_response(
    tmp_path: Path,
) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "post-drift")
    transport = FakeTransport(
        [
            *_identity_responses(package),
            _generate_response(package),
            *_identity_responses(package, loaded=True),
        ],
    )
    result = _execute_fixture(
        package,
        runtime,
        manifest,
        blobs,
        output,
        transport,
        prefix="post-drift",
    )
    assert result.status == "invalid"
    run = json.loads((result.path / "runs/0001.json").read_bytes())
    assert run["validity"] == "invalid"
    assert run["raw_response_base64"] is None
    assert run["envelope_base64"] is None


def test_loaded_model_alias_with_same_manifest_is_not_claimed_cold(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "alias-loaded")
    post = _identity_responses(package)
    post[-1] = _response(
        {
            "models": [
                {
                    "name": "different-alias:latest",
                    "digest": package.model_artifact.manifest_digest,
                }
            ]
        }
    )
    result = _execute_fixture(
        package,
        runtime,
        manifest,
        blobs,
        output,
        FakeTransport(
            [
                *_identity_responses(package),
                _generate_response(package),
                *post,
            ]
        ),
        prefix="alias-loaded",
    )
    assert result.status == "invalid"
    assert replay_ollama_bundle(result.path).status == "invalid"


def test_budget_is_consumed_before_transport_side_effect() -> None:
    ledger = ollama_module.ActionBudgetLedger(
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    request = TransportRequest("version", "GET", "/api/version", b"", 1, 1, 2)
    with pytest.raises(ContractError, match="budget exhausted before action"):
        ledger.before(request, identity=True, inference=False)


def test_fake_transport_enforces_response_bound_before_returning_bytes() -> None:
    transport = FakeTransport(
        [TransportResponse(200, _JSON_CONTENT_TYPE, b"too-large", "127.0.0.1")],
    )
    with pytest.raises(TransportFailureError, match="byte budget"):
        transport.request(TransportRequest("version", "GET", "/api/version", b"", 1, 1, 2))


def test_package_rejects_request_body_and_budget_drift(tmp_path: Path) -> None:
    package, *_rest = _make_package(tmp_path / "tamper")
    request_drift = json.loads(canonical_json(package.value))
    request_drift["protocol"]["request_sha256"] = digest_bytes(b"different")
    with pytest.raises(ContractError, match="request-body bytes drifted"):
        verify_prospective_package(request_drift)

    budget_drift = json.loads(canonical_json(package.value))
    budget_drift["declaration"]["action_budget"]["network_requests"] = 10
    with pytest.raises(ContractError, match="action budget"):
        verify_prospective_package(budget_drift)


def test_redirect_status_is_refused_without_generation(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "redirect")
    responses = _identity_responses(package)
    responses[0] = TransportResponse(302, _JSON_CONTENT_TYPE, b"{}", "127.0.0.1")
    transport = FakeTransport(responses)
    result = _execute_fixture(
        package,
        runtime,
        manifest,
        blobs,
        output,
        transport,
        prefix="redirect",
    )
    assert result.status == "refused"
    assert all(request.operation != "generate" for request in transport.requests)


def test_separately_authorized_preflight_cannot_call_generation(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "preflight")
    transport = FakeTransport(_identity_responses(package))
    result = preflight_synthetic(
        package=package,
        authorization=make_authorization(package, "preflight_only", _PREFLIGHT_NONCE),
        output_root=output,
        runtime_artifact=runtime,
        model_manifest=manifest,
        blob_root=blobs,
        transport=transport,
        bundle_prefix="preflight",
    )
    assert result.status == "accepted"
    assert [request.operation for request in transport.requests] == [
        "version",
        "tags",
        "show",
        "ps",
    ]
    terminal = json.loads((result.path / "terminal.json").read_bytes())
    assert terminal["generation_path_called"] is False
    assert terminal["model_action_performed"] is False
    replay = replay_ollama_bundle(result.path)
    assert replay.status == "accepted"
    assert replay.action_count == 4
    assert replay.inference_request_count == 0


def test_refused_preflight_bundle_replays_without_generation(tmp_path: Path) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "preflight-refused")
    transport = FakeTransport(_identity_responses(package, version="different"))
    result = preflight_synthetic(
        package=package,
        authorization=make_authorization(package, "preflight_only", _PREFLIGHT_NONCE),
        output_root=output,
        runtime_artifact=runtime,
        model_manifest=manifest,
        blob_root=blobs,
        transport=transport,
        bundle_prefix="preflight-refused",
    )
    assert result.status == "refused"
    replay = replay_ollama_bundle(result.path)
    assert replay.status == "refused"
    assert replay.action_count == 4
    assert replay.inference_request_count == 0


def test_prospective_and_authorization_cli_are_offline(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    package, *_rest = _make_package(tmp_path / "cli")
    generated_nonce = tmp_path / "generated.nonce"
    assert (
        run(
            [
                "ollama",
                "authorization-nonce-init",
                str(generated_nonce),
            ]
        )
        == 0
    )
    generated = json.loads(capfd.readouterr().out)
    assert generated["nonce_sha256"] == digest_bytes(generated_nonce.read_bytes())
    assert generated_nonce.stat().st_mode & 0o077 == 0
    package_path = tmp_path / "package.json"
    authorization_path = tmp_path / "authorization.json"
    nonce_path = tmp_path / "generation.nonce"
    nonce_path.write_bytes(_GENERATION_NONCE.encode())
    nonce_path.chmod(0o600)
    write_prospective_package(package_path, package.value)
    assert run(["ollama", "prospective-verify", str(package_path)]) == 0
    verified = json.loads(capfd.readouterr().out)
    assert verified["package_id"] == package.identity
    assert verified["network_actions"] == 0
    assert (
        run(
            [
                "ollama",
                "authorize",
                str(package_path),
                "generation",
                str(authorization_path),
                "--nonce-file",
                str(nonce_path),
            ],
        )
        == 0
    )
    authorized = json.loads(capfd.readouterr().out)
    assert authorized["phase"] == "generation"
    assert authorized["model_actions"] == 0
    assert authorization_path.is_file()


def test_cli_execution_and_preflight_reject_mismatched_phase_before_transport(
    tmp_path: Path,
) -> None:
    package, runtime, manifest, blobs, output = _make_package(tmp_path / "cli-refusal")
    package_path = tmp_path / "cli-refusal-package.json"
    generation_path = tmp_path / "cli-generation.json"
    identity_path = tmp_path / "cli-identity.json"
    write_prospective_package(package_path, package.value)
    generation = make_authorization(package, "generation", _GENERATION_NONCE)
    identity = make_authorization(package, "identity_guard", _IDENTITY_NONCE)
    write_authorization(generation_path, generation)
    write_authorization(identity_path, identity)
    common = [
        str(package_path),
        str(output),
        "--runtime-artifact",
        str(runtime),
        "--model-manifest",
        str(manifest),
        "--blob-root",
        str(blobs),
    ]
    with pytest.raises(ContractError, match="preflight_only authorization"):
        run(
            [
                "ollama",
                "preflight",
                str(package_path),
                str(generation_path),
                *common[1:],
            ],
        )
    with pytest.raises(ContractError, match="identity_guard authorization"):
        run(
            [
                "ollama",
                "execute",
                str(package_path),
                str(generation_path),
                str(generation_path),
                *common[1:],
            ],
        )
    assert not list(output.glob(".localinferencelab-consumed-*"))


def test_output_root_fixture_and_evidence_cli_paths(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    initialized = tmp_path / "initialized"
    initialized.mkdir(mode=0o700)
    assert (
        run(
            [
                "ollama",
                "output-root-init",
                str(initialized),
                "--nonce",
                "cli-output-root",
            ],
        )
        == 0
    )
    assert json.loads(capfd.readouterr().out)["model_actions"] == 0

    fixture_root = tmp_path / "cli-fixtures"
    fixture_root.mkdir()
    assert run(["ollama", "fixture-compile", str(fixture_root)]) == 0
    summary = json.loads(capfd.readouterr().out)
    assert summary["evidence_status"] == "synthetic_transport_contract_evidence_only"
    accepted = next(item for item in summary["outcomes"] if item["outcome"] == "accepted")
    assert (
        run(
            [
                "ollama",
                "evidence-replay",
                str(fixture_root / accepted["path"]),
            ],
        )
        == 0
    )
    replay = json.loads(capfd.readouterr().out)
    assert replay["status"] == "accepted"
    assert replay["network_actions"] == 0


def test_recorded_fake_transport_bundles_are_deterministic(tmp_path: Path) -> None:
    first_root = tmp_path / "recorded-first"
    second_root = tmp_path / "recorded-second"
    first_root.mkdir()
    second_root.mkdir()
    first = compile_ollama_contract_fixtures(first_root)
    second = compile_ollama_contract_fixtures(second_root)
    assert first == second
    assert first["evidence_status"] == "synthetic_transport_contract_evidence_only"
    assert first["external_network_actions"] == 0
    outcomes = cast("list[dict[str, JsonValue]]", first["outcomes"])
    assert [item["outcome"] for item in outcomes] == ["accepted", "invalid", "refused"]
    for item in outcomes:
        first_bundle = first_root / cast("str", item["path"])
        second_bundle = second_root / cast("str", item["path"])
        assert _bundle_files(first_bundle) == _bundle_files(second_bundle)
        assert replay_ollama_bundle(first_bundle).bundle_root == item["bundle_root"]
