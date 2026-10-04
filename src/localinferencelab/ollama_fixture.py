"""Deterministic sealed-script Ollama contract evidence."""

from __future__ import annotations

from pathlib import Path
from typing import cast

from localinferencelab.canonical import JsonValue, canonical_identity, canonical_json, digest_bytes
from localinferencelab.contracts import (
    Fact,
    HostIdentity,
    ModelIdentity,
    RuntimeFact,
    RuntimeIdentity,
)
from localinferencelab.ollama import (
    TransportResponse,
    build_prospective_package,
    execute_synthetic,
    initialize_output_root,
    inspect_model_artifacts,
    make_authorization,
    replay_ollama_bundle,
    verify_prospective_package,
)

_CONTENT_TYPE = "application/json"


def _write_inputs(root: Path) -> tuple[Path, Path, Path]:
    inputs = root / ".synthetic-ollama-inputs"
    inputs.mkdir()
    runtime = inputs / "ollama"
    runtime.write_bytes(b"synthetic preinstalled ollama runtime")
    blobs = inputs / "blobs"
    blobs.mkdir()
    config = canonical_json({"architecture": "fixture", "context_length": 256})
    layer = b"synthetic preinstalled model layer"
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
    manifest_path = inputs / "manifest"
    manifest_path.write_bytes(manifest)
    return runtime, manifest_path, blobs


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


def _package(
    output_root_id: str,
    runtime_path: Path,
    manifest_path: Path,
    blob_root: Path,
    outcome: str,
) -> dict[str, JsonValue]:
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
        "run_id": f"ollama-synthetic-{outcome}",
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
        "prompt_base64": "UmV0dXJuIG9uZSBzeW50aGV0aWMgZml4dHVyZSByZXNwb25zZS4",
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
            "preflight_only": digest_bytes(
                f"{outcome}-fixture-preflight-authorization-nonce".encode()
            ),
            "identity_guard": digest_bytes(
                f"{outcome}-fixture-identity-authorization-nonce".encode()
            ),
            "generation": digest_bytes(
                f"{outcome}-fixture-generation-authorization-nonce".encode()
            ),
        },
        "disposition": "authorized",
    }
    return build_prospective_package(
        spec,
        runtime_artifact=runtime_path,
        model_manifest=manifest_path,
        blob_root=blob_root,
    )


def _response(value: JsonValue, *, status: int = 200) -> TransportResponse:
    return TransportResponse(status, _CONTENT_TYPE, canonical_json(value), "127.0.0.1")


def _identity_responses(
    package: dict[str, JsonValue],
    *,
    version: str = "0.12.0",
) -> list[TransportResponse]:
    verified = verify_prospective_package(package)
    return [
        _response({"version": version}),
        _response(
            {
                "models": [
                    {
                        "name": verified.canonical_model_name,
                        "digest": verified.model_artifact.manifest_digest,
                    },
                ],
            },
        ),
        _response(_show_body()),
        _response({"models": []}),
    ]


def _generate_response(package: dict[str, JsonValue]) -> TransportResponse:
    verified = verify_prospective_package(package)
    return _response(
        {
            "model": verified.canonical_model_name,
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


def compile_ollama_contract_fixtures(output_root: Path) -> dict[str, JsonValue]:
    """Publish accepted, invalid, and refused sealed-script evidence bundles."""
    runtime, manifest, blobs = _write_inputs(output_root)
    output_root_id = initialize_output_root(
        output_root,
        "synthetic-ollama-output-root",
        synthetic_fixture=True,
    )
    summaries: list[JsonValue] = []
    for outcome in ("accepted", "invalid", "refused"):
        package_value = _package(output_root_id, runtime, manifest, blobs, outcome)
        package = verify_prospective_package(package_value)
        if outcome == "accepted":
            outcomes = (
                *_identity_responses(package_value),
                _generate_response(package_value),
                *_identity_responses(package_value),
            )
        elif outcome == "invalid":
            outcomes = (
                *_identity_responses(package_value),
                TransportResponse(200, _CONTENT_TYPE, b"{", "127.0.0.1"),
                *_identity_responses(package_value),
            )
        else:
            outcomes = tuple(_identity_responses(package_value, version="identity-drift"))
        result = execute_synthetic(
            package=package,
            identity_authorization=make_authorization(
                package,
                "identity_guard",
                f"{outcome}-fixture-identity-authorization-nonce",
            ),
            generation_authorization=make_authorization(
                package,
                "generation",
                f"{outcome}-fixture-generation-authorization-nonce",
            ),
            output_root=output_root,
            runtime_artifact=runtime,
            model_manifest=manifest,
            blob_root=blobs,
            outcomes=outcomes,
            bundle_prefix=f"localinferencelab-ollama-{outcome}-synthetic-v1",
        )
        replay = replay_ollama_bundle(result.path)
        summaries.append(
            {
                "outcome": outcome,
                "path": result.path.name,
                "bundle_root": replay.bundle_root,
                "status": replay.status,
                "action_count": replay.action_count,
                "inference_request_count": replay.inference_request_count,
                "run_validity": replay.run_validity,
            },
        )
    return {
        "record_type": "ollama_synthetic_fixture_summary",
        "schema_version": "1.0",
        "evidence_status": "synthetic_transport_contract_evidence_only",
        "external_network_actions": 0,
        "model_actions": 0,
        "downloads": 0,
        "outcomes": summaries,
    }
