"""Deterministic synthetic fixture for the complete offline pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from localinferencelab.analysis import analyze_runs
from localinferencelab.canonical import (
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    encode_bytes,
)
from localinferencelab.contracts import (
    ActionBudget,
    Eligibility,
    ExecutionDeclaration,
    Fact,
    FixtureSource,
    HostIdentity,
    Measurement,
    ModelIdentity,
    NativeMetric,
    Protocol,
    RunRecord,
    RuntimeIdentity,
    SamplerControls,
    record_bytes,
    record_id,
)
from localinferencelab.custody import publish_bundle, replay_bundle


def _synthetic_digest(label: str) -> str:
    return digest_bytes(f"synthetic-fixture:{label}".encode())


def _metrics(backend: str, offset: int) -> tuple[NativeMetric, ...]:
    common = (
        NativeMetric("prompt_eval_count", 7, "tokens", "synthetic", None),
        NativeMetric("generation_count", 4, "tokens", "synthetic", None),
        NativeMetric(
            "generation_duration_ns",
            400_000_000 + offset,
            "nanoseconds",
            "synthetic",
            None,
        ),
        NativeMetric(
            "total_duration_ns",
            720_000_000 + offset,
            "nanoseconds",
            "synthetic",
            None,
        ),
        NativeMetric(
            "ttft_ns",
            None,
            "nanoseconds",
            "unavailable",
            "fixture backend did not expose a TTFT boundary",
        ),
    )
    if backend == "mlx-lm":
        return common + (
            NativeMetric(
                "load_duration_ns",
                None,
                "nanoseconds",
                "unavailable",
                "synthetic MLX-LM fixture does not model load duration",
            ),
        )
    return common + (
        NativeMetric(
            "load_duration_ns",
            120_000_000,
            "nanoseconds",
            "synthetic",
            None,
        ),
    )


def _measurements() -> tuple[Measurement, ...]:
    return (
        Measurement(
            "memory",
            "not_collected",
            None,
            "bytes",
            "unavailable",
            "fixture does not claim process, Metal, or GPU memory",
        ),
        Measurement(
            "energy",
            "not_collected",
            None,
            "microjoules",
            "unavailable",
            "v1 has no privileged reviewed energy protocol",
        ),
    )


def _make_run(
    *,
    run_id: str,
    order: int,
    backend: str,
    protocol_id: str,
    runtime_id: str,
    model_id: str,
    host_id: str,
    declaration_id: str,
    cache_cohort: str,
    text: str,
    tokens: tuple[int, ...],
    metric_offset: int,
) -> RunRecord:
    raw = text.encode()
    envelope = canonical_json(
        {
            "fixture_backend": backend,
            "finish_reason": "length",
            "response_text": text,
            "synthetic": True,
        },
    )
    request = canonical_json(
        {
            "backend": backend,
            "protocol_id": protocol_id,
            "runtime_id": runtime_id,
            "model_id": model_id,
            "cache_cohort": cache_cohort,
        },
    )
    return RunRecord(
        "run_record",
        "1.0",
        run_id,
        order,
        cast("Any", backend),
        protocol_id,
        runtime_id,
        model_id,
        host_id,
        declaration_id,
        cast("Any", cache_cohort),
        "synthetic_fixture",
        "valid",
        None,
        0,
        0,
        encode_bytes(request),
        digest_bytes(request),
        encode_bytes(raw),
        digest_bytes(raw),
        text,
        digest_bytes(text.encode()),
        tokens,
        canonical_identity(list(tokens)),
        "length",
        encode_bytes(envelope),
        digest_bytes(envelope),
        _metrics(backend, metric_offset),
        _measurements(),
    )


def fixture_content() -> dict[str, bytes]:
    """Build the deterministic source-custodied fixture content."""
    host = HostIdentity(
        "host_identity",
        "1.0",
        "synthetic_fixture",
        "non_apple_ci",
        "fixture-architecture",
        "fixture-chip-not-observed",
        4,
        8,
        17_179_869_184,
        "fixture-os",
        "1.0",
        "fixture-build",
        (
            Fact("fixture_only", "true"),
            Fact("apple_silicon_eligible", "false"),
        ),
    )
    runtimes = {
        "mlx-lm": RuntimeIdentity(
            "runtime_identity",
            "1.0",
            "mlx-lm",
            "synthetic_fixture",
            None,
            "mlx-lm",
            "fixture-0",
            None,
            None,
            _synthetic_digest("mlx-install-manifest"),
            ("fixture-no-execution",),
            ("synthetic capability surface only",),
            False,
        ),
        "llama.cpp": RuntimeIdentity(
            "runtime_identity",
            "1.0",
            "llama.cpp",
            "synthetic_fixture",
            "llama-server",
            None,
            "fixture-0",
            "fixture-commit",
            _synthetic_digest("llama-binary"),
            None,
            ("fixture-no-execution",),
            ("synthetic capability surface only",),
            False,
        ),
    }
    models = {
        "mlx-lm": ModelIdentity(
            "model_identity",
            "1.0",
            "mlx-lm",
            "mlx_snapshot",
            "synthetic_fixture",
            "fixture-family-mlx-representation",
            None,
            _synthetic_digest("mlx-file-manifest"),
            _synthetic_digest("mlx-config"),
            _synthetic_digest("mlx-tokenizer"),
            None,
            "unproven",
            None,
        ),
        "llama.cpp": ModelIdentity(
            "model_identity",
            "1.0",
            "llama.cpp",
            "gguf",
            "synthetic_fixture",
            "fixture-family-gguf-representation",
            _synthetic_digest("gguf-bytes"),
            None,
            None,
            _synthetic_digest("gguf-tokenizer-metadata"),
            _synthetic_digest("gguf-metadata"),
            "unproven",
            None,
        ),
    }
    host_id = record_id(host)
    runtime_ids = {backend: record_id(record) for backend, record in runtimes.items()}
    model_ids = {backend: record_id(record) for backend, record in models.items()}
    prompt = b"Reply with the fixture token sequence."
    protocol = Protocol(
        "protocol",
        "1.0",
        "synthetic-two-backend-repeatability-v1",
        encode_bytes(prompt),
        digest_bytes(prompt),
        _synthetic_digest("chat-template"),
        SamplerControls(4242, 0, 1_000_000, 1, 0, 1_000_000),
        4,
        512,
        ("cold_process_model", "warm_prompt_kv_cache"),
        2,
        "backend_blocked",
        ("mlx-lm", "llama.cpp"),
        1,
        30_000,
        0,
        tuple(sorted(runtime_ids.values())),
        tuple(sorted(model_ids.values())),
        (host_id,),
    )
    protocol_id = record_id(protocol)
    declarations: dict[str, ExecutionDeclaration] = {}
    eligibility: dict[str, Eligibility] = {}
    for backend in ("mlx-lm", "llama.cpp"):
        declaration = ExecutionDeclaration(
            "execution_declaration",
            "1.0",
            "model_execution_forbidden",
            protocol_id,
            cast("Any", backend),
            runtime_ids[backend],
            model_ids[backend],
            "exact_identity",
            host_id,
            "non_apple_ci",
            _synthetic_digest("fixture-publication-root"),
            ActionBudget(0, 0, 0, 0),
        )
        declaration_id = record_id(declaration)
        declarations[backend] = declaration
        eligibility[backend] = Eligibility(
            "eligibility",
            "1.0",
            "model_execution_forbidden",
            declaration_id,
            protocol_id,
            runtime_ids[backend],
            model_ids[backend],
            host_id,
            (),
            (
                "fixture policy forbids model execution",
                "all model, network, and download action budgets are zero",
            ),
        )

    runs = [
        _make_run(
            run_id="mlx-cold-001",
            order=1,
            backend="mlx-lm",
            protocol_id=protocol_id,
            runtime_id=runtime_ids["mlx-lm"],
            model_id=model_ids["mlx-lm"],
            host_id=host_id,
            declaration_id=record_id(declarations["mlx-lm"]),
            cache_cohort="cold_process_model",
            text="fixture exact output",
            tokens=(101, 202, 303, 404),
            metric_offset=0,
        ),
        _make_run(
            run_id="mlx-cold-002",
            order=2,
            backend="mlx-lm",
            protocol_id=protocol_id,
            runtime_id=runtime_ids["mlx-lm"],
            model_id=model_ids["mlx-lm"],
            host_id=host_id,
            declaration_id=record_id(declarations["mlx-lm"]),
            cache_cohort="cold_process_model",
            text="fixture exact output",
            tokens=(101, 202, 303, 404),
            metric_offset=10_000_000,
        ),
        _make_run(
            run_id="llama-warm-cache-001",
            order=3,
            backend="llama.cpp",
            protocol_id=protocol_id,
            runtime_id=runtime_ids["llama.cpp"],
            model_id=model_ids["llama.cpp"],
            host_id=host_id,
            declaration_id=record_id(declarations["llama.cpp"]),
            cache_cohort="warm_prompt_kv_cache",
            text="fixture divergent output A",
            tokens=(501, 602, 703, 804),
            metric_offset=20_000_000,
        ),
        _make_run(
            run_id="llama-warm-cache-002",
            order=4,
            backend="llama.cpp",
            protocol_id=protocol_id,
            runtime_id=runtime_ids["llama.cpp"],
            model_id=model_ids["llama.cpp"],
            host_id=host_id,
            declaration_id=record_id(declarations["llama.cpp"]),
            cache_cohort="warm_prompt_kv_cache",
            text="fixture divergent output B",
            tokens=(501, 602, 703, 805),
            metric_offset=30_000_000,
        ),
    ]
    model_by_id = {record_id(record): record for record in models.values()}
    analysis = analyze_runs(runs, model_by_id)
    source = FixtureSource(
        "fixture_source",
        "1.0",
        "synthetic-two-backend-repeatability-v1",
        "model_execution_forbidden",
        0,
        0,
        0,
        0,
        "synthetic_not_hardware_evidence",
        4,
        1,
        1,
        ("unproven",),
    )
    content = {
        "source/fixture.json": record_bytes(source),
        "protocol.json": record_bytes(protocol),
        "identities/host.json": record_bytes(host),
        "identities/runtime-mlx-lm.json": record_bytes(runtimes["mlx-lm"]),
        "identities/runtime-llama-cpp.json": record_bytes(runtimes["llama.cpp"]),
        "identities/model-mlx-lm.json": record_bytes(models["mlx-lm"]),
        "identities/model-llama-cpp.json": record_bytes(models["llama.cpp"]),
        "authorizations/mlx-lm.json": record_bytes(declarations["mlx-lm"]),
        "authorizations/llama-cpp.json": record_bytes(declarations["llama.cpp"]),
        "eligibility/mlx-lm.json": record_bytes(eligibility["mlx-lm"]),
        "eligibility/llama-cpp.json": record_bytes(eligibility["llama.cpp"]),
        "analysis.json": canonical_json(analysis),
    }
    for run in runs:
        content[f"runs/{run.run_order:04d}-{run.run_id}.json"] = record_bytes(run)
    return content


def compile_fixture(output_root: Path) -> tuple[Path, dict[str, JsonValue]]:
    """Publish and immediately offline-replay the deterministic fixture."""
    destination = publish_bundle(
        fixture_content(),
        output_root,
        name_prefix="localinferencelab-fixture-v1",
    )
    result = replay_bundle(destination)
    summary = result.to_dict()
    summary["path"] = destination.name
    summary["evidence_status"] = "synthetic_not_hardware_evidence"
    summary["model_actions"] = 0
    summary["network_actions"] = 0
    summary["download_actions"] = 0
    return destination, summary
