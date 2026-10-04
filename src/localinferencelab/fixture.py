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
    CachePreparation,
    ConcurrencyIdentity,
    Eligibility,
    ExecutionDeclaration,
    Fact,
    FixtureSource,
    HostIdentity,
    Measurement,
    ModelIdentity,
    ModelInstance,
    NativeMetric,
    ProcessInstance,
    Protocol,
    RunRecord,
    RunScheduleEntry,
    RuntimeFact,
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
    process_instance_id: str,
    model_instance_id: str,
    cache_preparation_id: str,
    concurrency_id: str,
    concurrency_wave: int,
    cache_cohort: str,
    request: bytes,
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
    record = RunRecord(
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
        process_instance_id,
        model_instance_id,
        cache_preparation_id,
        concurrency_id,
        concurrency_wave,
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
    return RunRecord.from_dict(record.to_dict())


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
            (
                RuntimeFact("runner", "mlx"),
                RuntimeFact("metal", "unobserved"),
            ),
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
            (
                RuntimeFact("runner", "llama.cpp"),
                RuntimeFact("metal", "unobserved"),
            ),
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
        ),
    }
    host_id = record_id(host)
    runtime_ids = {backend: record_id(record) for backend, record in runtimes.items()}
    model_ids = {backend: record_id(record) for backend, record in models.items()}
    processes = {
        backend: ProcessInstance.from_dict(
            ProcessInstance(
                "process_instance",
                "1.0",
                cast("Any", backend),
                runtime_ids[backend],
                host_id,
                "synthetic_fixture",
                f"synthetic-{backend}-process-1",
                1,
            ).to_dict(),
        )
        for backend in ("mlx-lm", "llama.cpp")
    }
    process_ids = {backend: record_id(record) for backend, record in processes.items()}
    model_instances = {
        backend: ModelInstance.from_dict(
            ModelInstance(
                "model_instance",
                "1.0",
                cast("Any", backend),
                process_ids[backend],
                model_ids[backend],
                "synthetic_fixture",
                f"synthetic-{backend}-model-1",
                512,
                1,
                None,
            ).to_dict(),
        )
        for backend in ("mlx-lm", "llama.cpp")
    }
    model_instance_ids = {backend: record_id(record) for backend, record in model_instances.items()}
    prompt = b"Reply with the fixture token sequence."
    prompt_sha256 = digest_bytes(prompt)
    warmup_request = canonical_json(
        {
            "backend": "llama.cpp",
            "prompt_sha256": prompt_sha256,
            "purpose": "synthetic-cache-lineage",
        },
    )
    mlx_cold = CachePreparation.from_dict(
        CachePreparation(
            "cache_preparation",
            "1.0",
            "mlx-lm",
            model_instance_ids["mlx-lm"],
            "synthetic_fixture",
            "cold_process_model",
            None,
            ("new_process", "load_model", "clear_prompt_cache"),
            (),
            0,
            0,
            0,
        ).to_dict(),
    )
    mlx_warm_model = CachePreparation.from_dict(
        CachePreparation(
            "cache_preparation",
            "1.0",
            "mlx-lm",
            model_instance_ids["mlx-lm"],
            "synthetic_fixture",
            "warm_model_cold_prompt_cache",
            record_id(mlx_cold),
            ("reuse_process", "reuse_model", "clear_prompt_cache"),
            (),
            0,
            0,
            0,
        ).to_dict(),
    )
    llama_cold = CachePreparation.from_dict(
        CachePreparation(
            "cache_preparation",
            "1.0",
            "llama.cpp",
            model_instance_ids["llama.cpp"],
            "synthetic_fixture",
            "cold_process_model",
            None,
            ("new_process", "load_model", "clear_prompt_cache"),
            (),
            0,
            0,
            0,
        ).to_dict(),
    )
    llama_warm = CachePreparation.from_dict(
        CachePreparation(
            "cache_preparation",
            "1.0",
            "llama.cpp",
            model_instance_ids["llama.cpp"],
            "synthetic_fixture",
            "warm_prompt_kv_cache",
            record_id(llama_cold),
            (
                "reuse_process",
                "reuse_model",
                "prefill_prompt_cache",
                "reuse_prompt_kv_cache",
            ),
            (digest_bytes(warmup_request),),
            0,
            7,
            7,
        ).to_dict(),
    )
    cache_preparations = {
        "mlx-cold-lineage": mlx_cold,
        "mlx-warm-model": mlx_warm_model,
        "llama-cold-lineage": llama_cold,
        "llama-warm": llama_warm,
    }
    cache_preparation_ids = {name: record_id(record) for name, record in cache_preparations.items()}
    concurrency = ConcurrencyIdentity.from_dict(
        ConcurrencyIdentity(
            "concurrency_identity",
            "1.0",
            1,
            0,
            0,
            "serial",
            (),
        ).to_dict(),
    )
    concurrency_id = record_id(concurrency)
    requests = {
        "mlx-lm": canonical_json(
            {
                "backend": "mlx-lm",
                "cache_preparation_id": cache_preparation_ids["mlx-warm-model"],
                "chat_template_sha256": _synthetic_digest("chat-template"),
                "model_id": model_ids["mlx-lm"],
                "prompt_sha256": prompt_sha256,
                "runtime_id": runtime_ids["mlx-lm"],
            },
        ),
        "llama.cpp": canonical_json(
            {
                "backend": "llama.cpp",
                "cache_preparation_id": cache_preparation_ids["llama-warm"],
                "chat_template_sha256": _synthetic_digest("chat-template"),
                "model_id": model_ids["llama.cpp"],
                "prompt_sha256": prompt_sha256,
                "runtime_id": runtime_ids["llama.cpp"],
            },
        ),
    }
    schedule = (
        RunScheduleEntry(
            1,
            "mlx-warm-model-001",
            "mlx-lm",
            runtime_ids["mlx-lm"],
            model_ids["mlx-lm"],
            host_id,
            process_ids["mlx-lm"],
            model_instance_ids["mlx-lm"],
            cache_preparation_ids["mlx-warm-model"],
            concurrency_id,
            1,
            "warm_model_cold_prompt_cache",
            digest_bytes(requests["mlx-lm"]),
        ),
        RunScheduleEntry(
            2,
            "mlx-warm-model-002",
            "mlx-lm",
            runtime_ids["mlx-lm"],
            model_ids["mlx-lm"],
            host_id,
            process_ids["mlx-lm"],
            model_instance_ids["mlx-lm"],
            cache_preparation_ids["mlx-warm-model"],
            concurrency_id,
            2,
            "warm_model_cold_prompt_cache",
            digest_bytes(requests["mlx-lm"]),
        ),
        RunScheduleEntry(
            3,
            "llama-warm-cache-001",
            "llama.cpp",
            runtime_ids["llama.cpp"],
            model_ids["llama.cpp"],
            host_id,
            process_ids["llama.cpp"],
            model_instance_ids["llama.cpp"],
            cache_preparation_ids["llama-warm"],
            concurrency_id,
            3,
            "warm_prompt_kv_cache",
            digest_bytes(requests["llama.cpp"]),
        ),
        RunScheduleEntry(
            4,
            "llama-warm-cache-002",
            "llama.cpp",
            runtime_ids["llama.cpp"],
            model_ids["llama.cpp"],
            host_id,
            process_ids["llama.cpp"],
            model_instance_ids["llama.cpp"],
            cache_preparation_ids["llama-warm"],
            concurrency_id,
            4,
            "warm_prompt_kv_cache",
            digest_bytes(requests["llama.cpp"]),
        ),
    )
    protocol = Protocol.from_dict(
        Protocol(
            "protocol",
            "1.0",
            "synthetic-two-backend-repeatability-v1",
            encode_bytes(prompt),
            prompt_sha256,
            _synthetic_digest("chat-template"),
            SamplerControls(4242, 0, 1_000_000, 1, 0, 1_000_000),
            4,
            512,
            ("warm_model_cold_prompt_cache", "warm_prompt_kv_cache"),
            2,
            "backend_blocked",
            ("mlx-lm", "llama.cpp"),
            1,
            30_000,
            0,
            tuple(sorted(runtime_ids.values())),
            tuple(sorted(model_ids.values())),
            (host_id,),
            schedule,
        ).to_dict(),
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
            run_id="mlx-warm-model-001",
            order=1,
            backend="mlx-lm",
            protocol_id=protocol_id,
            runtime_id=runtime_ids["mlx-lm"],
            model_id=model_ids["mlx-lm"],
            host_id=host_id,
            declaration_id=record_id(declarations["mlx-lm"]),
            process_instance_id=process_ids["mlx-lm"],
            model_instance_id=model_instance_ids["mlx-lm"],
            cache_preparation_id=cache_preparation_ids["mlx-warm-model"],
            concurrency_id=concurrency_id,
            concurrency_wave=1,
            cache_cohort="warm_model_cold_prompt_cache",
            request=requests["mlx-lm"],
            text="fixture exact output",
            tokens=(101, 202, 303, 404),
            metric_offset=0,
        ),
        _make_run(
            run_id="mlx-warm-model-002",
            order=2,
            backend="mlx-lm",
            protocol_id=protocol_id,
            runtime_id=runtime_ids["mlx-lm"],
            model_id=model_ids["mlx-lm"],
            host_id=host_id,
            declaration_id=record_id(declarations["mlx-lm"]),
            process_instance_id=process_ids["mlx-lm"],
            model_instance_id=model_instance_ids["mlx-lm"],
            cache_preparation_id=cache_preparation_ids["mlx-warm-model"],
            concurrency_id=concurrency_id,
            concurrency_wave=2,
            cache_cohort="warm_model_cold_prompt_cache",
            request=requests["mlx-lm"],
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
            process_instance_id=process_ids["llama.cpp"],
            model_instance_id=model_instance_ids["llama.cpp"],
            cache_preparation_id=cache_preparation_ids["llama-warm"],
            concurrency_id=concurrency_id,
            concurrency_wave=3,
            cache_cohort="warm_prompt_kv_cache",
            request=requests["llama.cpp"],
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
            process_instance_id=process_ids["llama.cpp"],
            model_instance_id=model_instance_ids["llama.cpp"],
            cache_preparation_id=cache_preparation_ids["llama-warm"],
            concurrency_id=concurrency_id,
            concurrency_wave=4,
            cache_cohort="warm_prompt_kv_cache",
            request=requests["llama.cpp"],
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
        0,
        0,
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
        **{
            f"state/process/{record_id(record)}.json": record_bytes(record)
            for record in processes.values()
        },
        **{
            f"state/model/{record_id(record)}.json": record_bytes(record)
            for record in model_instances.values()
        },
        **{
            f"state/cache/{record_id(record)}.json": record_bytes(record)
            for record in cache_preparations.values()
        },
        f"state/concurrency/{concurrency_id}.json": record_bytes(concurrency),
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
