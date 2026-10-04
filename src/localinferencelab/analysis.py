"""Identity-aware, within-backend repeatability analysis."""

from __future__ import annotations

from collections import defaultdict
from typing import cast

from localinferencelab.canonical import JsonValue, canonical_identity
from localinferencelab.contracts import ModelIdentity, NativeMetric, RunRecord, record_id


def _metric_summary(metrics: list[NativeMetric]) -> dict[str, JsonValue]:
    observed = [metric.value for metric in metrics if metric.availability != "unavailable"]
    values = [value for value in observed if value is not None]
    reasons = sorted(
        {metric.reason for metric in metrics if metric.reason is not None},
    )
    evidence = sorted({metric.availability for metric in metrics})
    return {
        "unit": metrics[0].unit,
        "evidence": cast("list[JsonValue]", evidence),
        "value_count": len(values),
        "minimum": min(values) if values else None,
        "maximum": max(values) if values else None,
        "sum": sum(values) if values else None,
        "unavailable_reasons": cast("list[JsonValue]", reasons),
    }


def _metric_value(run: RunRecord, name: str, unit: str) -> int | None:
    for metric in run.native_metrics:
        if metric.name == name and metric.unit == unit and metric.availability != "unavailable":
            return metric.value
    return None


def _throughput(run: RunRecord) -> int | None:
    count = _metric_value(run, "generation_count", "tokens")
    duration_ns = _metric_value(run, "generation_duration_ns", "nanoseconds")
    if count is None or duration_ns is None or duration_ns == 0:
        return None
    return count * 1_000_000_000_000_000 // duration_ns


def analyze_runs(
    runs: list[RunRecord],
    models: dict[str, ModelIdentity],
) -> dict[str, JsonValue]:
    """Compute deterministic cohort-isolated repeatability and performance summaries."""
    groups: dict[tuple[str, str, str, str, str, str, str], list[RunRecord]] = defaultdict(list)
    for run in runs:
        group_key = (
            run.backend,
            run.runtime_id,
            run.model_id,
            run.host_id,
            run.protocol_id,
            run.cache_cohort,
            run.request_sha256,
        )
        groups[group_key].append(run)

    group_records: list[JsonValue] = []
    for key in sorted(groups, key=lambda item: tuple(item)):
        ordered = sorted(groups[key], key=lambda item: (item.run_order, item.run_id))
        valid = [run for run in ordered if run.validity == "valid"]
        metric_names = sorted({metric.name for run in valid for metric in run.native_metrics})
        metric_summaries: dict[str, JsonValue] = {}
        for name in metric_names:
            named = [
                metric for run in valid for metric in run.native_metrics if metric.name == name
            ]
            units = {metric.unit for metric in named}
            if len(units) != 1:
                raise ValueError(f"native metric unit drift for {name}")
            metric_summaries[name] = _metric_summary(named)

        all_valid = len(valid) == len(ordered)
        token_sets = [run.token_ids_sha256 for run in valid]
        token_status: str
        if not token_sets or any(value is None for value in token_sets):
            token_status = "unavailable"
        elif len(set(token_sets)) == 1:
            token_status = "equal"
        else:
            token_status = "different"

        throughputs = [value for run in valid if (value := _throughput(run)) is not None]
        key_record: dict[str, JsonValue] = {
            "backend": key[0],
            "runtime_id": key[1],
            "model_id": key[2],
            "host_id": key[3],
            "protocol_id": key[4],
            "cache_cohort": key[5],
            "request_sha256": key[6],
        }
        group_records.append(
            {
                "group_id": canonical_identity(key_record),
                "key": key_record,
                "run_ids": [run.run_id for run in ordered],
                "run_count": len(ordered),
                "all_valid": all_valid,
                "exact_repeatability": {
                    "raw_response": (
                        "equal"
                        if all_valid and len({run.raw_response_sha256 for run in valid}) == 1
                        else "different"
                    ),
                    "text": (
                        "equal"
                        if all_valid and len({run.text_sha256 for run in valid}) == 1
                        else "different"
                    ),
                    "token_ids": token_status,
                    "finish_reason": (
                        "equal"
                        if all_valid and len({run.finish_reason for run in valid}) == 1
                        else "different"
                    ),
                    "structured_envelope": (
                        "equal"
                        if all_valid and len({run.envelope_sha256 for run in valid}) == 1
                        else "different"
                    ),
                },
                "semantic_projection": {
                    "status": "not_defined",
                    "reason": "v1 fixture evaluates exact outputs without an LLM judge",
                },
                "native_metrics": metric_summaries,
                "derived_throughput": {
                    "method": "generation_count / generation_duration_ns",
                    "unit": "tokens_per_second_millionths",
                    "values": cast("list[JsonValue]", throughputs),
                    "availability": "available" if throughputs else "unavailable",
                },
            },
        )

    model_records = sorted(models.items())
    representation_pairs: list[JsonValue] = []
    for left_index, (left_id, left) in enumerate(model_records):
        for right_id, right in model_records[left_index + 1 :]:
            if left.backend == right.backend:
                continue
            mapped = (
                left.cross_representation_equivalence == "mapped"
                and right.cross_representation_equivalence == "mapped"
                and left.mapping_artifact_sha256 == right.mapping_artifact_sha256
            )
            representation_pairs.append(
                {
                    "left_model_id": left_id,
                    "right_model_id": right_id,
                    "left_representation": left.representation,
                    "right_representation": right.representation,
                    "equivalence": "mapped" if mapped else "unproven",
                },
            )

    return {
        "record_type": "analysis",
        "schema_version": "1.0",
        "primary_scope": "within_backend_repeatability",
        "cross_backend_scope": "descriptive_identity_aware_only",
        "cache_pooling": "forbidden",
        "groups": group_records,
        "representation_pairs": representation_pairs,
        "run_record_ids": [record_id(run) for run in sorted(runs, key=lambda item: item.run_order)],
        "non_claims": [
            "synthetic fixture metrics are not hardware benchmark evidence",
            "seed controls do not prove determinism",
            "process RSS does not measure Metal or GPU memory",
            "energy is unavailable in v1",
            "different model representations are not equivalent without a mapping artifact",
        ],
    }
