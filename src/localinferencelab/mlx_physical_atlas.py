"""Deterministic, process-free contracts for future physical MLX observations."""

from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_canonical_json_file,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_determinism_canary import determinism_canary_spec

SCHEMA_VERSION = "1.0"
STUDY_NAME = "apple_silicon_mlx_determinism_atlas_physical_v1"
_CONTROL_LIMIT = 32
_DIGEST_LENGTH = 71
_MAX_ELEMENTS = 4_096
_MAX_RANK = 4
_SEED_MATERIAL = (
    "LocalInferenceLab Apple-Silicon MLX Determinism Atlas physical observation contract v1"
)
_SEED_HEX = hashlib.sha256(_SEED_MATERIAL.encode("utf-8")).hexdigest()
_DTYPE_BYTES = {"bfloat16": 2, "float16": 2, "float32": 4}
_DTYPE_CODEBOOK = {
    "float16": ("00c0", "00bc", "00b8", "0000", "0038", "003c", "0040", "0042"),
    "bfloat16": ("00c0", "80bf", "00bf", "0000", "003f", "803f", "0040", "4040"),
    "float32": (
        "000000c0",
        "000080bf",
        "000000bf",
        "00000000",
        "0000003f",
        "0000803f",
        "00000040",
        "00004040",
    ),
}
_OPERATION_ORDER = (
    "matrix_multiply",
    "softmax",
    "rms_normalization",
    "layer_normalization",
    "top_k",
)
_CELL_MATRIX = tuple(
    (operation, dtype, mode)
    for operation in _OPERATION_ORDER[:-1]
    for dtype, mode in (
        ("float16", "eager"),
        ("bfloat16", "eager"),
        ("float32", "eager"),
        ("float32", "compiled"),
    )
) + (
    ("top_k", "float32", "eager"),
    ("top_k", "float32", "compiled"),
)
_ZERO_ACTIONS: dict[str, int] = {
    "authorization_actions": 0,
    "backend_queries": 0,
    "device_queries": 0,
    "metal_queries": 0,
    "mlx_imports": 0,
    "mlx_lm_imports": 0,
    "mlx_tensor_operations": 0,
    "model_or_tokenizer_actions": 0,
    "network_actions": 0,
    "package_installations": 0,
    "process_actions": 0,
    "runtime_queries": 0,
    "synchronizations": 0,
}
_IDENTITY_BINDINGS: dict[str, JsonValue] = {
    "reviewed_candidate": {
        "identity": "sha256:4f87b4678c31c0cd08534c58485e2b242c74936737b8f9c6c96319454ada358d",
        "status": "reviewed_static_candidate_not_runtime_evidence",
    },
    "reviewed_qualification": {
        "identity": "sha256:3d789caf4e65581265dc686aed30df0d4612388710b20a2dabc36e2d906711df",
        "status": "eligible_for_human_review_not_authority",
    },
    "reviewed_target": {
        "identity": "sha256:008f7c3ac60614bc6909822180a4bc0b9be17eaf0aa3abc23829eb2842c4fdc0",
        "status": "prospective_target_not_observed_runtime_evidence",
    },
    "reviewed_worker": {
        "identity": None,
        "status": "unavailable",
    },
    "reviewed_authorization": {
        "identity": None,
        "status": "unavailable",
    },
}
_ACCEPTANCE_BLOCKERS = [
    "accepted_physical_observation_compiler_unimplemented",
    "authoritative_observer_and_custody_unavailable",
    "reviewed_authorization_identity_unavailable",
    "reviewed_worker_identity_unavailable",
    "runtime_execution_command_absent",
]


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = 4_096) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum count {maximum}")
    return value


def _keys(value: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str, *, maximum: int = 4_096) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(
    value: JsonValue,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ContractError(f"{label} must be <= {maximum}")
    return value


def _sha256(value: JsonValue, label: str) -> str:
    digest = _text(value, label, maximum=_DIGEST_LENGTH)
    if (
        len(digest) != _DIGEST_LENGTH
        or not digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in digest[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return digest


def _identity_record(
    content: dict[str, JsonValue],
    identity_field: str,
) -> dict[str, JsonValue]:
    record = dict(content)
    record[identity_field] = canonical_identity(content)
    return record


def _shape(value: JsonValue, label: str) -> tuple[int, ...]:
    dimensions = _array(value, label, maximum=_MAX_RANK)
    if not dimensions:
        raise ContractError(f"{label} must have rank >= 1")
    parsed = tuple(
        _integer(item, f"{label}[{index}]", minimum=1, maximum=_MAX_ELEMENTS)
        for index, item in enumerate(dimensions)
    )
    if math.prod(parsed) > _MAX_ELEMENTS:
        raise ContractError(f"{label} exceeds maximum element count {_MAX_ELEMENTS}")
    return parsed


def _operation_content(
    operation_name: str,
    mathematical_definition: str,
    valid_dtypes: list[str],
    input_contract: list[dict[str, JsonValue]],
    output_contract: list[dict[str, JsonValue]],
    axes: dict[str, JsonValue],
    constants_and_evaluation: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    return {
        "operation_name": operation_name,
        "operation_version": "1",
        "mathematical_definition": mathematical_definition,
        "valid_dtypes": cast("list[JsonValue]", valid_dtypes),
        "input_contract": cast("list[JsonValue]", input_contract),
        "output_contract": cast("list[JsonValue]", output_contract),
        "axes": axes,
        "layout": "row_major_contiguous",
        "constants_and_evaluation": constants_and_evaluation,
        "implementation_or_runtime_support_claim": "none",
    }


def _tensor_contract(name: str, shape: list[int], dtype_source: str) -> dict[str, JsonValue]:
    return {
        "name": name,
        "shape": cast("list[JsonValue]", shape),
        "dtype": dtype_source,
        "layout": "row_major_contiguous",
    }


def _operations() -> list[dict[str, JsonValue]]:
    common_casting: dict[str, JsonValue] = {
        "evaluation_dtype": "float32",
        "input_casting": "exact_source_value_to_float32",
        "output_casting": "round_to_nearest_ties_to_even_to_cell_dtype",
        "intermediate_rounding": "round_to_nearest_ties_to_even_to_float32",
    }
    definitions = [
        _operation_content(
            "matrix_multiply",
            "output[i,j]=sum_k(left[i,k]*right[k,j])",
            ["float16", "bfloat16", "float32"],
            [
                _tensor_contract("left", [4, 8], "cell_dtype"),
                _tensor_contract("right", [8, 4], "cell_dtype"),
            ],
            [_tensor_contract("output", [4, 4], "cell_dtype")],
            {"contracted_left_axis": 1, "contracted_right_axis": 0},
            {
                **common_casting,
                "accumulation_dtype": "float32",
                "accumulation_order": "ascending_k",
                "initial_accumulator": "positive_zero_float32",
                "product_rounding": "float32_before_addition",
                "sum_rounding": "float32_after_each_addition",
            },
        ),
        _operation_content(
            "softmax",
            (
                "maximum=max(input,axis=2);shifted=input-maximum;"
                "numerator=exp(shifted);output=numerator/sum(numerator,axis=2)"
            ),
            ["float16", "bfloat16", "float32"],
            [_tensor_contract("input", [2, 4, 8], "cell_dtype")],
            [_tensor_contract("output", [2, 4, 8], "cell_dtype")],
            {"axis": 2, "keepdims": True},
            {
                **common_casting,
                "accumulation_dtype": "float32",
                "exponentiation": "exact_real_exp_then_round_to_float32",
                "maximum_reduction_order": "ascending_axis_index",
                "maximum_tie_policy": "lowest_axis_index",
                "normalization_sum_order": "ascending_axis_index",
                "stability_transform": "subtract_axis_maximum",
            },
        ),
        _operation_content(
            "rms_normalization",
            "output=input*reciprocal_sqrt(mean(input^2,axis=2)+epsilon)",
            ["float16", "bfloat16", "float32"],
            [_tensor_contract("input", [2, 4, 8], "cell_dtype")],
            [_tensor_contract("output", [2, 4, 8], "cell_dtype")],
            {"axis": 2, "keepdims": True},
            {
                **common_casting,
                "accumulation_dtype": "float32",
                "epsilon": {
                    "dtype": "float32",
                    "endianness": "little",
                    "data_hex": "6f12833a",
                },
                "mean_divisor": 8,
                "reduction_order": "ascending_axis_index",
                "reciprocal_sqrt": "exact_real_reciprocal_sqrt_then_round_to_float32",
                "square_rounding": "float32_before_accumulation",
            },
        ),
        _operation_content(
            "layer_normalization",
            (
                "mean=sum(input,axis=2)/8;variance=sum((input-mean)^2,axis=2)/8;"
                "output=(input-mean)*reciprocal_sqrt(variance+epsilon)"
            ),
            ["float16", "bfloat16", "float32"],
            [_tensor_contract("input", [2, 4, 8], "cell_dtype")],
            [_tensor_contract("output", [2, 4, 8], "cell_dtype")],
            {"axis": 2, "keepdims": True},
            {
                **common_casting,
                "accumulation_dtype": "float32",
                "algorithm": "two_pass_mean_then_centered_variance",
                "epsilon": {
                    "dtype": "float32",
                    "endianness": "little",
                    "data_hex": "acc52737",
                },
                "mean_divisor": 8,
                "mean_reduction_order": "ascending_axis_index",
                "reciprocal_sqrt": "exact_real_reciprocal_sqrt_then_round_to_float32",
                "variance_reduction_order": "ascending_axis_index",
            },
        ),
        _operation_content(
            "top_k",
            (
                "for each row return the four greatest values sorted descending and their "
                "original indices;equal values sort by lowest original index"
            ),
            ["float32"],
            [_tensor_contract("input", [2, 16], "cell_dtype")],
            [
                _tensor_contract("values", [2, 4], "cell_dtype"),
                _tensor_contract("indices", [2, 4], "int32"),
            ],
            {"axis": 1, "k": 4},
            {
                **common_casting,
                "accumulation_dtype": "not_applicable",
                "index_dtype": "int32",
                "nan_input_policy": "input_generator_emits_finite_values_only",
                "ordering": "value_descending_then_original_index_ascending",
                "value_comparison": "exact_float32_total_order_over_finite_values",
            },
        ),
    ]
    return [_identity_record(definition, "operation_spec_id") for definition in definitions]


def _cell_name(operation_name: str, dtype: str, evaluation_mode: str) -> str:
    return f"{operation_name}_{dtype}_{evaluation_mode}"


def _input_payload(
    cell_name: str,
    input_name: str,
    dtype: str,
    shape: list[int],
) -> dict[str, JsonValue]:
    element_count = math.prod(shape)
    codebook = _DTYPE_CODEBOOK[dtype]
    payload = bytearray()
    for element_index in range(element_count):
        domain = (f"{STUDY_NAME}\0{cell_name}\0{input_name}\0{element_index}\0{_SEED_HEX}").encode()
        selector = hashlib.sha256(domain).digest()[0] % len(codebook)
        payload.extend(bytes.fromhex(codebook[selector]))
    return {
        "input_name": input_name,
        "dtype": dtype,
        "shape": cast("list[JsonValue]", shape),
        "layout": "row_major_contiguous",
        "endianness": "little",
        "element_count": element_count,
        "payload_byte_count": len(payload),
        "payload_sha256": digest_bytes(bytes(payload)),
    }


def _cell(
    operation: dict[str, JsonValue],
    dtype: str,
    evaluation_mode: str,
) -> dict[str, JsonValue]:
    operation_name = cast("str", operation["operation_name"])
    name = _cell_name(operation_name, dtype, evaluation_mode)
    inputs: list[dict[str, JsonValue]] = []
    for input_value in cast("list[JsonValue]", operation["input_contract"]):
        input_contract = cast("dict[str, JsonValue]", input_value)
        input_name = cast("str", input_contract["name"])
        shape = cast("list[int]", input_contract["shape"])
        inputs.append(_input_payload(name, input_name, dtype, shape))
    input_set: dict[str, JsonValue] = {
        "algorithm": "sha256_domain_separated_finite_codebook_v1",
        "seed_derivation": "sha256_of_utf8_seed_material",
        "seed_material": _SEED_MATERIAL,
        "seed_hex": _SEED_HEX,
        "selection": "sha256_domain_first_byte_modulo_eight",
        "finite_codebook_values": ["-2", "-1", "-0.5", "+0", "+0.5", "+1", "+2", "+3"],
        "inputs": cast("list[JsonValue]", inputs),
    }
    input_set["canonical_input_set_id"] = canonical_identity(input_set)
    content: dict[str, JsonValue] = {
        "cell_name": name,
        "operation_name": operation_name,
        "operation_version": operation["operation_version"],
        "operation_spec_id": operation["operation_spec_id"],
        "dtype": dtype,
        "evaluation_mode": evaluation_mode,
        "compile_policy": (
            "compile_exact_closed_operation_once_per_process_before_any_warmup_or_observation"
            if evaluation_mode == "compiled"
            else "not_compiled"
        ),
        "input_contract": operation["input_contract"],
        "output_contract": operation["output_contract"],
        "axes": operation["axes"],
        "layout": operation["layout"],
        "constants_and_evaluation": operation["constants_and_evaluation"],
        "input_generation": input_set,
        "support_status": "prospective_unverified_future_mlx_support",
    }
    return _identity_record(content, "cell_id")


def _run_protocol() -> dict[str, JsonValue]:
    return {
        "cell_order": "exact_study_cell_array_order",
        "cold_process_count_per_cell": 3,
        "cold_observations_per_process": 1,
        "warm_process_count_per_cell": 1,
        "warmup_repetitions_per_warm_process": 2,
        "observed_repetitions_per_warm_process": 5,
        "total_observations_per_cell": 8,
        "retry_count": 0,
        "process_order": "cold_process_ordinals_0_1_2_then_warm_process_ordinal_3",
        "compiled_mode_timing": (
            "compilation_completes_before_warmup_or_observation_and_is_not_an_observation"
        ),
        "synchronization_points": [
            "input_materialization_complete_before_operation",
            "compilation_complete_before_first_operation_when_compiled",
            "operation_complete_before_output_readback",
            "output_bytes_materialized_before_process_advance",
        ],
        "timing_measurements": "forbidden",
        "selective_reruns": "forbidden",
    }


def _comparison_contract() -> dict[str, JsonValue]:
    return {
        "tensor_compatibility": "dtype_shape_layout_endianness_and_element_count_must_match",
        "exact_equality": "identical_payload_bytes_after_metadata_validation",
        "mismatch_count": "count_of_native_dtype_element_bit_patterns_that_differ",
        "maximum_absolute_error": "maximum_abs_left_minus_right_over_finite_pairs",
        "maximum_relative_error": (
            "maximum_abs_left_minus_right_divided_by_max_abs_operand_over_finite_pairs;"
            "zero_over_zero_is_zero"
        ),
        "rms_error": "sqrt(sum_squared_finite_pair_error_divided_by_finite_pair_count)",
        "error_value_encoding": "ieee_754_binary64_big_endian_hex",
        "ulp_distance": (
            "maximum_monotonic_native_dtype_code_distance_over_finite_pairs_with_signed_zeros"
            "_mapped_to_one_code"
        ),
        "nan_policy": "both_nan_requires_identical_sign_and_payload_else_special_mismatch",
        "infinity_policy": "both_infinite_requires_identical_sign_else_special_mismatch",
        "non_finite_error_policy": "exclude_from_abs_relative_rms_and_ulp_then_count_separately",
        "top_k_index_policy": "int32_indices_require_exact_shape_and_payload_equality",
        "acceptance_threshold": "same_condition_observations_must_be_exactly_equal",
    }


def _evidence_contract() -> dict[str, JsonValue]:
    return {
        "categories": {
            "static_specification": {
                "runs_allowed": False,
                "physical_claim_allowed": False,
                "promotable": False,
            },
            "synthetic_fixture": {
                "runs_allowed": True,
                "physical_claim_allowed": False,
                "promotable": False,
            },
            "physical_observation": {
                "runs_allowed": True,
                "physical_claim_allowed": True,
                "acceptance_requires_authoritative_custody": True,
            },
        },
        "category_is_immutable": True,
        "static_or_synthetic_promotion_to_physical": "forbidden",
        "caller_supplied_provenance": "rejected_as_authority",
        "physical_acceptance_in_this_revision": "impossible",
        "physical_acceptance_blockers": list(_ACCEPTANCE_BLOCKERS),
        "required_observation_provenance_fields": [
            "collector_identity_id",
            "runtime_identity_id",
            "device_identity_id",
            "metal_identity_id",
            "worker_identity_id",
            "authorization_identity_id",
            "process_identity_ids",
            "observation_started_at_utc",
            "observation_completed_at_utc",
        ],
        "required_custody_fields": [
            "input_snapshot_id",
            "output_root_id",
            "worker_launch_receipt_id",
            "synchronization_receipt_ids",
            "raw_output_artifact_ids",
            "parent_validation_receipt_id",
        ],
    }


def _legacy_relationship() -> dict[str, JsonValue]:
    legacy = determinism_canary_spec()
    coverage = cast("dict[str, JsonValue]", legacy["synthetic_fixture_coverage"])
    return {
        "relationship": "versioned_successor_physical_subset_without_identity_rewrite",
        "legacy_record_type": legacy["record_type"],
        "legacy_schema_version": legacy["schema_version"],
        "legacy_canary_spec_id": legacy["spec_id"],
        "legacy_prospective_cell_count": coverage["prospective_matrix_cell_count"],
        "legacy_represented_synthetic_cell_count": coverage["represented_synthetic_cell_count"],
        "legacy_accepted_physical_observation_count": 0,
        "historical_cell_or_record_identity_rewritten": False,
    }


def physical_atlas_study_spec() -> dict[str, JsonValue]:
    """Return the exact process-free physical-observation study contract."""
    operations = _operations()
    by_name = {cast("str", operation["operation_name"]): operation for operation in operations}
    cells = [
        _cell(by_name[operation_name], dtype, evaluation_mode)
        for operation_name, dtype, evaluation_mode in _CELL_MATRIX
    ]
    content: dict[str, JsonValue] = {
        "record_type": "mlx_physical_atlas_study_spec",
        "schema_version": SCHEMA_VERSION,
        "study_name": STUDY_NAME,
        "study_version": "1",
        "scope": "model_free_transformer_relevant_primitives",
        "relationship_to_legacy_canary": _legacy_relationship(),
        "operations": cast("list[JsonValue]", operations),
        "selected_cells": cast("list[JsonValue]", cells),
        "selected_cell_count": len(cells),
        "run_protocol": _run_protocol(),
        "comparison_contract": _comparison_contract(),
        "reviewed_identity_slots": dict(_IDENTITY_BINDINGS),
        "evidence_and_custody_contract": _evidence_contract(),
        "current_state": {
            "selected_physical_study_cell_count": len(cells),
            "physical_observation_candidate_count": 0,
            "accepted_physical_observation_count": 0,
            "permission_to_execute": False,
            "physical_execution_implemented": False,
            "promotable_record_count": 0,
        },
        "zero_action_statement": (
            "this specification installs imports loads queries synchronizes and executes "
            "neither MLX nor MLX-LM nor Metal and makes no measured-behavior claim"
        ),
        "static_action_counters": dict(_ZERO_ACTIONS),
    }
    return _identity_record(content, "study_id")


def _verify_zero_actions(value: JsonValue, label: str) -> None:
    counters = _mapping(value, label)
    _keys(counters, set(_ZERO_ACTIONS), label)
    for name in sorted(_ZERO_ACTIONS):
        if _integer(counters[name], f"{label}.{name}") != 0:
            raise ContractError(f"{label}.{name} must remain zero")


def _verify_cell_dimensions(cell: dict[str, JsonValue], label: str) -> None:
    input_contracts = _array(cell["input_contract"], f"{label}.input_contract", maximum=4)
    output_contracts = _array(cell["output_contract"], f"{label}.output_contract", maximum=4)
    for index, contract_value in enumerate([*input_contracts, *output_contracts]):
        contract = _mapping(contract_value, f"{label}.tensor_contract[{index}]")
        _keys(contract, {"name", "shape", "dtype", "layout"}, f"{label}.tensor_contract[{index}]")
        _shape(contract["shape"], f"{label}.tensor_contract[{index}].shape")
        if contract["layout"] != "row_major_contiguous":
            raise ContractError(f"{label}.tensor_contract[{index}].layout is unsupported")
    axes = _mapping(cell["axes"], f"{label}.axes")
    operation_name = _text(cell["operation_name"], f"{label}.operation_name")
    if operation_name == "matrix_multiply":
        if axes != {"contracted_left_axis": 1, "contracted_right_axis": 0}:
            raise ContractError(f"{label}.axes invalid for matrix multiplication")
    elif operation_name == "top_k":
        if axes != {"axis": 1, "k": 4}:
            raise ContractError(f"{label}.axes invalid for top-k")
    elif axes != {"axis": 2, "keepdims": True}:
        raise ContractError(f"{label}.axes invalid for normalization or softmax")


def verify_physical_atlas_study_spec(value: JsonValue) -> dict[str, JsonValue]:
    """Reject field drift, invalid dimensions, and unsupported selected cells."""
    spec = _mapping(value, "mlx_physical_atlas_study_spec")
    expected = physical_atlas_study_spec()
    _keys(spec, set(expected), "mlx_physical_atlas_study_spec")
    if spec["schema_version"] != SCHEMA_VERSION:
        raise ContractError("mixed or unsupported physical atlas schema version")
    identity = _sha256(spec["study_id"], "mlx_physical_atlas_study_spec.study_id")
    content = dict(spec)
    del content["study_id"]
    if canonical_identity(content) != identity:
        raise ContractError("physical atlas study identity mismatch")
    operations = _array(spec["operations"], "physical atlas operations", maximum=16)
    expected_operations = cast("list[JsonValue]", expected["operations"])
    operation_dtypes: dict[str, set[str]] = {}
    operation_ids: dict[str, str] = {}
    for index, operation_value in enumerate(operations):
        operation = _mapping(operation_value, f"physical atlas operations[{index}]")
        expected_operation = cast("dict[str, JsonValue]", expected_operations[index])
        _keys(operation, set(expected_operation), f"physical atlas operations[{index}]")
        name = _text(operation["operation_name"], f"physical atlas operations[{index}].name")
        operation_dtypes[name] = {
            _text(dtype, f"physical atlas operations[{index}].valid_dtypes")
            for dtype in _array(
                operation["valid_dtypes"],
                f"physical atlas operations[{index}].valid_dtypes",
                maximum=3,
            )
        }
        operation_ids[name] = _sha256(
            operation["operation_spec_id"],
            f"physical atlas operations[{index}].operation_spec_id",
        )
        operation_content = dict(operation)
        del operation_content["operation_spec_id"]
        if canonical_identity(operation_content) != operation["operation_spec_id"]:
            raise ContractError(f"physical atlas operation identity mismatch: {name}")
    cells = _array(spec["selected_cells"], "physical atlas selected_cells", maximum=64)
    expected_cells = cast("list[JsonValue]", expected["selected_cells"])
    if _integer(spec["selected_cell_count"], "physical atlas selected_cell_count") != len(cells):
        raise ContractError("physical atlas selected cell count mismatch")
    seen_cell_ids: set[str] = set()
    observed_matrix: list[tuple[str, str, str]] = []
    for index, cell_value in enumerate(cells):
        cell = _mapping(cell_value, f"physical atlas selected_cells[{index}]")
        expected_cell = cast("dict[str, JsonValue]", expected_cells[index])
        _keys(cell, set(expected_cell), f"physical atlas selected_cells[{index}]")
        operation_name = _text(
            cell["operation_name"],
            f"physical atlas selected_cells[{index}].operation_name",
        )
        dtype = _text(cell["dtype"], f"physical atlas selected_cells[{index}].dtype")
        evaluation_mode = _text(
            cell["evaluation_mode"],
            f"physical atlas selected_cells[{index}].evaluation_mode",
        )
        if operation_name not in operation_dtypes or dtype not in operation_dtypes[operation_name]:
            raise ContractError(
                f"unsupported dtype/operation combination: {operation_name}/{dtype}"
            )
        if evaluation_mode not in {"compiled", "eager"}:
            raise ContractError("physical atlas evaluation mode must be eager or compiled")
        if cell["operation_spec_id"] != operation_ids[operation_name]:
            raise ContractError("physical atlas cell operation identity mismatch")
        _verify_cell_dimensions(cell, f"physical atlas selected_cells[{index}]")
        cell_id = _sha256(
            cell["cell_id"],
            f"physical atlas selected_cells[{index}].cell_id",
        )
        if cell_id in seen_cell_ids:
            raise ContractError("duplicate physical atlas cell identity")
        seen_cell_ids.add(cell_id)
        cell_content = dict(cell)
        del cell_content["cell_id"]
        if canonical_identity(cell_content) != cell_id:
            raise ContractError("physical atlas cell identity mismatch")
        observed_matrix.append((operation_name, dtype, evaluation_mode))
    if tuple(observed_matrix) != _CELL_MATRIX:
        raise ContractError("physical atlas selected cells are missing, duplicated, or reordered")
    _verify_zero_actions(spec["static_action_counters"], "physical atlas static_action_counters")
    if canonical_json(spec) != canonical_json(expected):
        raise ContractError("physical atlas study content drift")
    return dict(spec)


def _step_sync_points(evaluation_mode: str) -> list[JsonValue]:
    points: list[JsonValue] = ["input_materialization_complete_before_operation"]
    if evaluation_mode == "compiled":
        points.append("compilation_complete_before_first_operation_when_compiled")
    points.extend(
        [
            "operation_complete_before_output_readback",
            "output_bytes_materialized_before_process_advance",
        ]
    )
    return points


def _planned_steps(cell: dict[str, JsonValue]) -> list[dict[str, JsonValue]]:
    evaluation_mode = cast("str", cell["evaluation_mode"])
    synchronization_points = _step_sync_points(evaluation_mode)
    steps: list[dict[str, JsonValue]] = []
    observation_index = 0
    for process_ordinal in range(3):
        steps.append(
            {
                "global_step_index": len(steps),
                "process_ordinal": process_ordinal,
                "process_classification": "cold_process",
                "step_kind": "observation",
                "repetition_index": 0,
                "observation_index": observation_index,
                "retry_index": 0,
                "synchronization_points": list(synchronization_points),
            }
        )
        observation_index += 1
    for repetition_index in range(2):
        steps.append(
            {
                "global_step_index": len(steps),
                "process_ordinal": 3,
                "process_classification": "warm_process",
                "step_kind": "warmup_not_observation",
                "repetition_index": repetition_index,
                "observation_index": None,
                "retry_index": 0,
                "synchronization_points": list(synchronization_points),
            }
        )
    for repetition_index in range(5):
        steps.append(
            {
                "global_step_index": len(steps),
                "process_ordinal": 3,
                "process_classification": "warm_process",
                "step_kind": "observation",
                "repetition_index": repetition_index,
                "observation_index": observation_index,
                "retry_index": 0,
                "synchronization_points": list(synchronization_points),
            }
        )
        observation_index += 1
    return steps


def prospective_observation_envelope(cell_name: str) -> dict[str, JsonValue]:
    """Compile one identity-bound unobserved envelope; provenance is never caller supplied."""
    spec = physical_atlas_study_spec()
    cells = {
        cast("str", cast("dict[str, JsonValue]", cell)["cell_name"]): cast(
            "dict[str, JsonValue]", cell
        )
        for cell in cast("list[JsonValue]", spec["selected_cells"])
    }
    try:
        cell = cells[cell_name]
    except KeyError as error:
        raise ContractError(f"unknown physical atlas cell: {cell_name}") from error
    steps = _planned_steps(cell)
    content: dict[str, JsonValue] = {
        "record_type": "mlx_physical_observation_envelope",
        "schema_version": SCHEMA_VERSION,
        "study_id": spec["study_id"],
        "cell_id": cell["cell_id"],
        "cell_name": cell["cell_name"],
        "evidence_category": "static_specification",
        "record_state": "prospective_unobserved",
        "identity_bindings": spec["reviewed_identity_slots"],
        "input_bindings": cell["input_generation"],
        "run_plan": {
            "protocol": spec["run_protocol"],
            "planned_step_count": len(steps),
            "planned_observation_count": 8,
            "planned_steps": cast("list[JsonValue]", steps),
        },
        "observed_runs": [],
        "comparison_summary": None,
        "provenance": {
            "source_kind": "none_unobserved",
            "collector_identity_id": None,
            "runtime_identity_id": None,
            "device_identity_id": None,
            "metal_identity_id": None,
            "worker_identity_id": None,
            "authorization_identity_id": None,
            "process_identity_ids": [],
            "observation_started_at_utc": None,
            "observation_completed_at_utc": None,
            "caller_supplied_provenance_accepted": False,
            "static_or_synthetic_promoted_to_physical": False,
        },
        "custody": {
            "input_snapshot_id": None,
            "output_root_id": None,
            "worker_launch_receipt_id": None,
            "synchronization_receipt_ids": [],
            "raw_output_artifact_ids": [],
            "parent_validation_receipt_id": None,
        },
        "acceptance": {
            "accepted_physical_observation": False,
            "promotable": False,
            "blockers": list(_ACCEPTANCE_BLOCKERS),
        },
        "static_action_counters": dict(_ZERO_ACTIONS),
    }
    return _identity_record(content, "record_id")


def verify_observation_envelope(value: JsonValue) -> dict[str, JsonValue]:
    """Verify one exact prospective envelope and reject self-asserted provenance."""
    envelope = _mapping(value, "mlx_physical_observation_envelope")
    cell_name = _text(envelope.get("cell_name"), "mlx_physical_observation_envelope.cell_name")
    expected = prospective_observation_envelope(cell_name)
    _keys(envelope, set(expected), "mlx_physical_observation_envelope")
    if envelope["schema_version"] != SCHEMA_VERSION:
        raise ContractError("mixed or unsupported observation envelope schema version")
    if envelope["evidence_category"] != "static_specification":
        raise ContractError("caller-supplied physical or synthetic provenance is not accepted")
    if envelope["record_state"] != "prospective_unobserved":
        raise ContractError("current observation envelopes must remain unobserved")
    record_id = _sha256(envelope["record_id"], "mlx_physical_observation_envelope.record_id")
    content = dict(envelope)
    del content["record_id"]
    if canonical_identity(content) != record_id:
        raise ContractError("physical observation envelope identity mismatch")
    run_plan = _mapping(envelope["run_plan"], "physical observation envelope run_plan")
    steps = _array(
        run_plan["planned_steps"],
        "physical observation envelope planned_steps",
        maximum=32,
    )
    expected_steps = cast(
        "list[JsonValue]",
        cast("dict[str, JsonValue]", expected["run_plan"])["planned_steps"],
    )
    if canonical_json(steps) != canonical_json(expected_steps):
        raise ContractError("planned runs are missing, duplicated, or reordered")
    for index, step_value in enumerate(steps):
        step = _mapping(step_value, f"physical observation envelope planned_steps[{index}]")
        sync_points = _array(
            step["synchronization_points"],
            f"physical observation envelope planned_steps[{index}].synchronization_points",
            maximum=4,
        )
        if canonical_json(sync_points) != canonical_json(
            cast("dict[str, JsonValue]", expected_steps[index])["synchronization_points"]
        ):
            raise ContractError("required synchronization point missing or reordered")
    if envelope["observed_runs"] != [] or envelope["comparison_summary"] is not None:
        raise ContractError("prospective envelope cannot contain observed results")
    if canonical_json(envelope["identity_bindings"]) != canonical_json(_IDENTITY_BINDINGS):
        raise ContractError("observation identity binding mismatch")
    if canonical_json(envelope["provenance"]) != canonical_json(expected["provenance"]):
        raise ContractError("caller-supplied provenance is self-asserted and rejected")
    if canonical_json(envelope["custody"]) != canonical_json(expected["custody"]):
        raise ContractError("caller-supplied custody is self-asserted and rejected")
    _verify_zero_actions(
        envelope["static_action_counters"],
        "physical observation envelope static_action_counters",
    )
    if canonical_json(envelope) != canonical_json(expected):
        raise ContractError("physical observation envelope content drift")
    return dict(envelope)


def physical_observation_envelope_set() -> dict[str, JsonValue]:
    """Return the ordered set of unobserved envelopes for every selected cell."""
    spec = physical_atlas_study_spec()
    envelopes = [
        prospective_observation_envelope(
            cast("str", cast("dict[str, JsonValue]", cell)["cell_name"])
        )
        for cell in cast("list[JsonValue]", spec["selected_cells"])
    ]
    content: dict[str, JsonValue] = {
        "record_type": "mlx_physical_observation_envelope_set",
        "schema_version": SCHEMA_VERSION,
        "study_id": spec["study_id"],
        "evidence_category": "static_specification",
        "envelope_count": len(envelopes),
        "envelopes": cast("list[JsonValue]", envelopes),
        "accepted_physical_observation_count": 0,
        "promotable_record_count": 0,
        "static_action_counters": dict(_ZERO_ACTIONS),
    }
    return _identity_record(content, "envelope_set_id")


def verify_observation_envelope_set(value: JsonValue) -> dict[str, JsonValue]:
    """Verify the complete ordered prospective envelope set."""
    envelope_set = _mapping(value, "mlx_physical_observation_envelope_set")
    expected = physical_observation_envelope_set()
    _keys(envelope_set, set(expected), "mlx_physical_observation_envelope_set")
    if envelope_set["schema_version"] != SCHEMA_VERSION:
        raise ContractError("mixed or unsupported envelope-set schema version")
    identity = _sha256(
        envelope_set["envelope_set_id"],
        "mlx_physical_observation_envelope_set.envelope_set_id",
    )
    content = dict(envelope_set)
    del content["envelope_set_id"]
    if canonical_identity(content) != identity:
        raise ContractError("physical observation envelope-set identity mismatch")
    envelopes = _array(
        envelope_set["envelopes"],
        "mlx_physical_observation_envelope_set.envelopes",
        maximum=64,
    )
    count = _integer(
        envelope_set["envelope_count"],
        "mlx_physical_observation_envelope_set.envelope_count",
    )
    if count != len(envelopes):
        raise ContractError("physical observation envelope count mismatch")
    identities: list[str] = []
    for envelope in envelopes:
        verified = verify_observation_envelope(envelope)
        identities.append(cast("str", verified["record_id"]))
    if len(set(identities)) != len(identities):
        raise ContractError("duplicate physical observation envelope")
    _verify_zero_actions(
        envelope_set["static_action_counters"],
        "physical observation envelope-set static_action_counters",
    )
    if canonical_json(envelope_set) != canonical_json(expected):
        raise ContractError("physical observation envelopes are missing, duplicated, or reordered")
    return dict(envelope_set)


def verify_physical_atlas_record(value: JsonValue) -> dict[str, JsonValue]:
    """Dispatch strict verification for physical-atlas contract records."""
    record = _mapping(value, "MLX physical atlas record")
    record_type = record.get("record_type")
    if record_type == "mlx_physical_atlas_study_spec":
        return verify_physical_atlas_study_spec(record)
    if record_type == "mlx_physical_observation_envelope":
        return verify_observation_envelope(record)
    if record_type == "mlx_physical_observation_envelope_set":
        return verify_observation_envelope_set(record)
    raise ContractError(f"unsupported MLX physical atlas record type: {record_type}")


def load_physical_atlas_record(path: Path) -> dict[str, JsonValue]:
    """Load one canonical physical-atlas record without any runtime action."""
    return verify_physical_atlas_record(load_canonical_json_file(path, "MLX physical atlas record"))


def physical_atlas_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Inspect a verified record with explicit historical and physical counts."""
    record = verify_physical_atlas_record(value)
    record_type = cast("str", record["record_type"])
    identity_field = {
        "mlx_physical_atlas_study_spec": "study_id",
        "mlx_physical_observation_envelope": "record_id",
        "mlx_physical_observation_envelope_set": "envelope_set_id",
    }[record_type]
    return {
        "record_type": record_type,
        "identity": record[identity_field],
        "record_evidence_category": record.get("evidence_category", "static_specification"),
        "legacy_prospective_cell_count": 48,
        "legacy_represented_synthetic_cell_count": 8,
        "legacy_accepted_physical_observation_count": 0,
        "selected_physical_study_cell_count": len(_CELL_MATRIX),
        "physical_observation_candidate_count": 0,
        "accepted_physical_observation_count": 0,
        "promotable_record_count": 0,
        "mlx_imports": 0,
        "mlx_lm_imports": 0,
        "process_actions": 0,
        "device_or_metal_queries": 0,
        "hardware_synchronizations": 0,
        "mlx_tensor_operations": 0,
        "model_actions": 0,
        "network_actions": 0,
    }


@dataclass(frozen=True, slots=True)
class _Tensor:
    dtype: str
    shape: tuple[int, ...]
    payload: bytes
    codes: tuple[int, ...]


def _parse_tensor(value: JsonValue, label: str) -> _Tensor:
    tensor = _mapping(value, label)
    expected_fields = {
        "dtype",
        "shape",
        "layout",
        "endianness",
        "data_hex",
        "payload_sha256",
    }
    _keys(tensor, expected_fields, label)
    dtype = _text(tensor["dtype"], f"{label}.dtype")
    if dtype not in _DTYPE_BYTES:
        raise ContractError(f"{label}.dtype is unsupported")
    shape = _shape(tensor["shape"], f"{label}.shape")
    if tensor["layout"] != "row_major_contiguous":
        raise ContractError(f"{label}.layout must be row_major_contiguous")
    if tensor["endianness"] != "little":
        raise ContractError(f"{label}.endianness must be little")
    data_hex = _text(tensor["data_hex"], f"{label}.data_hex", maximum=32_768)
    if data_hex != data_hex.lower() or any(
        character not in "0123456789abcdef" for character in data_hex
    ):
        raise ContractError(f"{label}.data_hex must be lowercase hexadecimal")
    try:
        payload = bytes.fromhex(data_hex)
    except ValueError as error:
        raise ContractError(f"{label}.data_hex is malformed") from error
    element_count = math.prod(shape)
    byte_width = _DTYPE_BYTES[dtype]
    if len(payload) != element_count * byte_width:
        raise ContractError(f"{label} payload length does not match dtype and shape")
    if _sha256(tensor["payload_sha256"], f"{label}.payload_sha256") != digest_bytes(payload):
        raise ContractError(f"{label} payload digest mismatch")
    codes = tuple(
        int.from_bytes(payload[offset : offset + byte_width], "little")
        for offset in range(0, len(payload), byte_width)
    )
    return _Tensor(dtype=dtype, shape=shape, payload=payload, codes=codes)


def _code_to_float(dtype: str, code: int) -> float:
    if dtype == "float16":
        return cast("float", struct.unpack("<e", code.to_bytes(2, "little"))[0])
    if dtype == "bfloat16":
        return cast("float", struct.unpack("<f", (code << 16).to_bytes(4, "little"))[0])
    return cast("float", struct.unpack("<f", code.to_bytes(4, "little"))[0])


def _is_zero(dtype: str, code: int) -> bool:
    bits = _DTYPE_BYTES[dtype] * 8
    return code & ((1 << (bits - 1)) - 1) == 0


def _ordered_ulp_code(dtype: str, code: int) -> int:
    bits = _DTYPE_BYTES[dtype] * 8
    sign_bit = 1 << (bits - 1)
    magnitude = code & (sign_bit - 1)
    if magnitude == 0:
        return sign_bit
    if code & sign_bit:
        return sign_bit - magnitude
    return sign_bit + magnitude


def _binary64_hex(value: float) -> dict[str, JsonValue]:
    return {
        "encoding": "ieee_754_binary64_big_endian_hex",
        "value_hex": struct.pack(">d", value).hex(),
    }


def compare_physical_outputs(
    left_value: JsonValue,
    right_value: JsonValue,
) -> dict[str, JsonValue]:
    """Compare bounded float tensors with the physical-atlas edge policy."""
    left = _parse_tensor(left_value, "physical comparison left")
    right = _parse_tensor(right_value, "physical comparison right")
    if left.dtype != right.dtype or left.shape != right.shape:
        raise ContractError("physical comparison metadata mismatch")
    mismatch_count = 0
    finite_pair_count = 0
    finite_mismatch_count = 0
    nan_pair_count = 0
    infinity_pair_count = 0
    signed_zero_bit_difference_count = 0
    special_mismatch_count = 0
    maximum_absolute_error = 0.0
    maximum_relative_error = 0.0
    squared_errors: list[float] = []
    maximum_ulp_distance = 0
    for left_code, right_code in zip(left.codes, right.codes, strict=True):
        if left_code != right_code:
            mismatch_count += 1
        left_number = _code_to_float(left.dtype, left_code)
        right_number = _code_to_float(right.dtype, right_code)
        left_nan = math.isnan(left_number)
        right_nan = math.isnan(right_number)
        if left_nan or right_nan:
            if left_nan and right_nan:
                nan_pair_count += 1
                if left_code != right_code:
                    special_mismatch_count += 1
            else:
                special_mismatch_count += 1
            continue
        left_infinite = math.isinf(left_number)
        right_infinite = math.isinf(right_number)
        if left_infinite or right_infinite:
            if left_infinite and right_infinite and left_code == right_code:
                infinity_pair_count += 1
            else:
                special_mismatch_count += 1
            continue
        finite_pair_count += 1
        if _is_zero(left.dtype, left_code) and _is_zero(right.dtype, right_code):
            if left_code != right_code:
                signed_zero_bit_difference_count += 1
            absolute_error = 0.0
            relative_error = 0.0
        else:
            absolute_error = abs(left_number - right_number)
            denominator = max(abs(left_number), abs(right_number))
            relative_error = 0.0 if denominator == 0.0 else absolute_error / denominator
        if absolute_error != 0.0:
            finite_mismatch_count += 1
        maximum_absolute_error = max(maximum_absolute_error, absolute_error)
        maximum_relative_error = max(maximum_relative_error, relative_error)
        squared_errors.append(absolute_error * absolute_error)
        maximum_ulp_distance = max(
            maximum_ulp_distance,
            abs(
                _ordered_ulp_code(left.dtype, left_code)
                - _ordered_ulp_code(right.dtype, right_code)
            ),
        )
    rms_error = (
        math.sqrt(math.fsum(squared_errors) / finite_pair_count) if finite_pair_count else 0.0
    )
    numerical_equal = finite_mismatch_count == 0 and special_mismatch_count == 0
    return {
        "exact_equal": left.payload == right.payload,
        "numerical_equal": numerical_equal,
        "element_count": len(left.codes),
        "mismatch_count": mismatch_count,
        "finite_pair_count": finite_pair_count,
        "finite_mismatch_count": finite_mismatch_count,
        "nan_pair_count": nan_pair_count,
        "infinity_pair_count": infinity_pair_count,
        "signed_zero_bit_difference_count": signed_zero_bit_difference_count,
        "special_mismatch_count": special_mismatch_count,
        "maximum_absolute_error": _binary64_hex(maximum_absolute_error),
        "maximum_relative_error": _binary64_hex(maximum_relative_error),
        "rms_error": _binary64_hex(rms_error),
        "maximum_signed_zero_normalized_ulp_distance": maximum_ulp_distance,
    }


def _canonical_bytes(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


@dataclass(frozen=True, slots=True)
class PhysicalAtlasReplayResult:
    """Verified summary of one closed static physical-atlas contract bundle."""

    bundle_root: str
    study_id: str
    envelope_set_id: str
    selected_physical_study_cell_count: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "study_id": self.study_id,
            "envelope_set_id": self.envelope_set_id,
            "legacy_prospective_cell_count": 48,
            "legacy_represented_synthetic_cell_count": 8,
            "legacy_accepted_physical_observation_count": 0,
            "selected_physical_study_cell_count": self.selected_physical_study_cell_count,
            "physical_observation_candidate_count": 0,
            "accepted_physical_observation_count": 0,
            "promotable_record_count": 0,
            "mlx_imports": 0,
            "mlx_lm_imports": 0,
            "process_actions": 0,
            "device_or_metal_queries": 0,
            "hardware_synchronizations": 0,
            "mlx_tensor_operations": 0,
            "model_actions": 0,
            "network_actions": 0,
        }


def compile_physical_atlas_fixture(output_root: Path) -> tuple[Path, PhysicalAtlasReplayResult]:
    """Publish the exact static study and envelopes with zero runtime actions."""
    spec = physical_atlas_study_spec()
    envelopes = physical_observation_envelope_set()
    source: dict[str, JsonValue] = {
        "record_type": "mlx_physical_atlas_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_category": "static_specification",
        "measured_behavior_claims": 0,
        "accepted_physical_observations": 0,
        "promotable_records": 0,
        "zero_action_statement": (
            "fixture compilation performs no MLX MLX-LM or Metal installation import load query "
            "synchronization or execution"
        ),
        "static_action_counters": dict(_ZERO_ACTIONS),
    }
    destination = publish_bundle(
        {
            "source/fixture-source.json": canonical_json(source),
            "source/physical-atlas-study.json": canonical_json(spec),
            "prospective-observation-envelopes.json": canonical_json(envelopes),
        },
        output_root,
        name_prefix="localinferencelab-mlx-physical-atlas-static-v1",
    )
    return destination, replay_physical_atlas_fixture(destination)


def replay_physical_atlas_fixture(bundle: Path) -> PhysicalAtlasReplayResult:
    """Replay the closed static contract without imports, processes, or hardware access."""
    content_root, files = read_closed_bundle(bundle)
    expected_files = {
        "source/fixture-source.json",
        "source/physical-atlas-study.json",
        "prospective-observation-envelopes.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected_files:
        raise ContractError("MLX physical atlas fixture bundle has an invalid content set")
    source = _mapping(
        _canonical_bytes(files["source/fixture-source.json"], "physical atlas fixture source"),
        "mlx_physical_atlas_fixture_source",
    )
    expected_source: dict[str, JsonValue] = {
        "record_type": "mlx_physical_atlas_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_category": "static_specification",
        "measured_behavior_claims": 0,
        "accepted_physical_observations": 0,
        "promotable_records": 0,
        "zero_action_statement": (
            "fixture compilation performs no MLX MLX-LM or Metal installation import load query "
            "synchronization or execution"
        ),
        "static_action_counters": dict(_ZERO_ACTIONS),
    }
    if canonical_json(source) != canonical_json(expected_source):
        raise ContractError("MLX physical atlas fixture source drift")
    _verify_zero_actions(source["static_action_counters"], "physical atlas fixture source actions")
    spec = verify_physical_atlas_study_spec(
        _canonical_bytes(
            files["source/physical-atlas-study.json"],
            "physical atlas study specification",
        )
    )
    envelopes = verify_observation_envelope_set(
        _canonical_bytes(
            files["prospective-observation-envelopes.json"],
            "physical observation envelope set",
        )
    )
    if envelopes["study_id"] != spec["study_id"]:
        raise ContractError("physical atlas fixture study binding mismatch")
    return PhysicalAtlasReplayResult(
        bundle_root=content_root,
        study_id=cast("str", spec["study_id"]),
        envelope_set_id=cast("str", envelopes["envelope_set_id"]),
        selected_physical_study_cell_count=cast("int", spec["selected_cell_count"]),
    )
