"""Process-free MLX determinism canary specifications and synthetic replay."""

from __future__ import annotations

import math
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

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

SCHEMA_VERSION = "1.0"
_MAX_RANK = 4
_MAX_ELEMENTS = 4_096
_MAX_TENSOR_BYTES = 16_384
_MAX_CASES = 128
_MAX_RESULTS = 512
_CONTROL_CHARACTER_LIMIT = 32
_SHA256_ID_LENGTH = 71
_BFLOAT16_ROUND_TIE = 0x8000
_UINT16_MASK = 0xFFFF
_DTYPE_BYTES = {"float16": 2, "bfloat16": 2, "float32": 4}
_EVALUATION_MODES = {"deferred_evaluation", "explicit_evaluation"}
_SUPPORT_STATUSES = {
    "unverified_future_support",
}
_FIXTURE_CASE_BY_CELL = {
    "elementwise_add_float32_explicit_evaluation": "elementwise_add_float32",
    "identity_edges_float32_deferred_evaluation": "identity_edges_float32",
    "matrix_multiply_float16_deferred_evaluation": "matrix_multiply_float16",
    "multiply_add_fused_float32_explicit_evaluation": "multiply_add_fused_float32",
    "multiply_add_unfused_float32_deferred_evaluation": "multiply_add_unfused_float32",
    "reduction_sum_bfloat16_explicit_evaluation": "reduction_sum_bfloat16",
    "rms_normalization_float16_deferred_evaluation": "rms_normalization_float16",
    "softmax_float32_explicit_evaluation": "softmax_float32",
}
_OUTPUT_SEMANTICS: dict[str, JsonValue] = {
    "byte_encoding": "ieee_754_binary_interchange",
    "canonical_byte_order": "declared_per_tensor",
    "bitwise_equality": "identical_payload_bytes_after_exact_compatible_metadata_validation",
    "nan_policy": "payload_and_sign_must_match_for_numerical_equality",
    "infinity_policy": "sign_must_match_for_numerical_equality",
    "signed_zero_policy": "numerically_equal_but_bit_difference_reported",
    "absolute_error": "maximum_abs_left_minus_right_over_finite_pairs",
    "relative_error": (
        "maximum_abs_left_minus_right_divided_by_max_abs_operand_over_finite_pairs;"
        "zero_over_zero_is_zero"
    ),
    "error_value_encoding": "ieee_754_binary64_big_endian_hex",
    "ulp_distance": (
        "maximum_ordered_native_dtype_code_distance_over_finite_pairs;signed_zeros_normalized_equal"
    ),
    "non_finite_error_handling": "excluded_from_error_maxima_and_counted_separately",
    "metadata_mismatch_handling": "reject_without_comparison",
}


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, maximum: int) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum count {maximum}")
    return value


def _keys(data: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - data.keys()
    extra = data.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str, *, maximum: int = 1_024) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value):
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


def _boolean(value: JsonValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _sha256(value: JsonValue, label: str) -> str:
    digest = _text(value, label, maximum=_SHA256_ID_LENGTH)
    if (
        len(digest) != _SHA256_ID_LENGTH
        or not digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in digest[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return digest


def _identifier(value: JsonValue, label: str) -> str:
    identifier = _text(value, label, maximum=96)
    if any(character not in "abcdefghijklmnopqrstuvwxyz0123456789_" for character in identifier):
        raise ContractError(f"{label} must use lowercase snake_case")
    return identifier


def _literal(value: JsonValue, allowed: set[str], label: str) -> str:
    text = _text(value, label)
    if text not in allowed:
        raise ContractError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return text


def _identity_record(
    content: dict[str, JsonValue],
    identity_field: str,
) -> dict[str, JsonValue]:
    record = dict(content)
    record[identity_field] = canonical_identity(record)
    return record


def _operation(
    operation_id: str,
    family: str,
    form: str,
    expression: str,
    input_arity: int,
    output_rank: int,
    parameter_schema: list[dict[str, JsonValue]],
    synthetic_derivation: str,
) -> dict[str, JsonValue]:
    content: dict[str, JsonValue] = {
        "operation_id": operation_id,
        "family": family,
        "form": form,
        "mathematical_contract": expression,
        "input_arity": input_arity,
        "output_rank": output_rank,
        "parameter_schema": cast("list[JsonValue]", parameter_schema),
        "synthetic_derivation": synthetic_derivation,
        "implementation_claim": "none",
    }
    return _identity_record(content, "operation_spec_id")


def _parameter(name: str, value_type: str, constraint: str) -> dict[str, JsonValue]:
    return {
        "name": name,
        "value_type": value_type,
        "constraint": constraint,
        "required": True,
    }


def _operations() -> list[dict[str, JsonValue]]:
    return [
        _operation(
            "elementwise_add",
            "elementwise_arithmetic",
            "single_operation",
            "output[i]=left[i]+right[i]",
            2,
            1,
            [
                _parameter("arithmetic_precision", "dtype", "equal_to_matrix_dtype"),
                _parameter(
                    "rounding_mode",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "ieee_add_in_declared_precision_then_round_once_to_output_dtype",
        ),
        _operation(
            "identity_edges",
            "elementwise_arithmetic",
            "identity",
            "output[i]=input[i]",
            1,
            1,
            [_parameter("transfer_mode", "literal", "byte_preserving")],
            "copy_input_payload_bytes_without_numeric_canonicalization",
        ),
        _operation(
            "matrix_multiply",
            "matmul",
            "single_operation",
            "output[i,j]=sum_k(left[i,k]*right[k,j])",
            2,
            2,
            [
                _parameter("transpose_left", "boolean", "explicit"),
                _parameter("transpose_right", "boolean", "explicit"),
                _parameter("multiply_precision", "dtype", "equal_to_matrix_dtype"),
                _parameter("accumulation_precision", "dtype", "equal_to_matrix_dtype"),
                _parameter(
                    "initial_accumulator",
                    "typed_scalar_bytes",
                    "positive_zero_in_accumulation_precision",
                ),
                _parameter("accumulation_order", "literal", "ascending_k"),
                _parameter(
                    "intermediate_rounding",
                    "literal",
                    "round_each_product_and_sum_to_accumulation_precision",
                ),
                _parameter(
                    "output_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "row_major_ascending_k_scalar_products_and_sums_under_declared_rounding",
        ),
        _operation(
            "multiply_add_fused",
            "fused_unfused",
            "fused",
            "output[i]=fused_multiply_add(a[i],b[i],c[i])",
            3,
            1,
            [
                _parameter("fusion_mode", "literal", "fused_single_rounding"),
                _parameter("arithmetic_precision", "dtype", "equal_to_matrix_dtype"),
                _parameter(
                    "product_add_contract",
                    "literal",
                    "exact_product_plus_addend_then_one_round",
                ),
                _parameter(
                    "output_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "exact_product_plus_addend_then_one_round_to_output_dtype",
        ),
        _operation(
            "multiply_add_unfused",
            "fused_unfused",
            "unfused",
            "output[i]=(a[i]*b[i])+c[i] with an observable intermediate",
            3,
            1,
            [
                _parameter("fusion_mode", "literal", "unfused_two_roundings"),
                _parameter("multiply_precision", "dtype", "equal_to_matrix_dtype"),
                _parameter(
                    "product_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter("addition_precision", "dtype", "equal_to_matrix_dtype"),
                _parameter(
                    "output_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "round_product_to_dtype_then_add_and_round_to_output_dtype",
        ),
        _operation(
            "reduction_sum",
            "reduction",
            "sum_all",
            "output=sum(input,axis=axes,keepdims=keepdims)",
            1,
            1,
            [
                _parameter("axes", "integer_array", "rank_checked_explicit_axes"),
                _parameter("keepdims", "boolean", "explicit"),
                _parameter("accumulation_precision", "dtype", "explicit"),
                _parameter(
                    "initial_accumulator",
                    "typed_scalar_bytes",
                    "positive_zero_in_accumulation_precision",
                ),
                _parameter("reduction_order", "literal", "ascending_linear_index"),
                _parameter(
                    "intermediate_rounding",
                    "literal",
                    "round_each_sum_to_accumulation_precision",
                ),
                _parameter(
                    "output_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "ascending_index_scalar_sum_with_declared_intermediate_and_output_rounding",
        ),
        _operation(
            "rms_normalization",
            "normalization",
            "rms",
            "output=input*reciprocal_sqrt(mean(input^2,axes,keepdims)+epsilon)",
            1,
            1,
            [
                _parameter("axes", "integer_array", "rank_checked_explicit_axes"),
                _parameter("keepdims", "boolean", "explicit"),
                _parameter("epsilon", "typed_scalar_bytes", "exact_dtype_endianness_and_bits"),
                _parameter("square_precision", "dtype", "explicit"),
                _parameter(
                    "square_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter("accumulation_precision", "dtype", "explicit"),
                _parameter(
                    "initial_accumulator",
                    "typed_scalar_bytes",
                    "positive_zero_in_accumulation_precision",
                ),
                _parameter("reduction_order", "literal", "ascending_linear_index"),
                _parameter("mean_divisor", "integer", "exact_reduced_element_count"),
                _parameter(
                    "mean_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter("epsilon_addition_precision", "dtype", "explicit"),
                _parameter(
                    "epsilon_addition_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter(
                    "reciprocal_sqrt_contract",
                    "literal",
                    "exact_real_reciprocal_sqrt_then_round",
                ),
                _parameter(
                    "reciprocal_sqrt_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter("output_multiply_precision", "dtype", "explicit"),
                _parameter(
                    "output_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "execute_the_declared_scalar_steps_and_round_after_each_named_stage",
        ),
        _operation(
            "softmax",
            "softmax",
            "last_axis",
            "output=exp(input-max(input,axis))/sum(exp_shifted,axis)",
            1,
            1,
            [
                _parameter("axis", "integer", "rank_checked_explicit_axis"),
                _parameter("stability_transform", "literal", "subtract_axis_maximum"),
                _parameter("max_reduction_order", "literal", "ascending_linear_index"),
                _parameter("max_tie_policy", "literal", "first_index"),
                _parameter("subtraction_precision", "dtype", "explicit"),
                _parameter(
                    "subtraction_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter(
                    "exponentiation_contract",
                    "literal",
                    "exact_real_exponential_then_round",
                ),
                _parameter(
                    "exponentiation_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
                _parameter("accumulation_precision", "dtype", "explicit"),
                _parameter(
                    "initial_accumulator",
                    "typed_scalar_bytes",
                    "positive_zero_in_accumulation_precision",
                ),
                _parameter("accumulation_order", "literal", "ascending_linear_index"),
                _parameter("division_precision", "dtype", "explicit"),
                _parameter(
                    "output_rounding",
                    "literal",
                    "round_to_nearest_ties_to_even",
                ),
            ],
            "stable_scalar_softmax_under_declared_stage_precision_and_rounding",
        ),
    ]


def _operation_parameters(  # noqa: PLR0911
    operation_id: str,
    dtype: str,
) -> dict[str, JsonValue]:
    rounding = "round_to_nearest_ties_to_even"
    positive_zero: dict[str, JsonValue] = {
        "dtype": dtype,
        "endianness": "little",
        "data_hex": "0000" if dtype != "float32" else "00000000",
    }
    if operation_id == "elementwise_add":
        return {"arithmetic_precision": dtype, "rounding_mode": rounding}
    if operation_id == "identity_edges":
        return {"transfer_mode": "byte_preserving"}
    if operation_id == "matrix_multiply":
        return {
            "transpose_left": False,
            "transpose_right": False,
            "multiply_precision": dtype,
            "accumulation_precision": dtype,
            "initial_accumulator": positive_zero,
            "accumulation_order": "ascending_k",
            "intermediate_rounding": ("round_each_product_and_sum_to_accumulation_precision"),
            "output_rounding": rounding,
        }
    if operation_id == "multiply_add_fused":
        return {
            "fusion_mode": "fused_single_rounding",
            "arithmetic_precision": dtype,
            "product_add_contract": "exact_product_plus_addend_then_one_round",
            "output_rounding": rounding,
        }
    if operation_id == "multiply_add_unfused":
        return {
            "fusion_mode": "unfused_two_roundings",
            "multiply_precision": dtype,
            "product_rounding": rounding,
            "addition_precision": dtype,
            "output_rounding": rounding,
        }
    if operation_id == "reduction_sum":
        return {
            "axes": [0],
            "keepdims": True,
            "accumulation_precision": dtype,
            "initial_accumulator": positive_zero,
            "reduction_order": "ascending_linear_index",
            "intermediate_rounding": "round_each_sum_to_accumulation_precision",
            "output_rounding": rounding,
        }
    if operation_id == "rms_normalization":
        return {
            "axes": [0],
            "keepdims": True,
            "epsilon": {
                "dtype": dtype,
                "endianness": "little",
                "data_hex": "0000" if dtype != "float32" else "00000000",
            },
            "square_precision": dtype,
            "square_rounding": rounding,
            "accumulation_precision": dtype,
            "initial_accumulator": positive_zero,
            "reduction_order": "ascending_linear_index",
            "mean_divisor": 2,
            "mean_rounding": rounding,
            "epsilon_addition_precision": dtype,
            "epsilon_addition_rounding": rounding,
            "reciprocal_sqrt_contract": "exact_real_reciprocal_sqrt_then_round",
            "reciprocal_sqrt_rounding": rounding,
            "output_multiply_precision": dtype,
            "output_rounding": rounding,
        }
    if operation_id == "softmax":
        return {
            "axis": 0,
            "stability_transform": "subtract_axis_maximum",
            "max_reduction_order": "ascending_linear_index",
            "max_tie_policy": "first_index",
            "subtraction_precision": dtype,
            "subtraction_rounding": rounding,
            "exponentiation_contract": "exact_real_exponential_then_round",
            "exponentiation_rounding": rounding,
            "accumulation_precision": dtype,
            "initial_accumulator": positive_zero,
            "accumulation_order": "ascending_linear_index",
            "division_precision": dtype,
            "output_rounding": rounding,
        }
    raise ContractError(f"unsupported operation parameter contract: {operation_id}")


def _matrix_cell(
    operation: dict[str, JsonValue],
    dtype: str,
    evaluation_mode: str,
) -> dict[str, JsonValue]:
    cell_id = f"{cast('str', operation['operation_id'])}_{dtype}_{evaluation_mode}"
    return {
        "cell_id": cell_id,
        "operation_id": operation["operation_id"],
        "operation_spec_id": operation["operation_spec_id"],
        "dtype": dtype,
        "evaluation_mode": evaluation_mode,
        "support_status": "unverified_future_support",
        "fixture_representation_status": (
            "embedded_synthetic_fixture_available"
            if cell_id in _FIXTURE_CASE_BY_CELL
            else "prospective_only_no_fixture"
        ),
        "synthetic_fixture_case_id": _FIXTURE_CASE_BY_CELL.get(cell_id),
        "reason": "Schema 1.0 has no runtime observation or authorization acceptance path.",
    }


def _operation_matrix() -> list[JsonValue]:
    return [
        _matrix_cell(operation, dtype, evaluation_mode)
        for operation in _operations()
        for dtype in sorted(_DTYPE_BYTES)
        for evaluation_mode in sorted(_EVALUATION_MODES)
    ]


def determinism_canary_spec() -> dict[str, JsonValue]:
    """Return the pinned process-free prospective determinism canary specification."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_canary_spec",
        "schema_version": SCHEMA_VERSION,
        "scope": "prospective_runtime_independent_comparison_contract",
        "runtime_execution": "permanently_disabled_in_schema_1_0",
        "operations": cast("list[JsonValue]", _operations()),
        "dtypes": [
            {
                "dtype": "bfloat16",
                "bytes_per_element": 2,
                "format": "ieee_754_bfloat16",
                "future_mlx_support": "unverified_future_support",
            },
            {
                "dtype": "float16",
                "bytes_per_element": 2,
                "format": "ieee_754_binary16",
                "future_mlx_support": "unverified_future_support",
            },
            {
                "dtype": "float32",
                "bytes_per_element": 4,
                "format": "ieee_754_binary32",
                "future_mlx_support": "unverified_future_support",
            },
        ],
        "evaluation_modes": [
            {
                "evaluation_mode": "deferred_evaluation",
                "prospective_contract": (
                    "a future runtime may defer computation until bounded output materialization"
                ),
                "schema_1_0_behavior": "synthetic_label_only_no_runtime_or_sync_action",
            },
            {
                "evaluation_mode": "explicit_evaluation",
                "prospective_contract": (
                    "a future runtime materializes the operation boundary before output capture"
                ),
                "schema_1_0_behavior": "synthetic_label_only_no_runtime_or_sync_action",
            },
        ],
        "matrix": _operation_matrix(),
        "synthetic_fixture_coverage": {
            "prospective_matrix_cell_count": 48,
            "represented_synthetic_cell_count": len(_FIXTURE_CASE_BY_CELL),
            "prospective_only_cell_count": 48 - len(_FIXTURE_CASE_BY_CELL),
            "coverage_claim": "structural_subset_not_full_matrix_coverage",
        },
        "future_case_registry_contract": {
            "status": "unavailable_and_rejected_in_schema_1_0",
            "minimum_future_schema": "greater_than_1_0",
            "required_registry_identity": "canonical_content_identity",
            "required_unique_binding_fields": [
                "case_id",
                "case_contract_id",
                "matrix_cell_id",
                "operation_id",
                "operation_spec_id",
                "dtype",
                "evaluation_mode",
                "operation_parameters",
                "inputs",
                "expected_output_policy",
            ],
            "structural_rules": [
                "each case binds exactly one declared matrix cell",
                "operation dtype and evaluation mode equal the referenced cell",
                "operation parameters satisfy the referenced operation schema",
                "all tensor descriptors are bounded and content addressed",
                "duplicate case or contract identities are forbidden",
                "schema 1.0 verification rejects registry and physical result records",
            ],
        },
        "comparison_semantics": _OUTPUT_SEMANTICS,
        "bounds": {
            "maximum_rank": _MAX_RANK,
            "maximum_elements_per_tensor": _MAX_ELEMENTS,
            "maximum_bytes_per_tensor": _MAX_TENSOR_BYTES,
            "maximum_fixture_cases": _MAX_CASES,
            "maximum_results_per_atlas": _MAX_RESULTS,
        },
        "future_experiment_protocol": {
            "authorization_status": "not_available_in_schema_1_0",
            "timing_measurements": "forbidden_unless_separately_authorized",
            "retries_per_observation": 0,
            "selective_reruns": "forbidden",
            "dimensions": [
                {
                    "dimension_id": "cold_process_repetition",
                    "predeclared_observation_count": 5,
                    "unit": "one_new_process_per_observation",
                },
                {
                    "dimension_id": "cpu_vs_gpu",
                    "predeclared_observation_count": 10,
                    "unit": "five_cpu_and_five_gpu_observations",
                },
                {
                    "dimension_id": "explicit_synchronization",
                    "predeclared_observation_count": 10,
                    "unit": (
                        "five_output_materialization_only_and_five_explicit_synchronization_"
                        "observations"
                    ),
                },
                {
                    "dimension_id": "fused_vs_unfused",
                    "predeclared_observation_count": 10,
                    "unit": "five_fused_and_five_unfused_observations",
                },
                {
                    "dimension_id": "within_process_repetition",
                    "predeclared_observation_count": 5,
                    "unit": "five_evaluations_in_one_process",
                },
            ],
            "acceptance_rules": [
                {
                    "rule_id": "same_condition_repeatability",
                    "scope": "same_operation_dtype_shape_device_form_evaluation_and_sync",
                    "decision": "accept_only_if_every_output_is_bitwise_equal",
                },
                {
                    "rule_id": "cross_condition_equivalence",
                    "scope": "cpu_vs_gpu_fused_vs_unfused_or_sync_mode",
                    "decision": "report_only_no_acceptance_without_separate_reviewed_threshold",
                },
                {
                    "rule_id": "future_invalid_observation",
                    "scope": "dtype_shape_endianness_or_length_mismatch",
                    "decision": "reject_record_without_computing_metrics",
                },
                {
                    "rule_id": "retry_policy",
                    "scope": "every_predeclared_observation",
                    "decision": "zero_retries_and_no_replacement_of_failed_observations",
                },
            ],
        },
        "non_actions": {
            "mlx_imports": 0,
            "mlx_lm_imports": 0,
            "worker_starts": 0,
            "backend_queries": 0,
            "device_queries": 0,
            "metal_queries": 0,
            "hardware_synchronizations": 0,
            "mlx_tensor_operations": 0,
            "model_or_tokenizer_actions": 0,
            "network_actions": 0,
            "cloud_actions": 0,
            "spend_actions": 0,
        },
        "non_claims": [
            "synthetic vectors do not describe real MLX behavior",
            "synthetic vectors do not describe real Metal behavior",
            "matrix inclusion does not assert future runtime support",
            "eight fixtures do not represent the forty prospective-only cells",
            "schema 1.0 rejects authorized and physical observation records",
            "no timing or performance conclusion is defined",
        ],
    }
    return _identity_record(content, "spec_id")


def verify_determinism_canary_spec(value: JsonValue) -> dict[str, JsonValue]:
    """Verify the exact pinned prospective specification."""
    spec = _mapping(value, "mlx_determinism_canary_spec")
    expected_keys = set(determinism_canary_spec())
    _keys(spec, expected_keys, "mlx_determinism_canary_spec")
    if (
        spec["record_type"] != "mlx_determinism_canary_spec"
        or spec["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported MLX determinism canary specification")
    _sha256(spec["spec_id"], "mlx_determinism_canary_spec.spec_id")
    matrix = _array(spec["matrix"], "mlx_determinism_canary_spec.matrix", _MAX_RESULTS)
    for index, item in enumerate(matrix):
        cell = _mapping(item, f"mlx_determinism_canary_spec.matrix[{index}]")
        _literal(
            cell.get("support_status"),
            _SUPPORT_STATUSES,
            f"mlx_determinism_canary_spec.matrix[{index}].support_status",
        )
    if canonical_json(spec) != canonical_json(determinism_canary_spec()):
        raise ContractError("MLX determinism canary specification differs from the pinned contract")
    return dict(spec)


def _tensor(
    name: str,
    dtype: str,
    shape: list[int],
    data_hex: str,
    *,
    endianness: str = "little",
) -> dict[str, JsonValue]:
    data = bytes.fromhex(data_hex)
    descriptor: dict[str, JsonValue] = {
        "name": name,
        "dtype": dtype,
        "shape": cast("list[JsonValue]", shape),
        "endianness": endianness,
        "data_hex": data_hex,
        "payload_sha256": digest_bytes(data),
    }
    descriptor["canonical_output_digest"] = canonical_identity(descriptor)
    return descriptor


def _fixture_case(
    case_id: str,
    operation_id: str,
    dtype: str,
    evaluation_mode: str,
    inputs: list[dict[str, JsonValue]],
    expected: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    operations = {cast("str", operation["operation_id"]): operation for operation in _operations()}
    operation = operations[operation_id]
    matrix_cell_id = f"{operation_id}_{dtype}_{evaluation_mode}"
    if _FIXTURE_CASE_BY_CELL.get(matrix_cell_id) != case_id:
        raise ContractError(f"fixture case is not declared for matrix cell: {case_id}")
    content: dict[str, JsonValue] = {
        "case_id": case_id,
        "matrix_cell_id": matrix_cell_id,
        "operation_id": operation_id,
        "operation_spec_id": operation["operation_spec_id"],
        "dtype": dtype,
        "evaluation_mode": evaluation_mode,
        "operation_parameters": _operation_parameters(operation_id, dtype),
        "inputs": cast("list[JsonValue]", inputs),
        "expected_output": expected,
        "expected_output_derivation": operation["synthetic_derivation"],
        "evidence_kind": "synthetic_fixture",
        "runtime_behavior_claim": "none",
    }
    return _identity_record(content, "case_contract_id")


def determinism_fixture_set() -> dict[str, JsonValue]:
    """Return exact embedded scalar/byte vectors with no random generation."""
    cases = [
        _fixture_case(
            "elementwise_add_float32",
            "elementwise_add",
            "float32",
            "explicit_evaluation",
            [
                _tensor("left", "float32", [4], "0000803f000080bf0000000000000080"),
                _tensor("right", "float32", [4], "000000400000803f0000008000000000"),
            ],
            _tensor("output", "float32", [4], "00004040000000000000000000000000"),
        ),
        _fixture_case(
            "identity_edges_float32",
            "identity_edges",
            "float32",
            "deferred_evaluation",
            [
                _tensor(
                    "input",
                    "float32",
                    [5],
                    "00000000000000800000807f000080ff0000c07f",
                )
            ],
            _tensor(
                "output",
                "float32",
                [5],
                "00000000000000800000807f000080ff0000c07f",
            ),
        ),
        _fixture_case(
            "matrix_multiply_float16",
            "matrix_multiply",
            "float16",
            "deferred_evaluation",
            [
                _tensor("left", "float16", [2, 2], "003c004000420044"),
                _tensor("right", "float16", [2, 2], "003c00000000003c"),
            ],
            _tensor("output", "float16", [2, 2], "003c004000420044"),
        ),
        _fixture_case(
            "multiply_add_fused_float32",
            "multiply_add_fused",
            "float32",
            "explicit_evaluation",
            [
                _tensor("a", "float32", [1], "0000803f"),
                _tensor("b", "float32", [1], "00000040"),
                _tensor("c", "float32", [1], "00004040"),
            ],
            _tensor("output", "float32", [1], "0000a040"),
        ),
        _fixture_case(
            "multiply_add_unfused_float32",
            "multiply_add_unfused",
            "float32",
            "deferred_evaluation",
            [
                _tensor("a", "float32", [1], "0000803f"),
                _tensor("b", "float32", [1], "00000040"),
                _tensor("c", "float32", [1], "00004040"),
            ],
            _tensor("output", "float32", [1], "0000a040"),
        ),
        _fixture_case(
            "reduction_sum_bfloat16",
            "reduction_sum",
            "bfloat16",
            "explicit_evaluation",
            [_tensor("input", "bfloat16", [4], "803f004040408040")],
            _tensor("output", "bfloat16", [1], "2041"),
        ),
        _fixture_case(
            "rms_normalization_float16",
            "rms_normalization",
            "float16",
            "deferred_evaluation",
            [_tensor("input", "float16", [2], "003c00bc")],
            _tensor("output", "float16", [2], "003c00bc"),
        ),
        _fixture_case(
            "softmax_float32",
            "softmax",
            "float32",
            "explicit_evaluation",
            [_tensor("input", "float32", [2], "0000000000000000")],
            _tensor("output", "float32", [2], "0000003f0000003f"),
        ),
    ]
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_fixture_set",
        "schema_version": SCHEMA_VERSION,
        "spec_id": determinism_canary_spec()["spec_id"],
        "evidence_status": "synthetic_embedded_scalar_byte_fixtures_only",
        "random_generator": "absent",
        "case_count": len(cases),
        "cases": cast("list[JsonValue]", cases),
        "all_positive_records_are_synthetic": True,
    }
    return _identity_record(content, "fixture_set_id")


def verify_determinism_fixture_set(value: JsonValue) -> dict[str, JsonValue]:
    """Verify the exact pinned embedded fixture set."""
    fixtures = _mapping(value, "mlx_determinism_fixture_set")
    _keys(fixtures, set(determinism_fixture_set()), "mlx_determinism_fixture_set")
    _sha256(fixtures["spec_id"], "mlx_determinism_fixture_set.spec_id")
    _sha256(fixtures["fixture_set_id"], "mlx_determinism_fixture_set.fixture_set_id")
    _integer(
        fixtures["case_count"],
        "mlx_determinism_fixture_set.case_count",
        maximum=_MAX_CASES,
    )
    _boolean(
        fixtures["all_positive_records_are_synthetic"],
        "mlx_determinism_fixture_set.all_positive_records_are_synthetic",
    )
    cases = _array(fixtures["cases"], "mlx_determinism_fixture_set.cases", _MAX_CASES)
    if fixtures["case_count"] != len(cases):
        raise ContractError("fixture case count mismatch")
    specification = determinism_canary_spec()
    matrix = {
        cast("str", _mapping(item, "matrix cell")["cell_id"]): _mapping(item, "matrix cell")
        for item in cast("list[JsonValue]", specification["matrix"])
    }
    operations = {
        cast("str", _mapping(item, "operation")["operation_id"]): _mapping(item, "operation")
        for item in cast("list[JsonValue]", specification["operations"])
    }
    seen_case_ids: set[str] = set()
    seen_contract_ids: set[str] = set()
    for case_index, item in enumerate(cases):
        case = _mapping(item, f"fixture.cases[{case_index}]")
        _keys(
            case,
            {
                "case_id",
                "case_contract_id",
                "matrix_cell_id",
                "operation_id",
                "operation_spec_id",
                "dtype",
                "evaluation_mode",
                "operation_parameters",
                "inputs",
                "expected_output",
                "expected_output_derivation",
                "evidence_kind",
                "runtime_behavior_claim",
            },
            f"fixture.cases[{case_index}]",
        )
        case_id = _identifier(case["case_id"], f"fixture.cases[{case_index}].case_id")
        contract_id = _sha256(
            case["case_contract_id"],
            f"fixture.cases[{case_index}].case_contract_id",
        )
        if case_id in seen_case_ids or contract_id in seen_contract_ids:
            raise ContractError("fixture cases require unique case and contract identities")
        seen_case_ids.add(case_id)
        seen_contract_ids.add(contract_id)
        case_content = dict(case)
        del case_content["case_contract_id"]
        if contract_id != canonical_identity(case_content):
            raise ContractError("fixture case contract identity mismatch")
        matrix_cell_id = _identifier(
            case["matrix_cell_id"],
            f"fixture.cases[{case_index}].matrix_cell_id",
        )
        cell = matrix.get(matrix_cell_id)
        if (
            cell is None
            or cell["fixture_representation_status"] != "embedded_synthetic_fixture_available"
            or cell["synthetic_fixture_case_id"] != case_id
        ):
            raise ContractError(
                "fixture case is not the declared representation of its matrix cell"
            )
        operation_id = _identifier(
            case["operation_id"],
            f"fixture.cases[{case_index}].operation_id",
        )
        operation = operations.get(operation_id)
        if (
            operation is None
            or case["operation_spec_id"] != operation["operation_spec_id"]
            or cell["operation_id"] != operation_id
            or cell["operation_spec_id"] != operation["operation_spec_id"]
            or cell["dtype"] != case["dtype"]
            or cell["evaluation_mode"] != case["evaluation_mode"]
        ):
            raise ContractError("fixture operation or matrix-cell binding mismatch")
        if canonical_json(case["operation_parameters"]) != canonical_json(
            _operation_parameters(operation_id, cast("str", case["dtype"]))
        ):
            raise ContractError("fixture operation parameter drift")
        if case["expected_output_derivation"] != operation["synthetic_derivation"]:
            raise ContractError("fixture expected-output derivation mismatch")
        if case["evidence_kind"] != "synthetic_fixture" or case["runtime_behavior_claim"] != "none":
            raise ContractError("fixture cases must remain synthetic non-runtime evidence")
        parsed_inputs = []
        for tensor_index, tensor in enumerate(
            _array(case["inputs"], f"fixture.cases[{case_index}].inputs", 8)
        ):
            parsed_inputs.append(
                _parse_tensor(tensor, f"fixture.cases[{case_index}].inputs[{tensor_index}]")
            )
        if len(parsed_inputs) != operation["input_arity"]:
            raise ContractError("fixture input arity differs from its operation")
        parsed_output = _parse_tensor(
            case["expected_output"],
            f"fixture.cases[{case_index}].expected_output",
        )
        if (
            any(tensor.dtype != case["dtype"] for tensor in parsed_inputs)
            or parsed_output.dtype != case["dtype"]
            or len(parsed_output.shape) != operation["output_rank"]
        ):
            raise ContractError("fixture tensor dtype or output rank differs from its operation")
        if _derive_fixture_output(case, parsed_inputs) != parsed_output.data:
            raise ContractError(
                "fixture expected bytes differ from the fully bound scalar derivation"
            )
    if seen_case_ids != set(_FIXTURE_CASE_BY_CELL.values()):
        raise ContractError("fixture set does not contain the exact represented synthetic subset")
    if canonical_json(fixtures) != canonical_json(determinism_fixture_set()):
        raise ContractError("MLX determinism fixture set differs from pinned embedded bytes")
    return dict(fixtures)


@dataclass(frozen=True, slots=True)
class _ParsedTensor:
    record: dict[str, JsonValue]
    dtype: str
    shape: tuple[int, ...]
    endianness: Literal["big", "little"]
    data: bytes
    element_count: int


def _parse_tensor(value: JsonValue, label: str) -> _ParsedTensor:
    tensor = _mapping(value, label)
    fields = {
        "name",
        "dtype",
        "shape",
        "endianness",
        "data_hex",
        "payload_sha256",
        "canonical_output_digest",
    }
    _keys(tensor, fields, label)
    _identifier(tensor["name"], f"{label}.name")
    dtype = _literal(tensor["dtype"], set(_DTYPE_BYTES), f"{label}.dtype")
    endianness = cast(
        "Literal['big', 'little']",
        _literal(tensor["endianness"], {"big", "little"}, f"{label}.endianness"),
    )
    shape_values = _array(tensor["shape"], f"{label}.shape", _MAX_RANK)
    if not shape_values:
        raise ContractError(f"{label}.shape must not be empty")
    shape = tuple(
        _integer(item, f"{label}.shape[{index}]", minimum=1, maximum=_MAX_ELEMENTS)
        for index, item in enumerate(shape_values)
    )
    element_count = math.prod(shape)
    if element_count > _MAX_ELEMENTS:
        raise ContractError(f"{label} exceeds maximum element count {_MAX_ELEMENTS}")
    data_hex = _text(tensor["data_hex"], f"{label}.data_hex", maximum=_MAX_TENSOR_BYTES * 2)
    if len(data_hex) % 2 or any(character not in "0123456789abcdef" for character in data_hex):
        raise ContractError(f"{label}.data_hex must be lowercase even-length hexadecimal")
    data = bytes.fromhex(data_hex)
    expected_bytes = element_count * _DTYPE_BYTES[dtype]
    if len(data) != expected_bytes:
        raise ContractError(
            f"{label} payload length {len(data)} does not match dtype/shape {expected_bytes}"
        )
    if len(data) > _MAX_TENSOR_BYTES:
        raise ContractError(f"{label} exceeds maximum byte count {_MAX_TENSOR_BYTES}")
    if tensor["payload_sha256"] != digest_bytes(data):
        raise ContractError(f"{label} payload digest mismatch")
    _sha256(tensor["payload_sha256"], f"{label}.payload_sha256")
    _sha256(tensor["canonical_output_digest"], f"{label}.canonical_output_digest")
    digest_content = dict(tensor)
    del digest_content["canonical_output_digest"]
    if tensor["canonical_output_digest"] != canonical_identity(digest_content):
        raise ContractError(f"{label} canonical output digest mismatch")
    return _ParsedTensor(dict(tensor), dtype, shape, endianness, data, element_count)


def _element_codes(tensor: _ParsedTensor) -> list[int]:
    width = _DTYPE_BYTES[tensor.dtype]
    return [
        int.from_bytes(tensor.data[offset : offset + width], tensor.endianness)
        for offset in range(0, len(tensor.data), width)
    ]


def _code_to_float(dtype: str, code: int) -> float:
    if dtype == "float32":
        return cast("float", struct.unpack(">f", code.to_bytes(4, "big"))[0])
    if dtype == "float16":
        return cast("float", struct.unpack(">e", code.to_bytes(2, "big"))[0])
    return cast("float", struct.unpack(">f", (code << 16).to_bytes(4, "big"))[0])


def _float_to_code(dtype: str, value: float) -> int:
    if dtype == "float32":
        return int.from_bytes(struct.pack(">f", value), "big")
    if dtype == "float16":
        return int.from_bytes(struct.pack(">e", value), "big")
    bits = int.from_bytes(struct.pack(">f", value), "big")
    upper = bits >> 16
    lower = bits & _UINT16_MASK
    if lower > _BFLOAT16_ROUND_TIE or (lower == _BFLOAT16_ROUND_TIE and upper & 1):
        upper = (upper + 1) & _UINT16_MASK
    return upper


def _round_to_dtype(dtype: str, value: float) -> float:
    return _code_to_float(dtype, _float_to_code(dtype, value))


def _typed_scalar_value(value: JsonValue, dtype: str, label: str) -> float:
    scalar = _mapping(value, label)
    _keys(scalar, {"dtype", "endianness", "data_hex"}, label)
    if scalar["dtype"] != dtype:
        raise ContractError(f"{label} dtype mismatch")
    endianness = cast(
        "Literal['big', 'little']",
        _literal(scalar["endianness"], {"big", "little"}, f"{label}.endianness"),
    )
    data_hex = _text(scalar["data_hex"], f"{label}.data_hex", maximum=8)
    data = bytes.fromhex(data_hex)
    if len(data) != _DTYPE_BYTES[dtype]:
        raise ContractError(f"{label} byte length mismatch")
    return _code_to_float(dtype, int.from_bytes(data, endianness))


def _encode_derived_values(
    dtype: str,
    endianness: Literal["big", "little"],
    values: list[float],
) -> bytes:
    return b"".join(
        _float_to_code(dtype, value).to_bytes(_DTYPE_BYTES[dtype], endianness) for value in values
    )


def _derive_fixture_output(
    case: dict[str, JsonValue],
    inputs: list[_ParsedTensor],
) -> bytes:
    operation_id = cast("str", case["operation_id"])
    dtype = cast("str", case["dtype"])
    parameters = _mapping(case["operation_parameters"], "fixture operation parameters")
    decoded = [
        [_code_to_float(dtype, code) for code in _element_codes(tensor)] for tensor in inputs
    ]
    values: list[float]
    if operation_id == "identity_edges":
        return inputs[0].data
    if operation_id == "elementwise_add":
        values = [
            _round_to_dtype(dtype, left + right)
            for left, right in zip(decoded[0], decoded[1], strict=True)
        ]
    elif operation_id == "matrix_multiply":
        left_rows, inner = inputs[0].shape
        right_inner, right_columns = inputs[1].shape
        if inner != right_inner:
            raise ContractError("fixture matrix dimensions are incompatible")
        initial = _typed_scalar_value(
            parameters["initial_accumulator"],
            dtype,
            "matrix initial accumulator",
        )
        values = []
        for row in range(left_rows):
            for column in range(right_columns):
                accumulator = initial
                for index in range(inner):
                    product = _round_to_dtype(
                        dtype,
                        decoded[0][row * inner + index]
                        * decoded[1][index * right_columns + column],
                    )
                    accumulator = _round_to_dtype(dtype, accumulator + product)
                values.append(_round_to_dtype(dtype, accumulator))
    elif operation_id in {"multiply_add_fused", "multiply_add_unfused"}:
        values = []
        for left, right, addend in zip(
            decoded[0],
            decoded[1],
            decoded[2],
            strict=True,
        ):
            product = left * right
            if operation_id == "multiply_add_unfused":
                product = _round_to_dtype(dtype, product)
            values.append(_round_to_dtype(dtype, product + addend))
    elif operation_id == "reduction_sum":
        accumulator = _typed_scalar_value(
            parameters["initial_accumulator"],
            dtype,
            "reduction initial accumulator",
        )
        for item in decoded[0]:
            accumulator = _round_to_dtype(dtype, accumulator + item)
        values = [_round_to_dtype(dtype, accumulator)]
    elif operation_id == "rms_normalization":
        accumulator = _typed_scalar_value(
            parameters["initial_accumulator"],
            dtype,
            "normalization initial accumulator",
        )
        for item in decoded[0]:
            square = _round_to_dtype(dtype, item * item)
            accumulator = _round_to_dtype(dtype, accumulator + square)
        divisor = cast("int", parameters["mean_divisor"])
        mean = _round_to_dtype(dtype, accumulator / divisor)
        epsilon = _typed_scalar_value(
            parameters["epsilon"],
            dtype,
            "normalization epsilon",
        )
        stabilized = _round_to_dtype(dtype, mean + epsilon)
        scale = _round_to_dtype(dtype, 1.0 / math.sqrt(stabilized))
        values = [_round_to_dtype(dtype, item * scale) for item in decoded[0]]
    elif operation_id == "softmax":
        maximum = max(decoded[0])
        exponentials = [
            _round_to_dtype(dtype, math.exp(_round_to_dtype(dtype, item - maximum)))
            for item in decoded[0]
        ]
        denominator = _typed_scalar_value(
            parameters["initial_accumulator"],
            dtype,
            "softmax initial accumulator",
        )
        for item in exponentials:
            denominator = _round_to_dtype(dtype, denominator + item)
        values = [_round_to_dtype(dtype, item / denominator) for item in exponentials]
    else:
        raise ContractError(f"unsupported fixture derivation operation: {operation_id}")
    return _encode_derived_values(dtype, inputs[0].endianness, values)


def _is_zero(dtype: str, code: int) -> bool:
    magnitude_mask = 0x7FFF if dtype != "float32" else 0x7FFFFFFF
    return code & magnitude_mask == 0


def _ulp_distance(dtype: str, left: int, right: int) -> int:
    if _is_zero(dtype, left) and _is_zero(dtype, right):
        return 0
    bits = 32 if dtype == "float32" else 16
    sign = 1 << (bits - 1)
    mask = (1 << bits) - 1

    def ordered(code: int) -> int:
        if code & sign:
            return ~code & mask
        return (code | sign) - 1

    return abs(ordered(left) - ordered(right))


def _binary64_hex(value: float) -> str:
    return struct.pack(">d", value).hex()


def compare_outputs(left_value: JsonValue, right_value: JsonValue) -> dict[str, JsonValue]:
    """Compare two bounded output tensors with explicit IEEE edge semantics."""
    left = _parse_tensor(left_value, "comparison.left")
    right = _parse_tensor(right_value, "comparison.right")
    if (
        left.dtype != right.dtype
        or left.shape != right.shape
        or left.endianness != right.endianness
        or left.element_count != right.element_count
    ):
        raise ContractError("comparison metadata mismatch: dtype, shape, and endianness must match")

    finite_pair_count = 0
    nan_pair_count = 0
    infinity_pair_count = 0
    signed_zero_pair_count = 0
    special_mismatch_count = 0
    maximum_absolute_error = 0.0
    maximum_relative_error = 0.0
    maximum_ulp_distance = 0
    for left_code, right_code in zip(
        _element_codes(left),
        _element_codes(right),
        strict=True,
    ):
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
            if left_infinite and right_infinite and left_number == right_number:
                infinity_pair_count += 1
            else:
                special_mismatch_count += 1
            continue
        finite_pair_count += 1
        if _is_zero(left.dtype, left_code) and _is_zero(right.dtype, right_code):
            if left_code != right_code:
                signed_zero_pair_count += 1
            absolute_error = 0.0
            relative_error = 0.0
        else:
            absolute_error = abs(left_number - right_number)
            denominator = max(abs(left_number), abs(right_number))
            relative_error = 0.0 if denominator == 0.0 else absolute_error / denominator
        maximum_absolute_error = max(maximum_absolute_error, absolute_error)
        maximum_relative_error = max(maximum_relative_error, relative_error)
        maximum_ulp_distance = max(
            maximum_ulp_distance,
            _ulp_distance(left.dtype, left_code, right_code),
        )

    numerical_equal = (
        special_mismatch_count == 0 and maximum_absolute_error == 0.0 and maximum_ulp_distance == 0
    )
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_comparison",
        "schema_version": SCHEMA_VERSION,
        "evidence_scope": "byte_comparison_only_no_runtime_provenance",
        "semantics": _OUTPUT_SEMANTICS,
        "left": left.record,
        "right": right.record,
        "element_count": left.element_count,
        "bitwise_equal": left.data == right.data,
        "canonical_output_digest_equal": (
            left.record["canonical_output_digest"] == right.record["canonical_output_digest"]
        ),
        "numerical_equal": numerical_equal,
        "finite_pair_count": finite_pair_count,
        "nan_pair_count": nan_pair_count,
        "infinity_pair_count": infinity_pair_count,
        "signed_zero_bit_difference_count": signed_zero_pair_count,
        "special_mismatch_count": special_mismatch_count,
        "maximum_absolute_error": {
            "encoding": "ieee_754_binary64_big_endian_hex",
            "value_hex": _binary64_hex(maximum_absolute_error),
        },
        "maximum_relative_error": {
            "encoding": "ieee_754_binary64_big_endian_hex",
            "value_hex": _binary64_hex(maximum_relative_error),
        },
        "maximum_ulp_distance": maximum_ulp_distance,
    }
    return _identity_record(content, "comparison_id")


def verify_comparison(value: JsonValue) -> dict[str, JsonValue]:
    """Recompute and verify one comparison record."""
    comparison = _mapping(value, "mlx_determinism_comparison")
    expected_keys = set(compare_outputs(comparison.get("left"), comparison.get("right")))
    _keys(comparison, expected_keys, "mlx_determinism_comparison")
    _sha256(comparison["comparison_id"], "mlx_determinism_comparison.comparison_id")
    rebuilt = compare_outputs(comparison["left"], comparison["right"])
    if canonical_json(comparison) != canonical_json(rebuilt):
        raise ContractError("MLX determinism comparison metric or identity mismatch")
    return dict(comparison)


def build_synthetic_result(case: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Build one explicitly synthetic result by copying embedded expected bytes."""
    fixtures = determinism_fixture_set()
    matching_cases = [
        _mapping(item, "fixture case")
        for item in cast("list[JsonValue]", fixtures["cases"])
        if _mapping(item, "fixture case")["case_id"] == case.get("case_id")
    ]
    if len(matching_cases) != 1 or canonical_json(case) != canonical_json(matching_cases[0]):
        raise ContractError("synthetic results require an exact pinned represented fixture case")
    case = matching_cases[0]
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_result",
        "schema_version": SCHEMA_VERSION,
        "spec_id": determinism_canary_spec()["spec_id"],
        "fixture_set_id": fixtures["fixture_set_id"],
        "case_id": case["case_id"],
        "case_contract_id": case["case_contract_id"],
        "matrix_cell_id": case["matrix_cell_id"],
        "operation_id": case["operation_id"],
        "operation_spec_id": case["operation_spec_id"],
        "dtype": case["dtype"],
        "evaluation_mode": case["evaluation_mode"],
        "operation_parameters": case["operation_parameters"],
        "evidence_kind": "synthetic_fixture",
        "synthetic_source": {
            "record_type": "mlx_determinism_synthetic_source",
            "acquisition_mode": "embedded_scalar_byte_copy",
            "physical_observation": False,
            "authorization_status": "not_available_in_schema_1_0",
            "runtime_identity_status": "not_applicable_to_synthetic_fixture",
        },
        "output": case["expected_output"],
        "runtime_behavior_claim": "none",
    }
    return _identity_record(content, "result_id")


def verify_determinism_result(value: JsonValue) -> dict[str, JsonValue]:
    """Verify one pinned synthetic result; schema 1.0 rejects physical observations."""
    result = _mapping(value, "mlx_determinism_result")
    fields = {
        "record_type",
        "schema_version",
        "spec_id",
        "fixture_set_id",
        "case_id",
        "case_contract_id",
        "matrix_cell_id",
        "operation_id",
        "operation_spec_id",
        "dtype",
        "evaluation_mode",
        "operation_parameters",
        "evidence_kind",
        "synthetic_source",
        "output",
        "runtime_behavior_claim",
        "result_id",
    }
    _keys(result, fields, "mlx_determinism_result")
    if (
        result["record_type"] != "mlx_determinism_result"
        or result["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported MLX determinism result")
    _sha256(result["spec_id"], "mlx_determinism_result.spec_id")
    _sha256(result["fixture_set_id"], "mlx_determinism_result.fixture_set_id")
    _identifier(result["case_id"], "mlx_determinism_result.case_id")
    _sha256(result["case_contract_id"], "mlx_determinism_result.case_contract_id")
    _identifier(result["matrix_cell_id"], "mlx_determinism_result.matrix_cell_id")
    _identifier(result["operation_id"], "mlx_determinism_result.operation_id")
    _sha256(result["operation_spec_id"], "mlx_determinism_result.operation_spec_id")
    _literal(result["dtype"], set(_DTYPE_BYTES), "mlx_determinism_result.dtype")
    _literal(
        result["evaluation_mode"],
        _EVALUATION_MODES,
        "mlx_determinism_result.evaluation_mode",
    )
    if result["evidence_kind"] != "synthetic_fixture":
        raise ContractError("schema 1.0 rejects authorized and physical observation records")
    source = _mapping(result["synthetic_source"], "mlx_determinism_result.synthetic_source")
    _keys(
        source,
        {
            "record_type",
            "acquisition_mode",
            "physical_observation",
            "authorization_status",
            "runtime_identity_status",
        },
        "mlx_determinism_result.synthetic_source",
    )
    if (
        source["record_type"] != "mlx_determinism_synthetic_source"
        or source["acquisition_mode"] != "embedded_scalar_byte_copy"
        or _boolean(
            source["physical_observation"],
            "mlx_determinism_result.synthetic_source.physical_observation",
        )
        or source["authorization_status"] != "not_available_in_schema_1_0"
        or source["runtime_identity_status"] != "not_applicable_to_synthetic_fixture"
    ):
        raise ContractError("result source must remain synthetic and non-physical")
    _text(result["runtime_behavior_claim"], "mlx_determinism_result.runtime_behavior_claim")
    if result["runtime_behavior_claim"] != "none":
        raise ContractError("synthetic result cannot make a runtime behavior claim")
    output = _parse_tensor(result["output"], "mlx_determinism_result.output")
    if output.dtype != result["dtype"]:
        raise ContractError("result dtype does not match output dtype")
    fixtures = determinism_fixture_set()
    if (
        result["spec_id"] != determinism_canary_spec()["spec_id"]
        or result["fixture_set_id"] != fixtures["fixture_set_id"]
    ):
        raise ContractError("result is not bound to the pinned canary spec and fixture set")
    matching_cases = [
        _mapping(item, "fixture case")
        for item in cast("list[JsonValue]", fixtures["cases"])
        if _mapping(item, "fixture case")["case_id"] == result["case_id"]
    ]
    if len(matching_cases) != 1:
        raise ContractError("result references an unknown fixture case")
    case = matching_cases[0]
    if (
        result["case_contract_id"] != case["case_contract_id"]
        or result["matrix_cell_id"] != case["matrix_cell_id"]
        or result["operation_id"] != case["operation_id"]
        or result["operation_spec_id"] != case["operation_spec_id"]
        or result["dtype"] != case["dtype"]
        or result["evaluation_mode"] != case["evaluation_mode"]
        or canonical_json(result["operation_parameters"])
        != canonical_json(case["operation_parameters"])
    ):
        raise ContractError("result case, cell, operation, parameters, or dtype binding mismatch")
    expected_output = _parse_tensor(case["expected_output"], "fixture expected output")
    if (
        output.shape != expected_output.shape
        or output.endianness != expected_output.endianness
        or output.record["name"] != expected_output.record["name"]
    ):
        raise ContractError("result output metadata differs from its fixture")
    if canonical_json(output.record) != canonical_json(expected_output.record):
        raise ContractError("synthetic result output must equal the embedded expected bytes")
    _sha256(result["result_id"], "mlx_determinism_result.result_id")
    result_content = dict(result)
    del result_content["result_id"]
    if result["result_id"] != canonical_identity(result_content):
        raise ContractError("MLX determinism result identity mismatch")
    return dict(result)


def synthetic_result_set() -> dict[str, JsonValue]:
    """Return the deterministic set of synthetic result records."""
    fixtures = determinism_fixture_set()
    cases = cast("list[JsonValue]", fixtures["cases"])
    results = [build_synthetic_result(_mapping(case, "fixture case")) for case in cases]
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_result_set",
        "schema_version": SCHEMA_VERSION,
        "spec_id": determinism_canary_spec()["spec_id"],
        "fixture_set_id": fixtures["fixture_set_id"],
        "evidence_status": "synthetic_results_only",
        "result_count": len(results),
        "results": cast("list[JsonValue]", results),
    }
    return _identity_record(content, "result_set_id")


def verify_synthetic_result_set(value: JsonValue) -> dict[str, JsonValue]:
    """Verify every synthetic result and the coordinated set identity."""
    result_set = _mapping(value, "mlx_determinism_result_set")
    _keys(result_set, set(synthetic_result_set()), "mlx_determinism_result_set")
    results = _array(
        result_set["results"],
        "mlx_determinism_result_set.results",
        _MAX_RESULTS,
    )
    count = _integer(
        result_set["result_count"],
        "mlx_determinism_result_set.result_count",
        maximum=_MAX_RESULTS,
    )
    if count != len(results):
        raise ContractError("synthetic result count mismatch")
    for result in results:
        verify_determinism_result(result)
    _sha256(result_set["result_set_id"], "mlx_determinism_result_set.result_set_id")
    if canonical_json(result_set) != canonical_json(synthetic_result_set()):
        raise ContractError("synthetic result set semantic or identity drift")
    return dict(result_set)


def synthetic_determinism_atlas() -> dict[str, JsonValue]:
    """Build the machine-readable synthetic atlas from exact fixture comparisons."""
    fixtures = determinism_fixture_set()
    results = synthetic_result_set()
    cases = {
        cast("str", _mapping(item, "fixture case")["case_id"]): _mapping(item, "fixture case")
        for item in cast("list[JsonValue]", fixtures["cases"])
    }
    entries: list[JsonValue] = []
    for result_value in cast("list[JsonValue]", results["results"]):
        result = _mapping(result_value, "synthetic result")
        case = cases[cast("str", result["case_id"])]
        comparison = compare_outputs(case["expected_output"], result["output"])
        entries.append(
            {
                "case_id": result["case_id"],
                "case_contract_id": result["case_contract_id"],
                "matrix_cell_id": result["matrix_cell_id"],
                "operation_id": result["operation_id"],
                "operation_spec_id": result["operation_spec_id"],
                "dtype": result["dtype"],
                "evaluation_mode": result["evaluation_mode"],
                "operation_parameters": result["operation_parameters"],
                "result_id": result["result_id"],
                "comparison": comparison,
                "verification_rule": "synthetic_expected_output_integrity",
                "verification_status": "verified_synthetic_fixture_integrity",
            }
        )
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_atlas",
        "schema_version": SCHEMA_VERSION,
        "spec_id": determinism_canary_spec()["spec_id"],
        "fixture_set_id": fixtures["fixture_set_id"],
        "result_set_id": results["result_set_id"],
        "evidence_scope": "synthetic_fixture_only",
        "entry_count": len(entries),
        "entries": entries,
        "all_positive_records_are_synthetic": True,
        "real_mlx_behavior_claims": 0,
        "real_metal_behavior_claims": 0,
    }
    return _identity_record(content, "atlas_id")


def verify_synthetic_determinism_atlas(value: JsonValue) -> dict[str, JsonValue]:
    """Verify every comparison and the coordinated synthetic atlas identity."""
    atlas = _mapping(value, "mlx_determinism_atlas")
    _keys(atlas, set(synthetic_determinism_atlas()), "mlx_determinism_atlas")
    entries = _array(atlas["entries"], "mlx_determinism_atlas.entries", _MAX_RESULTS)
    count = _integer(
        atlas["entry_count"], "mlx_determinism_atlas.entry_count", maximum=_MAX_RESULTS
    )
    if count != len(entries):
        raise ContractError("determinism atlas entry count mismatch")
    for index, item in enumerate(entries):
        entry = _mapping(item, f"mlx_determinism_atlas.entries[{index}]")
        verify_comparison(entry["comparison"])
    _boolean(
        atlas["all_positive_records_are_synthetic"],
        "mlx_determinism_atlas.all_positive_records_are_synthetic",
    )
    _integer(atlas["real_mlx_behavior_claims"], "mlx_determinism_atlas.real_mlx_behavior_claims")
    _integer(
        atlas["real_metal_behavior_claims"],
        "mlx_determinism_atlas.real_metal_behavior_claims",
    )
    _sha256(atlas["atlas_id"], "mlx_determinism_atlas.atlas_id")
    if canonical_json(atlas) != canonical_json(synthetic_determinism_atlas()):
        raise ContractError("synthetic determinism atlas semantic or identity drift")
    return dict(atlas)


def verify_canary_record(value: JsonValue) -> dict[str, JsonValue]:
    """Dispatch strict verification for one canary record."""
    record = _mapping(value, "MLX determinism canary record")
    record_type = record.get("record_type")
    if record_type == "mlx_determinism_canary_spec":
        return verify_determinism_canary_spec(record)
    if record_type == "mlx_determinism_fixture_set":
        return verify_determinism_fixture_set(record)
    if record_type == "mlx_determinism_result":
        return verify_determinism_result(record)
    if record_type == "mlx_determinism_result_set":
        return verify_synthetic_result_set(record)
    if record_type == "mlx_determinism_comparison":
        return verify_comparison(record)
    if record_type == "mlx_determinism_atlas":
        return verify_synthetic_determinism_atlas(record)
    raise ContractError(f"unsupported MLX determinism canary record type: {record_type}")


def load_canary_record(path: Path) -> dict[str, JsonValue]:
    """Load one exact canonical canary record from a no-follow regular file."""
    return verify_canary_record(load_canonical_json_file(path, "MLX determinism canary record"))


def canary_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Return a bounded inspection projection without physical actions."""
    record = verify_canary_record(value)
    record_type = cast("str", record["record_type"])
    identity_field = {
        "mlx_determinism_canary_spec": "spec_id",
        "mlx_determinism_fixture_set": "fixture_set_id",
        "mlx_determinism_result": "result_id",
        "mlx_determinism_result_set": "result_set_id",
        "mlx_determinism_comparison": "comparison_id",
        "mlx_determinism_atlas": "atlas_id",
    }[record_type]
    output: dict[str, JsonValue] = {
        "record_type": record_type,
        "identity": record[identity_field],
        "evidence_scope": (
            record.get("evidence_scope")
            or record.get("evidence_status")
            or record.get("evidence_kind")
            or "prospective_specification"
        ),
        "mlx_imports": 0,
        "process_actions": 0,
        "device_or_metal_queries": 0,
        "hardware_synchronizations": 0,
        "model_actions": 0,
        "network_actions": 0,
    }
    for field in ("case_count", "result_count", "entry_count"):
        if field in record:
            output[field] = record[field]
    return output


@dataclass(frozen=True, slots=True)
class CanaryReplayResult:
    """Verified summary of one closed synthetic canary bundle replay."""

    bundle_root: str
    spec_id: str
    fixture_set_id: str
    result_set_id: str
    atlas_id: str
    matrix_cell_count: int
    fixture_case_count: int
    atlas_entry_count: int
    verified_synthetic_entries: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "spec_id": self.spec_id,
            "fixture_set_id": self.fixture_set_id,
            "result_set_id": self.result_set_id,
            "atlas_id": self.atlas_id,
            "matrix_cell_count": self.matrix_cell_count,
            "fixture_case_count": self.fixture_case_count,
            "atlas_entry_count": self.atlas_entry_count,
            "verified_synthetic_entries": self.verified_synthetic_entries,
            "evidence_scope": "synthetic_fixture_only",
            "mlx_imports": 0,
            "process_actions": 0,
            "device_or_metal_queries": 0,
            "hardware_synchronizations": 0,
            "model_actions": 0,
            "network_actions": 0,
        }


def compile_determinism_fixture(output_root: Path) -> tuple[Path, CanaryReplayResult]:
    """Publish the deterministic synthetic atlas with zero runtime actions."""
    spec = determinism_canary_spec()
    fixtures = determinism_fixture_set()
    results = synthetic_result_set()
    atlas = synthetic_determinism_atlas()
    source: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_embedded_scalar_byte_fixtures_only",
        "all_positive_records_are_synthetic": True,
        "fixture_value_random_generator_calls": 0,
        "mlx_imports": 0,
        "mlx_lm_imports": 0,
        "process_actions": 0,
        "backend_queries": 0,
        "device_queries": 0,
        "metal_queries": 0,
        "hardware_synchronizations": 0,
        "mlx_tensor_operations": 0,
        "model_or_tokenizer_actions": 0,
        "authorization_actions": 0,
        "network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }
    destination = publish_bundle(
        {
            "source/fixture-source.json": canonical_json(source),
            "source/canary-spec.json": canonical_json(spec),
            "source/fixture-set.json": canonical_json(fixtures),
            "synthetic-results.json": canonical_json(results),
            "determinism-atlas.json": canonical_json(atlas),
        },
        output_root,
        name_prefix="localinferencelab-mlx-determinism-canary-synthetic-v1",
    )
    return destination, replay_determinism_fixture(destination)


def _canonical_bytes(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def replay_determinism_fixture(bundle: Path) -> CanaryReplayResult:
    """Replay one closed synthetic atlas without imports, processes, or hardware access."""
    content_root, files = read_closed_bundle(bundle)
    expected_files = {
        "source/fixture-source.json",
        "source/canary-spec.json",
        "source/fixture-set.json",
        "synthetic-results.json",
        "determinism-atlas.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected_files:
        raise ContractError("MLX determinism fixture bundle has an invalid content set")
    source = _mapping(
        _canonical_bytes(files["source/fixture-source.json"], "canary fixture source"),
        "mlx_determinism_fixture_source",
    )
    expected_source = {
        "record_type": "mlx_determinism_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_embedded_scalar_byte_fixtures_only",
        "all_positive_records_are_synthetic": True,
        "fixture_value_random_generator_calls": 0,
        "mlx_imports": 0,
        "mlx_lm_imports": 0,
        "process_actions": 0,
        "backend_queries": 0,
        "device_queries": 0,
        "metal_queries": 0,
        "hardware_synchronizations": 0,
        "mlx_tensor_operations": 0,
        "model_or_tokenizer_actions": 0,
        "authorization_actions": 0,
        "network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }
    if canonical_json(source) != canonical_json(expected_source):
        raise ContractError("MLX determinism fixture source drift")
    spec = verify_determinism_canary_spec(
        _canonical_bytes(files["source/canary-spec.json"], "canary specification")
    )
    fixtures = verify_determinism_fixture_set(
        _canonical_bytes(files["source/fixture-set.json"], "canary fixture set")
    )
    results = verify_synthetic_result_set(
        _canonical_bytes(files["synthetic-results.json"], "synthetic canary results")
    )
    atlas = verify_synthetic_determinism_atlas(
        _canonical_bytes(files["determinism-atlas.json"], "synthetic determinism atlas")
    )
    if (
        fixtures["spec_id"] != spec["spec_id"]
        or results["spec_id"] != spec["spec_id"]
        or atlas["spec_id"] != spec["spec_id"]
        or results["fixture_set_id"] != fixtures["fixture_set_id"]
        or atlas["fixture_set_id"] != fixtures["fixture_set_id"]
        or atlas["result_set_id"] != results["result_set_id"]
    ):
        raise ContractError("MLX determinism bundle coordinated identity mismatch")
    entries = cast("list[JsonValue]", atlas["entries"])
    return CanaryReplayResult(
        content_root,
        cast("str", spec["spec_id"]),
        cast("str", fixtures["fixture_set_id"]),
        cast("str", results["result_set_id"]),
        cast("str", atlas["atlas_id"]),
        len(cast("list[JsonValue]", spec["matrix"])),
        cast("int", fixtures["case_count"]),
        cast("int", atlas["entry_count"]),
        sum(
            _mapping(entry, "atlas entry")["verification_status"]
            == "verified_synthetic_fixture_integrity"
            for entry in entries
        ),
    )


def write_canary_record(path: Path, value: JsonValue) -> None:
    """Write one verified canary record without replacing an existing file."""
    record = verify_canary_record(value)
    with path.open("xb") as output:
        output.write(canonical_json(record))
        output.flush()
        os.fsync(output.fileno())
