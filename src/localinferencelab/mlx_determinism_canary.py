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
_DTYPE_BYTES = {"float16": 2, "bfloat16": 2, "float32": 4}
_EVALUATION_MODES = {"deferred_evaluation", "explicit_evaluation"}
_SUPPORT_STATUSES = {
    "unverified_future_support",
    "unsupported_by_authorized_runtime",
    "verified_by_authorized_observation",
}
_EVIDENCE_KINDS = {"synthetic_fixture", "authorized_observation"}
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


def _optional_sha256(value: JsonValue, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


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
) -> dict[str, JsonValue]:
    return {
        "operation_id": operation_id,
        "family": family,
        "form": form,
        "mathematical_contract": expression,
        "input_arity": input_arity,
        "output_rank": output_rank,
        "implementation_claim": "none",
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
        ),
        _operation(
            "identity_edges",
            "elementwise_arithmetic",
            "identity",
            "output[i]=input[i]",
            1,
            1,
        ),
        _operation(
            "matrix_multiply",
            "matmul",
            "single_operation",
            "output[i,j]=sum_k(left[i,k]*right[k,j])",
            2,
            2,
        ),
        _operation(
            "multiply_add_fused",
            "fused_unfused",
            "fused",
            "output[i]=fused_multiply_add(a[i],b[i],c[i])",
            3,
            1,
        ),
        _operation(
            "multiply_add_unfused",
            "fused_unfused",
            "unfused",
            "output[i]=(a[i]*b[i])+c[i] with an observable intermediate",
            3,
            1,
        ),
        _operation(
            "reduction_sum",
            "reduction",
            "sum_all",
            "output[0]=sum_i(input[i])",
            1,
            1,
        ),
        _operation(
            "rms_normalization",
            "normalization",
            "rms",
            "output[i]=input[i]/sqrt(mean(input^2)+epsilon)",
            1,
            1,
        ),
        _operation(
            "softmax",
            "softmax",
            "last_axis",
            "output[i]=exp(input[i]-max(input))/sum_j(exp(input[j]-max(input)))",
            1,
            1,
        ),
    ]


def _operation_matrix() -> list[JsonValue]:
    return [
        {
            "cell_id": f"{cast('str', operation['operation_id'])}_{dtype}_{evaluation_mode}",
            "operation_id": operation["operation_id"],
            "dtype": dtype,
            "evaluation_mode": evaluation_mode,
            "support_status": "unverified_future_support",
            "support_evidence_id": None,
            "reason": (
                "No authorized MLX runtime observation is bound to this prospective combination."
            ),
        }
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
        "matrix": _operation_matrix(),
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
                    "rule_id": "invalid_observation",
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
            "tensor_operations": 0,
            "model_or_tokenizer_actions": 0,
            "network_actions": 0,
            "cloud_actions": 0,
            "spend_actions": 0,
        },
        "non_claims": [
            "synthetic vectors do not describe real MLX behavior",
            "synthetic vectors do not describe real Metal behavior",
            "matrix inclusion does not assert future runtime support",
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
    return {
        "case_id": case_id,
        "operation_id": operation_id,
        "dtype": dtype,
        "evaluation_mode": evaluation_mode,
        "inputs": cast("list[JsonValue]", inputs),
        "expected_output": expected,
        "evidence_kind": "synthetic_fixture",
        "runtime_behavior_claim": "none",
    }


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
    for case_index, item in enumerate(cases):
        case = _mapping(item, f"fixture.cases[{case_index}]")
        for tensor_index, tensor in enumerate(
            _array(case["inputs"], f"fixture.cases[{case_index}].inputs", 8)
        ):
            _parse_tensor(tensor, f"fixture.cases[{case_index}].inputs[{tensor_index}]")
        _parse_tensor(case["expected_output"], f"fixture.cases[{case_index}].expected_output")
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
        return (~code & mask) if code & sign else code | sign

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
    content: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_result",
        "schema_version": SCHEMA_VERSION,
        "spec_id": determinism_canary_spec()["spec_id"],
        "fixture_set_id": determinism_fixture_set()["fixture_set_id"],
        "case_id": case["case_id"],
        "operation_id": case["operation_id"],
        "dtype": case["dtype"],
        "evaluation_mode": case["evaluation_mode"],
        "evidence_kind": "synthetic_fixture",
        "condition": {
            "device_class": "synthetic_not_applicable",
            "synchronization_mode": "synthetic_not_applicable",
            "process_mode": "synthetic_not_applicable",
            "observation_index": 0,
            "fusion_form": (
                case["operation_id"]
                if case["operation_id"] in {"multiply_add_fused", "multiply_add_unfused"}
                else "not_applicable"
            ),
        },
        "attempt": {
            "attempt_index": 1,
            "retry_count": 0,
            "replaces_result_id": None,
        },
        "provenance": {
            "acquisition_mode": "embedded_scalar_byte_copy",
            "authorization_evidence_id": None,
            "runtime_identity_id": None,
            "device_identity_id": None,
            "process_instance_id": None,
        },
        "output": case["expected_output"],
        "runtime_behavior_claim": "none",
    }
    return _identity_record(content, "result_id")


def verify_determinism_result(value: JsonValue) -> dict[str, JsonValue]:
    """Verify one synthetic or future externally acquired result record."""
    result = _mapping(value, "mlx_determinism_result")
    fields = {
        "record_type",
        "schema_version",
        "spec_id",
        "fixture_set_id",
        "case_id",
        "operation_id",
        "dtype",
        "evaluation_mode",
        "evidence_kind",
        "condition",
        "attempt",
        "provenance",
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
    _identifier(result["operation_id"], "mlx_determinism_result.operation_id")
    _literal(result["dtype"], set(_DTYPE_BYTES), "mlx_determinism_result.dtype")
    _literal(
        result["evaluation_mode"],
        _EVALUATION_MODES,
        "mlx_determinism_result.evaluation_mode",
    )
    evidence_kind = _literal(
        result["evidence_kind"],
        _EVIDENCE_KINDS,
        "mlx_determinism_result.evidence_kind",
    )
    condition = _mapping(result["condition"], "mlx_determinism_result.condition")
    _keys(
        condition,
        {
            "device_class",
            "synchronization_mode",
            "process_mode",
            "observation_index",
            "fusion_form",
        },
        "mlx_determinism_result.condition",
    )
    device_class = _literal(
        condition["device_class"],
        {"cpu", "gpu", "synthetic_not_applicable"},
        "mlx_determinism_result.condition.device_class",
    )
    synchronization_mode = _literal(
        condition["synchronization_mode"],
        {
            "explicit_synchronization",
            "output_materialization_only",
            "synthetic_not_applicable",
        },
        "mlx_determinism_result.condition.synchronization_mode",
    )
    process_mode = _literal(
        condition["process_mode"],
        {
            "cold_process_repetition",
            "synthetic_not_applicable",
            "within_process_repetition",
        },
        "mlx_determinism_result.condition.process_mode",
    )
    observation_index = _integer(
        condition["observation_index"],
        "mlx_determinism_result.condition.observation_index",
        maximum=5,
    )
    fusion_form = _literal(
        condition["fusion_form"],
        {
            "multiply_add_fused",
            "multiply_add_unfused",
            "not_applicable",
        },
        "mlx_determinism_result.condition.fusion_form",
    )
    attempt = _mapping(result["attempt"], "mlx_determinism_result.attempt")
    _keys(
        attempt,
        {"attempt_index", "retry_count", "replaces_result_id"},
        "mlx_determinism_result.attempt",
    )
    if (
        _integer(
            attempt["attempt_index"],
            "mlx_determinism_result.attempt.attempt_index",
            minimum=1,
            maximum=1,
        )
        != 1
        or _integer(
            attempt["retry_count"],
            "mlx_determinism_result.attempt.retry_count",
            maximum=0,
        )
        != 0
        or attempt["replaces_result_id"] is not None
    ):
        raise ContractError(
            "determinism results permit one attempt, zero retries, and no replacement"
        )
    provenance = _mapping(result["provenance"], "mlx_determinism_result.provenance")
    provenance_fields = {
        "acquisition_mode",
        "authorization_evidence_id",
        "runtime_identity_id",
        "device_identity_id",
        "process_instance_id",
    }
    _keys(provenance, provenance_fields, "mlx_determinism_result.provenance")
    _text(provenance["acquisition_mode"], "mlx_determinism_result.provenance.acquisition_mode")
    identity_fields = (
        "authorization_evidence_id",
        "runtime_identity_id",
        "device_identity_id",
        "process_instance_id",
    )
    identities = tuple(
        _optional_sha256(provenance[field], f"mlx_determinism_result.provenance.{field}")
        for field in identity_fields
    )
    if evidence_kind == "synthetic_fixture":
        if any(identity is not None for identity in identities):
            raise ContractError(
                "synthetic result cannot contain runtime or authorization identities"
            )
        if (
            provenance["acquisition_mode"] != "embedded_scalar_byte_copy"
            or result["runtime_behavior_claim"] != "none"
            or device_class != "synthetic_not_applicable"
            or synchronization_mode != "synthetic_not_applicable"
            or process_mode != "synthetic_not_applicable"
            or observation_index != 0
        ):
            raise ContractError("synthetic result must remain an embedded non-runtime record")
    else:
        if any(identity is None for identity in identities):
            raise ContractError("authorized observation requires every provenance identity")
        if (
            device_class == "synthetic_not_applicable"
            or synchronization_mode == "synthetic_not_applicable"
            or process_mode == "synthetic_not_applicable"
            or observation_index == 0
            or result["runtime_behavior_claim"] != "authorized_observation_only"
        ):
            raise ContractError(
                "authorized observation requires every declared experiment condition"
            )
    _text(result["runtime_behavior_claim"], "mlx_determinism_result.runtime_behavior_claim")
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
        result["operation_id"] != case["operation_id"]
        or result["dtype"] != case["dtype"]
        or result["evaluation_mode"] != case["evaluation_mode"]
    ):
        raise ContractError("result operation, dtype, or evaluation mode differs from its fixture")
    expected_output = _parse_tensor(case["expected_output"], "fixture expected output")
    if (
        output.shape != expected_output.shape
        or output.endianness != expected_output.endianness
        or output.record["name"] != expected_output.record["name"]
    ):
        raise ContractError("result output metadata differs from its fixture")
    expected_fusion_form = (
        result["operation_id"]
        if result["operation_id"] in {"multiply_add_fused", "multiply_add_unfused"}
        else "not_applicable"
    )
    if fusion_form != expected_fusion_form:
        raise ContractError("result fusion form differs from its operation")
    if evidence_kind == "synthetic_fixture" and canonical_json(output.record) != canonical_json(
        expected_output.record
    ):
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
                "operation_id": result["operation_id"],
                "dtype": result["dtype"],
                "evaluation_mode": result["evaluation_mode"],
                "result_id": result["result_id"],
                "comparison": comparison,
                "acceptance_rule": "same_condition_repeatability",
                "acceptance_status": "accepted_synthetic_contract_example",
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
    accepted_synthetic_entries: int

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
            "accepted_synthetic_entries": self.accepted_synthetic_entries,
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
        "tensor_operations": 0,
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
        "tensor_operations": 0,
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
            _mapping(entry, "atlas entry")["acceptance_status"]
            == "accepted_synthetic_contract_example"
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
