"""Adversarial tests for the process-free MLX determinism canary."""

from __future__ import annotations

import ast
import builtins
import json
import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_determinism_canary import (
    build_synthetic_result,
    canary_inspection,
    compare_outputs,
    compile_determinism_fixture,
    determinism_canary_spec,
    determinism_fixture_set,
    replay_determinism_fixture,
    synthetic_determinism_atlas,
    synthetic_result_set,
    verify_canary_record,
    verify_determinism_result,
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


def _rehash_tensor(tensor: dict[str, JsonValue]) -> None:
    data_hex = cast("str", tensor["data_hex"])
    tensor["payload_sha256"] = digest_bytes(bytes.fromhex(data_hex))
    content = dict(tensor)
    content.pop("canonical_output_digest", None)
    tensor["canonical_output_digest"] = canonical_identity(content)


def _rehash(record: dict[str, JsonValue], identity_field: str) -> None:
    content = dict(record)
    content.pop(identity_field, None)
    record[identity_field] = canonical_identity(content)


def _case(case_id: str) -> dict[str, JsonValue]:
    for value in _list(determinism_fixture_set()["cases"]):
        case = _dict(value)
        if case["case_id"] == case_id:
            return case
    raise AssertionError(f"missing fixture case {case_id}")


def _case_from_fixture(
    fixtures: dict[str, JsonValue],
    case_id: str,
) -> dict[str, JsonValue]:
    for value in _list(fixtures["cases"]):
        case = _dict(value)
        if case["case_id"] == case_id:
            return case
    raise AssertionError(f"missing fixture case {case_id}")


def _scalar_tensor(dtype: str, data_hex: str) -> dict[str, JsonValue]:
    template_case = {
        "float16": "rms_normalization_float16",
        "bfloat16": "reduction_sum_bfloat16",
        "float32": "multiply_add_fused_float32",
    }[dtype]
    tensor = _copy(_case(template_case)["expected_output"])
    tensor["shape"] = [1]
    tensor["data_hex"] = data_hex
    _rehash_tensor(tensor)
    return tensor


def _output(capfd: pytest.CaptureFixture[str]) -> dict[str, JsonValue]:
    captured = capfd.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert isinstance(value, dict)
    return cast("dict[str, JsonValue]", value)


def test_spec_matrix_is_complete_prospective_and_explicit() -> None:
    spec = determinism_canary_spec()
    operations = _list(spec["operations"])
    assert {_dict(operation)["family"] for operation in operations} >= {
        "elementwise_arithmetic",
        "matmul",
        "reduction",
        "softmax",
        "normalization",
        "fused_unfused",
    }
    matrix = _list(spec["matrix"])
    assert len(matrix) == len(operations) * 3 * 2 == 48
    assert {_dict(cell)["dtype"] for cell in matrix} == {
        "float16",
        "bfloat16",
        "float32",
    }
    assert {_dict(cell)["evaluation_mode"] for cell in matrix} == {
        "explicit_evaluation",
        "deferred_evaluation",
    }
    assert {_dict(cell)["support_status"] for cell in matrix} == {"unverified_future_support"}
    represented = [
        _dict(cell)
        for cell in matrix
        if _dict(cell)["fixture_representation_status"] == "embedded_synthetic_fixture_available"
    ]
    prospective_only = [
        _dict(cell)
        for cell in matrix
        if _dict(cell)["fixture_representation_status"] == "prospective_only_no_fixture"
    ]
    assert len(represented) == 8
    assert len(prospective_only) == 40
    assert all(cell["synthetic_fixture_case_id"] is not None for cell in represented)
    assert all(cell["synthetic_fixture_case_id"] is None for cell in prospective_only)
    coverage = _dict(spec["synthetic_fixture_coverage"])
    assert coverage == {
        "prospective_matrix_cell_count": 48,
        "represented_synthetic_cell_count": 8,
        "prospective_only_cell_count": 40,
        "coverage_claim": "structural_subset_not_full_matrix_coverage",
    }
    registry = _dict(spec["future_case_registry_contract"])
    assert registry["status"] == "unavailable_and_rejected_in_schema_1_0"

    protocol = _dict(spec["future_experiment_protocol"])
    assert protocol["retries_per_observation"] == 0
    dimensions = {
        cast("str", _dict(item)["dimension_id"]): _dict(item)
        for item in _list(protocol["dimensions"])
    }
    assert set(dimensions) == {
        "within_process_repetition",
        "cold_process_repetition",
        "cpu_vs_gpu",
        "fused_vs_unfused",
        "explicit_synchronization",
    }
    assert all(
        cast("int", dimension["predeclared_observation_count"]) > 0
        for dimension in dimensions.values()
    )
    assert protocol["timing_measurements"] == "forbidden_unless_separately_authorized"


def test_embedded_vectors_are_exact_bounded_and_rng_independent() -> None:
    fixtures = determinism_fixture_set()
    assert fixtures["random_generator"] == "absent"
    assert fixtures["all_positive_records_are_synthetic"] is True
    assert fixtures["case_count"] == 8
    assert {cast("str", _dict(case)["dtype"]) for case in _list(fixtures["cases"])} == {
        "float16",
        "bfloat16",
        "float32",
    }
    verify_canary_record(fixtures)
    results = synthetic_result_set()
    assert results["evidence_status"] == "synthetic_results_only"
    for result in _list(results["results"]):
        assert _dict(result)["evidence_kind"] == "synthetic_fixture"
        source = _dict(_dict(result)["synthetic_source"])
        assert source["physical_observation"] is False
        assert source["authorization_status"] == "not_available_in_schema_1_0"
    atlas = synthetic_determinism_atlas()
    assert atlas["all_positive_records_are_synthetic"] is True
    assert atlas["real_mlx_behavior_claims"] == 0
    assert atlas["real_metal_behavior_claims"] == 0


def test_every_fixture_binds_one_represented_cell_and_complete_operation_parameters() -> None:
    specification = determinism_canary_spec()
    operations = {
        cast("str", _dict(item)["operation_id"]): _dict(item)
        for item in _list(specification["operations"])
    }
    matrix = {
        cast("str", _dict(item)["cell_id"]): _dict(item) for item in _list(specification["matrix"])
    }
    for value in _list(determinism_fixture_set()["cases"]):
        case = _dict(value)
        operation = operations[cast("str", case["operation_id"])]
        cell = matrix[cast("str", case["matrix_cell_id"])]
        parameter_names = {
            cast("str", _dict(parameter)["name"])
            for parameter in _list(operation["parameter_schema"])
        }
        assert set(_dict(case["operation_parameters"])) == parameter_names
        assert case["operation_spec_id"] == operation["operation_spec_id"]
        assert cell["operation_spec_id"] == operation["operation_spec_id"]
        assert cell["synthetic_fixture_case_id"] == case["case_id"]
        assert cell["fixture_representation_status"] == "embedded_synthetic_fixture_available"


def test_rms_fixture_binds_exact_epsilon_axis_precision_rounding_and_derivation() -> None:
    case = _case("rms_normalization_float16")
    parameters = _dict(case["operation_parameters"])
    assert parameters["axes"] == [0]
    assert parameters["keepdims"] is True
    assert parameters["epsilon"] == {
        "dtype": "float16",
        "endianness": "little",
        "data_hex": "0000",
    }
    assert parameters["square_precision"] == "float16"
    assert parameters["accumulation_precision"] == "float16"
    assert parameters["epsilon_addition_precision"] == "float16"
    assert parameters["output_multiply_precision"] == "float16"
    assert parameters["output_rounding"] == "round_to_nearest_ties_to_even"
    assert case["expected_output_derivation"] == (
        "execute_the_declared_scalar_steps_and_round_after_each_named_stage"
    )
    assert _dict(_list(case["inputs"])[0])["data_hex"] == _dict(case["expected_output"])["data_hex"]


_RMS_PARAMETER_NAMES = (
    "axes",
    "keepdims",
    "epsilon",
    "square_precision",
    "square_rounding",
    "accumulation_precision",
    "initial_accumulator",
    "reduction_order",
    "mean_divisor",
    "mean_rounding",
    "epsilon_addition_precision",
    "epsilon_addition_rounding",
    "reciprocal_sqrt_contract",
    "reciprocal_sqrt_rounding",
    "output_multiply_precision",
    "output_rounding",
)


@pytest.mark.parametrize("parameter_name", _RMS_PARAMETER_NAMES)
def test_rms_parameter_drift_fails_after_coordinated_rehash(parameter_name: str) -> None:
    fixtures = _copy(determinism_fixture_set())
    case = _case_from_fixture(fixtures, "rms_normalization_float16")
    parameters = _dict(case["operation_parameters"])
    original = parameters[parameter_name]
    if isinstance(original, bool):
        parameters[parameter_name] = not original
    elif isinstance(original, int):
        parameters[parameter_name] = original + 1
    elif isinstance(original, list):
        parameters[parameter_name] = [1]
    elif isinstance(original, dict):
        replacement = _copy(original)
        replacement["data_hex"] = "0100"
        parameters[parameter_name] = replacement
    else:
        parameters[parameter_name] = f"{original}_drift"
    _rehash(case, "case_contract_id")
    _rehash(fixtures, "fixture_set_id")
    with pytest.raises(ContractError, match="parameter drift"):
        verify_canary_record(fixtures)


def test_rms_evaluation_mode_drift_fails_after_coordinated_rehash() -> None:
    fixtures = _copy(determinism_fixture_set())
    case = _case_from_fixture(fixtures, "rms_normalization_float16")
    case["evaluation_mode"] = "explicit_evaluation"
    _rehash(case, "case_contract_id")
    _rehash(fixtures, "fixture_set_id")
    with pytest.raises(ContractError, match="binding mismatch"):
        verify_canary_record(fixtures)


def test_comparison_reports_bitwise_digest_error_ulp_and_ieee_edges() -> None:
    edge_output = _copy(_case("identity_edges_float32")["expected_output"])
    exact = compare_outputs(edge_output, edge_output)
    assert exact["bitwise_equal"] is True
    assert exact["canonical_output_digest_equal"] is True
    assert exact["numerical_equal"] is True
    assert exact["finite_pair_count"] == 2
    assert exact["nan_pair_count"] == 1
    assert exact["infinity_pair_count"] == 2
    assert exact["special_mismatch_count"] == 0

    signed_zero = _copy(edge_output)
    signed_zero["data_hex"] = "00000080000000800000807f000080ff0000c07f"
    _rehash_tensor(signed_zero)
    zero_comparison = compare_outputs(edge_output, signed_zero)
    assert zero_comparison["bitwise_equal"] is False
    assert zero_comparison["canonical_output_digest_equal"] is False
    assert zero_comparison["numerical_equal"] is True
    assert zero_comparison["signed_zero_bit_difference_count"] == 1
    assert zero_comparison["maximum_ulp_distance"] == 0
    assert _dict(zero_comparison["maximum_absolute_error"])["value_hex"] == "0000000000000000"

    softmax_output = _copy(_case("softmax_float32")["expected_output"])
    one_ulp = _copy(softmax_output)
    one_ulp["data_hex"] = "0100003f0000003f"
    _rehash_tensor(one_ulp)
    ulp_comparison = compare_outputs(softmax_output, one_ulp)
    assert ulp_comparison["numerical_equal"] is False
    assert ulp_comparison["maximum_ulp_distance"] == 1
    assert _dict(ulp_comparison["maximum_absolute_error"])["value_hex"] != "0000000000000000"
    assert _dict(ulp_comparison["maximum_relative_error"])["value_hex"] != "0000000000000000"

    nan_payload = _copy(edge_output)
    nan_payload["data_hex"] = "00000000000000800000807f000080ff0100c07f"
    _rehash_tensor(nan_payload)
    nan_comparison = compare_outputs(edge_output, nan_payload)
    assert nan_comparison["nan_pair_count"] == 1
    assert nan_comparison["special_mismatch_count"] == 1
    assert nan_comparison["numerical_equal"] is False


@pytest.mark.parametrize(
    ("dtype", "negative_min", "negative_zero", "positive_zero", "positive_min"),
    [
        ("float16", "0180", "0080", "0000", "0100"),
        ("bfloat16", "0180", "0080", "0000", "0100"),
        ("float32", "01000080", "00000080", "00000000", "01000000"),
    ],
)
def test_ulp_order_collapses_signed_zero_across_zero_in_both_directions(
    dtype: str,
    negative_min: str,
    negative_zero: str,
    positive_zero: str,
    positive_min: str,
) -> None:
    pairs = [
        (negative_min, positive_zero, 1),
        (positive_zero, negative_min, 1),
        (negative_zero, positive_min, 1),
        (positive_min, negative_zero, 1),
        (negative_min, positive_min, 2),
        (positive_min, negative_min, 2),
    ]
    for left, right, expected_distance in pairs:
        comparison = compare_outputs(
            _scalar_tensor(dtype, left),
            _scalar_tensor(dtype, right),
        )
        assert comparison["maximum_ulp_distance"] == expected_distance


def test_comparison_rejects_shape_dtype_length_and_bool_integer_ambiguity() -> None:
    output = _copy(_case("softmax_float32")["expected_output"])
    reshaped = _copy(output)
    reshaped["shape"] = [1, 2]
    _rehash_tensor(reshaped)
    with pytest.raises(ContractError, match="metadata mismatch"):
        compare_outputs(output, reshaped)

    wrong_dtype = _copy(output)
    wrong_dtype["dtype"] = "bfloat16"
    with pytest.raises(ContractError, match="payload length"):
        compare_outputs(output, wrong_dtype)

    wrong_length = _copy(output)
    wrong_length["data_hex"] = "0000003f"
    _rehash_tensor(wrong_length)
    with pytest.raises(ContractError, match="payload length"):
        compare_outputs(output, wrong_length)

    bool_shape = _copy(output)
    bool_shape["shape"] = [True, 2]
    with pytest.raises(ContractError, match="integer"):
        compare_outputs(output, bool_shape)


def _unknown_field(value: dict[str, JsonValue]) -> None:
    value["unexpected"] = True


def _forged_observed_synthetic(value: dict[str, JsonValue]) -> None:
    value["evidence_kind"] = "authorized_observation"
    _rehash(value, "result_id")


def _forged_physical_source(value: dict[str, JsonValue]) -> None:
    _dict(value["synthetic_source"])["physical_observation"] = True
    _rehash(value, "result_id")


def _forged_synthetic_identity(value: dict[str, JsonValue]) -> None:
    _dict(value["synthetic_source"])["runtime_identity_id"] = "sha256:" + ("1" * 64)
    _rehash(value, "result_id")


def _bool_result_count(value: dict[str, JsonValue]) -> None:
    value["result_count"] = True
    _rehash(value, "result_set_id")


@pytest.mark.parametrize(
    "mutate",
    [
        _unknown_field,
        _forged_observed_synthetic,
        _forged_physical_source,
        _forged_synthetic_identity,
    ],
)
def test_result_schema_rejects_malformed_or_physical_evidence(
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    result = _copy(build_synthetic_result(_case("softmax_float32")))
    mutate(result)
    with pytest.raises(ContractError):
        verify_determinism_result(result)


def test_self_asserted_identity_hashes_cannot_create_an_observation() -> None:
    result = _copy(build_synthetic_result(_case("softmax_float32")))
    result["evidence_kind"] = "authorized_observation"
    result["observation_condition"] = {
        "device_class": "gpu",
        "synchronization_mode": "explicit_synchronization",
        "process_mode": "cold_process_repetition",
        "observation_index": 1,
    }
    result["self_asserted_provenance"] = {
        "acquisition_mode": "future_external_authorized_protocol",
        "authorization_evidence_id": "sha256:" + ("1" * 64),
        "runtime_identity_id": "sha256:" + ("2" * 64),
        "device_identity_id": "sha256:" + ("3" * 64),
        "process_instance_id": "sha256:" + ("4" * 64),
    }
    result["runtime_behavior_claim"] = "authorized_observation_only"
    _rehash(result, "result_id")
    with pytest.raises(ContractError):
        verify_determinism_result(result)


def test_future_case_registry_record_is_rejected_in_schema_1_0() -> None:
    registry: dict[str, JsonValue] = {
        "record_type": "mlx_determinism_case_registry",
        "schema_version": "1.0",
        "registry_id": "sha256:" + ("1" * 64),
        "cases": [],
    }
    with pytest.raises(ContractError, match="unsupported"):
        verify_canary_record(registry)


def test_result_rejects_undeclared_or_mismatched_matrix_cell() -> None:
    result = _copy(build_synthetic_result(_case("softmax_float32")))
    result["matrix_cell_id"] = "softmax_bfloat16_deferred_evaluation"
    _rehash(result, "result_id")
    with pytest.raises(ContractError, match="binding mismatch"):
        verify_determinism_result(result)

    undeclared = _copy(build_synthetic_result(_case("softmax_float32")))
    undeclared["matrix_cell_id"] = "softmax_float64_explicit_evaluation"
    _rehash(undeclared, "result_id")
    with pytest.raises(ContractError, match="binding mismatch"):
        verify_determinism_result(undeclared)

    prospective_only_case = _copy(_case("softmax_float32"))
    prospective_only_case["case_id"] = "softmax_bfloat16_deferred"
    prospective_only_case["matrix_cell_id"] = "softmax_bfloat16_deferred_evaluation"
    prospective_only_case["dtype"] = "bfloat16"
    _rehash(prospective_only_case, "case_contract_id")
    with pytest.raises(ContractError, match="exact pinned represented fixture"):
        build_synthetic_result(prospective_only_case)


def test_result_set_rejects_boolean_count() -> None:
    result_set = _copy(synthetic_result_set())
    _bool_result_count(result_set)
    with pytest.raises(ContractError, match="integer"):
        verify_canary_record(result_set)


def test_fixture_is_byte_identical_and_replays_offline(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_replay = compile_determinism_fixture(first_root)
    second, second_replay = compile_determinism_fixture(second_root)
    assert first.name == second.name
    first_content_root, first_files = read_closed_bundle(first)
    second_content_root, second_files = read_closed_bundle(second)
    assert first_content_root == second_content_root
    assert first_files == second_files
    assert first_replay == second_replay
    assert first_replay.matrix_cell_count == 48
    assert first_replay.fixture_case_count == 8
    assert first_replay.verified_synthetic_entries == 8
    assert replay_determinism_fixture(first) == first_replay


def test_replay_rejects_coordinated_rehash_extra_missing_and_noncanonical(
    tmp_path: Path,
) -> None:
    original_root = tmp_path / "original"
    original_root.mkdir()
    original, _replay = compile_determinism_fixture(original_root)
    _content_root, files = read_closed_bundle(original)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    republished_root = tmp_path / "republished"
    republished_root.mkdir()

    coordinated = dict(content)
    results = _copy(json.loads(coordinated["synthetic-results.json"]))
    result = _dict(_list(results["results"])[-1])
    output = _dict(result["output"])
    output["data_hex"] = "0100003f0000003f"
    _rehash_tensor(output)
    _rehash(result, "result_id")
    _rehash(results, "result_set_id")
    coordinated["synthetic-results.json"] = canonical_json(results)
    atlas = _copy(json.loads(coordinated["determinism-atlas.json"]))
    atlas["result_set_id"] = results["result_set_id"]
    entry = _dict(_list(atlas["entries"])[-1])
    entry["result_id"] = result["result_id"]
    entry["comparison"] = compare_outputs(
        _case("softmax_float32")["expected_output"],
        output,
    )
    entry["verification_status"] = "invalid_synthetic_fixture_integrity"
    _rehash(atlas, "atlas_id")
    coordinated["determinism-atlas.json"] = canonical_json(atlas)
    coordinated_bundle = publish_bundle(
        coordinated,
        republished_root,
        name_prefix="coordinated",
    )
    with pytest.raises(ContractError):
        replay_determinism_fixture(coordinated_bundle)

    extra = dict(content)
    extra["extra.json"] = b"{}"
    extra_bundle = publish_bundle(extra, republished_root, name_prefix="extra")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_determinism_fixture(extra_bundle)

    missing = dict(content)
    missing.pop("source/canary-spec.json")
    missing_bundle = publish_bundle(missing, republished_root, name_prefix="missing")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_determinism_fixture(missing_bundle)

    noncanonical = dict(content)
    noncanonical["source/fixture-set.json"] = json.dumps(
        json.loads(noncanonical["source/fixture-set.json"]),
        indent=2,
    ).encode()
    noncanonical_bundle = publish_bundle(
        noncanonical,
        republished_root,
        name_prefix="noncanonical",
    )
    with pytest.raises(ContractError, match="canonical JSON bytes"):
        replay_determinism_fixture(noncanonical_bundle)


def test_contract_paths_cross_no_import_process_socket_or_hardware_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals_value: dict[str, object] | None = None,
        locals_value: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name == "mlx" or name.startswith(("mlx.", "mlx_lm")):
            raise AssertionError("canary attempted to import an MLX runtime")
        return original_import(name, globals_value, locals_value, fromlist, level)

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("canary crossed a physical-action boundary")

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(os, "posix_spawnp", forbidden)

    verify_canary_record(determinism_canary_spec())
    verify_canary_record(determinism_fixture_set())
    verify_canary_record(synthetic_result_set())
    inspection = canary_inspection(synthetic_determinism_atlas())
    assert inspection["mlx_imports"] == 0
    assert inspection["process_actions"] == 0
    assert inspection["device_or_metal_queries"] == 0
    root = tmp_path / "bundle"
    root.mkdir()
    bundle, _result = compile_determinism_fixture(root)
    replay_determinism_fixture(bundle)


def test_canary_module_has_no_runtime_or_transport_import_surface() -> None:
    module_path = Path(__file__).parents[1] / "src/localinferencelab/mlx_determinism_canary.py"
    tree = ast.parse(module_path.read_text())
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", 1)[0])
    assert imported_roots.isdisjoint({"mlx", "mlx_lm", "socket", "subprocess", "http", "urllib"})


def test_canary_cli_spec_verify_inspect_compile_and_replay(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert run(["mlx", "determinism-canary-spec"]) == 0
    spec_bytes = capfd.readouterr().out.encode()
    spec_path = tmp_path / "spec.json"
    spec_path.write_bytes(spec_bytes)

    assert run(["mlx", "determinism-canary-verify", str(spec_path)]) == 0
    verified = _output(capfd)
    assert verified["status"] == "valid"
    assert verified["record_type"] == "mlx_determinism_canary_spec"
    assert verified["mlx_imports"] == 0

    atlas_path = tmp_path / "atlas.json"
    atlas_path.write_bytes(canonical_json(synthetic_determinism_atlas()))
    assert run(["mlx", "determinism-canary-inspect", str(atlas_path)]) == 0
    inspected = _output(capfd)
    assert inspected["status"] == "inspected"
    assert inspected["entry_count"] == 8

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    assert run(["mlx", "determinism-canary-fixture-compile", str(fixture_root)]) == 0
    compiled = _output(capfd)
    assert compiled["status"] == "compiled"
    assert compiled["evidence_scope"] == "synthetic_fixture_only"
    bundle = fixture_root / cast("str", compiled["path"])
    assert run(["mlx", "determinism-canary-replay", str(bundle)]) == 0
    replayed = _output(capfd)
    assert replayed["status"] == "replayed"
    assert replayed["verified_synthetic_entries"] == 8
    assert replayed["process_actions"] == 0
