"""Adversarial tests for the process-free physical MLX atlas contract."""

from __future__ import annotations

import ast
import json
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
from localinferencelab.mlx_physical_atlas import (
    compare_physical_outputs,
    compile_physical_atlas_fixture,
    physical_atlas_inspection,
    physical_atlas_study_spec,
    physical_observation_envelope_set,
    prospective_observation_envelope,
    replay_physical_atlas_fixture,
    verify_observation_envelope,
    verify_observation_envelope_set,
    verify_physical_atlas_study_spec,
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


def _rehash(record: dict[str, JsonValue], identity_field: str) -> None:
    content = dict(record)
    content.pop(identity_field, None)
    record[identity_field] = canonical_identity(content)


def _tensor(dtype: str, shape: list[int], data_hex: str) -> dict[str, JsonValue]:
    payload = bytes.fromhex(data_hex)
    return {
        "dtype": dtype,
        "shape": cast("list[JsonValue]", shape),
        "layout": "row_major_contiguous",
        "endianness": "little",
        "data_hex": data_hex,
        "payload_sha256": digest_bytes(payload),
    }


def _output(capfd: pytest.CaptureFixture[str]) -> dict[str, JsonValue]:
    captured = capfd.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert isinstance(value, dict)
    return cast("dict[str, JsonValue]", value)


def _bundle_files(bundle: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(bundle)): path.read_bytes()
        for path in sorted(bundle.rglob("*"))
        if path.is_file()
    }


def test_exact_v1_study_is_bounded_identity_bound_and_preserves_48_8_0_truth() -> None:
    spec = physical_atlas_study_spec()
    assert spec["study_id"] == (
        "sha256:231214ab37eea562b70a52639e3bbfd92b6d3cc56a42a026b670c43db8a45d33"
    )
    verify_physical_atlas_study_spec(spec)
    assert spec["selected_cell_count"] == 18
    operations = {
        cast("str", _dict(operation)["operation_name"]): _dict(operation)
        for operation in _list(spec["operations"])
    }
    assert set(operations) == {
        "matrix_multiply",
        "softmax",
        "rms_normalization",
        "layer_normalization",
        "argmax",
    }
    for name in (
        "matrix_multiply",
        "softmax",
        "rms_normalization",
        "layer_normalization",
    ):
        assert operations[name]["valid_dtypes"] == ["float16", "bfloat16", "float32"]
    assert operations["argmax"]["valid_dtypes"] == ["float32"]
    argmax_constants = _dict(operations["argmax"]["constants_and_evaluation"])
    assert argmax_constants["index_dtype"] == "uint32"
    assert argmax_constants["output_casting_by_name"] == {"indices": "none_native_uint32"}
    assert argmax_constants["tie_policy"] == "lowest_axis_index"
    assert _dict(argmax_constants["upstream_binding"])["revision"] == (
        "2f324cc3b200700b422db4811ae3ff8bd5bf48b4"
    )
    relationship = _dict(spec["relationship_to_legacy_canary"])
    assert relationship == {
        "relationship": "versioned_successor_physical_subset_without_identity_rewrite",
        "legacy_record_type": "mlx_determinism_canary_spec",
        "legacy_schema_version": "1.0",
        "legacy_canary_spec_id": relationship["legacy_canary_spec_id"],
        "legacy_prospective_cell_count": 48,
        "legacy_represented_synthetic_cell_count": 8,
        "legacy_accepted_physical_observation_count": 0,
        "historical_cell_or_record_identity_rewritten": False,
    }
    identity_slots = _dict(spec["reviewed_identity_slots"])
    assert _dict(identity_slots["reviewed_worker"])["identity"] is None
    assert _dict(identity_slots["reviewed_authorization"])["identity"] is None
    state = _dict(spec["current_state"])
    assert state["physical_observation_candidate_count"] == 0
    assert state["accepted_physical_observation_count"] == 0
    assert state["promotable_record_count"] == 0
    assert state["permission_to_execute"] is False


def test_cells_bind_exact_shapes_axes_inputs_constants_modes_and_run_order() -> None:
    spec = physical_atlas_study_spec()
    cells = [_dict(cell) for cell in _list(spec["selected_cells"])]
    assert len({cast("str", cell["cell_id"]) for cell in cells}) == 18
    assert sum(cell["evaluation_mode"] == "compiled" for cell in cells) == 5
    for cell in cells:
        input_generation = _dict(cell["input_generation"])
        assert input_generation["algorithm"] == "sha256_domain_separated_finite_codebook_v1"
        assert len(cast("str", input_generation["seed_hex"])) == 64
        for input_value in _list(input_generation["inputs"]):
            input_descriptor = _dict(input_value)
            assert cast("str", input_descriptor["payload_sha256"]).startswith("sha256:")
            assert input_descriptor["layout"] == "row_major_contiguous"
    envelope = prospective_observation_envelope("matrix_multiply_float32_compiled")
    run_plan = _dict(envelope["run_plan"])
    steps = [_dict(step) for step in _list(run_plan["planned_steps"])]
    assert [step["global_step_index"] for step in steps] == list(range(10))
    assert [step["process_ordinal"] for step in steps] == [0, 1, 2, 3, 3, 3, 3, 3, 3, 3]
    assert sum(step["step_kind"] == "observation" for step in steps) == 8
    assert all(step["retry_index"] == 0 for step in steps)
    assert all(
        "operation_complete_before_output_readback" in step["synchronization_points"]
        for step in steps
    )
    comparison_plan = _dict(envelope["comparison_plan"])
    assert comparison_plan["required_pair_count"] == 28
    assert comparison_plan["required_comparison_record_count"] == 28
    assert len(_list(comparison_plan["required_pairs"])) == 28
    assert len(_list(envelope["comparison_records"])) == 28
    aggregate = _dict(envelope["comparison_aggregate"])
    assert aggregate["present_metric_record_count"] == 0
    assert aggregate["missing_metric_record_count"] == 28
    assert aggregate["aggregate_accepted"] is False
    assert aggregate["favorable_subset_accepted"] is False


@pytest.mark.parametrize("field", ["study_name", "comparison_contract"])
def test_spec_field_set_is_exact(field: str) -> None:
    missing = _copy(physical_atlas_study_spec())
    del missing[field]
    _rehash(missing, "study_id")
    with pytest.raises(ContractError, match="missing keys"):
        verify_physical_atlas_study_spec(missing)

    extra = _copy(physical_atlas_study_spec())
    extra["unexpected"] = True
    _rehash(extra, "study_id")
    with pytest.raises(ContractError, match="unknown keys"):
        verify_physical_atlas_study_spec(extra)


def test_observation_envelope_field_set_is_exact() -> None:
    missing = _copy(prospective_observation_envelope("matrix_multiply_float16_eager"))
    del missing["comparison_aggregate"]
    _rehash(missing, "record_id")
    with pytest.raises(ContractError, match="missing keys"):
        verify_observation_envelope(missing)

    extra = _copy(prospective_observation_envelope("matrix_multiply_float16_eager"))
    extra["observed_authorization_hash"] = "sha256:" + ("1" * 64)
    _rehash(extra, "record_id")
    with pytest.raises(ContractError, match="unknown keys"):
        verify_observation_envelope(extra)


def test_invalid_dimension_axis_and_dtype_operation_combinations_fail_closed() -> None:
    invalid_dimension = _copy(physical_atlas_study_spec())
    dimension_cell = _dict(_list(invalid_dimension["selected_cells"])[0])
    input_contract = _dict(_list(dimension_cell["input_contract"])[0])
    input_contract["shape"] = [0, 8]
    _rehash(dimension_cell, "cell_id")
    _rehash(invalid_dimension, "study_id")
    with pytest.raises(ContractError, match="integer >= 1"):
        verify_physical_atlas_study_spec(invalid_dimension)

    invalid_axis = _copy(physical_atlas_study_spec())
    axis_cell = _dict(_list(invalid_axis["selected_cells"])[4])
    _dict(axis_cell["axes"])["axis"] = 3
    _rehash(axis_cell, "cell_id")
    _rehash(invalid_axis, "study_id")
    with pytest.raises(ContractError, match="axes invalid"):
        verify_physical_atlas_study_spec(invalid_axis)

    unsupported_dtype = _copy(physical_atlas_study_spec())
    argmax_cell = _dict(_list(unsupported_dtype["selected_cells"])[-1])
    argmax_cell["dtype"] = "bfloat16"
    _rehash(argmax_cell, "cell_id")
    _rehash(unsupported_dtype, "study_id")
    with pytest.raises(ContractError, match="unsupported dtype/operation combination"):
        verify_physical_atlas_study_spec(unsupported_dtype)


def test_extra_operation_and_cell_fail_with_contract_errors_not_index_errors() -> None:
    extra_operation = _copy(physical_atlas_study_spec())
    _list(extra_operation["operations"]).append(_list(extra_operation["operations"])[0])
    _rehash(extra_operation, "study_id")
    with pytest.raises(ContractError, match="operation count mismatch"):
        verify_physical_atlas_study_spec(extra_operation)

    extra_cell = _copy(physical_atlas_study_spec())
    _list(extra_cell["selected_cells"]).append(_list(extra_cell["selected_cells"])[0])
    extra_cell["selected_cell_count"] = 19
    _rehash(extra_cell, "study_id")
    with pytest.raises(ContractError, match="cell array length mismatch"):
        verify_physical_atlas_study_spec(extra_cell)


@pytest.mark.parametrize(
    ("dtype", "negative_min", "negative_zero", "positive_zero", "positive_min"),
    [
        ("float16", "0180", "0080", "0000", "0100"),
        ("bfloat16", "0180", "0080", "0000", "0100"),
        ("float32", "01000080", "00000080", "00000000", "01000000"),
    ],
)
def test_signed_zero_normalized_ulp_is_monotonic_across_zero(
    dtype: str,
    negative_min: str,
    negative_zero: str,
    positive_zero: str,
    positive_min: str,
) -> None:
    signed_zero = compare_physical_outputs(
        _tensor(dtype, [1], negative_zero),
        _tensor(dtype, [1], positive_zero),
    )
    assert signed_zero["exact_equal"] is False
    assert signed_zero["numerical_equal"] is True
    assert signed_zero["mismatch_count"] == 1
    assert signed_zero["signed_zero_bit_difference_count"] == 1
    assert signed_zero["maximum_signed_zero_normalized_ulp_distance"] == 0

    for left, right, expected_distance in (
        (negative_min, positive_zero, 1),
        (positive_zero, negative_min, 1),
        (negative_zero, positive_min, 1),
        (positive_min, negative_zero, 1),
        (negative_min, positive_min, 2),
        (positive_min, negative_min, 2),
    ):
        comparison = compare_physical_outputs(
            _tensor(dtype, [1], left),
            _tensor(dtype, [1], right),
        )
        assert comparison["maximum_signed_zero_normalized_ulp_distance"] == expected_distance


def test_nan_infinity_and_finite_error_metrics_follow_exact_policy() -> None:
    exact = _tensor(
        "float32",
        [5],
        "0000c07f0000807f000080ff000000000000803f",
    )
    comparison = compare_physical_outputs(exact, exact)
    assert comparison["exact_equal"] is True
    assert comparison["numerical_equal"] is True
    assert comparison["nan_pair_count"] == 1
    assert comparison["infinity_pair_count"] == 2
    assert comparison["finite_pair_count"] == 2
    assert comparison["special_mismatch_count"] == 0
    assert _dict(comparison["rms_error"])["value_hex"] == "0000000000000000"

    changed = _tensor(
        "float32",
        [5],
        "0100c07f000080ff000080ff000000000100803f",
    )
    mismatch = compare_physical_outputs(exact, changed)
    assert mismatch["mismatch_count"] == 3
    assert mismatch["infinity_pair_count"] == 2
    assert mismatch["special_mismatch_count"] == 2
    assert mismatch["finite_mismatch_count"] == 1
    assert mismatch["numerical_equal"] is False
    assert _dict(mismatch["maximum_absolute_error"])["value_hex"] != "0000000000000000"
    assert _dict(mismatch["maximum_relative_error"])["value_hex"] != "0000000000000000"
    assert _dict(mismatch["rms_error"])["value_hex"] != "0000000000000000"


def test_argmax_binds_tie_heavy_reference_and_exact_uint32_comparison() -> None:
    spec = physical_atlas_study_spec()
    argmax_cells = [
        _dict(cell)
        for cell in _list(spec["selected_cells"])
        if _dict(cell)["operation_name"] == "argmax"
    ]
    assert [cell["cell_name"] for cell in argmax_cells] == [
        "argmax_float32_eager",
        "argmax_float32_compiled",
    ]
    for cell in argmax_cells:
        assert cell["axes"] == {"axis": 1, "keepdims": False}
        output = _dict(_list(cell["output_contract"])[0])
        assert output == {
            "name": "indices",
            "shape": [2],
            "dtype": "uint32",
            "layout": "row_major_contiguous",
        }
        reference = _dict(_dict(cell["input_generation"])["reference_output"])
        assert reference["dtype"] == "uint32"
        assert reference["shape"] == [2]
        assert reference["all_rows_are_tie_heavy"] is True
        assert all(
            cast("int", count) >= 2 for count in _list(reference["maximum_tie_counts_by_row"])
        )
        assert reference["physical_observation"] is False

    left = _tensor("uint32", [4], "00000000070000000700000002000000")
    right = _tensor("uint32", [4], "00000000070000000300000002000000")
    exact = compare_physical_outputs(left, left)
    assert exact == {
        "comparison_kind": "exact_uint32",
        "exact_equal": True,
        "element_count": 4,
        "mismatch_count": 0,
        "equal_element_count": 4,
    }
    mismatch = compare_physical_outputs(left, right)
    assert mismatch == {
        "comparison_kind": "exact_uint32",
        "exact_equal": False,
        "element_count": 4,
        "mismatch_count": 1,
        "equal_element_count": 3,
    }

    invalid = _tensor("uint32", [4], "00000000070000000700000002000000")
    invalid["data_hex"] = "000000000700000007000000"
    invalid["payload_sha256"] = digest_bytes(bytes.fromhex(cast("str", invalid["data_hex"])))
    with pytest.raises(ContractError, match="payload length"):
        compare_physical_outputs(invalid, left)


def test_envelope_rejects_duplicate_reordered_runs_and_missing_synchronization() -> None:
    reordered = _copy(prospective_observation_envelope("softmax_float32_compiled"))
    reordered_steps = _list(_dict(reordered["run_plan"])["planned_steps"])
    reordered_steps[0], reordered_steps[1] = reordered_steps[1], reordered_steps[0]
    _rehash(reordered, "record_id")
    with pytest.raises(ContractError, match="missing, duplicated, or reordered"):
        verify_observation_envelope(reordered)

    duplicated = _copy(prospective_observation_envelope("softmax_float32_compiled"))
    duplicated_steps = _list(_dict(duplicated["run_plan"])["planned_steps"])
    duplicated_steps[1] = duplicated_steps[0]
    _rehash(duplicated, "record_id")
    with pytest.raises(ContractError, match="missing, duplicated, or reordered"):
        verify_observation_envelope(duplicated)

    missing_sync = _copy(prospective_observation_envelope("softmax_float32_compiled"))
    first_step = _dict(_list(_dict(missing_sync["run_plan"])["planned_steps"])[0])
    first_step["synchronization_points"] = [
        point
        for point in _list(first_step["synchronization_points"])
        if point != "operation_complete_before_output_readback"
    ]
    _rehash(missing_sync, "record_id")
    with pytest.raises(ContractError, match=r"planned runs|required synchronization"):
        verify_observation_envelope(missing_sync)


def test_comparison_templates_reject_missing_duplicate_reordered_and_favorable_subsets() -> None:
    envelope = prospective_observation_envelope("matrix_multiply_float32_eager")
    pairs = [_dict(pair) for pair in _list(_dict(envelope["comparison_plan"])["required_pairs"])]
    assert sum(pair["pair_class"] == "cold_all_pairs" for pair in pairs) == 3
    assert sum(pair["pair_class"] == "warm_all_pairs" for pair in pairs) == 10
    assert sum(pair["pair_class"] == "cold_warm_all_pairs" for pair in pairs) == 15

    missing = _copy(envelope)
    _list(missing["comparison_records"]).pop()
    _rehash(missing, "record_id")
    with pytest.raises(ContractError, match="record count mismatch"):
        verify_observation_envelope(missing)

    duplicate = _copy(envelope)
    duplicate_records = _list(duplicate["comparison_records"])
    duplicate_records[1] = duplicate_records[0]
    _rehash(duplicate, "record_id")
    with pytest.raises(ContractError, match="duplicate"):
        verify_observation_envelope(duplicate)

    reordered = _copy(envelope)
    reordered_records = _list(reordered["comparison_records"])
    reordered_records[0], reordered_records[1] = reordered_records[1], reordered_records[0]
    _rehash(reordered, "record_id")
    with pytest.raises(ContractError, match=r"reordered|subset-selected"):
        verify_observation_envelope(reordered)

    favorable_subset = _copy(envelope)
    favorable_record = _dict(_list(favorable_subset["comparison_records"])[0])
    favorable_record["metrics"] = {
        "comparison_kind": "floating_ieee_754",
        "exact_equal": True,
    }
    favorable_record["pair_accepted"] = True
    _rehash(favorable_record, "comparison_record_id")
    favorable_subset["comparison_records"] = [favorable_record]
    aggregate = _dict(favorable_subset["comparison_aggregate"])
    aggregate["present_metric_record_count"] = 1
    aggregate["missing_metric_record_count"] = 27
    aggregate["exact_equal_record_count"] = 1
    aggregate["aggregate_accepted"] = True
    aggregate["favorable_subset_accepted"] = True
    _rehash(favorable_subset, "record_id")
    with pytest.raises(ContractError, match="subsets are forbidden"):
        verify_observation_envelope(favorable_subset)


def test_identity_mismatch_caller_provenance_and_mixed_versions_are_rejected() -> None:
    identity_mismatch = _copy(prospective_observation_envelope("argmax_float32_eager"))
    identity_mismatch["cell_id"] = "sha256:" + ("1" * 64)
    _rehash(identity_mismatch, "record_id")
    with pytest.raises(ContractError, match="content drift"):
        verify_observation_envelope(identity_mismatch)

    caller_provenance = _copy(prospective_observation_envelope("argmax_float32_eager"))
    _dict(caller_provenance["provenance"])["runtime_identity_id"] = "sha256:" + ("2" * 64)
    _dict(caller_provenance["provenance"])["caller_supplied_provenance_accepted"] = True
    _rehash(caller_provenance, "record_id")
    with pytest.raises(ContractError, match="caller-supplied provenance"):
        verify_observation_envelope(caller_provenance)

    mixed_version = _copy(prospective_observation_envelope("argmax_float32_eager"))
    mixed_version["schema_version"] = "1.1"
    _rehash(mixed_version, "record_id")
    with pytest.raises(ContractError, match="mixed or unsupported"):
        verify_observation_envelope(mixed_version)


def test_envelope_set_rejects_missing_duplicate_and_reordered_records() -> None:
    for mutation in ("missing", "duplicate", "reordered"):
        envelope_set = _copy(physical_observation_envelope_set())
        envelopes = _list(envelope_set["envelopes"])
        if mutation == "missing":
            envelopes.pop()
            envelope_set["envelope_count"] = len(envelopes)
        elif mutation == "duplicate":
            envelopes[1] = envelopes[0]
        else:
            envelopes[0], envelopes[1] = envelopes[1], envelopes[0]
        _rehash(envelope_set, "envelope_set_id")
        with pytest.raises(ContractError):
            verify_observation_envelope_set(envelope_set)


def test_inspection_labels_prospective_synthetic_and_physical_counts() -> None:
    inspection = physical_atlas_inspection(physical_atlas_study_spec())
    assert inspection["legacy_prospective_cell_count"] == 48
    assert inspection["legacy_represented_synthetic_cell_count"] == 8
    assert inspection["legacy_accepted_physical_observation_count"] == 0
    assert inspection["selected_physical_study_cell_count"] == 18
    assert inspection["physical_observation_candidate_count"] == 0
    assert inspection["accepted_physical_observation_count"] == 0
    assert inspection["promotable_record_count"] == 0


def test_fixture_compile_and_replay_are_deterministic_and_zero_action(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_result = compile_physical_atlas_fixture(first_root)
    second, second_result = compile_physical_atlas_fixture(second_root)
    assert _bundle_files(first) == _bundle_files(second)
    assert first_result.study_id == second_result.study_id
    assert first_result.envelope_set_id == second_result.envelope_set_id
    replay = replay_physical_atlas_fixture(first).to_dict()
    assert replay["legacy_prospective_cell_count"] == 48
    assert replay["legacy_represented_synthetic_cell_count"] == 8
    assert replay["accepted_physical_observation_count"] == 0
    assert replay["promotable_record_count"] == 0
    assert replay["mlx_imports"] == 0
    assert replay["device_or_metal_queries"] == 0
    assert replay["hardware_synchronizations"] == 0


def test_cli_spec_verify_inspect_compile_and_replay(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert run(["mlx", "physical-atlas-spec"]) == 0
    spec = _output(capfd)
    spec_path = tmp_path / "physical-atlas-spec.json"
    spec_path.write_bytes(canonical_json(spec))

    assert run(["mlx", "physical-atlas-verify", str(spec_path)]) == 0
    assert _output(capfd)["status"] == "valid"
    assert run(["mlx", "physical-atlas-inspect", str(spec_path)]) == 0
    inspection = _output(capfd)
    assert inspection["status"] == "inspected"
    assert inspection["legacy_prospective_cell_count"] == 48
    assert inspection["legacy_represented_synthetic_cell_count"] == 8
    assert inspection["accepted_physical_observation_count"] == 0

    bundle_root = tmp_path / "bundle"
    bundle_root.mkdir()
    assert run(["mlx", "physical-atlas-fixture-compile", str(bundle_root)]) == 0
    compiled = _output(capfd)
    bundle = bundle_root / cast("str", compiled["path"])
    assert compiled["status"] == "compiled"
    assert compiled["accepted_physical_observation_count"] == 0
    assert run(["mlx", "physical-atlas-replay", str(bundle)]) == 0
    assert _output(capfd)["status"] == "replayed"


def test_module_has_no_mlx_metal_process_or_network_imports() -> None:
    module_path = Path(__file__).parents[1] / "src" / "localinferencelab" / "mlx_physical_atlas.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported_roots.add(node.module.split(".", maxsplit=1)[0])
    assert imported_roots.isdisjoint(
        {"mlx", "mlx_lm", "subprocess", "socket", "urllib", "requests", "httpx"}
    )
