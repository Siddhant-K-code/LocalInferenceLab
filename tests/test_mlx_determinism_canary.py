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
    assert all(_dict(cell)["support_evidence_id"] is None for cell in matrix)

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
        provenance = _dict(_dict(result)["provenance"])
        assert all(
            provenance[field] is None
            for field in (
                "authorization_evidence_id",
                "runtime_identity_id",
                "device_identity_id",
                "process_instance_id",
            )
        )
    atlas = synthetic_determinism_atlas()
    assert atlas["all_positive_records_are_synthetic"] is True
    assert atlas["real_mlx_behavior_claims"] == 0
    assert atlas["real_metal_behavior_claims"] == 0


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


def _forged_synthetic_runtime_identity(value: dict[str, JsonValue]) -> None:
    _dict(value["provenance"])["runtime_identity_id"] = "sha256:" + ("1" * 64)
    _rehash(value, "result_id")


def _bool_result_count(value: dict[str, JsonValue]) -> None:
    value["result_count"] = True
    _rehash(value, "result_set_id")


@pytest.mark.parametrize(
    "mutate",
    [_unknown_field, _forged_observed_synthetic, _forged_synthetic_runtime_identity],
)
def test_result_schema_rejects_malformed_or_forged_provenance(
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    result = _copy(build_synthetic_result(_case("softmax_float32")))
    mutate(result)
    with pytest.raises(ContractError):
        verify_determinism_result(result)


def test_future_authorized_result_binds_every_experiment_dimension() -> None:
    result = _copy(build_synthetic_result(_case("softmax_float32")))
    result["evidence_kind"] = "authorized_observation"
    result["condition"] = {
        "device_class": "gpu",
        "synchronization_mode": "explicit_synchronization",
        "process_mode": "cold_process_repetition",
        "observation_index": 1,
        "fusion_form": "not_applicable",
    }
    result["provenance"] = {
        "acquisition_mode": "future_external_authorized_protocol",
        "authorization_evidence_id": "sha256:" + ("1" * 64),
        "runtime_identity_id": "sha256:" + ("2" * 64),
        "device_identity_id": "sha256:" + ("3" * 64),
        "process_instance_id": "sha256:" + ("4" * 64),
    }
    output = _dict(result["output"])
    output["data_hex"] = "0100003f0000003f"
    _rehash_tensor(output)
    result["runtime_behavior_claim"] = "authorized_observation_only"
    _rehash(result, "result_id")
    verified = verify_determinism_result(result)
    assert _dict(verified["condition"])["observation_index"] == 1
    comparison = compare_outputs(
        _case("softmax_float32")["expected_output"],
        verified["output"],
    )
    assert comparison["maximum_ulp_distance"] == 1


def test_result_rejects_retry_or_replacement() -> None:
    result = _copy(build_synthetic_result(_case("softmax_float32")))
    _dict(result["attempt"])["retry_count"] = 1
    _rehash(result, "result_id")
    with pytest.raises(ContractError, match="must be <= 0"):
        verify_determinism_result(result)


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
    assert first_replay.accepted_synthetic_entries == 8
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
    entry["acceptance_status"] = "rejected_synthetic_contract_example"
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
    assert replayed["accepted_synthetic_entries"] == 8
    assert replayed["process_actions"] == 0
