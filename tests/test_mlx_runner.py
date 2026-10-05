"""Adversarial tests for the offline direct MLX contract."""

from __future__ import annotations

import ast
import builtins
import http.client
import inspect
import json
import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_manifest as mlx_manifest_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_fixture import (
    compile_mlx_fixture,
    replay_mlx_fixture,
    synthetic_model_manifest,
    synthetic_runtime_manifest,
)
from localinferencelab.mlx_manifest import (
    closed_runtime_environment,
    compile_model_manifest,
    compile_runtime_manifest,
    load_model_manifest,
    load_runtime_manifest,
    verify_model_manifest,
    verify_runtime_manifest,
    verify_runtime_scan_spec,
    write_manifest,
)
from localinferencelab.mlx_runner import (
    FOUNDATION_COMMIT,
    MLX_LM_REVISION,
    MLX_REVISION,
    build_mlx_prospective_package,
    load_mlx_prospective_package,
    mlx_capability_report,
    mlx_eligibility_inspection,
    mlx_study_spec,
    verify_mlx_prospective_package,
    verify_mlx_study_spec,
    write_mlx_prospective_package,
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


def _output(capfd: pytest.CaptureFixture[str]) -> dict[str, JsonValue]:
    captured = capfd.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert isinstance(value, dict)
    return cast("dict[str, JsonValue]", value)


def _runtime_scan_spec() -> dict[str, JsonValue]:
    return {
        "record_type": "mlx_runtime_scan_spec",
        "schema_version": "1.0",
        "python": {
            "implementation": "CPython",
            "version": "3.12.10",
            "abi": "cp312",
            "platform": "macosx_15_0_arm64",
        },
        "expected_distributions": [
            {"name": "mlx", "version": "0.29.3"},
            {"name": "mlx-lm", "version": "0.30.6"},
        ],
        "selected_module_files": [
            "mlx/__init__.py",
            "mlx_lm/__init__.py",
            "mlx_lm/generate.py",
            "mlx_lm/models/cache.py",
            "mlx_lm/sample_utils.py",
            "mlx_lm/utils.py",
        ],
        "environment": closed_runtime_environment(),
    }


def _write_runtime_tree(root: Path) -> tuple[Path, Path, Path]:
    runtime = root / "runtime"
    (runtime / "mlx").mkdir(parents=True)
    (runtime / "mlx_lm" / "models").mkdir(parents=True)
    (runtime / "mlx-0.29.3.dist-info").mkdir()
    (runtime / "mlx_lm-0.30.6.dist-info").mkdir()
    files = {
        "mlx/__init__.py": b"# local MLX package fixture\n",
        "mlx_lm/__init__.py": b"# local MLX-LM package fixture\n",
        "mlx_lm/generate.py": b"# local generation fixture\n",
        "mlx_lm/models/cache.py": b"# local cache fixture\n",
        "mlx_lm/sample_utils.py": b"# local sampler fixture\n",
        "mlx_lm/utils.py": b"# local loading fixture\n",
        "mlx-0.29.3.dist-info/METADATA": (b"Metadata-Version: 2.4\nName: mlx\nVersion: 0.29.3\n\n"),
        "mlx_lm-0.30.6.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: mlx-lm\nVersion: 0.30.6\nRequires-Dist: mlx==0.29.3\n\n"
        ),
    }
    for relative, data in files.items():
        (runtime / relative).write_bytes(data)
    interpreter = root / "python"
    interpreter.write_bytes(b"sealed interpreter fixture")
    interpreter.chmod(0o700)
    worker = root / "worker.py"
    worker.write_bytes(b"# sealed future worker fixture; never executed\n")
    worker.chmod(0o600)
    return runtime, interpreter, worker


def _write_model_tree(root: Path) -> Path:
    model = root / "model"
    model.mkdir(parents=True)
    (model / "config.json").write_bytes(
        canonical_json({"architectures": ["Fixture"], "model_type": "fixture"})
    )
    (model / "tokenizer_config.json").write_bytes(
        canonical_json(
            {
                "chat_template": "{{ messages | fixture }}",
                "eos_token_id": 1,
            }
        )
    )
    (model / "tokenizer.json").write_bytes(
        canonical_json({"model": {"type": "fixture", "vocab": {"fixture": 0}}})
    )
    (model / "model.safetensors").write_bytes(b"sealed local weight fixture")
    return model


def _reidentify(value: dict[str, JsonValue], identity_field: str) -> None:
    content = dict(value)
    del content[identity_field]
    value[identity_field] = canonical_identity(content)


def test_pinned_spec_defines_private_worker_and_closed_execution_gate() -> None:
    spec = verify_mlx_study_spec(mlx_study_spec())
    binding = _dict(spec["contract_binding"])
    assert binding["foundation_commit"] == FOUNDATION_COMMIT
    assert binding["mlx_lm_revision"] == MLX_LM_REVISION
    assert binding["mlx_revision"] == MLX_REVISION
    protocol = _dict(spec["worker_protocol"])
    assert protocol["transport"] == "parent_created_inherited_af_unix_socketpair"
    assert protocol["discoverable_listener"] is False
    assert protocol["concurrency"] == 1
    assert protocol["attempts_per_run"] == 1
    assert protocol["retries"] == 0
    assert protocol["warmups"] == 0
    assert protocol["message_sequence"] == [
        "parent_hello",
        "worker_identity",
        "authorize_once",
        "authorization_ack",
        "generate_once",
        "result_or_terminal_error",
        "shutdown",
        "shutdown_ack",
    ]
    controls = _dict(spec["controls"])
    sampler = _dict(controls["sampler"])
    assert sampler["temperature_millionths"] == 0
    assert sampler["greedy_semantics"] == "mx_argmax_no_prng_consumption"
    assert sampler["seed_is_control_not_determinism_guarantee"] is True
    result = _dict(spec["result_contract"])
    assert result["generated_token_ids"] == "required_exact_sequence"
    assert result["ttft"] == "unavailable_not_manufactured"
    assert "do_not_prove" in cast("str", result["backend_fact_limit"])
    gate = _dict(spec["execution_gate"])
    assert gate["production_worker_start_implemented"] is False
    assert gate["observed_execution_reachable"] is False
    assert gate["authorization_may_be_consumed"] is False


def test_runtime_and_model_compilers_are_static_complete_closures(tmp_path: Path) -> None:
    runtime, interpreter, worker = _write_runtime_tree(tmp_path)
    runtime_manifest = compile_runtime_manifest(
        _runtime_scan_spec(),
        runtime,
        interpreter,
        worker,
    )
    assert runtime_manifest["evidence_kind"] == "offline_filesystem_manifest"
    assert runtime_manifest["imports_performed"] == 0
    assert runtime_manifest["process_actions"] == 0
    assert runtime_manifest["network_actions"] == 0
    assert len(_list(runtime_manifest["files"])) == 8
    distributions = _list(runtime_manifest["distributions"])
    assert [_dict(item)["name"] for item in distributions] == ["mlx", "mlx-lm"]

    model = _write_model_tree(tmp_path)
    model_manifest = compile_model_manifest(model)
    assert model_manifest["evidence_kind"] == "offline_filesystem_manifest"
    assert model_manifest["weight_files"] == ["model.safetensors"]
    assert model_manifest["tokenizer_files"] == ["tokenizer.json"]
    assert _dict(model_manifest["chat_template"])["source"] == (
        "tokenizer_config.json:chat_template"
    )
    assert model_manifest["model_loads"] == 0
    assert model_manifest["tokenizer_loads"] == 0
    assert model_manifest["network_actions"] == 0

    runtime_path = tmp_path / "runtime-manifest.json"
    model_path = tmp_path / "model-manifest.json"
    write_manifest(runtime_path, runtime_manifest)
    write_manifest(model_path, model_manifest)
    assert load_runtime_manifest(runtime_path) == runtime_manifest
    assert load_model_manifest(model_path) == model_manifest


def test_builtin_package_is_explicitly_incomplete_and_ineligible() -> None:
    package = build_mlx_prospective_package(mlx_study_spec())
    inspection = mlx_eligibility_inspection(package)
    assert inspection["decision"] == "ineligible"
    assert inspection["declaration_complete"] is False
    assert inspection["observed_execution_reachable"] is False
    assert inspection["authorization_may_be_consumed"] is False
    assert inspection["worker_process_may_start"] is False
    missing = set(cast("list[str]", inspection["missing_requirements"]))
    assert {
        "exact_runtime_manifest",
        "exact_local_model_manifest",
        "exact_chat_template",
        "wired_limit_bytes",
        "cache_limit_bytes",
        "active_backend_device_evidence",
        "one_shot_authorization",
    }.issubset(missing)
    assert inspection["physical_gpu_actions"] == 0
    assert inspection["model_actions"] == 0
    assert inspection["network_actions"] == 0
    assert inspection["process_actions"] == 0


def test_static_manifests_do_not_unlock_execution() -> None:
    package = build_mlx_prospective_package(
        mlx_study_spec(),
        runtime_manifest=synthetic_runtime_manifest(),
        model_manifest=synthetic_model_manifest(),
    )
    inspection = mlx_eligibility_inspection(package)
    missing = set(cast("list[str]", inspection["missing_requirements"]))
    assert inspection["observed_execution_reachable"] is False
    assert "non_synthetic_runtime_manifest" in missing
    assert "non_synthetic_model_manifest" in missing
    assert "exact_runtime_manifest" not in missing
    assert "exact_local_model_manifest" not in missing


def test_synthetic_manifests_cannot_be_relabeled_as_filesystem_evidence() -> None:
    runtime = _copy(synthetic_runtime_manifest())
    runtime["evidence_kind"] = "offline_filesystem_manifest"
    _reidentify(runtime, "manifest_id")
    with pytest.raises(ContractError, match="evidence kind"):
        verify_runtime_manifest(runtime)

    model = _copy(synthetic_model_manifest())
    model["evidence_kind"] = "offline_filesystem_manifest"
    _reidentify(model, "manifest_id")
    with pytest.raises(ContractError, match="evidence kind"):
        verify_model_manifest(model)


def _spec_unknown(value: dict[str, JsonValue]) -> None:
    value["unexpected"] = True


def _spec_protocol_order(value: dict[str, JsonValue]) -> None:
    sequence = _list(_dict(value["worker_protocol"])["message_sequence"])
    sequence[1], sequence[2] = sequence[2], sequence[1]


def _spec_retry(value: dict[str, JsonValue]) -> None:
    _dict(value["worker_protocol"])["retries"] = 1


def _spec_concurrency(value: dict[str, JsonValue]) -> None:
    _dict(value["worker_protocol"])["concurrency"] = 2


def _spec_sampler(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["controls"])["sampler"])["temperature_millionths"] = 1


def _spec_seed_bool(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["controls"])["sampler"])["seed"] = True


def _spec_cache_reuse(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["controls"])["cache"])["reuse"] = True


def _spec_template(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["controls"])["tokenization"])["apply_chat_template"] = False


def _spec_max_tokens(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["controls"])["generation"])["max_tokens"] = 65


def _spec_stop(value: dict[str, JsonValue]) -> None:
    _dict(_dict(value["controls"])["generation"])["stop"] = "text_suffix"


def _spec_token_ids(value: dict[str, JsonValue]) -> None:
    _dict(value["result_contract"])["generated_token_ids"] = "optional"


def _spec_ttft_overclaim(value: dict[str, JsonValue]) -> None:
    _dict(value["result_contract"])["ttft"] = "native_observed"


def _spec_metal_overclaim(value: dict[str, JsonValue]) -> None:
    _dict(value["result_contract"])["backend_fact_limit"] = "proves_gpu_execution"


def _spec_execution_enable(value: dict[str, JsonValue]) -> None:
    _dict(value["execution_gate"])["observed_execution_reachable"] = True


@pytest.mark.parametrize(
    "mutate",
    [
        _spec_unknown,
        _spec_protocol_order,
        _spec_retry,
        _spec_concurrency,
        _spec_sampler,
        _spec_seed_bool,
        _spec_cache_reuse,
        _spec_template,
        _spec_max_tokens,
        _spec_stop,
        _spec_token_ids,
        _spec_ttft_overclaim,
        _spec_metal_overclaim,
        _spec_execution_enable,
    ],
)
def test_study_spec_rejects_protocol_control_and_claim_drift(
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    spec = _copy(mlx_study_spec())
    mutate(spec)
    with pytest.raises(ContractError):
        verify_mlx_study_spec(spec)


def test_scan_spec_rejects_path_environment_and_unbounded_expansion() -> None:
    traversal = _copy(_runtime_scan_spec())
    _list(traversal["selected_module_files"])[0] = "../mlx.py"
    with pytest.raises(ContractError, match="relative path"):
        verify_runtime_scan_spec(traversal)

    injected = _copy(_runtime_scan_spec())
    _list(injected["environment"]).append({"name": "PYTHONPATH", "value": "injected-path"})
    with pytest.raises(ContractError, match="closed allowlist"):
        verify_runtime_scan_spec(injected)

    duplicate = _copy(_runtime_scan_spec())
    distributions = _list(duplicate["expected_distributions"])
    distributions.append(_copy(_dict(distributions[0])))
    with pytest.raises(ContractError, match="unique and sorted"):
        verify_runtime_scan_spec(duplicate)

    excessive = _copy(_runtime_scan_spec())
    excessive["expected_distributions"] = [
        {"name": f"dependency-{index:03d}", "version": "1"} for index in range(257)
    ]
    with pytest.raises(ContractError, match="maximum count"):
        verify_runtime_scan_spec(excessive)


def test_scanners_reject_symlink_special_file_import_injection_and_custom_code(
    tmp_path: Path,
) -> None:
    symlink_root = tmp_path / "symlink"
    model = _write_model_tree(symlink_root)
    (model / "alias.json").symlink_to(model / "config.json")
    with pytest.raises(ContractError, match="symlink"):
        compile_model_manifest(model)

    fifo_root = tmp_path / "fifo"
    fifo_model = _write_model_tree(fifo_root)
    os.mkfifo(fifo_model / "blocked.txt")
    with pytest.raises(ContractError, match="special file"):
        compile_model_manifest(fifo_model)

    runtime_root = tmp_path / "runtime-injection"
    runtime, interpreter, worker = _write_runtime_tree(runtime_root)
    (runtime / "ambient.pth").write_text("injected-path", encoding="utf-8")
    with pytest.raises(ContractError, match="import-path injection"):
        compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)

    injection_paths = [
        "sitecustomize/__init__.py",
        "sitecustomize.pyc",
        "sitecustomize.cpython-313-darwin.so",
        "usercustomize/__init__.py",
    ]
    for index, injection_path in enumerate(injection_paths):
        injection_root = tmp_path / f"injection-{index}"
        runtime, interpreter, worker = _write_runtime_tree(injection_root)
        injected = runtime / injection_path
        injected.parent.mkdir(parents=True, exist_ok=True)
        injected.write_bytes(b"synthetic injection")
        with pytest.raises(ContractError, match="import-path injection"):
            compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)

    editable_root = tmp_path / "editable"
    runtime, interpreter, worker = _write_runtime_tree(editable_root)
    (runtime / "mlx-0.29.3.dist-info" / "direct_url.json").write_bytes(
        canonical_json(
            {
                "dir_info": {"editable": True},
                "url": "file:///private/source",
            }
        )
    )
    with pytest.raises(ContractError, match="editable install"):
        compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)

    custom_root = tmp_path / "custom"
    custom_model = _write_model_tree(custom_root)
    (custom_model / "config.json").write_bytes(
        canonical_json({"model_file": "custom_model.py", "model_type": "fixture"})
    )
    (custom_model / "custom_model.py").write_text("raise AssertionError", encoding="utf-8")
    with pytest.raises(ContractError, match=r"unsupported file|custom code"):
        compile_model_manifest(custom_model)

    remote_root = tmp_path / "remote"
    remote_model = _write_model_tree(remote_root)
    (remote_model / "config.json").write_bytes(
        canonical_json(
            {
                "auto_map": {"AutoModel": "repository--custom.Model"},
                "model_type": "fixture",
            }
        )
    )
    with pytest.raises(ContractError, match="remote or custom code"):
        compile_model_manifest(remote_model)


def test_runtime_scan_rejects_descendant_directory_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runtime, interpreter, worker = _write_runtime_tree(tmp_path)
    target_inode = (runtime / "mlx").stat().st_ino
    original_stable_tuple = mlx_manifest_module._stable_tuple  # noqa: SLF001
    observations = 0

    def drifting_stable_tuple(metadata: os.stat_result) -> tuple[int, ...]:
        nonlocal observations
        stable = original_stable_tuple(metadata)
        if metadata.st_ino == target_inode:
            observations += 1
            if observations == 3:
                return (*stable[:-1], stable[-1] + 1)
        return stable

    monkeypatch.setattr(mlx_manifest_module, "_stable_tuple", drifting_stable_tuple)
    with pytest.raises(ContractError, match="directory changed during scan"):
        compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)


def test_model_scanner_rejects_missing_extra_and_malformed_shards(tmp_path: Path) -> None:
    missing_index_root = tmp_path / "missing-index"
    model = _write_model_tree(missing_index_root)
    (model / "model-00001-of-00002.safetensors").write_bytes(b"extra shard")
    with pytest.raises(ContractError, match=r"lacks model\.safetensors\.index\.json"):
        compile_model_manifest(model)

    wrong_index_root = tmp_path / "wrong-index"
    indexed_model = _write_model_tree(wrong_index_root)
    (indexed_model / "model-00001-of-00002.safetensors").write_bytes(b"extra shard")
    (indexed_model / "model.safetensors.index.json").write_bytes(
        canonical_json(
            {
                "weight_map": {
                    "fixture.weight": "model-00002-of-00002.safetensors",
                }
            }
        )
    )
    with pytest.raises(ContractError, match="missing or extra shards"):
        compile_model_manifest(indexed_model)

    missing_tokenizer_root = tmp_path / "missing-tokenizer"
    no_tokenizer = _write_model_tree(missing_tokenizer_root)
    (no_tokenizer / "tokenizer.json").unlink()
    with pytest.raises(ContractError, match="no tokenizer vocabulary"):
        compile_model_manifest(no_tokenizer)


def test_same_size_file_replacement_changes_physical_and_content_identity(tmp_path: Path) -> None:
    model = _write_model_tree(tmp_path)
    first = compile_model_manifest(model)
    weight = model / "model.safetensors"
    original = weight.read_bytes()
    weight.unlink()
    weight.write_bytes(b"x" * len(original))
    second = compile_model_manifest(model)
    assert first["manifest_id"] != second["manifest_id"]
    first_file = next(
        _dict(item) for item in _list(first["files"]) if _dict(item)["path"] == "model.safetensors"
    )
    second_file = next(
        _dict(item) for item in _list(second["files"]) if _dict(item)["path"] == "model.safetensors"
    )
    assert first_file["size_bytes"] == second_file["size_bytes"]
    assert first_file["inode"] != second_file["inode"]
    assert first_file["sha256"] != second_file["sha256"]


def test_manifests_reject_unknown_bool_digest_and_closure_drift() -> None:
    runtime = _copy(synthetic_runtime_manifest())
    runtime["unexpected"] = True
    with pytest.raises(ContractError, match="unknown keys"):
        verify_runtime_manifest(runtime)

    model = _copy(synthetic_model_manifest())
    model["model_loads"] = False
    _reidentify(model, "manifest_id")
    with pytest.raises(ContractError, match="integer"):
        verify_model_manifest(model)

    runtime = _copy(synthetic_runtime_manifest())
    runtime["manifest_id"] = "sha256:" + ("A" * 64)
    with pytest.raises(ContractError, match="lowercase"):
        verify_runtime_manifest(runtime)

    model = _copy(synthetic_model_manifest())
    _dict(model["resolved_directory"])["closure_sha256"] = "sha256:" + ("0" * 64)
    _reidentify(model, "manifest_id")
    with pytest.raises(ContractError, match="closure digest"):
        verify_model_manifest(model)

    runtime = _copy(synthetic_runtime_manifest())
    runtime["selected_module_files"] = []
    _reidentify(runtime, "manifest_id")
    with pytest.raises(ContractError, match="module files must be non-empty"):
        verify_runtime_manifest(runtime)


def test_runtime_manifest_binds_direct_url_projection(tmp_path: Path) -> None:
    runtime, interpreter, worker = _write_runtime_tree(tmp_path)
    (runtime / "mlx-0.29.3.dist-info" / "direct_url.json").write_bytes(
        canonical_json(
            {
                "dir_info": {"editable": False},
                "url": "file:///sealed-wheel-source",
            }
        )
    )
    manifest = compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)
    mlx_distribution = next(
        _dict(item) for item in _list(manifest["distributions"]) if _dict(item)["name"] == "mlx"
    )
    assert mlx_distribution["direct_url_sha256"] is not None
    mlx_distribution["direct_url_sha256"] = None
    _reidentify(manifest, "manifest_id")
    with pytest.raises(ContractError, match="direct URL projection"):
        verify_runtime_manifest(manifest)


def test_model_manifest_binds_exact_weight_index_projection(tmp_path: Path) -> None:
    model = _write_model_tree(tmp_path)
    (model / "model-00001-of-00002.safetensors").write_bytes(b"synthetic shard one")
    (model / "model-00002-of-00002.safetensors").write_bytes(b"synthetic shard two")
    (model / "model.safetensors").unlink()
    (model / "model.safetensors.index.json").write_bytes(
        canonical_json(
            {
                "weight_map": {
                    "layer.0": "model-00001-of-00002.safetensors",
                    "layer.1": "model-00002-of-00002.safetensors",
                }
            }
        )
    )
    manifest = compile_model_manifest(model)
    manifest["weight_index_path"] = "config.json"
    manifest["weight_index_sha256"] = manifest["config_sha256"]
    _reidentify(manifest, "manifest_id")
    with pytest.raises(ContractError, match="weight-index path projection"):
        verify_model_manifest(manifest)


def test_package_rejects_forged_eligibility_identity_and_noncanonical_bytes(
    tmp_path: Path,
) -> None:
    package = _copy(build_mlx_prospective_package(mlx_study_spec()))
    _dict(package["eligibility"])["observed_execution_reachable"] = True
    _reidentify(package, "package_id")
    with pytest.raises(ContractError, match="semantic or eligibility drift"):
        verify_mlx_prospective_package(package)

    package = _copy(build_mlx_prospective_package(mlx_study_spec()))
    _dict(package["non_actions"])["worker_process_starts"] = False
    _reidentify(package, "package_id")
    with pytest.raises(ContractError, match="integer"):
        verify_mlx_prospective_package(package)

    package_path = tmp_path / "package.json"
    package_path.write_text(
        json.dumps(build_mlx_prospective_package(mlx_study_spec()), indent=2),
        encoding="utf-8",
    )
    with pytest.raises(ContractError, match="canonical JSON"):
        load_mlx_prospective_package(package_path)

    duplicate_path = tmp_path / "duplicate.json"
    data = canonical_json(build_mlx_prospective_package(mlx_study_spec()))
    duplicate_path.write_bytes(data[:-1] + b',"schema_version":"1.0"}')
    with pytest.raises(ContractError, match="duplicate JSON key"):
        load_mlx_prospective_package(duplicate_path)


def test_fixture_is_byte_identical_refused_and_closed(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_result = compile_mlx_fixture(first_root)
    second, second_result = compile_mlx_fixture(second_root)
    assert first.name == second.name
    assert first_result == second_result
    assert first_result.decision == "ineligible"
    assert first_result.physical_actions == 0
    assert read_closed_bundle(first)[1] == read_closed_bundle(second)[1]
    assert replay_mlx_fixture(first) == first_result
    readme = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    for identity in (
        first_result.runtime_manifest_id,
        first_result.model_manifest_id,
        first_result.package_id,
        first_result.bundle_root,
    ):
        assert identity in readme


def test_fixture_replay_rejects_coordinated_tampering_extra_and_missing(
    tmp_path: Path,
) -> None:
    original_root = tmp_path / "original"
    republish_root = tmp_path / "republish"
    original_root.mkdir()
    republish_root.mkdir()
    original, _result = compile_mlx_fixture(original_root)
    _content_root, files = read_closed_bundle(original)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }

    tampered = dict(content)
    package = _copy(json.loads(tampered["prospective-package.json"]))
    _dict(package["eligibility"])["worker_process_may_start"] = True
    _reidentify(package, "package_id")
    tampered["prospective-package.json"] = canonical_json(package)
    coordinated = publish_bundle(tampered, republish_root, name_prefix="mlx-tampered")
    with pytest.raises(ContractError):
        replay_mlx_fixture(coordinated)

    extra = dict(content)
    extra["worker-output.json"] = b"{}"
    extra_bundle = publish_bundle(extra, republish_root, name_prefix="mlx-extra")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_mlx_fixture(extra_bundle)

    missing = dict(content)
    missing.pop("manifests/model.json")
    missing_bundle = publish_bundle(missing, republish_root, name_prefix="mlx-missing")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_mlx_fixture(missing_bundle)


def test_contract_and_fixture_paths_cross_no_physical_action_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("offline MLX contract crossed a physical-action boundary")

    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals_value: dict[str, object] | None = None,
        locals_value: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name.split(".", 1)[0] in {"mlx", "mlx_lm"}:
            raise AssertionError("MLX runtime import attempted")
        return original_import(name, globals_value, locals_value, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(http.client, "HTTPConnection", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "fork", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden)

    package = build_mlx_prospective_package(mlx_study_spec())
    verify_mlx_prospective_package(package)
    output_root = tmp_path / "fixture"
    output_root.mkdir()
    bundle, result = compile_mlx_fixture(output_root)
    assert result.physical_actions == 0
    replay_mlx_fixture(bundle)


def test_new_modules_have_no_runtime_socket_or_process_import_path() -> None:
    root = Path(__file__).parents[1] / "src" / "localinferencelab"
    forbidden_imports = {"mlx", "mlx_lm", "socket", "subprocess"}
    forbidden_calls = {
        "create_connection",
        "fork",
        "Popen",
        "posix_spawn",
        "socket",
    }
    for name in ("mlx_manifest.py", "mlx_runner.py", "mlx_fixture.py"):
        tree = ast.parse((root / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".", 1)[0] not in forbidden_imports for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".", 1)[0] not in forbidden_imports
            elif isinstance(node, ast.Call):
                function = node.func
                called = (
                    function.attr
                    if isinstance(function, ast.Attribute)
                    else function.id
                    if isinstance(function, ast.Name)
                    else ""
                )
                assert called not in forbidden_calls


def test_synthetic_api_has_no_custom_dispatch_transport_probe_or_script(
    tmp_path: Path,
) -> None:
    assert list(inspect.signature(compile_mlx_fixture).parameters) == ["output_root"]
    with pytest.raises(TypeError):
        compile_mlx_fixture(tmp_path, object())  # type: ignore[call-arg]


def test_capability_report_never_overclaims_backend_or_metal() -> None:
    report = mlx_capability_report()
    assert report["architecture"] == "parent_owned_private_inherited_descriptor_worker"
    assert report["production_worker_launch"] is False
    assert report["runtime_import"] is False
    assert report["device_query"] is False
    assert report["metal_initialization"] is False
    assert report["inference"] is False
    assert report["subprocess"] is False
    assert report["metal_claim"] == "per_kernel_execution_not_programmatically_provable"


def test_mlx_cli_spec_manifest_package_inspection_fixture_and_replay(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert run(["mlx", "capability-report"]) == 0
    assert _output(capfd)["production_worker_launch"] is False

    assert run(["mlx", "prospective-spec"]) == 0
    captured = capfd.readouterr()
    assert captured.err == ""
    spec_path = tmp_path / "spec.json"
    spec_path.write_bytes(captured.out.encode("utf-8"))

    package_path = tmp_path / "package.json"
    assert run(["mlx", "prospective-create", str(spec_path), str(package_path)]) == 0
    created = _output(capfd)
    assert created["status"] == "created"
    assert created["decision"] == "ineligible"
    assert created["process_actions"] == 0

    assert run(["mlx", "prospective-verify", str(package_path)]) == 0
    assert _output(capfd)["status"] == "valid"
    assert run(["mlx", "eligibility-inspect", str(package_path)]) == 0
    assert _output(capfd)["worker_process_may_start"] is False

    runtime, interpreter, worker = _write_runtime_tree(tmp_path / "cli-runtime")
    scan_spec = tmp_path / "runtime-scan-spec.json"
    scan_spec.write_bytes(canonical_json(_runtime_scan_spec()))
    runtime_manifest = tmp_path / "runtime-manifest.json"
    assert (
        run(
            [
                "mlx",
                "runtime-manifest-create",
                str(scan_spec),
                str(runtime),
                str(interpreter),
                str(worker),
                str(runtime_manifest),
            ]
        )
        == 0
    )
    assert _output(capfd)["process_actions"] == 0

    model = _write_model_tree(tmp_path / "cli-model")
    model_manifest = tmp_path / "model-manifest.json"
    assert run(["mlx", "model-manifest-create", str(model), str(model_manifest)]) == 0
    assert _output(capfd)["model_loads"] == 0

    closed_package = tmp_path / "closed-package.json"
    assert (
        run(
            [
                "mlx",
                "prospective-create",
                str(spec_path),
                str(closed_package),
                "--runtime-manifest",
                str(runtime_manifest),
                "--model-manifest",
                str(model_manifest),
            ]
        )
        == 0
    )
    closed = _output(capfd)
    assert closed["runtime_manifest_id"] is not None
    assert closed["model_manifest_id"] is not None
    assert closed["observed_execution_reachable"] is False

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    assert run(["mlx", "fixture-compile", str(fixture_root)]) == 0
    compiled = _output(capfd)
    assert compiled["status"] == "compiled"
    assert compiled["physical_actions"] == 0
    bundle = fixture_root / cast("str", compiled["path"])
    assert run(["mlx", "fixture-replay", str(bundle)]) == 0
    replayed = _output(capfd)
    assert replayed["status"] == "replayed"
    assert replayed["bundle_root"] == compiled["bundle_root"]
    assert replayed["external_network_actions"] == 0


def test_package_writer_is_no_replace_and_canonical(tmp_path: Path) -> None:
    path = tmp_path / "package.json"
    package = build_mlx_prospective_package(mlx_study_spec())
    write_mlx_prospective_package(path, package)
    assert path.read_bytes() == canonical_json(package)
    with pytest.raises(FileExistsError):
        write_mlx_prospective_package(path, package)
