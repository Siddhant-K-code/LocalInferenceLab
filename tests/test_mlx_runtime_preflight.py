"""Sealed-fake and adversarial tests for the runtime-only MLX preflight."""

from __future__ import annotations

import ast
import json
import platform
import sys
import sysconfig
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_runtime_preflight as preflight_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_custody import PROTOCOL_ID as INERT_PROTOCOL_ID
from localinferencelab.mlx_custody import WORKER_CODE_ID as INERT_WORKER_CODE_ID
from localinferencelab.mlx_manifest import (
    closed_runtime_environment,
    compile_runtime_manifest,
)
from localinferencelab.mlx_runtime_preflight import (
    EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256,
    MLX_LM_REVISION,
    MLX_LM_VERSION,
    MLX_REVISION,
    MLX_VERSION,
    build_runtime_preflight_package,
    run_runtime_preflight,
    runtime_preflight_capability_report,
    runtime_preflight_spec,
    verify_install_receipt,
    verify_runtime_lock,
)


def _dict(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    copied = json.loads(canonical_json(value))
    assert isinstance(copied, dict)
    return cast("dict[str, JsonValue]", copied)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path.resolve(strict=True)


def _write_fake_runtime(
    root: Path,
    *,
    mlx_lm_import_error: bool = False,
    forbidden_write_attempt: bool = False,
) -> Path:
    if mlx_lm_import_error and forbidden_write_attempt:
        raise ValueError("fake runtime may select only one import failure")
    runtime = root / "runtime"
    (runtime / "mlx" / "core").mkdir(parents=True)
    (runtime / "mlx_lm" / "models").mkdir(parents=True)
    (runtime / f"mlx-{MLX_VERSION}.dist-info").mkdir()
    (runtime / f"mlx_lm-{MLX_LM_VERSION}.dist-info").mkdir()
    (runtime / "mlx" / "core" / "__init__.py").write_text(
        "\n".join(
            [
                f'__version__ = "{MLX_VERSION}"',
                "class Device:",
                "    def __repr__(self):",
                '        return "Device(gpu, 0)"',
                "class Stream:",
                "    def __repr__(self):",
                '        return "Stream(0, Device(gpu, 0))"',
                "class Metal:",
                "    @staticmethod",
                "    def is_available():",
                "        return True",
                "metal = Metal()",
                "def default_device():",
                "    return Device()",
                "def default_stream(_device):",
                "    return Stream()",
                "def synchronize():",
                "    return None",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (runtime / "mlx_lm" / "__init__.py").write_text(
        (
            'raise RuntimeError("sealed import failure")\n'
            if mlx_lm_import_error
            else (
                'open("forbidden-runtime-preflight-write", "w")\n'
                if forbidden_write_attempt
                else f'__version__ = "{MLX_LM_VERSION}"\n'
            )
        ),
        encoding="utf-8",
    )
    for path in (
        runtime / "mlx_lm" / "generate.py",
        runtime / "mlx_lm" / "models" / "cache.py",
        runtime / "mlx_lm" / "sample_utils.py",
        runtime / "mlx_lm" / "utils.py",
    ):
        path.write_text("SEALED_FAKE = True\n", encoding="utf-8")
    (runtime / f"mlx-{MLX_VERSION}.dist-info" / "METADATA").write_text(
        f"Name: mlx\nVersion: {MLX_VERSION}\n\n",
        encoding="utf-8",
    )
    (runtime / f"mlx_lm-{MLX_LM_VERSION}.dist-info" / "METADATA").write_text(
        f"Name: mlx-lm\nVersion: {MLX_LM_VERSION}\nRequires-Dist: mlx=={MLX_VERSION}\n\n",
        encoding="utf-8",
    )
    return runtime.resolve(strict=True)


def _runtime_scan_spec() -> dict[str, JsonValue]:
    return {
        "record_type": "mlx_runtime_scan_spec",
        "schema_version": "1.0",
        "python": {
            "implementation": platform.python_implementation(),
            "version": platform.python_version(),
            "abi": f"cp{sys.version_info.major}{sys.version_info.minor}",
            "platform": sysconfig.get_platform(),
        },
        "expected_distributions": [
            {"name": "mlx", "version": MLX_VERSION},
            {"name": "mlx-lm", "version": MLX_LM_VERSION},
        ],
        "selected_module_files": [
            "mlx/core/__init__.py",
            "mlx_lm/__init__.py",
            "mlx_lm/generate.py",
            "mlx_lm/models/cache.py",
            "mlx_lm/sample_utils.py",
            "mlx_lm/utils.py",
        ],
        "environment": closed_runtime_environment(),
    }


def _synthetic_lock(manifest: dict[str, JsonValue]) -> dict[str, JsonValue]:
    distributions = cast("list[JsonValue]", manifest["distributions"])
    artifacts = []
    for item in distributions:
        distribution = _dict(item)
        name = cast("str", distribution["name"])
        version = cast("str", distribution["version"])
        filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
        artifacts.append(
            {
                "name": name,
                "version": version,
                "filename": filename,
                "url": f"https://files.pythonhosted.org/packages/fake/{filename}",
                "size_bytes": len(filename),
                "sha256": digest_bytes(filename.encode("ascii")),
            }
        )
    lock: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_lock",
        "schema_version": "1.0",
        "evidence_kind": "synthetic_fixture",
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python_abi": f"cp{sys.version_info.major}{sys.version_info.minor}",
        },
        "reviewed_sources": [
            {"distribution": "mlx", "version": MLX_VERSION, "revision": MLX_REVISION},
            {
                "distribution": "mlx-lm",
                "version": MLX_LM_VERSION,
                "revision": MLX_LM_REVISION,
            },
        ],
        "requested": [f"mlx-lm=={MLX_LM_VERSION}", f"mlx=={MLX_VERSION}"],
        "artifacts": artifacts,
    }
    lock["lock_id"] = canonical_identity(lock)
    return verify_runtime_lock(lock, allow_synthetic=True)


def _synthetic_receipt(
    manifest: dict[str, JsonValue],
    runtime_lock: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    distributions = [
        {
            "name": _dict(item)["name"],
            "version": _dict(item)["version"],
            "metadata_sha256": _dict(item)["metadata_sha256"],
        }
        for item in cast("list[JsonValue]", manifest["distributions"])
    ]
    package_root = _dict(manifest["package_root"])
    receipt: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_install_receipt",
        "schema_version": "1.0",
        "evidence_kind": "synthetic_fixture",
        "lock_id": runtime_lock["lock_id"],
        "runtime_manifest_id": manifest["manifest_id"],
        "runtime_root_closure_sha256": package_root["closure_sha256"],
        "installer": {"name": "uv", "version": "synthetic", "invocations": 1},
        "preparation_actions": [
            {
                "sequence": 1,
                "operation": "final_root_install",
                "outcome": "completed",
                "physical_network_access": True,
                "index_domains": ["files.pythonhosted.org", "pypi.org"],
                "artifact_fetches": len(_list(runtime_lock["artifacts"])),
                "exact_http_request_count": None,
                "model_repository_requests": 0,
                "arbitrary_url_requests": 0,
                "credential_material_recorded": False,
            }
        ],
        "dependency_semantic_closure": {
            "status": "satisfied_exact_fixture",
            "requesting_distribution": f"mlx-lm=={MLX_LM_VERSION}",
            "declared_requirement": f"mlx=={MLX_VERSION}",
            "selected_distribution": f"mlx=={MLX_VERSION}",
            "resolver_outcome": "synthetic_exact_match",
            "substitution_performed": False,
        },
        "package_network_actions": {
            "scope": "exact_locked_pypi_runtime_artifacts_only",
            "index_domains": ["files.pythonhosted.org", "pypi.org"],
            "artifact_fetches": len(_list(runtime_lock["artifacts"])),
            "final_root_artifact_fetches": len(_list(runtime_lock["artifacts"])),
            "exact_http_request_count": None,
            "model_repository_requests": 0,
            "arbitrary_url_requests": 0,
            "credential_material_recorded": False,
        },
        "installed_distributions": distributions,
        "artifacts": runtime_lock["artifacts"],
    }
    receipt["receipt_id"] = canonical_identity(receipt)
    return verify_install_receipt(
        receipt,
        runtime_lock=runtime_lock,
        runtime_manifest=manifest,
        allow_synthetic=True,
    )


@pytest.fixture
def fake_preflight_bundle(tmp_path: Path) -> tuple[Path, dict[str, JsonValue]]:
    runtime = _write_fake_runtime(tmp_path)
    interpreter = Path(sys.executable).resolve(strict=True)
    worker = (
        Path(preflight_module.__file__)
        .with_name("mlx_runtime_preflight_worker.py")
        .resolve(strict=True)
    )
    manifest = compile_runtime_manifest(
        _runtime_scan_spec(),
        runtime,
        interpreter,
        worker,
    )
    runtime_lock = _synthetic_lock(manifest)
    receipt = _synthetic_receipt(manifest, runtime_lock)
    output = _private_directory(tmp_path / "output")
    bundle, replay = run_runtime_preflight(
        manifest,
        runtime_lock,
        receipt,
        runtime,
        interpreter,
        output,
        allow_synthetic=True,
    )
    assert replay.terminal_state == "completed_and_closed"
    return bundle, manifest


def test_runtime_preflight_spec_and_capability_are_additive_and_pure() -> None:
    spec = runtime_preflight_spec()
    report = runtime_preflight_capability_report()
    assert spec["action"] == "mlx_runtime_preflight_only"
    assert spec["allowed_probes"] == sorted(_list(spec["allowed_probes"]))
    assert report["explicit_processful_command"] == "mlx runtime-preflight"
    assert report["model_load"] is False
    assert report["generation"] is False
    assert report["download"] is False
    assert spec["protocol_id"] != INERT_PROTOCOL_ID
    assert spec["worker_code_id"] != INERT_WORKER_CODE_ID
    worker = (
        Path(preflight_module.__file__).with_name("mlx_runtime_preflight_worker.py").read_bytes()
    )
    assert digest_bytes(worker) == EXPECTED_RUNTIME_WORKER_PROGRAM_SHA256


def test_sealed_fake_runtime_preflight_replays_without_process_or_import(
    fake_preflight_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, manifest = fake_preflight_bundle
    result, inspection = preflight_module._replay_runtime_preflight_snapshot(  # noqa: SLF001
        bundle,
        allow_synthetic=True,
    )
    assert result.runtime_manifest_id == manifest["manifest_id"]
    assert result.metal_is_available is True
    assert result.default_device_representation == "Device(gpu, 0)"
    assert result.synchronization_completed is True
    assert result.imported_module_count > result.bound_runtime_module_count >= 2
    assert inspection["runtime_preflight_observed"] is True
    assert inspection["observed_generation_reachable"] is False
    assert "applicable_dependency_distribution_closure" in _list(
        inspection["remaining_requirements"]
    )


def test_runtime_preflight_replay_rejects_extra_and_coordinated_tampering(
    fake_preflight_bundle: tuple[Path, dict[str, JsonValue]],
    tmp_path: Path,
) -> None:
    bundle, _manifest = fake_preflight_bundle
    _root, files = read_closed_bundle(bundle)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    extra = _private_directory(tmp_path / "extra")
    content["unexpected.json"] = canonical_json({"unexpected": True})
    extra_bundle = publish_bundle(content, extra, name_prefix="tampered-extra")
    with pytest.raises(ContractError, match="invalid content set"):
        preflight_module._replay_runtime_preflight_snapshot(  # noqa: SLF001
            extra_bundle,
            allow_synthetic=True,
        )

    coordinated = _private_directory(tmp_path / "coordinated")
    del content["unexpected.json"]
    worker = bytearray(content["source/worker-program.py"])
    worker[-1] ^= 1
    content["source/worker-program.py"] = bytes(worker)
    manifest = _dict(load_json_bytes(content["runtime-manifest.json"]))
    _dict(manifest["worker_program"])["sha256"] = digest_bytes(bytes(worker))
    manifest_content = dict(manifest)
    del manifest_content["manifest_id"]
    manifest["manifest_id"] = canonical_identity(manifest_content)
    content["runtime-manifest.json"] = canonical_json(manifest)
    coordinated_bundle = publish_bundle(content, coordinated, name_prefix="tampered-worker")
    with pytest.raises(ContractError, match="sealed bytes"):
        preflight_module._replay_runtime_preflight_snapshot(  # noqa: SLF001
            coordinated_bundle,
            allow_synthetic=True,
        )


def test_runtime_worker_has_no_forbidden_action_surface() -> None:
    worker_path = (
        Path(preflight_module.__file__)
        .with_name("mlx_runtime_preflight_worker.py")
        .resolve(strict=True)
    )
    tree = ast.parse(worker_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported_roots & {
        "mlx",
        "mlx_lm",
        "subprocess",
        "urllib",
        "requests",
        "huggingface_hub",
        "modelscope",
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called_attributes & {
        "load",
        "load_model",
        "load_tokenizer",
        "generate",
        "stream_generate",
        "snapshot_download",
        "make_prompt_cache",
        "zeros",
        "ones",
        "array",
        "eval",
    }
    dynamic_imports = [
        node.args[0].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "importlib"
        and node.func.attr == "import_module"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ]
    assert dynamic_imports == ["mlx.core", "mlx_lm"]
    mlx_calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "mlx"
    }
    assert mlx_calls == {"default_device", "default_stream", "synchronize"}


def test_runtime_preflight_terminal_import_error_is_closed_and_replayable(
    tmp_path: Path,
) -> None:
    runtime = _write_fake_runtime(tmp_path, mlx_lm_import_error=True)
    interpreter = Path(sys.executable).resolve(strict=True)
    worker = (
        Path(preflight_module.__file__)
        .with_name("mlx_runtime_preflight_worker.py")
        .resolve(strict=True)
    )
    manifest = compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)
    runtime_lock = _synthetic_lock(manifest)
    receipt = _synthetic_receipt(manifest, runtime_lock)
    bundle, result = run_runtime_preflight(
        manifest,
        runtime_lock,
        receipt,
        runtime,
        interpreter,
        _private_directory(tmp_path / "output"),
        allow_synthetic=True,
    )
    assert result.terminal_state == "terminal_error_and_closed"
    replay, inspection = preflight_module._replay_runtime_preflight_snapshot(  # noqa: SLF001
        bundle,
        allow_synthetic=True,
    )
    assert replay.terminal_state == "terminal_error_and_closed"
    assert replay.authorization_consumptions == 1
    assert replay.model_actions == 0
    assert inspection["runtime_preflight_observed"] is False
    assert "active_backend_device_evidence" in _list(inspection["remaining_requirements"])
    assert "worker_reported_imported_module_closure" in _list(inspection["remaining_requirements"])
    assert inspection["observed_generation_reachable"] is False


def test_runtime_preflight_result_rejects_extra_bool_and_duplicate_module_fields(
    fake_preflight_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, manifest = fake_preflight_bundle
    _root, files = read_closed_bundle(bundle)
    transcript = _dict(load_json_bytes(files["transcript.json"]))
    frames = _list(transcript["frames"])
    result_frame = _dict(frames[5])
    result = _dict(load_json_bytes(decode_bytes(cast("str", result_frame["payload_base64"]))))
    authorization = _dict(load_json_bytes(files["authorization.json"]))
    request_nonce = cast("str", result["request_nonce"])

    extra = _copy(result)
    extra["unknown"] = "rejected"
    with pytest.raises(ContractError, match="unknown keys"):
        preflight_module._verify_preflight_result(  # noqa: SLF001
            extra,
            authorization=authorization,
            request_nonce=request_nonce,
            runtime_manifest=manifest,
        )

    ambiguous = _copy(result)
    _dict(ambiguous["action_ledger"])["synchronizations"] = True
    with pytest.raises(ContractError, match="must be an integer"):
        preflight_module._verify_preflight_result(  # noqa: SLF001
            ambiguous,
            authorization=authorization,
            request_nonce=request_nonce,
            runtime_manifest=manifest,
        )

    duplicate = _copy(result)
    modules = _list(duplicate["imported_modules"])
    modules.append(_copy(modules[0]))
    modules.sort(key=lambda item: cast("str", _dict(item)["name"]))
    with pytest.raises(ContractError, match="unique and sorted"):
        preflight_module._verify_preflight_result(  # noqa: SLF001
            duplicate,
            authorization=authorization,
            request_nonce=request_nonce,
            runtime_manifest=manifest,
        )


def test_runtime_preflight_forbidden_attempt_failure_custody_is_truthful_and_replayable(
    tmp_path: Path,
) -> None:
    runtime = _write_fake_runtime(tmp_path, forbidden_write_attempt=True)
    interpreter = Path(sys.executable).resolve(strict=True)
    worker = (
        Path(preflight_module.__file__)
        .with_name("mlx_runtime_preflight_worker.py")
        .resolve(strict=True)
    )
    manifest = compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)
    runtime_lock = _synthetic_lock(manifest)
    receipt = _synthetic_receipt(manifest, runtime_lock)
    output = _private_directory(tmp_path / "output")
    with pytest.raises(ContractError, match="performed or attempted a forbidden action"):
        run_runtime_preflight(
            manifest,
            runtime_lock,
            receipt,
            runtime,
            interpreter,
            output,
            allow_synthetic=True,
        )

    failure_path = next(output.glob(".localinferencelab-mlx-runtime-preflight-terminal-*.json"))
    consumption_path = next(output.glob(".localinferencelab-mlx-runtime-preflight-consumed-*.json"))
    consumption = _dict(load_json_bytes(consumption_path.read_bytes()))
    failure = preflight_module.replay_runtime_preflight_terminal_failure(failure_path)
    assert failure["terminal_state"] == "failed_closed"
    assert failure["authorization_id"] == consumption["authorization_id"]
    assert failure["consumption_id"] == consumption["consumption_id"]
    assert failure["phase"] == "preflight_result"
    assert _dict(failure["recorded_frame_counts"]) == {
        "parent_to_worker": 3,
        "worker_to_parent": 3,
    }
    projection = _dict(failure["rejected_result_projection"])
    assert projection["observed_preflight_accepted"] is False
    assert projection["worker_status"] == "terminal_error"
    assert projection["worker_error_phase"] == "import_mlx_lm"
    assert _dict(projection["worker_action_ledger"])["mlx_imports"] == 1
    assert _dict(projection["worker_action_ledger"])["mlx_lm_imports"] == 0
    assert _dict(projection["worker_non_action_ledger"])["filesystem_mutations"] == 1
    assert projection["forbidden_action_attempt_count"] == 1
    assert projection["forbidden_actions_completed"] == 0
    assert projection["backend_facts_accepted"] is False
    assert projection["synchronization_accepted"] is False
    assert _dict(failure["child_wait"])["signal"] == 15

    original_authorization = cast("str", failure["authorization_id"])
    original_consumption = cast("str", failure["consumption_id"])
    coordinated = _copy(failure)
    coordinated["authorization_id"] = digest_bytes(b"forged authorization")
    coordinated_content = dict(coordinated)
    del coordinated_content["failure_id"]
    coordinated["failure_id"] = canonical_identity(coordinated_content)
    with pytest.raises(ContractError, match="authorization binding"):
        preflight_module.verify_runtime_preflight_terminal_failure(
            coordinated,
            expected_authorization_id=original_authorization,
            expected_consumption_id=original_consumption,
        )

    completed = _copy(failure)
    _dict(completed["rejected_result_projection"])["forbidden_actions_completed"] = 1
    completed_content = dict(completed)
    del completed_content["failure_id"]
    completed["failure_id"] = canonical_identity(completed_content)
    with pytest.raises(ContractError, match="forbidden-action accounting"):
        preflight_module.verify_runtime_preflight_terminal_failure(
            completed,
            expected_authorization_id=original_authorization,
            expected_consumption_id=original_consumption,
        )


def test_runtime_lock_receipt_and_package_reject_drift(tmp_path: Path) -> None:
    runtime = _write_fake_runtime(tmp_path)
    interpreter = Path(sys.executable).resolve(strict=True)
    worker = (
        Path(preflight_module.__file__)
        .with_name("mlx_runtime_preflight_worker.py")
        .resolve(strict=True)
    )
    manifest = compile_runtime_manifest(_runtime_scan_spec(), runtime, interpreter, worker)
    runtime_lock = _synthetic_lock(manifest)
    receipt = _synthetic_receipt(manifest, runtime_lock)
    build_runtime_preflight_package(
        manifest,
        runtime_lock,
        receipt,
        allow_synthetic=True,
    )
    wrong_version = _copy(runtime_lock)
    _dict(_list(wrong_version["artifacts"])[0])["version"] = "999"
    wrong_version_content = dict(wrong_version)
    del wrong_version_content["lock_id"]
    wrong_version["lock_id"] = canonical_identity(wrong_version_content)
    with pytest.raises(ContractError, match="exact reviewed MLX"):
        verify_runtime_lock(wrong_version, allow_synthetic=True)
    wrong_receipt = _copy(receipt)
    _dict(wrong_receipt["package_network_actions"])["model_repository_requests"] = 1
    wrong_receipt_content = dict(wrong_receipt)
    del wrong_receipt_content["receipt_id"]
    wrong_receipt["receipt_id"] = canonical_identity(wrong_receipt_content)
    with pytest.raises(ContractError, match="network scope"):
        verify_install_receipt(
            wrong_receipt,
            runtime_lock=runtime_lock,
            runtime_manifest=manifest,
            allow_synthetic=True,
        )


def test_runtime_preflight_cli_pure_surfaces_and_help(capfd: pytest.CaptureFixture[str]) -> None:
    assert run(["mlx", "runtime-preflight-capability-report"]) == 0
    report = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert report["model_load"] is False
    assert run(["mlx", "runtime-preflight-spec"]) == 0
    spec = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))
    assert spec["action"] == "mlx_runtime_preflight_only"
    with pytest.raises(SystemExit) as exit_info:
        run(["mlx", "runtime-preflight", "--help"])
    assert exit_info.value.code == 0
    help_text = capfd.readouterr().out
    normalized_help = " ".join(help_text.split())
    assert "import MLX/MLX-LM" in normalized_help
    assert "no model/tokenizer discovery, download, or load" in normalized_help


def test_observed_negative_projection_replays_pure_and_rejects_binding_tamper(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    projection_path = (
        Path(preflight_module.__file__).resolve(strict=True).parents[2]
        / "evidence"
        / "mlx-runtime-preflight-negative-v1.json"
    )
    projection = preflight_module.replay_observed_negative_projection(projection_path)
    assert projection["outcome"] == "failed_closed"
    assert projection["observed_preflight_accepted"] is False
    assert projection["retry_count"] == 0
    assert _dict(projection["eligibility"])["observed_requirements_closed"] == []

    assert (
        run(
            [
                "mlx",
                "runtime-preflight-negative-replay",
                str(projection_path),
            ]
        )
        == 0
    )
    replayed = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))
    assert replayed["status"] == "replayed_failed_closed"
    assert replayed["mlx_imports_during_replay"] == 0
    assert replayed["process_actions_during_replay"] == 0

    tampered = _copy(projection)
    _dict(tampered["raw_bindings"])["authorization_id"] = digest_bytes(
        b"coordinated forged authorization"
    )
    tampered_content = dict(tampered)
    del tampered_content["projection_id"]
    tampered["projection_id"] = canonical_identity(tampered_content)
    tampered_path = tmp_path / "tampered-negative-projection.json"
    tampered_path.write_bytes(canonical_json(tampered))
    with pytest.raises(ContractError, match="content drift"):
        preflight_module.replay_observed_negative_projection(tampered_path)
