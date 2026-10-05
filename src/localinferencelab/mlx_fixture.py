"""Deterministic offline refusal fixture for the direct MLX contract."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_manifest import (
    SCHEMA_VERSION,
    closed_runtime_environment,
    verify_model_manifest,
    verify_runtime_manifest,
    verify_runtime_scan_spec,
)
from localinferencelab.mlx_runner import (
    build_mlx_prospective_package,
    mlx_eligibility_inspection,
    mlx_study_spec,
    verify_mlx_prospective_package,
    verify_mlx_study_spec,
)


def _file(path: str, data: bytes, inode: int) -> dict[str, JsonValue]:
    return {
        "path": path,
        "device": 7,
        "inode": inode,
        "mode": 0o600,
        "link_count": 1,
        "owner_scope": "synthetic_fixture",
        "size_bytes": len(data),
        "sha256": digest_bytes(data),
    }


def _physical_file(data: bytes, inode: int, *, executable: bool) -> dict[str, JsonValue]:
    return {
        "device": 7,
        "inode": inode,
        "mode": 0o700 if executable else 0o600,
        "link_count": 1,
        "owner_scope": "synthetic_fixture",
        "size_bytes": len(data),
        "sha256": digest_bytes(data),
    }


def _root(files: list[JsonValue], inode: int) -> dict[str, JsonValue]:
    total = sum(cast("int", cast("dict[str, JsonValue]", item)["size_bytes"]) for item in files)
    return {
        "device": 7,
        "inode": inode,
        "mode": 0o700,
        "link_count": 2,
        "owner_scope": "synthetic_fixture",
        "file_count": len(files),
        "total_size_bytes": total,
        "closure_sha256": canonical_identity(files),
    }


def _runtime_scan_spec() -> dict[str, JsonValue]:
    modules: list[JsonValue] = [
        "mlx/__init__.py",
        "mlx_lm/__init__.py",
        "mlx_lm/generate.py",
        "mlx_lm/models/cache.py",
        "mlx_lm/sample_utils.py",
        "mlx_lm/utils.py",
    ]
    return verify_runtime_scan_spec(
        {
            "record_type": "mlx_runtime_scan_spec",
            "schema_version": SCHEMA_VERSION,
            "python": {
                "implementation": "CPython",
                "version": "3.12.synthetic",
                "abi": "cp312-synthetic",
                "platform": "macosx_synthetic_arm64",
            },
            "expected_distributions": [
                {"name": "mlx", "version": "0.synthetic"},
                {"name": "mlx-lm", "version": "0.synthetic"},
            ],
            "selected_module_files": modules,
            "environment": closed_runtime_environment(),
        }
    )


def synthetic_runtime_manifest() -> dict[str, JsonValue]:
    """Return an immutable fake package closure that cannot execute."""
    contents = {
        "mlx/__init__.py": b"# sealed synthetic MLX package marker\n",
        "mlx-0.synthetic.dist-info/METADATA": (
            b"Metadata-Version: 2.4\nName: mlx\nVersion: 0.synthetic\n\n"
        ),
        "mlx_lm/__init__.py": b"# sealed synthetic MLX-LM package marker\n",
        "mlx_lm/generate.py": b"# sealed synthetic generate module marker\n",
        "mlx_lm/models/cache.py": b"# sealed synthetic cache module marker\n",
        "mlx_lm/sample_utils.py": b"# sealed synthetic sampler module marker\n",
        "mlx_lm/utils.py": b"# sealed synthetic loading module marker\n",
        "mlx_lm-0.synthetic.dist-info/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: mlx-lm\n"
            b"Version: 0.synthetic\n"
            b"Requires-Dist: mlx==0.synthetic\n\n"
        ),
    }
    files: list[JsonValue] = [
        _file(path, contents[path], 1_000 + index) for index, path in enumerate(sorted(contents))
    ]
    file_map = {
        cast("str", cast("dict[str, JsonValue]", item)["path"]): cast(
            "dict[str, JsonValue]",
            item,
        )
        for item in files
    }
    spec = _runtime_scan_spec()
    interpreter = b"sealed synthetic interpreter bytes"
    worker = b"sealed synthetic direct-worker bytes; no executable behavior"
    manifest: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_manifest",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "synthetic_fixture",
        "scan_spec_id": canonical_identity(spec),
        "python": spec["python"],
        "interpreter": _physical_file(interpreter, 900, executable=True),
        "worker_program": _physical_file(worker, 901, executable=False),
        "environment": spec["environment"],
        "distributions": [
            {
                "name": "mlx",
                "version": "0.synthetic",
                "metadata_path": "mlx-0.synthetic.dist-info/METADATA",
                "metadata_sha256": file_map["mlx-0.synthetic.dist-info/METADATA"]["sha256"],
                "requires_dist": [],
                "editable": False,
                "direct_url_sha256": None,
            },
            {
                "name": "mlx-lm",
                "version": "0.synthetic",
                "metadata_path": "mlx_lm-0.synthetic.dist-info/METADATA",
                "metadata_sha256": file_map["mlx_lm-0.synthetic.dist-info/METADATA"]["sha256"],
                "requires_dist": ["mlx==0.synthetic"],
                "editable": False,
                "direct_url_sha256": None,
            },
        ],
        "selected_module_files": spec["selected_module_files"],
        "package_root": _root(files, 800),
        "files": files,
        "imports_performed": 0,
        "process_actions": 0,
        "network_actions": 0,
    }
    manifest["manifest_id"] = canonical_identity(manifest)
    return verify_runtime_manifest(manifest)


def synthetic_model_manifest() -> dict[str, JsonValue]:
    """Return an immutable fake local-snapshot closure that cannot be loaded."""
    chat_template = "{{ messages | synthetic_fixture_only }}"
    contents = {
        "config.json": canonical_json(
            {
                "architectures": ["SyntheticFixture"],
                "model_type": "synthetic_fixture",
            }
        ),
        "model.safetensors": b"sealed synthetic non-model weight bytes",
        "tokenizer.json": canonical_json(
            {"model": {"type": "SyntheticFixture", "vocab": {"fixture": 0}}}
        ),
        "tokenizer_config.json": canonical_json(
            {
                "chat_template": chat_template,
                "eos_token_id": 1,
            }
        ),
    }
    files: list[JsonValue] = [
        _file(path, contents[path], 2_000 + index) for index, path in enumerate(sorted(contents))
    ]
    file_map = {
        cast("str", cast("dict[str, JsonValue]", item)["path"]): cast(
            "dict[str, JsonValue]",
            item,
        )
        for item in files
    }
    manifest: dict[str, JsonValue] = {
        "record_type": "mlx_model_manifest",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "synthetic_fixture",
        "representation": "mlx_snapshot",
        "resolved_directory": _root(files, 1_800),
        "files": files,
        "config_sha256": file_map["config.json"]["sha256"],
        "tokenizer_config_sha256": file_map["tokenizer_config.json"]["sha256"],
        "tokenizer_files": ["tokenizer.json"],
        "weight_files": ["model.safetensors"],
        "weight_index_path": None,
        "weight_index_sha256": None,
        "weight_index_referenced_shards": [],
        "chat_template": {
            "source": "tokenizer_config.json:chat_template",
            "sha256": digest_bytes(chat_template.encode("utf-8")),
        },
        "custom_code": "forbidden_absent",
        "network_resolution": "forbidden_not_performed",
        "model_loads": 0,
        "tokenizer_loads": 0,
        "network_actions": 0,
    }
    manifest["manifest_id"] = canonical_identity(manifest)
    return verify_model_manifest(manifest)


def _fixture_source() -> dict[str, JsonValue]:
    return {
        "record_type": "mlx_direct_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_offline_refusal_contract_evidence",
        "observed_hardware_evidence": False,
        "producer_reachable_execution": False,
        "sealed_values_only": True,
        "mlx_imports": 0,
        "mlx_lm_imports": 0,
        "metal_initializations": 0,
        "device_queries": 0,
        "model_loads": 0,
        "tokenizer_loads": 0,
        "inference_requests": 0,
        "worker_process_starts": 0,
        "subprocess_calls": 0,
        "socket_calls": 0,
        "listener_creations": 0,
        "physical_network_requests": 0,
        "model_downloads": 0,
        "model_cache_mutations": 0,
        "authorization_nonce_consumptions": 0,
        "output_root_consumptions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }


@dataclass(frozen=True, slots=True)
class MlxFixtureReplayResult:
    """Summary of one deterministic offline refusal-fixture replay."""

    bundle_root: str
    package_id: str
    runtime_manifest_id: str
    model_manifest_id: str
    decision: str
    missing_requirements: int
    physical_actions: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "package_id": self.package_id,
            "runtime_manifest_id": self.runtime_manifest_id,
            "model_manifest_id": self.model_manifest_id,
            "decision": self.decision,
            "missing_requirements": self.missing_requirements,
            "physical_actions": self.physical_actions,
        }


def compile_mlx_fixture(output_root: Path) -> tuple[Path, MlxFixtureReplayResult]:
    """Publish the sealed ineligible contract after all values verify in memory."""
    spec = verify_mlx_study_spec(mlx_study_spec())
    runtime = synthetic_runtime_manifest()
    model = synthetic_model_manifest()
    package = build_mlx_prospective_package(
        spec,
        runtime_manifest=runtime,
        model_manifest=model,
    )
    verify_mlx_prospective_package(package)
    source = _fixture_source()
    destination = publish_bundle(
        {
            "source/fixture.json": canonical_json(source),
            "source/study-spec.json": canonical_json(spec),
            "manifests/runtime.json": canonical_json(runtime),
            "manifests/model.json": canonical_json(model),
            "prospective-package.json": canonical_json(package),
        },
        output_root,
        name_prefix="localinferencelab-mlx-direct-refused-synthetic-v1",
    )
    return destination, replay_mlx_fixture(destination)


def _canonical_value(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def replay_mlx_fixture(bundle: Path) -> MlxFixtureReplayResult:
    """Rebuild the sealed refusal and verify the receipt-closed bundle offline."""
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/fixture.json",
        "source/study-spec.json",
        "manifests/runtime.json",
        "manifests/model.json",
        "prospective-package.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("MLX fixture bundle has an invalid content set")
    source = _canonical_value(files["source/fixture.json"], "MLX fixture source")
    if canonical_json(source) != canonical_json(_fixture_source()):
        raise ContractError("MLX fixture source or zero-action claims drift")
    spec = verify_mlx_study_spec(
        _canonical_value(files["source/study-spec.json"], "MLX fixture study spec")
    )
    runtime = verify_runtime_manifest(
        _canonical_value(files["manifests/runtime.json"], "MLX fixture runtime manifest")
    )
    model = verify_model_manifest(
        _canonical_value(files["manifests/model.json"], "MLX fixture model manifest")
    )
    package = verify_mlx_prospective_package(
        _canonical_value(files["prospective-package.json"], "MLX fixture package")
    )
    expected_runtime = synthetic_runtime_manifest()
    expected_model = synthetic_model_manifest()
    expected_package = build_mlx_prospective_package(
        spec,
        runtime_manifest=expected_runtime,
        model_manifest=expected_model,
    )
    if (
        canonical_json(runtime) != canonical_json(expected_runtime)
        or canonical_json(model) != canonical_json(expected_model)
        or canonical_json(package) != canonical_json(expected_package)
    ):
        raise ContractError("MLX fixture semantic reconstruction mismatch")
    inspection = mlx_eligibility_inspection(package)
    missing = cast("list[JsonValue]", inspection["missing_requirements"])
    return MlxFixtureReplayResult(
        bundle_root=content_root,
        package_id=cast("str", package["package_id"]),
        runtime_manifest_id=cast("str", runtime["manifest_id"]),
        model_manifest_id=cast("str", model["manifest_id"]),
        decision=cast("str", inspection["decision"]),
        missing_requirements=len(missing),
        physical_actions=0,
    )
