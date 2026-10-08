"""Static qualification gate and adversarial reconstruction tests."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_qualification as qualification_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    encode_bytes,
    load_canonical_json_file,
    load_json_bytes,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_qualification import (
    ELIGIBLE,
    INELIGIBLE,
    build_qualification_record,
    compile_qualification_fixture,
    historical_incompatible_qualification_package,
    qualification_spec,
    replay_qualification_fixture,
    synthetic_eligible_qualification_package,
    verify_qualification_package,
    verify_qualification_record,
    worker_api_evidence_inspection,
    worker_api_evidence_spec,
)
from localinferencelab.mlx_runtime_preflight import (
    EXPECTED_OBSERVED_LOCK_ID,
    EXPECTED_OBSERVED_NEGATIVE_PROJECTION_ID,
    OBSERVED_AUTHORIZATION_ID,
    OBSERVED_CONSUMPTION_ID,
    OBSERVED_FAILURE_ID,
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


def _distribution(
    package: dict[str, JsonValue],
    name: str,
) -> dict[str, JsonValue]:
    for item in _list(package["distributions"]):
        distribution = _dict(item)
        if distribution["name"] == name:
            return distribution
    raise AssertionError(f"missing distribution {name}")


def _rehash_package(package: dict[str, JsonValue]) -> None:
    content = dict(package)
    content.pop("package_id", None)
    package["package_id"] = canonical_identity(content)


def _rehash_record(record: dict[str, JsonValue]) -> None:
    content = dict(record)
    content.pop("record_id", None)
    record["record_id"] = canonical_identity(content)


def _worker_api_evidence(
    package: dict[str, JsonValue],
    probe: str,
) -> dict[str, JsonValue]:
    for item in _list(package["worker_api_evidence"]):
        evidence = _dict(item)
        if evidence["probe"] == probe:
            return evidence
    raise AssertionError(f"missing worker API evidence {probe}")


def _worker_api_source(
    evidence: dict[str, JsonValue],
    path: str,
) -> dict[str, JsonValue]:
    for item in _list(evidence["sources"]):
        source = _dict(item)
        if source["path"] == path:
            return source
    raise AssertionError(f"missing worker API source {path}")


def _rehash_worker_api_source(source: dict[str, JsonValue]) -> None:
    content = dict(source)
    content.pop("source_id", None)
    source["source_id"] = canonical_identity(content)


def _set_worker_api_excerpt(source: dict[str, JsonValue], text: str) -> None:
    data = text.encode()
    source["excerpt_bytes_base64"] = encode_bytes(data)
    source["excerpt_sha256"] = digest_bytes(data)
    _rehash_worker_api_source(source)


def _rehash_worker_api_evidence(evidence: dict[str, JsonValue]) -> None:
    content = dict(evidence)
    content.pop("evidence_id", None)
    evidence["evidence_id"] = canonical_identity(content)


def _rehash_worker_api_bundle(package: dict[str, JsonValue]) -> None:
    package["worker_api_evidence_anchor_id"] = canonical_identity(package["worker_api_evidence"])
    _rehash_package(package)


def _committed_candidate_package() -> dict[str, JsonValue]:
    candidate_path = (
        Path(qualification_module.__file__).resolve(strict=True).parents[2]
        / "evidence"
        / "mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json"
    )
    return _dict(load_canonical_json_file(candidate_path, "real MLX candidate evidence"))


def _set_metadata_requirements(
    package: dict[str, JsonValue],
    distribution_name: str,
    requirements: list[str],
) -> None:
    distribution = _distribution(package, distribution_name)
    name = cast("str", distribution["name"])
    version = cast("str", distribution["version"])
    metadata = _dict(distribution["metadata"])
    previous = qualification_module.decode_bytes(cast("str", metadata["bytes_base64"]))
    requires_python = next(
        (
            line[17:]
            for line in previous.decode("ascii").splitlines()
            if line.startswith("Requires-Python: ")
        ),
        None,
    )
    data = qualification_module._metadata_bytes(  # noqa: SLF001
        name,
        version,
        requirements,
        requires_python=requires_python,
    )
    _set_metadata_and_wheel_bytes(
        package,
        distribution_name,
        data=data,
        requirements=requirements,
        requires_python=requires_python,
    )


def _set_metadata_and_wheel_bytes(
    package: dict[str, JsonValue],
    distribution_name: str,
    *,
    data: bytes,
    requirements: list[str],
    requires_python: str | None,
) -> None:
    distribution = _distribution(package, distribution_name)
    name = cast("str", distribution["name"])
    version = cast("str", distribution["version"])
    metadata = _dict(distribution["metadata"])
    metadata["bytes_base64"] = encode_bytes(data)
    metadata["sha256"] = digest_bytes(data)
    wheel = _dict(distribution["wheel"])
    tag = f"{wheel['python_tag']}-{wheel['abi_tag']}-{wheel['platform_tag']}"
    wheel_bytes = qualification_module._synthetic_wheel_bytes(  # noqa: SLF001
        name=name,
        version=version,
        tag=tag,
        requirements=requirements,
        requires_python=requires_python,
        metadata_bytes=data,
    )
    wheel["bytes_base64"] = encode_bytes(wheel_bytes)
    wheel["size_bytes"] = len(wheel_bytes)
    wheel["sha256"] = digest_bytes(wheel_bytes)
    _rehash_package(package)


def _as_reviewed_candidate(package: dict[str, JsonValue]) -> None:
    package["candidate_kind"] = "reviewed_candidate"
    for item in _list(package["distributions"]):
        distribution = _dict(item)
        name = cast("str", distribution["name"])
        source = _dict(distribution["source"])
        source["provenance"] = "reviewed_git_revision_and_tag"
        source["repository_url"] = f"https://github.com/example/{name}"
        wheel = _dict(distribution["wheel"])
        wheel["provenance"] = "reviewed_pypi_artifact"
        wheel["url"] = f"https://files.pythonhosted.org/packages/reviewed/{wheel['filename']}"
        _dict(distribution["metadata"])["evidence_scope"] = "complete_wheel_metadata"
    _rehash_package(package)


def _set_requires_python(
    package: dict[str, JsonValue],
    distribution_name: str,
    requires_python: str | None,
) -> None:
    distribution = _distribution(package, distribution_name)
    metadata = _dict(distribution["metadata"])
    metadata_bytes = qualification_module.decode_bytes(cast("str", metadata["bytes_base64"]))
    requirements = [
        line[15:]
        for line in metadata_bytes.decode("ascii").splitlines()
        if line.startswith("Requires-Dist: ")
    ]
    data = qualification_module._metadata_bytes(  # noqa: SLF001
        cast("str", distribution["name"]),
        cast("str", distribution["version"]),
        requirements,
        requires_python=requires_python,
    )
    _set_metadata_and_wheel_bytes(
        package,
        distribution_name,
        data=data,
        requirements=requirements,
        requires_python=requires_python,
    )


def _retag_synthetic_wheel(
    package: dict[str, JsonValue],
    distribution_name: str,
    *,
    python_tag: str,
    abi_tag: str,
    platform_tag: str,
) -> None:
    distribution = _distribution(package, distribution_name)
    wheel = _dict(distribution["wheel"])
    metadata = _dict(distribution["metadata"])
    metadata_bytes = qualification_module.decode_bytes(cast("str", metadata["bytes_base64"]))
    requirements = [
        line[15:]
        for line in metadata_bytes.decode("ascii").splitlines()
        if line.startswith("Requires-Dist: ")
    ]
    requires_python = next(
        (
            line[17:]
            for line in metadata_bytes.decode("ascii").splitlines()
            if line.startswith("Requires-Python: ")
        ),
        None,
    )
    name = cast("str", distribution["name"])
    version = cast("str", distribution["version"])
    filename = f"{name.replace('-', '_')}-{version}-{python_tag}-{abi_tag}-{platform_tag}.whl"
    wheel_bytes = qualification_module._synthetic_wheel_bytes(  # noqa: SLF001
        name=name,
        version=version,
        tag=f"{python_tag}-{abi_tag}-{platform_tag}",
        requirements=requirements,
        requires_python=requires_python,
        metadata_bytes=metadata_bytes,
    )
    wheel.update(
        {
            "abi_tag": abi_tag,
            "bytes_base64": encode_bytes(wheel_bytes),
            "filename": filename,
            "platform_tag": platform_tag,
            "python_tag": python_tag,
            "sha256": digest_bytes(wheel_bytes),
            "size_bytes": len(wheel_bytes),
            "url": f"https://fixtures.localinferencelab.invalid/wheels/{filename}",
        }
    )
    _rehash_package(package)


def test_spec_and_decisions_are_static_bounded_and_exact() -> None:
    spec = qualification_spec()
    frozen = _dict(spec["frozen_schema_1_0_negative"])
    assert frozen == {
        "authorization_id": OBSERVED_AUTHORIZATION_ID,
        "consumption_id": OBSERVED_CONSUMPTION_ID,
        "historical_protocol_id": (
            "sha256:c3df6f0eb9a67a00e1f1f180b0e34fd9b5ac5dd662b430f86ec29c87dd30727a"
        ),
        "historical_worker_code_id": (
            "sha256:bfd840635879dfae9a57fb11cae0e6ddef4f3f5f3b9b81f39e8e1cec51539fe3"
        ),
        "ids_modified": False,
        "negative_projection_id": EXPECTED_OBSERVED_NEGATIVE_PROJECTION_ID,
        "retry_authorized": False,
        "runtime_lock_id": EXPECTED_OBSERVED_LOCK_ID,
        "schema_1_0_state": "permanently_disabled",
        "terminal_failure_id": OBSERVED_FAILURE_ID,
    }
    assert spec["decisions"] == [ELIGIBLE, INELIGIBLE]
    assert spec["reviewed_candidate_anchors"] == [
        "sha256:e4bd7b6f5ce7656d1a490a6e4b39e23e1b9a6acaee55084744a8a267f0007f2c"
    ]
    api_spec = worker_api_evidence_spec()
    assert spec["worker_api_evidence_spec_id"] == api_spec["spec_id"]
    assert api_spec["reviewed_evidence_anchors"] == [
        "sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd"
    ]
    assert api_spec["claim_scope"] == "source_surface_availability_only"

    historical = build_qualification_record(historical_incompatible_qualification_package())
    eligible = build_qualification_record(synthetic_eligible_qualification_package())
    assert historical["decision"] == INELIGIBLE
    historical_blockers = cast("list[JsonValue]", historical["blockers"])
    assert any(
        cast("str", blocker).startswith(
            "dependency_unsatisfied:mlx-lm:"
            'mlx>=0.30.4; platform_system == "Darwin":selected=mlx==0.29.3'
        )
        for blocker in historical_blockers
    )
    assert eligible["decision"] == ELIGIBLE
    assert eligible["blockers"] == []
    counters = _dict(eligible["static_action_counters"])
    assert set(counters.values()) == {0}
    assessment = _dict(eligible["assessment"])
    closure = _dict(assessment["closure"])
    assert closure["standard_library_semantic_completeness_claimed"] is False
    assert closure["native_loader_semantic_completeness_claimed"] is False
    assert eligible["schema_1_0_remains_permanently_disabled"] is True


def test_committed_real_candidate_anchor_is_exact_and_ineligible() -> None:
    package = verify_qualification_package(_committed_candidate_package())
    assert package["qualification_spec_id"] == (
        "sha256:69bc8ad04e7eda3f091ed16524e97413081dd4fe385c7ca9262a304420534a6a"
    )
    assert package["package_id"] == (
        "sha256:c4bb9a295b15a9085ee3014c006cfc307ab63d650d3b1109d9bc348c915833f8"
    )
    assert package["worker_api_evidence_spec_id"] == (
        "sha256:6c83f627032a2c3db38eee34f804469a42e227a3af0a84ed5c0052a192d29e97"
    )
    assert package["worker_api_evidence_anchor_id"] == (
        "sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd"
    )
    assert package["top_level_requirements"] == ["mlx==0.30.4", "mlx-lm==0.30.6"]
    evidence_ids = {
        cast("str", _dict(item)["probe"]): _dict(item)["evidence_id"]
        for item in _list(package["worker_api_evidence"])
    }
    assert evidence_ids == {
        "default_device": (
            "sha256:6e04b78a79a8b17716b1efb25618d023049ab5e8f0c7b498df6b5b299749da11"
        ),
        "default_stream": (
            "sha256:1e93a3534716244fe96e0fcfd440a5ae936b6f388e29ed1ff585c89f3dffe7fc"
        ),
        "distribution_versions": (
            "sha256:57688975abdf7569e4fad5c7099d500be897ee76549fc2e8609b86731909097d"
        ),
        "import_mlx": ("sha256:1bd33b02a84ff9719003593526bd7ab79a06c15bfba7107e248ae17b1266a823"),
        "import_mlx_lm": (
            "sha256:003a14ef061dd62328bc79a5ee2e7a5acf45b112f2f7eb7051fde66418d30757"
        ),
        "metal_is_available": (
            "sha256:d1d9d82a71a480a38128a6dc054eb527cb26853930591c28a809e8d82284bdff"
        ),
        "synchronize": ("sha256:52e2da326c71114e5cd83da341e3f88dd6d3ed57704b7cf550eff12ead2b7fb2"),
    }
    distribution_versions = _worker_api_evidence(package, "distribution_versions")
    assert {
        (
            _dict(source)["repository_url"],
            _dict(source)["tag"],
            _dict(source)["revision"],
            _dict(source)["path"],
            _dict(source)["file_sha256"],
        )
        for source in _list(distribution_versions["sources"])
    } == {
        (
            "https://github.com/python/cpython",
            "v3.13.0",
            "60403a5409ff2c3f3b07dd2ca91a7a3e096839c7",
            "Lib/importlib/metadata/__init__.py",
            "sha256:5476c7c22a65f9e8b5a07b799336d87fa70e792758fd95b161b53b530e3b2654",
        )
    }

    mlx = _distribution(package, "mlx")
    assert _dict(mlx["source"]) == {
        "provenance": "reviewed_git_revision_and_tag",
        "repository_url": "https://github.com/ml-explore/mlx",
        "revision": "2f324cc3b200700b422db4811ae3ff8bd5bf48b4",
        "tag": "v0.30.4",
    }
    assert _dict(mlx["wheel"])["sha256"] == (
        "sha256:1f367534078b10dcb660393a554f97732c194977ac8318bb389a76a6307757f8"
    )
    assert _dict(mlx["metadata"])["sha256"] == (
        "sha256:c3b3faaf1dd2bd14b33a62e3eb6297a51f8108f12f8d66d05e6c74f3d5fd6d46"
    )

    mlx_lm = _distribution(package, "mlx-lm")
    assert _dict(mlx_lm["source"]) == {
        "provenance": "reviewed_git_revision_and_tag",
        "repository_url": "https://github.com/ml-explore/mlx-lm",
        "revision": "f18526f8d66f74728072e96d55acb6c451e92e88",
        "tag": "v0.30.6",
    }
    assert _dict(mlx_lm["wheel"])["sha256"] == (
        "sha256:a7405bd581eacc4bf8209d7a6b7f23629585a0d7c6740c2a97e51fee35b3b0e1"
    )
    assert _dict(mlx_lm["metadata"])["sha256"] == (
        "sha256:e5903a45bc0575fd6b8d68c67ba6cab13204995d103c1f1f32b52789f84bfb8f"
    )

    record = build_qualification_record(package)
    assessment = _dict(record["assessment"])
    assert assessment["review_anchor_id"] == (
        "sha256:e4bd7b6f5ce7656d1a490a6e4b39e23e1b9a6acaee55084744a8a267f0007f2c"
    )
    assert record["record_id"] == (
        "sha256:60a8e63505dea047f8db765effd80df29372d2d94d27193143610911ecaeace6"
    )
    assert record["decision"] == INELIGIBLE
    assert record["blockers"] == [
        "dependency_missing:mlx-lm:jinja2",
        "dependency_missing:mlx-lm:numpy",
        "dependency_missing:mlx-lm:protobuf",
        "dependency_missing:mlx-lm:pyyaml",
        "dependency_missing:mlx-lm:sentencepiece",
        "dependency_missing:mlx-lm:transformers>=5.0.0",
        'dependency_missing:mlx:mlx-metal==0.30.4; platform_system == "Darwin"',
    ]
    api_assessments = [_dict(item) for item in _list(assessment["worker_api_assessments"])]
    assert len(api_assessments) == 7
    assert all(item["evidence_present"] is True for item in api_assessments)
    assert all(
        item["claim_scope"] == "source_surface_availability_only" for item in api_assessments
    )
    inspection = worker_api_evidence_inspection(package)
    assert inspection["evidence_anchor_id"] == package["worker_api_evidence_anchor_id"]
    assert len(_list(inspection["evidence"])) == 7
    dependency_assessments = [_dict(item) for item in _list(assessment["dependency_assessments"])]
    pair_dependency = next(
        item
        for item in dependency_assessments
        if item["requirement"] == 'mlx>=0.30.4; platform_system == "Darwin"'
    )
    assert pair_dependency["selected_distribution"] == "mlx==0.30.4"
    assert pair_dependency["satisfied"] is True
    one_component_extra = next(
        item for item in dependency_assessments if item["requirement"] == 'numpy>=2; extra == "dev"'
    )
    assert one_component_extra["applicable"] is False
    assert all(_dict(item)["compatible"] is True for item in _list(assessment["wheel_assessments"]))
    assert set(_dict(record["static_action_counters"]).values()) == {0}


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ('"default_device"', '"renamed_device"', "must contain"),
        (
            "&mx::default_device",
            "&mx::default_device /* &mx::default_device */",
            "exactly 1 time",
        ),
    ],
)
def test_reviewed_worker_api_rejects_missing_renamed_or_duplicate_symbols(
    old: str,
    new: str,
    message: str,
) -> None:
    package = _copy(_committed_candidate_package())
    evidence = _worker_api_evidence(package, "default_device")
    source = _worker_api_source(evidence, "python/src/device.cpp")
    text = qualification_module.decode_bytes(cast("str", source["excerpt_bytes_base64"])).decode()
    _set_worker_api_excerpt(source, text.replace(old, new))
    _rehash_worker_api_evidence(evidence)
    _rehash_worker_api_bundle(package)
    with pytest.raises(ContractError, match=message):
        verify_qualification_package(package)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("module", "mlx", "semantic claim drift"),
        ("static_signature", "() -> object", "semantic claim drift"),
        ("claim_scope", "runtime_import_success", "exceeds source-surface evidence"),
        ("callable", 1, "must be a boolean"),
    ],
)
def test_reviewed_worker_api_rejects_signature_type_and_overclaim_drift(
    field: str,
    value: JsonValue,
    message: str,
) -> None:
    package = _copy(_committed_candidate_package())
    evidence = _worker_api_evidence(package, "default_device")
    evidence[field] = value
    _rehash_worker_api_evidence(evidence)
    _rehash_worker_api_bundle(package)
    with pytest.raises(ContractError, match=message):
        verify_qualification_package(package)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("path", "python/src/renamed-device.cpp", "not an accepted reviewed source file"),
        ("revision", "0" * 40, "tag, revision, or full-file hash drift"),
        ("tag", "v0.30.5", "tag, revision, or full-file hash drift"),
        ("file_sha256", "sha256:" + "0" * 64, "tag, revision, or full-file hash drift"),
    ],
)
def test_reviewed_worker_api_rejects_source_path_revision_and_tag_drift(
    field: str,
    value: JsonValue,
    message: str,
) -> None:
    package = _copy(_committed_candidate_package())
    evidence = _worker_api_evidence(package, "default_device")
    source = _worker_api_source(evidence, "python/src/device.cpp")
    source[field] = value
    _rehash_worker_api_source(source)
    _rehash_worker_api_evidence(evidence)
    _rehash_worker_api_bundle(package)
    with pytest.raises(ContractError, match=message):
        verify_qualification_package(package)


def test_reviewed_worker_api_rejects_dynamic_module_alias() -> None:
    package = _copy(_committed_candidate_package())
    evidence = _worker_api_evidence(package, "import_mlx")
    source = _worker_api_source(evidence, "setup.py")
    text = qualification_module.decode_bytes(cast("str", source["excerpt_bytes_base64"])).decode()
    _set_worker_api_excerpt(source, text.replace('"mlx.core"', "module_name", 1))
    _rehash_worker_api_evidence(evidence)
    _rehash_worker_api_bundle(package)
    with pytest.raises(ContractError, match="module name is dynamic or has drifted"):
        verify_qualification_package(package)


def test_reviewed_worker_api_rejects_boolean_as_line_number() -> None:
    package = _copy(_committed_candidate_package())
    evidence = _worker_api_evidence(package, "default_device")
    source = _worker_api_source(evidence, "python/src/device.cpp")
    source["excerpt_start_line"] = True
    _rehash_worker_api_source(source)
    _rehash_worker_api_evidence(evidence)
    _rehash_worker_api_bundle(package)
    with pytest.raises(ContractError, match="must be an integer"):
        verify_qualification_package(package)


def test_reviewed_worker_api_rejects_coordinated_excerpt_rehashing() -> None:
    package = _copy(_committed_candidate_package())
    evidence = _worker_api_evidence(package, "default_device")
    source = _worker_api_source(evidence, "python/src/device.cpp")
    text = qualification_module.decode_bytes(cast("str", source["excerpt_bytes_base64"])).decode()
    _set_worker_api_excerpt(
        source, text.replace("Get the default device.", "Get the default device. ")
    )
    _rehash_worker_api_evidence(evidence)
    _rehash_worker_api_bundle(package)
    with pytest.raises(ContractError, match="was not independently reviewed"):
        verify_qualification_package(package)


def test_qualification_module_has_no_runtime_action_surface() -> None:
    module_path = Path(qualification_module.__file__).resolve(strict=True)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
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
        "requests",
        "socket",
        "subprocess",
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called_attributes & {
        "exec",
        "fork",
        "import_module",
        "posix_spawn",
        "socket",
        "socketpair",
        "system",
        "urlopen",
    }


def test_qualification_fixture_is_deterministic_and_process_free(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_replay = compile_qualification_fixture(first_root)
    second, second_replay = compile_qualification_fixture(second_root)
    assert first.name == second.name
    assert first_replay.to_dict() == second_replay.to_dict() | {
        "bundle_root": first_replay.bundle_root
    }
    replay = replay_qualification_fixture(first)
    assert replay.eligible_decision == ELIGIBLE
    assert replay.ineligible_decision == INELIGIBLE
    assert replay.package_installations == 0
    assert replay.process_starts == 0
    assert replay.runtime_imports == 0
    assert replay.authorization_creations == 0


def test_cli_create_verify_inspect_spec_and_replay_are_static(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    candidate = tmp_path / "candidate.json"
    record = tmp_path / "record.json"
    candidate.write_bytes(canonical_json(synthetic_eligible_qualification_package()))
    assert (
        run(
            [
                "mlx",
                "runtime-qualification-create",
                str(candidate),
                str(record),
            ]
        )
        == 0
    )
    created = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert created["decision"] == ELIGIBLE
    assert set(_dict(created["static_action_counters"]).values()) == {0}
    assert run(["mlx", "runtime-qualification-verify", str(record)]) == 0
    verified = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert verified["status"] == "valid"
    assert run(["mlx", "runtime-qualification-inspect", str(record)]) == 0
    inspected = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert inspected["status"] == "inspected"
    assert inspected["schema_1_0_remains_permanently_disabled"] is True
    assert run(["mlx", "runtime-qualification-spec"]) == 0
    emitted_spec = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))
    assert emitted_spec == qualification_spec()
    assert run(["mlx", "runtime-worker-api-evidence-spec"]) == 0
    emitted_api_spec = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))
    assert emitted_api_spec == worker_api_evidence_spec()
    real_candidate = (
        Path(qualification_module.__file__).resolve(strict=True).parents[2]
        / "evidence"
        / "mlx-runtime-candidate-mlx-0.30.4-mlx-lm-0.30.6-v1.json"
    )
    assert run(["mlx", "runtime-worker-api-evidence-verify", str(real_candidate)]) == 0
    verified_api = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert verified_api["status"] == "valid"
    assert verified_api["claim_scope"] == "source_surface_availability_only"
    assert len(_list(verified_api["evidence"])) == 7

    fixture_root = tmp_path / "fixture"
    fixture_root.mkdir()
    assert (
        run(
            [
                "mlx",
                "runtime-qualification-fixture-compile",
                str(fixture_root),
            ]
        )
        == 0
    )
    compiled = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    bundle = fixture_root / cast("str", compiled["path"])
    assert run(["mlx", "runtime-qualification-replay", str(bundle)]) == 0
    replayed = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert replayed["status"] == "replayed"
    assert replayed["package_installations"] == 0
    assert replayed["process_starts"] == 0
    assert replayed["runtime_imports"] == 0
    assert replayed["authorization_creations"] == 0


@pytest.mark.parametrize("missing_field", ["target_environment", "worker_api_evidence"])
def test_package_rejects_missing_and_unknown_fields(missing_field: str) -> None:
    missing = _copy(synthetic_eligible_qualification_package())
    del missing[missing_field]
    _rehash_package(missing)
    with pytest.raises(ContractError, match="missing keys"):
        verify_qualification_package(missing)

    unknown = _copy(synthetic_eligible_qualification_package())
    unknown["authorization"] = {"permission": True}
    _rehash_package(unknown)
    with pytest.raises(ContractError, match="unknown keys"):
        verify_qualification_package(unknown)


def test_package_rejects_bool_counters_and_execution_or_authorization_claims() -> None:
    ambiguous = _copy(synthetic_eligible_qualification_package())
    _dict(ambiguous["static_action_counters"])["process_starts"] = False
    _rehash_package(ambiguous)
    with pytest.raises(ContractError, match="must be an integer"):
        verify_qualification_package(ambiguous)

    processful = _copy(synthetic_eligible_qualification_package())
    _dict(processful["static_action_counters"])["runtime_imports"] = 1
    _rehash_package(processful)
    with pytest.raises(ContractError, match="must remain zero"):
        verify_qualification_package(processful)

    authorized = _copy(synthetic_eligible_qualification_package())
    _dict(authorized["claims"])["permission_to_install_import_or_execute"] = True
    _rehash_package(authorized)
    with pytest.raises(ContractError, match="expand static claim scope"):
        verify_qualification_package(authorized)

    numeric_claim = _copy(synthetic_eligible_qualification_package())
    _dict(numeric_claim["claims"])["permission_to_install_import_or_execute"] = 0
    _rehash_package(numeric_claim)
    with pytest.raises(ContractError, match="expand static claim scope"):
        verify_qualification_package(numeric_claim)

    numeric_frozen_boolean = _copy(synthetic_eligible_qualification_package())
    _dict(numeric_frozen_boolean["frozen_schema_1_0_negative"])["retry_authorized"] = 0
    _rehash_package(numeric_frozen_boolean)
    with pytest.raises(ContractError, match="negative relationship drift"):
        verify_qualification_package(numeric_frozen_boolean)


def test_duplicate_metadata_and_extras_ambiguity_fail_closed() -> None:
    duplicate = _copy(synthetic_eligible_qualification_package())
    requirement = "mlx-metal==1.0.0"
    _set_metadata_requirements(duplicate, "mlx", [requirement, requirement])
    with pytest.raises(ContractError, match="must be unique"):
        verify_qualification_package(duplicate)

    ambiguous_extras = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(
        ambiguous_extras,
        "mlx",
        ["typing-extensions[foo,foo]>=4.0"],
    )
    with pytest.raises(ContractError, match="extras must be unique and sorted"):
        verify_qualification_package(ambiguous_extras)

    explicit_extras = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(
        explicit_extras,
        "mlx",
        ["typing-extensions[foo]>=4.0"],
    )
    record = build_qualification_record(explicit_extras)
    assert record["decision"] == INELIGIBLE
    assert any(
        cast("str", blocker).startswith("dependency_extras_forbidden:mlx:")
        for blocker in _list(record["blockers"])
    )


def test_reviewed_metadata_accepts_realistic_headers_body_and_unsorted_requirements() -> None:
    package = _copy(_committed_candidate_package())
    data = (
        b"Metadata-Version: 2.3\r\n"
        b"Name: mlx\r\n"
        b"Version: 0.30.4\r\n"
        b"Summary: Realistic static wheel metadata\r\n"
        b"Requires-Python: >=3.10\r\n"
        b"Project-URL: Source, https://github.com/ml-explore/mlx\r\n"
        b"Requires-Dist: typing-extensions>=4.0\r\n"
        b"Requires-Dist: mlx-metal==0.30.4\r\n"
        b"Description-Content-Type: text/markdown\r\n"
        b"\r\n"
        b"# MLX\r\n\r\nA realistic description body remains byte-bound.\r\n"
    )
    _set_metadata_and_wheel_bytes(
        package,
        "mlx",
        data=data,
        requirements=["typing-extensions>=4.0", "mlx-metal==0.30.4"],
        requires_python=">=3.10",
    )
    verified = verify_qualification_package(package)
    assert verified["package_id"] == package["package_id"]
    record = build_qualification_record(package)
    assert record["decision"] == INELIGIBLE
    assessment = _dict(record["assessment"])
    mlx_requirements = [
        cast("str", _dict(item)["requirement"])
        for item in _list(assessment["dependency_assessments"])
        if _dict(item)["requesting_distribution"] == "mlx"
    ]
    assert mlx_requirements == ["mlx-metal==0.30.4", "typing-extensions>=4.0"]
    assert (
        next(
            _dict(item)
            for item in _list(assessment["requires_python_assessments"])
            if _dict(item)["distribution"] == "mlx"
        )["satisfied"]
        is True
    )


@pytest.mark.parametrize(
    ("header", "value"),
    [
        ("Metadata-Version", "2.3"),
        ("Name", "mlx"),
        ("Version", "1.0.0"),
    ],
)
def test_reviewed_metadata_rejects_duplicate_identity_headers(
    header: str,
    value: str,
) -> None:
    package = _copy(synthetic_eligible_qualification_package())
    _as_reviewed_candidate(package)
    data = (
        "Metadata-Version: 2.3\n"
        "Name: mlx\n"
        "Version: 1.0.0\n"
        f"{header}: {value}\n"
        "Requires-Python: >=3.11\n"
        "Requires-Dist: mlx-metal==1.0.0\n\n"
    ).encode("ascii")
    _set_metadata_and_wheel_bytes(
        package,
        "mlx",
        data=data,
        requirements=["mlx-metal==1.0.0"],
        requires_python=">=3.11",
    )
    with pytest.raises(ContractError, match=f"exactly one {header}"):
        verify_qualification_package(package)


def test_reviewed_metadata_rejects_folded_dependency_and_exact_byte_drift() -> None:
    folded = _copy(synthetic_eligible_qualification_package())
    _as_reviewed_candidate(folded)
    folded_data = (
        b"Metadata-Version: 2.3\nName: mlx\nVersion: 1.0.0\n"
        b"Requires-Python: >=3.11\n"
        b'Requires-Dist: mlx-metal==1.0.0;\n platform_system == "Darwin"\n\n'
    )
    _set_metadata_and_wheel_bytes(
        folded,
        "mlx",
        data=folded_data,
        requirements=[],
        requires_python=">=3.11",
    )
    with pytest.raises(ContractError, match="may not fold Requires-Dist"):
        verify_qualification_package(folded)

    drift = _copy(synthetic_eligible_qualification_package())
    _as_reviewed_candidate(drift)
    distribution = _distribution(drift, "mlx")
    metadata = _dict(distribution["metadata"])
    changed = qualification_module.decode_bytes(cast("str", metadata["bytes_base64"])) + b"\n"
    metadata["bytes_base64"] = encode_bytes(changed)
    metadata["sha256"] = digest_bytes(changed)
    _rehash_package(drift)
    with pytest.raises(ContractError, match="wheel METADATA bytes differ"):
        verify_qualification_package(drift)


@pytest.mark.parametrize(
    "data",
    [
        (
            b"Metadata-Version: 2.3\nName: mlx\nVersion: 1.0.0\n"
            b"Summary: invalid-\x80\nRequires-Python: >=3.11\n"
            b"Requires-Dist: mlx-metal==1.0.0\n\n"
        ),
        (
            b"Metadata-Version: 2.3\nName: mlx\nVersion: 1.0.0\n"
            b"Requires-Python: >=3.11\nRequires-Dist: mlx-metal==1.0.0\n\n"
            b"description with invalid-\x80\n"
        ),
    ],
)
def test_reviewed_metadata_rejects_invalid_utf8(data: bytes) -> None:
    package = _copy(synthetic_eligible_qualification_package())
    _as_reviewed_candidate(package)
    _set_metadata_and_wheel_bytes(
        package,
        "mlx",
        data=data,
        requirements=["mlx-metal==1.0.0"],
        requires_python=">=3.11",
    )
    with pytest.raises(ContractError, match="not parseable Core Metadata"):
        verify_qualification_package(package)


@pytest.mark.parametrize(
    "requirements",
    [
        ["mlx-metal>=1.0,<2.0", "MLX-METAL<2.0.0,>=1.0.0"],
        [
            'mlx-metal==1.0.0; platform_system == "Darwin" and platform_machine == "arm64"',
            'mlx-metal==1.0.0; platform_machine == "arm64" and platform_system == "Darwin"',
        ],
    ],
)
def test_semantically_duplicate_requirements_are_rejected(requirements: list[str]) -> None:
    package = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(package, "mlx", requirements)
    with pytest.raises(ContractError, match="Requires-Dist entries must be unique"):
        verify_qualification_package(package)


def test_requires_python_is_assessed_and_fails_closed() -> None:
    satisfied = build_qualification_record(synthetic_eligible_qualification_package())
    assert all(
        _dict(item)["satisfied"] is True
        for item in _list(_dict(satisfied["assessment"])["requires_python_assessments"])
    )

    unsatisfied = _copy(synthetic_eligible_qualification_package())
    _set_requires_python(unsatisfied, "mlx-lm", ">=3.13")
    unsatisfied_record = build_qualification_record(unsatisfied)
    assert unsatisfied_record["decision"] == INELIGIBLE
    assert "requires_python_unsatisfied:mlx-lm:>=3.13:selected=3.12.0" in _list(
        unsatisfied_record["blockers"]
    )

    missing = _copy(synthetic_eligible_qualification_package())
    _set_requires_python(missing, "mlx", None)
    _as_reviewed_candidate(missing)
    with pytest.raises(ContractError, match="complete metadata requires Requires-Python"):
        verify_qualification_package(missing)

    duplicate = _copy(synthetic_eligible_qualification_package())
    _as_reviewed_candidate(duplicate)
    duplicate_data = (
        b"Metadata-Version: 2.3\nName: mlx\nVersion: 1.0.0\n"
        b"Requires-Python: >=3.11\nRequires-Python: <4.0\n"
        b"Requires-Dist: mlx-metal==1.0.0\n\n"
    )
    _set_metadata_and_wheel_bytes(
        duplicate,
        "mlx",
        data=duplicate_data,
        requirements=["mlx-metal==1.0.0"],
        requires_python=">=3.11",
    )
    with pytest.raises(ContractError, match="at most one Requires-Python"):
        verify_qualification_package(duplicate)

    unsupported = _copy(synthetic_eligible_qualification_package())
    _set_requires_python(unsupported, "mlx", ">=3.11, <4.0")
    with pytest.raises(ContractError, match="unsupported version specifier grammar"):
        verify_qualification_package(unsupported)


@pytest.mark.parametrize(
    "requirement",
    [
        "mlx",
        "mlx>=0.0",
        "mlx==1.0.0,>=1.0.0",
        "mlx==2.0.0",
        "mlx===1.0.0",
    ],
)
def test_top_level_requirements_must_be_exact_canonical_pins(requirement: str) -> None:
    package = _copy(synthetic_eligible_qualification_package())
    package["top_level_requirements"] = [requirement, "mlx-lm==1.0.0"]
    _rehash_package(package)
    record = build_qualification_record(package)
    assert record["decision"] == INELIGIBLE
    assert any(
        cast("str", blocker).startswith(f"top_level_requirement_not_exact_pin:{requirement}:")
        for blocker in _list(record["blockers"])
    )


def test_top_level_requirements_reject_duplicate_missing_and_unexpected_roots() -> None:
    duplicate = _copy(synthetic_eligible_qualification_package())
    duplicate["top_level_requirements"] = [
        "mlx==1.0.0",
        "mlx==1.0.0",
        "mlx-lm==1.0.0",
    ]
    _rehash_package(duplicate)
    with pytest.raises(ContractError, match="names must be unique and sorted"):
        verify_qualification_package(duplicate)

    missing = _copy(synthetic_eligible_qualification_package())
    missing["top_level_requirements"] = ["mlx-lm==1.0.0"]
    _rehash_package(missing)
    assert "missing_top_level_requirement:mlx" in _list(
        build_qualification_record(missing)["blockers"]
    )

    unexpected = _copy(synthetic_eligible_qualification_package())
    unexpected["top_level_requirements"] = [
        "mlx==1.0.0",
        "mlx-extra==1.0.0",
        "mlx-lm==1.0.0",
    ]
    _rehash_package(unexpected)
    assert "unexpected_top_level_requirement:mlx-extra" in _list(
        build_qualification_record(unexpected)["blockers"]
    )


def test_marker_mismatch_and_incomplete_closure_are_exact_blockers() -> None:
    marker_mismatch = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(
        marker_mismatch,
        "mlx-lm",
        [
            'mlx>=1.0.0; platform_system == "Darwin" and platform_machine == "arm64"',
            'typing-extensions>=4.0; platform_machine == "x86_64"',
        ],
    )
    marker_record = build_qualification_record(marker_mismatch)
    assert marker_record["decision"] == INELIGIBLE
    assert "unreachable_supplied_distribution:typing-extensions" in _list(marker_record["blockers"])
    dependency = next(
        _dict(item)
        for item in _list(_dict(marker_record["assessment"])["dependency_assessments"])
        if _dict(item)["requirement"] == 'typing-extensions>=4.0; platform_machine == "x86_64"'
    )
    assert dependency["applicable"] is False
    assert dependency["status"] == "inapplicable"

    incomplete = _copy(synthetic_eligible_qualification_package())
    incomplete["distributions"] = [
        item
        for item in _list(incomplete["distributions"])
        if _dict(item)["name"] != "typing-extensions"
    ]
    _rehash_package(incomplete)
    incomplete_record = build_qualification_record(incomplete)
    assert incomplete_record["decision"] == INELIGIBLE
    assert any(
        cast("str", blocker).startswith("dependency_missing:mlx-lm:typing-extensions")
        for blocker in _list(incomplete_record["blockers"])
    )


def test_wheel_tag_platform_and_abi_mismatches_are_ineligible() -> None:
    platform_mismatch = _copy(synthetic_eligible_qualification_package())
    _retag_synthetic_wheel(
        platform_mismatch,
        "mlx",
        python_tag="cp312",
        abi_tag="cp312",
        platform_tag="macosx_99_0_arm64",
    )
    platform_record = build_qualification_record(platform_mismatch)
    assert "wheel_tag_incompatible:mlx:cp312-cp312-macosx_99_0_arm64" in _list(
        platform_record["blockers"]
    )

    abi_mismatch = _copy(synthetic_eligible_qualification_package())
    _retag_synthetic_wheel(
        abi_mismatch,
        "mlx",
        python_tag="cp311",
        abi_tag="cp311",
        platform_tag="macosx_14_0_arm64",
    )
    abi_record = build_qualification_record(abi_mismatch)
    assert "wheel_tag_incompatible:mlx:cp311-cp311-macosx_14_0_arm64" in _list(
        abi_record["blockers"]
    )

    cross_major_abi3 = _copy(synthetic_eligible_qualification_package())
    _retag_synthetic_wheel(
        cross_major_abi3,
        "mlx",
        python_tag="cp40",
        abi_tag="abi3",
        platform_tag="macosx_14_0_arm64",
    )
    cross_major_record = build_qualification_record(cross_major_abi3)
    assert "wheel_tag_incompatible:mlx:cp40-abi3-macosx_14_0_arm64" in _list(
        cross_major_record["blockers"]
    )


def test_unsatisfied_dependency_has_selected_version_and_exact_explanation() -> None:
    package = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(package, "mlx", ["mlx-metal>=2.0.0"])
    record = build_qualification_record(package)
    assert record["decision"] == INELIGIBLE
    blocker = "dependency_unsatisfied:mlx:mlx-metal>=2.0.0:selected=mlx-metal==1.0.0"
    assert blocker in _list(record["blockers"])
    assessment = next(
        _dict(item)
        for item in _list(_dict(record["assessment"])["dependency_assessments"])
        if _dict(item)["requirement"] == "mlx-metal>=2.0.0"
    )
    assert assessment["selected_distribution"] == "mlx-metal==1.0.0"
    assert assessment["satisfied"] is False
    assert assessment["explanation"] == (
        "selected mlx-metal==1.0.0 does not satisfy mlx-metal>=2.0.0"
    )


def test_arbitrary_equality_is_exact_while_standard_equality_is_normalized() -> None:
    arbitrary = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(arbitrary, "mlx", ["mlx-metal===1.0"])
    arbitrary_record = build_qualification_record(arbitrary)
    assert arbitrary_record["decision"] == INELIGIBLE
    assert "dependency_unsatisfied:mlx:mlx-metal===1.0:selected=mlx-metal==1.0.0" in _list(
        arbitrary_record["blockers"]
    )

    normalized = _copy(synthetic_eligible_qualification_package())
    _set_metadata_requirements(normalized, "mlx", ["mlx-metal==1.0"])
    assert build_qualification_record(normalized)["decision"] == ELIGIBLE


def test_reviewed_and_historical_candidates_cannot_self_attest_eligibility() -> None:
    reviewed = _copy(synthetic_eligible_qualification_package())
    _as_reviewed_candidate(reviewed)
    with pytest.raises(ContractError, match="missing keys"):
        build_qualification_record(reviewed)

    historical = _copy(historical_incompatible_qualification_package())
    assert "historical_negative_projection_is_never_eligible" in _list(
        build_qualification_record(historical)["blockers"]
    )
    _dict(_distribution(historical, "mlx")["metadata"])["evidence_scope"] = (
        "complete_wheel_metadata"
    )
    _rehash_package(historical)
    with pytest.raises(ContractError, match="metadata scope differs"):
        verify_qualification_package(historical)


def test_api_tokens_are_pinned_not_caller_selected() -> None:
    package = _copy(synthetic_eligible_qualification_package())
    evidence = _dict(_list(package["worker_api_evidence"])[0])
    evidence_bytes = b"x\n"
    evidence["source_bytes_base64"] = encode_bytes(evidence_bytes)
    evidence["source_sha256"] = digest_bytes(evidence_bytes)
    evidence["symbol_token"] = "x"
    _rehash_package(package)
    with pytest.raises(ContractError, match="pinned probe symbol"):
        verify_qualification_package(package)


def test_source_wheel_metadata_and_identity_hash_drift_are_rejected() -> None:
    source_drift = _copy(synthetic_eligible_qualification_package())
    evidence = _dict(_list(source_drift["worker_api_evidence"])[0])
    evidence["source_bytes_base64"] = encode_bytes(b"changed source evidence\n")
    _rehash_package(source_drift)
    with pytest.raises(ContractError, match="source evidence digest mismatch"):
        verify_qualification_package(source_drift)

    wheel_drift = _copy(synthetic_eligible_qualification_package())
    _dict(_distribution(wheel_drift, "mlx")["wheel"])["filename"] = (
        "mlx-2.0.0-cp312-cp312-macosx_14_0_arm64.whl"
    )
    _rehash_package(wheel_drift)
    with pytest.raises(ContractError, match="filename distribution or version drift"):
        verify_qualification_package(wheel_drift)

    metadata_drift = _copy(synthetic_eligible_qualification_package())
    metadata = _dict(_distribution(metadata_drift, "mlx")["metadata"])
    metadata["bytes_base64"] = encode_bytes(b"changed metadata\n")
    _rehash_package(metadata_drift)
    with pytest.raises(ContractError, match="digest mismatch"):
        verify_qualification_package(metadata_drift)

    coordinated_metadata = _copy(synthetic_eligible_qualification_package())
    distribution = _distribution(coordinated_metadata, "mlx")
    metadata = _dict(distribution["metadata"])
    replacement = (
        b"Metadata-Version: 2.3\nName: mlx\nVersion: 1.0.0\n"
        b"Requires-Python: >=3.11\nRequires-Dist: mlx-metal>=2.0.0\n\n"
    )
    metadata["bytes_base64"] = encode_bytes(replacement)
    metadata["sha256"] = digest_bytes(replacement)
    _rehash_package(coordinated_metadata)
    with pytest.raises(ContractError, match="wheel METADATA bytes differ"):
        verify_qualification_package(coordinated_metadata)

    identity_drift = _copy(synthetic_eligible_qualification_package())
    identity_drift["candidate_name"] = "changed-without-rehash"
    with pytest.raises(ContractError, match="identity mismatch"):
        verify_qualification_package(identity_drift)


def test_coordinated_rehashing_cannot_preserve_a_stale_success_decision() -> None:
    record = _copy(build_qualification_record(synthetic_eligible_qualification_package()))
    embedded = _dict(record["qualification_package"])
    _set_metadata_requirements(embedded, "mlx", ["mlx-metal>=2.0.0"])
    record["qualification_package_id"] = embedded["package_id"]
    _rehash_record(record)
    with pytest.raises(ContractError, match="semantic reconstruction mismatch"):
        verify_qualification_record(record)


@pytest.mark.parametrize(
    ("surface", "replacement", "message"),
    [
        (
            "source",
            "https://evil.example/mlx",
            "allowed credential-free immutable URL",
        ),
        (
            "wheel",
            "https://evil.example/mlx-1.0.0-cp312-cp312-macosx_14_0_arm64.whl",
            "allowed credential-free immutable URL",
        ),
    ],
)
def test_unsupported_source_and_wheel_domains_are_rejected(
    surface: str,
    replacement: str,
    message: str,
) -> None:
    package = _copy(synthetic_eligible_qualification_package())
    mlx = _distribution(package, "mlx")
    if surface == "source":
        _dict(mlx["source"])["repository_url"] = replacement
    else:
        _dict(mlx["wheel"])["url"] = replacement
    _rehash_package(package)
    with pytest.raises(ContractError, match=message):
        verify_qualification_package(package)


def test_fixture_replay_rejects_extra_and_coordinated_rehashing(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    bundle, _replay = compile_qualification_fixture(root)
    _content_root, files = read_closed_bundle(bundle)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    extra_root = tmp_path / "extra"
    extra_root.mkdir()
    content["unexpected.json"] = canonical_json({"unexpected": True})
    extra = publish_bundle(content, extra_root, name_prefix="qualification-extra")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_qualification_fixture(extra)

    coordinated_root = tmp_path / "coordinated"
    coordinated_root.mkdir()
    del content["unexpected.json"]
    package = _dict(load_json_bytes(content["candidates/synthetic-eligible-package.json"]))
    package["candidate_name"] = "coordinated-rehash"
    _rehash_package(package)
    content["candidates/synthetic-eligible-package.json"] = canonical_json(package)
    coordinated = publish_bundle(
        content,
        coordinated_root,
        name_prefix="qualification-coordinated",
    )
    with pytest.raises(ContractError, match="semantic reconstruction mismatch"):
        replay_qualification_fixture(coordinated)
