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


def _set_metadata_requirements(
    package: dict[str, JsonValue],
    distribution_name: str,
    requirements: list[str],
) -> None:
    distribution = _distribution(package, distribution_name)
    name = cast("str", distribution["name"])
    version = cast("str", distribution["version"])
    data = (
        "\n".join(
            [
                "Metadata-Version: 2.3",
                f"Name: {name}",
                f"Version: {version}",
                *(f"Requires-Dist: {requirement}" for requirement in requirements),
            ]
        )
        + "\n\n"
    ).encode("ascii")
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
    )
    wheel["bytes_base64"] = encode_bytes(wheel_bytes)
    wheel["size_bytes"] = len(wheel_bytes)
    wheel["sha256"] = digest_bytes(wheel_bytes)
    _rehash_package(package)


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
    name = cast("str", distribution["name"])
    version = cast("str", distribution["version"])
    filename = f"{name.replace('-', '_')}-{version}-{python_tag}-{abi_tag}-{platform_tag}.whl"
    wheel_bytes = qualification_module._synthetic_wheel_bytes(  # noqa: SLF001
        name=name,
        version=version,
        tag=f"{python_tag}-{abi_tag}-{platform_tag}",
        requirements=requirements,
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
    with pytest.raises(ContractError, match="unique and sorted"):
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
    reviewed["candidate_kind"] = "reviewed_candidate"
    for item in _list(reviewed["distributions"]):
        distribution = _dict(item)
        name = cast("str", distribution["name"])
        source = _dict(distribution["source"])
        source["provenance"] = "reviewed_git_revision_and_tag"
        source["repository_url"] = f"https://github.com/example/{name}"
        wheel = _dict(distribution["wheel"])
        wheel["provenance"] = "reviewed_pypi_artifact"
        wheel["url"] = f"https://files.pythonhosted.org/packages/reviewed/{wheel['filename']}"
        _dict(distribution["metadata"])["evidence_scope"] = "complete_wheel_metadata"
    _rehash_package(reviewed)
    reviewed_record = build_qualification_record(reviewed)
    assert reviewed_record["decision"] == INELIGIBLE
    assert any(
        cast("str", blocker).startswith("reviewed_candidate_not_committed_in_spec:")
        for blocker in _list(reviewed_record["blockers"])
    )

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
        b"Metadata-Version: 2.3\nName: mlx\nVersion: 1.0.0\nRequires-Dist: mlx-metal>=2.0.0\n\n"
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
