"""Supplied exact-wheel closure custody tests."""

from __future__ import annotations

import io
import json
import os
import stat
import zipfile
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_wheel_custody as wheel_custody_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_json_bytes,
)
from localinferencelab.cli import run
from localinferencelab.mlx_qualification import (
    build_qualification_record,
    synthetic_eligible_qualification_package,
)
from localinferencelab.mlx_wheel_custody import (
    build_supplied_pack_qualification_record,
    build_wheel_evidence_manifest,
    load_supplied_pack_qualification_record,
    load_wheel_evidence_manifest,
    verify_supplied_pack_qualification_record,
    verify_supplied_wheel_pack,
    verify_wheel_evidence_manifest,
    wheel_evidence_manifest_anchor_spec,
    wheel_evidence_pack_spec,
    write_supplied_pack_qualification_record,
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


def _reviewed_candidate() -> dict[str, JsonValue]:
    package = synthetic_eligible_qualification_package()
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
    content = dict(package)
    content.pop("package_id")
    package["package_id"] = canonical_identity(content)
    return package


def _metadata(
    name: str,
    version: str,
    requirements: list[str],
    *,
    invalid_utf8: bool = False,
) -> bytes:
    data = (
        "\n".join(
            [
                "Metadata-Version: 2.3",
                f"Name: {name}",
                f"Version: {version}",
                "Requires-Python: >=3.12",
                *(f"Requires-Dist: {requirement}" for requirement in requirements),
                "",
                "",
            ]
        )
    ).encode("ascii")
    return data + (b"invalid-\x80" if invalid_utf8 else b"")


def _wheel(
    name: str,
    version: str,
    requirements: list[str],
    *,
    metadata: bytes | None = None,
    unsafe_path: str | None = None,
    extra_entries: list[tuple[str, int]] | None = None,
) -> tuple[str, bytes, bytes, bytes]:
    filename = f"{name.replace('-', '_')}-{version}-py3-none-any.whl"
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    metadata_bytes = metadata or _metadata(name, version, requirements)
    wheel_bytes = (
        "Wheel-Version: 1.0\n"
        "Generator: LocalInferenceLab custody fixture\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n\n"
    ).encode("ascii")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, data in (
            (f"{dist_info}/METADATA", metadata_bytes),
            (f"{dist_info}/WHEEL", wheel_bytes),
        ):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
        if unsafe_path is not None:
            entry = zipfile.ZipInfo(unsafe_path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, b"unsafe")
        for path, mode in extra_entries or []:
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = mode << 16
            archive.writestr(
                entry,
                b"" if stat.S_IFMT(mode) == stat.S_IFDIR else b"extra",
            )
    return filename, output.getvalue(), metadata_bytes, wheel_bytes


def _distribution(
    name: str,
    version: str,
    requirements: list[str],
    *,
    role: str,
    wheel_bytes: bytes | None = None,
    manifest_metadata: bytes | None = None,
    unsafe_path: str | None = None,
    extra_entries: list[tuple[str, int]] | None = None,
) -> tuple[dict[str, JsonValue], bytes]:
    filename, generated, embedded_metadata, wheel_metadata = _wheel(
        name,
        version,
        requirements,
        unsafe_path=unsafe_path,
        extra_entries=extra_entries,
    )
    supplied = generated if wheel_bytes is None else wheel_bytes
    metadata = embedded_metadata if manifest_metadata is None else manifest_metadata
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    distribution: dict[str, JsonValue] = {
        "name": name,
        "version": version,
        "role": role,
        "selected_by": ["pending"],
        "pypi_release_json_url": f"https://pypi.org/pypi/{name}/{version}/json",
        "artifact": {
            "filename": filename,
            "size_bytes": len(supplied),
            "sha256": digest_bytes(supplied),
            "url": f"https://files.pythonhosted.org/packages/fixture/{filename}",
            "python_tag": "py3",
            "abi_tag": "none",
            "platform_tag": "any",
        },
        "dist_info": {
            "directory": dist_info,
            "metadata_path": f"{dist_info}/METADATA",
            "wheel_path": f"{dist_info}/WHEEL",
        },
        "metadata": {
            "bytes_base64": encode_bytes(metadata),
            "size_bytes": len(metadata),
            "sha256": digest_bytes(metadata),
        },
        "wheel_metadata": {
            "bytes_base64": encode_bytes(wheel_metadata),
            "size_bytes": len(wheel_metadata),
            "sha256": digest_bytes(wheel_metadata),
            "tags": ["py3-none-any"],
        },
        "source": {
            "availability": "repository_only",
            "repository_url": f"https://github.com/example/{name}",
            "revision": None,
            "tag": None,
        },
    }
    return distribution, supplied


def _manifest(
    *,
    include_beta: bool = True,
    beta_requirements: list[str] | None = None,
    alpha_requirement: str = (
        'beta>=1.0; platform_system == "Darwin" and platform_machine == "arm64"'
    ),
    alpha_unsafe_path: str | None = None,
    alpha_manifest_metadata: bytes | None = None,
    alpha_extra_entries: list[tuple[str, int]] | None = None,
) -> tuple[dict[str, JsonValue], dict[str, bytes]]:
    alpha, alpha_bytes = _distribution(
        "alpha",
        "1.0.0",
        [alpha_requirement],
        role="root",
        manifest_metadata=alpha_manifest_metadata,
        unsafe_path=alpha_unsafe_path,
        extra_entries=alpha_extra_entries,
    )
    distributions = [alpha]
    wheels = {cast("str", _dict(alpha["artifact"])["filename"]): alpha_bytes}
    if include_beta:
        beta, beta_bytes = _distribution(
            "beta",
            "1.1.0",
            beta_requirements or [],
            role="transitive",
        )
        distributions.append(beta)
        wheels[cast("str", _dict(beta["artifact"])["filename"])] = beta_bytes
    manifest = build_wheel_evidence_manifest(
        candidate_anchor={
            "candidate_name": "synthetic-wheel-custody",
            "package_id": "sha256:" + ("1" * 64),
            "qualification_spec_id": "sha256:" + ("2" * 64),
            "review_anchor_id": "sha256:" + ("3" * 64),
        },
        target_environment={
            "implementation_name": "cpython",
            "macos_version": "15.0",
            "os_name": "posix",
            "platform_machine": "arm64",
            "platform_python_implementation": "CPython",
            "platform_system": "Darwin",
            "python_abi": "cp313",
            "python_full_version": "3.13.0",
            "python_version": "3.13",
            "sys_platform": "darwin",
        },
        roots=["alpha==1.0.0"],
        distributions=distributions,
        acquired_at_utc="2026-10-07T00:00:00Z",
    )
    return manifest, wheels


def _candidate_manifest(
    candidate: dict[str, JsonValue],
    review_anchor_id: str,
) -> tuple[dict[str, JsonValue], dict[str, bytes]]:
    distributions: list[dict[str, JsonValue]] = []
    wheels: dict[str, bytes] = {}
    for item in _list(candidate["distributions"]):
        candidate_distribution = _dict(item)
        name = cast("str", candidate_distribution["name"])
        version = cast("str", candidate_distribution["version"])
        wheel = _dict(candidate_distribution["wheel"])
        wheel_bytes = decode_bytes(cast("str", wheel["bytes_base64"]))
        filename = cast("str", wheel["filename"])
        metadata = _dict(candidate_distribution["metadata"])
        metadata_bytes = decode_bytes(cast("str", metadata["bytes_base64"]))
        dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            wheel_metadata = archive.read(f"{dist_info}/WHEEL")
        source = _dict(candidate_distribution["source"])
        distributions.append(
            {
                "name": name,
                "version": version,
                "role": "root" if name in {"mlx", "mlx-lm"} else "transitive",
                "selected_by": ["pending"],
                "pypi_release_json_url": f"https://pypi.org/pypi/{name}/{version}/json",
                "artifact": {
                    "filename": filename,
                    "size_bytes": len(wheel_bytes),
                    "sha256": digest_bytes(wheel_bytes),
                    "url": wheel["url"],
                    "python_tag": wheel["python_tag"],
                    "abi_tag": wheel["abi_tag"],
                    "platform_tag": wheel["platform_tag"],
                },
                "dist_info": {
                    "directory": dist_info,
                    "metadata_path": f"{dist_info}/METADATA",
                    "wheel_path": f"{dist_info}/WHEEL",
                },
                "metadata": {
                    "bytes_base64": encode_bytes(metadata_bytes),
                    "size_bytes": len(metadata_bytes),
                    "sha256": digest_bytes(metadata_bytes),
                },
                "wheel_metadata": {
                    "bytes_base64": encode_bytes(wheel_metadata),
                    "size_bytes": len(wheel_metadata),
                    "sha256": digest_bytes(wheel_metadata),
                    "tags": [f"{wheel['python_tag']}-{wheel['abi_tag']}-{wheel['platform_tag']}"],
                },
                "source": {
                    "availability": "bound_revision_and_tag",
                    "repository_url": source["repository_url"],
                    "revision": source["revision"],
                    "tag": source["tag"],
                },
            }
        )
        wheels[filename] = wheel_bytes
    manifest = build_wheel_evidence_manifest(
        candidate_anchor={
            "candidate_name": candidate["candidate_name"],
            "package_id": candidate["package_id"],
            "qualification_spec_id": candidate["qualification_spec_id"],
            "review_anchor_id": review_anchor_id,
        },
        target_environment={
            **_dict(candidate["target_environment"]),
            "platform_python_implementation": "CPython",
        },
        roots=sorted(cast("list[str]", candidate["top_level_requirements"])),
        distributions=distributions,
        acquired_at_utc="2026-10-07T00:00:00Z",
    )
    return manifest, wheels


def _write_pack(root: Path, wheels: dict[str, bytes]) -> None:
    root.mkdir()
    for filename, data in wheels.items():
        (root / filename).write_bytes(data)


def _rehash_manifest(manifest: dict[str, JsonValue]) -> str:
    content = dict(manifest)
    content.pop("manifest_id", None)
    identity = canonical_identity(content)
    manifest["manifest_id"] = identity
    return identity


def _replace_wheel_metadata(
    manifest: dict[str, JsonValue],
    data: bytes,
) -> str:
    distribution = _dict(_list(manifest["distributions"])[0])
    binding = _dict(distribution["wheel_metadata"])
    binding["bytes_base64"] = encode_bytes(data)
    binding["size_bytes"] = len(data)
    binding["sha256"] = digest_bytes(data)
    return _rehash_manifest(manifest)


def test_pack_spec_and_synthetic_pack_are_deterministic_and_exact(tmp_path: Path) -> None:
    spec = wheel_evidence_pack_spec()
    assert _dict(spec["bounds"])["maximum_manifest_bytes"] == 2 * 1024 * 1024
    anchor_spec = wheel_evidence_manifest_anchor_spec()
    assert anchor_spec["reviewed_manifest_ids"] == []
    manifest, wheels = _manifest()
    second_manifest, second_wheels = _manifest()
    assert canonical_json(manifest) == canonical_json(second_manifest)
    assert wheels == second_wheels
    selection = _dict(manifest["selection_policy"])
    assert selection["offline_verifier_attests_index_completeness"] is False
    assert selection["release_rule"] == (
        "externally_acquired_exact_manifest_version_no_index_optimality_claim"
    )
    assert selection["wheel_rule"] == (
        "externally_acquired_exact_manifest_artifact_target_compatibility_verified_only"
    )
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    result = verify_supplied_wheel_pack(
        manifest,
        pack,
        cast("str", manifest["manifest_id"]),
    )
    receipt = result.receipt()
    assert receipt["artifact_count"] == 2
    assert receipt["total_size_bytes"] == sum(map(len, wheels.values()))
    assert receipt["supplied_pack_verified"] is True
    assert receipt["committed_manifest_alone_proves_supplied_bytes_present"] is False
    assert receipt["package_installations"] == 0
    assert receipt["runtime_imports"] == 0


def test_cli_emits_spec_and_verifies_supplied_pack(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    manifest, wheels = _manifest()
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(canonical_json(manifest))
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    assert run(["mlx", "runtime-wheel-pack-spec"]) == 0
    emitted_spec = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8")))
    assert emitted_spec == wheel_evidence_pack_spec()
    assert (
        run(
            [
                "mlx",
                "runtime-wheel-pack-verify",
                str(manifest_path),
                str(pack),
                "--expected-manifest-id",
                cast("str", manifest["manifest_id"]),
            ]
        )
        == 0
    )
    verified = _dict(load_json_bytes(capfd.readouterr().out.encode("utf-8").strip()))
    assert verified["status"] == "verified"
    assert verified["artifact_count"] == 2
    assert verified["package_installations"] == 0
    assert verified["runtime_imports"] == 0


def test_manifest_loader_is_bounded_and_detects_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"x" * ((2 * 1024 * 1024) + 1))
    with pytest.raises(ContractError, match="unsafe file metadata or size"):
        load_wheel_evidence_manifest(oversized, "sha256:" + ("0" * 64))

    manifest, _wheels = _manifest()
    data = canonical_json(manifest)
    path = tmp_path / "manifest.json"
    path.write_bytes(data)
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(data)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        block = original_read(descriptor, size)
        if not block and not replaced:
            replacement.replace(path)
            replaced = True
        return block

    monkeypatch.setattr(os, "read", replace_after_read)
    with pytest.raises(ContractError, match=r"path changed|changed during"):
        load_wheel_evidence_manifest(
            path,
            cast("str", manifest["manifest_id"]),
        )
    assert replaced is True


def test_pack_rejects_tampered_bytes_and_coordinated_manifest_rehashing(
    tmp_path: Path,
) -> None:
    manifest, wheels = _manifest()
    expected = cast("str", manifest["manifest_id"])
    filename = sorted(wheels)[0]
    wheels[filename] += b"tampered"
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    with pytest.raises(ContractError, match=r"size|digest"):
        verify_supplied_wheel_pack(manifest, pack, expected)

    artifact = _dict(_dict(_list(manifest["distributions"])[0])["artifact"])
    artifact["size_bytes"] = len(wheels[filename])
    artifact["sha256"] = digest_bytes(wheels[filename])
    forged = _rehash_manifest(manifest)
    assert forged != expected
    with pytest.raises(ContractError, match="expected content address"):
        verify_supplied_wheel_pack(manifest, pack, expected)


def test_pack_hash_and_zip_inspection_use_one_immutable_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    replacement_metadata = _metadata(
        "alpha",
        "1.0.0",
        ['beta>=2.0; platform_system == "Darwin" and platform_machine == "arm64"'],
    )
    manifest, wheels = _manifest(alpha_manifest_metadata=replacement_metadata)
    replacement_filename, replacement, _metadata_bytes, _wheel_bytes = _wheel(
        "alpha",
        "1.0.0",
        [],
        metadata=replacement_metadata,
    )
    assert len(replacement) == len(wheels[replacement_filename])
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    original_read = os.read
    replaced = False

    def replace_after_hash(descriptor: int, size: int) -> bytes:
        nonlocal replaced
        block = original_read(descriptor, size)
        if not block and not replaced:
            (pack / replacement_filename).write_bytes(replacement)
            replaced = True
        return block

    monkeypatch.setattr(os, "read", replace_after_hash)
    with pytest.raises(ContractError, match="embedded METADATA differs"):
        verify_supplied_wheel_pack(
            manifest,
            pack,
            cast("str", manifest["manifest_id"]),
        )
    assert replaced is True


def test_manifest_rejects_url_hash_size_drift_and_booleans_as_integers(
    tmp_path: Path,
) -> None:
    manifest, wheels = _manifest()

    url_drift = _copy(manifest)
    artifact = _dict(_dict(_list(url_drift["distributions"])[0])["artifact"])
    artifact["url"] = f"https://evil.example/{artifact['filename']}"
    identity = _rehash_manifest(url_drift)
    with pytest.raises(ContractError, match="allowed credential-free HTTPS URL"):
        verify_wheel_evidence_manifest(url_drift, identity)

    hash_drift = _copy(manifest)
    _dict(_dict(_list(hash_drift["distributions"])[0])["artifact"])["sha256"] = "sha256:" + (
        "0" * 64
    )
    identity = _rehash_manifest(hash_drift)
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    with pytest.raises(ContractError, match="digest mismatch"):
        verify_supplied_wheel_pack(hash_drift, pack, identity)

    size_drift = _copy(manifest)
    artifact = _dict(_dict(_list(size_drift["distributions"])[0])["artifact"])
    artifact["size_bytes"] = cast("int", artifact["size_bytes"]) + 1
    identity = _rehash_manifest(size_drift)
    with pytest.raises(
        ContractError,
        match=r"semantic reconstruction mismatch|declared size|size or digest",
    ):
        verify_supplied_wheel_pack(size_drift, pack, identity)

    boolean_size = _copy(manifest)
    _dict(_dict(_list(boolean_size["distributions"])[0])["artifact"])["size_bytes"] = True
    identity = _rehash_manifest(boolean_size)
    with pytest.raises(ContractError, match="must be an integer"):
        verify_wheel_evidence_manifest(boolean_size, identity)

    boolean_claim = _copy(manifest)
    _dict(boolean_claim["claims"])["committed_manifest_alone_proves_supplied_bytes_present"] = 0
    identity = _rehash_manifest(boolean_claim)
    with pytest.raises(ContractError, match="claims drift"):
        verify_wheel_evidence_manifest(boolean_claim, identity)


@pytest.mark.parametrize(
    ("wheel_metadata", "error"),
    [
        (b"Root-Is-Purelib: true\nTag: py3-none-any\n\n", "Wheel-Version"),
        (
            b"Wheel-Version: 1.0\nWheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
            "Wheel-Version",
        ),
        (b"Wheel-Version: 1.0\nTag: py3-none-any\n\n", "Root-Is-Purelib"),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\n"
            b"Root-Is-Purelib: false\nTag: py3-none-any\n\n",
            "Root-Is-Purelib",
        ),
        (
            b"Wheel-Version: 2.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
            "unsupported Wheel-Version",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: yes\nTag: py3-none-any\n\n",
            "invalid Root-Is-Purelib",
        ),
        (
            b"Wheel-Version: 1.0\n continued\nRoot-Is-Purelib: true\nTag: py3-none-any\n\n",
            "folded headers",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n\nbody",
            "must not contain a body",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: malformed\n\n",
            "malformed Tag",
        ),
        (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\nTag: py3-none-any\n\n",
            "duplicate Tag",
        ),
    ],
)
def test_manifest_rejects_malformed_wheel_metadata(
    wheel_metadata: bytes,
    error: str,
) -> None:
    manifest, _wheels = _manifest()
    identity = _replace_wheel_metadata(manifest, wheel_metadata)
    with pytest.raises(ContractError, match=error):
        verify_wheel_evidence_manifest(manifest, identity)


def test_pack_rejects_raw_metadata_mismatch_and_malformed_utf8(tmp_path: Path) -> None:
    different = _metadata(
        "alpha",
        "1.0.0",
        ['beta>=1.0; platform_system == "Darwin" and platform_machine == "arm64"'],
    ).replace(b"Requires-Python:", b"Summary: manifest drift\nRequires-Python:")
    manifest, wheels = _manifest(alpha_manifest_metadata=different)
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    with pytest.raises(ContractError, match="embedded METADATA differs"):
        verify_supplied_wheel_pack(
            manifest,
            pack,
            cast("str", manifest["manifest_id"]),
        )

    alpha, _wheel_bytes = _distribution(
        "alpha",
        "1.0.0",
        [],
        role="root",
        manifest_metadata=_metadata("alpha", "1.0.0", [], invalid_utf8=True),
    )
    with pytest.raises(ContractError, match="valid UTF-8 Core Metadata"):
        build_wheel_evidence_manifest(
            candidate_anchor={
                "candidate_name": "invalid-utf8",
                "package_id": "sha256:" + ("1" * 64),
                "qualification_spec_id": "sha256:" + ("2" * 64),
                "review_anchor_id": "sha256:" + ("3" * 64),
            },
            target_environment=_dict(_manifest()[0]["target_environment"]),
            roots=["alpha==1.0.0"],
            distributions=[alpha],
            acquired_at_utc="2026-10-07T00:00:00Z",
        )


def test_marker_dependent_omission_and_recursive_gap_are_exact_blockers() -> None:
    marker_gap, _wheels = _manifest(include_beta=False)
    closure = _dict(marker_gap["closure"])
    assert closure["complete"] is False
    assert closure["blockers"] == [
        'dependency_missing:alpha:beta>=1.0; platform_system == "Darwin" '
        'and platform_machine == "arm64"'
    ]

    recursive_gap, _wheels = _manifest(beta_requirements=["gamma>=2.0"])
    closure = _dict(recursive_gap["closure"])
    assert closure["complete"] is False
    assert closure["blockers"] == ["dependency_missing:beta:gamma>=2.0"]

    inapplicable, _wheels = _manifest(
        include_beta=False,
        alpha_requirement='beta>=1.0; platform_system == "Linux"',
    )
    closure = _dict(inapplicable["closure"])
    assert closure["complete"] is True
    assert closure["blockers"] == []


def test_manifest_rejects_duplicate_distribution_and_canonical_name_collision() -> None:
    manifest, _wheels = _manifest()
    duplicate = _copy(manifest)
    distributions = _list(duplicate["distributions"])
    distributions.append(_copy(distributions[0]))
    identity = _rehash_manifest(duplicate)
    with pytest.raises(ContractError, match="canonical-name collision"):
        verify_wheel_evidence_manifest(duplicate, identity)

    noncanonical = _copy(manifest)
    _dict(_list(noncanonical["distributions"])[0])["name"] = "Alpha"
    identity = _rehash_manifest(noncanonical)
    with pytest.raises(ContractError, match="must already be normalized"):
        verify_wheel_evidence_manifest(noncanonical, identity)


def test_pack_rejects_unexpected_members_symlinks_and_hardlinks(tmp_path: Path) -> None:
    manifest, wheels = _manifest()
    expected = cast("str", manifest["manifest_id"])

    extra_pack = tmp_path / "extra"
    _write_pack(extra_pack, wheels)
    (extra_pack / "unexpected.whl").write_bytes(b"extra")
    with pytest.raises(ContractError, match="unexpected"):
        verify_supplied_wheel_pack(manifest, extra_pack, expected)

    filename = sorted(wheels)[0]
    symlink_pack = tmp_path / "symlink"
    _write_pack(symlink_pack, wheels)
    (symlink_pack / filename).unlink()
    (symlink_pack / filename).symlink_to(sorted(wheels)[1])
    with pytest.raises(ContractError, match="regular file"):
        verify_supplied_wheel_pack(manifest, symlink_pack, expected)

    hardlink_pack = tmp_path / "hardlink"
    _write_pack(hardlink_pack, wheels)
    external = tmp_path / "external.whl"
    os.link(hardlink_pack / filename, external)
    with pytest.raises(ContractError, match="exactly one hard link"):
        verify_supplied_wheel_pack(manifest, hardlink_pack, expected)


def test_pack_rejects_zip_path_traversal(tmp_path: Path) -> None:
    manifest, wheels = _manifest(alpha_unsafe_path="../outside")
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    with pytest.raises(ContractError, match="unsafe or ambiguous path"):
        verify_supplied_wheel_pack(
            manifest,
            pack,
            cast("str", manifest["manifest_id"]),
        )


@pytest.mark.parametrize(
    "entries",
    [
        [("payload", stat.S_IFREG | 0o644), ("payload/", stat.S_IFDIR | 0o755)],
        [("payload//", stat.S_IFDIR | 0o755)],
        [("payload/./child", stat.S_IFREG | 0o644)],
        [("payload", stat.S_IFDIR | 0o755)],
        [("payload/", stat.S_IFREG | 0o644)],
    ],
)
def test_pack_rejects_canonical_zip_path_and_type_ambiguity(
    tmp_path: Path,
    entries: list[tuple[str, int]],
) -> None:
    manifest, wheels = _manifest(alpha_extra_entries=entries)
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    with pytest.raises(
        ContractError,
        match=r"unsafe or ambiguous path|colliding canonical ZIP paths|link or special",
    ):
        verify_supplied_wheel_pack(
            manifest,
            pack,
            cast("str", manifest["manifest_id"]),
        )


def test_supplied_pack_qualification_requires_reconstruction(
    tmp_path: Path,
) -> None:
    candidate = _reviewed_candidate()
    candidate_record = build_qualification_record(candidate)
    assessment = _dict(candidate_record["assessment"])
    manifest, wheels = _candidate_manifest(
        candidate,
        cast("str", assessment["review_anchor_id"]),
    )
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    manifest_id = cast("str", manifest["manifest_id"])

    record = build_supplied_pack_qualification_record(
        candidate,
        manifest,
        pack,
        manifest_id,
    )
    assert record["decision"] == "ineligible"
    anchor_blocker = f"wheel_evidence_manifest_anchor_not_independently_reviewed:{manifest_id}"
    assert _list(record["blockers"]) == sorted(
        [*_list(candidate_record["blockers"]), anchor_blocker]
    )
    assert (
        record["wheel_evidence_manifest_anchor_spec_id"]
        == (wheel_evidence_manifest_anchor_spec()["spec_id"])
    )
    verify_supplied_pack_qualification_record(
        record,
        candidate,
        manifest,
        pack,
        manifest_id,
    )

    record_path = tmp_path / "qualification.json"
    write_supplied_pack_qualification_record(
        record_path,
        record,
        candidate,
        manifest,
        pack,
        manifest_id,
    )
    loaded = load_supplied_pack_qualification_record(
        record_path,
        candidate,
        manifest,
        pack,
        manifest_id,
    )
    assert loaded["record_id"] == record["record_id"]

    (pack / sorted(wheels)[0]).unlink()
    with pytest.raises(ContractError, match="member set mismatch"):
        verify_supplied_pack_qualification_record(
            record,
            candidate,
            manifest,
            pack,
            manifest_id,
        )


def test_unreviewed_manifest_anchor_blocks_coordinated_rehash(
    tmp_path: Path,
) -> None:
    manifest, wheels = _manifest()
    pack = tmp_path / "pack"
    _write_pack(pack, wheels)
    forged = _copy(manifest)
    _dict(forged["candidate_anchor"])["package_id"] = "sha256:" + ("4" * 64)
    forged_id = _rehash_manifest(forged)

    verify_supplied_wheel_pack(forged, pack, forged_id)
    blockers = wheel_custody_module._pack_record_blockers(  # noqa: SLF001
        {"blockers": []},
        forged,
    )
    assert blockers == [f"wheel_evidence_manifest_anchor_not_independently_reviewed:{forged_id}"]
