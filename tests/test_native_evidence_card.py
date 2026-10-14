"""Pinned publication, deterministic formats and inert repo/installed command boundaries."""

from __future__ import annotations

import importlib
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.native_confinement as native
import localinferencelab.native_confinement_after_startup as diagnostic
import localinferencelab.native_evidence_card as publication
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    encode_bytes,
    load_json_bytes,
)
from localinferencelab.native_confinement_contract import MAX_REPORT_BYTES, replay_bytes

ROOT = Path(__file__).parents[1]
PUBLISHED = ROOT / "docs/research/native-evidence"
FILENAMES = (
    "native-evidence-card.json",
    "native-evidence-card.md",
    "native-evidence-card.svg",
    "native-evidence-card-mobile.svg",
    "a-path-is-not-a-pin.md",
)


def _receipts() -> tuple[bytes, bytes]:
    return (
        (ROOT / "docs/evidence" / publication.PRE_EXEC_FILENAME).read_bytes(),
        (ROOT / "docs/evidence" / publication.AFTER_STARTUP_FILENAME).read_bytes(),
    )


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _rehash(value: dict[str, JsonValue]) -> None:
    value["record_id"] = canonical_identity(
        {key: item for key, item in value.items() if key != "record_id"}
    )


def _args(output: Path, *, pre_exec: Path | None = None) -> list[str]:
    return [
        "--pre-exec",
        str(pre_exec or ROOT / "docs/evidence" / publication.PRE_EXEC_FILENAME),
        "--after-startup",
        str(ROOT / "docs/evidence" / publication.AFTER_STARTUP_FILENAME),
        "--output-dir",
        str(output),
    ]


def test_exact_card_shape_counts_native_effects_and_no_personal_metadata() -> None:
    card = publication.build_card(*_receipts())
    assert card.keys() == {
        "record_type",
        "schema_version",
        "source_commit",
        "sources",
        "scope",
        "pre_exec",
        "after_startup",
        "replacement_object_changed",
        "limitations",
        "historical_current_source_disclosure_url",
        "card_id",
    }
    assert _object(card["pre_exec"])["counts"] == {
        "matched": 0,
        "unmet": 0,
        "unknown": 1,
        "untested": 14,
        "unavailable": 0,
    }
    after = _object(card["after_startup"])
    assert after["counts"] == {
        "matched": 12,
        "unmet": 2,
        "unknown": 1,
        "untested": 0,
        "unavailable": 0,
    }
    assert after["aggregate_disposition"] == "refused"
    rows = cast("list[dict[str, JsonValue]]", after["observations"])
    assert len(rows) == 15
    assert rows[7]["assessment"] == rows[-1]["assessment"] == "unmet"
    assert rows[11]["assessment"] == "unknown"
    assert _object(_object(rows[-1]["candidate"])["native_result"])["detail"] == 66
    assert _object(rows[11]["candidate"])["returncode"] == -6
    assert card["replacement_object_changed"] is True
    assert _object(card["scope"]) == {
        "helper": "C/libc with controlled synthetic fixture inputs",
        "host": {"system": "Darwin", "release": "27.0.0", "machine": "arm64"},
        "application_stage": "after_native_startup",
        "startup_confinement_proven": False,
        "runtime_authority": False,
        "physical_launch_approved": False,
        "production_bindings": None,
        "mlx_determinism": "not_measured",
        "model_latency_cost_gpu_performance": "not_measured",
        "offline_replay_authenticates_os_acquisition": False,
    }
    encoded = canonical_json(card)
    for field in (b'"pid"', b'"parent_pid"', b'"started_ns"', b'"inode"', b'"device"'):
        assert field not in encoded
    assert b"/Users/" not in encoded
    assert card["card_id"] == canonical_identity(
        {key: item for key, item in card.items() if key != "card_id"}
    )


@pytest.mark.parametrize("stage", ["pre_exec", "after_startup"])
def test_structurally_valid_caller_rehashed_observations_cannot_publish(stage: str) -> None:
    pre, post = _receipts()
    if stage == "pre_exec":
        report = replay_bytes(pre)
        _object(report["host"])["release"] = "28.0.0"
        _rehash(report)
        mutated = canonical_json(report)
        assert replay_bytes(mutated)["record_id"] != publication.PRE_EXEC_ID
        with pytest.raises(ContractError, match="pre-exec bytes"):
            publication.publication_artifacts(mutated, post)
    else:
        envelope = diagnostic.replay_bytes(post)
        report = _object(envelope["test_record"])
        rows = cast("list[dict[str, JsonValue]]", report["observations"])
        _object(rows[7]["candidate"])["stdout"] = encode_bytes(
            canonical_json({"operation": "socket_loopback", "ok": False, "errno": 1, "detail": 0})
            + b"\n"
        )
        rows[7]["disposition"] = "enforced"
        _rehash(report)
        _rehash(envelope)
        mutated = canonical_json(envelope)
        assert diagnostic.replay_bytes(mutated)["record_id"] != publication.AFTER_STARTUP_ID
        with pytest.raises(ContractError, match="after-startup bytes"):
            publication.publication_artifacts(pre, mutated)


@pytest.mark.parametrize("invalid", [b"", b"{}", b"\xff", b'{"x":1,"x":2}'])
def test_missing_or_invalid_bytes_refuse(invalid: bytes) -> None:
    pre, post = _receipts()
    with pytest.raises(ContractError, match="pre-exec bytes"):
        publication.build_card(invalid, post)
    with pytest.raises(ContractError, match="after-startup bytes"):
        publication.build_card(pre, invalid)


def test_byte_format_is_pinned_not_only_logical_content() -> None:
    pre, post = _receipts()
    with pytest.raises(ContractError, match="pre-exec bytes"):
        publication.build_card(pre + b"\n", post)
    with pytest.raises(ContractError, match="after-startup bytes"):
        publication.build_card(pre, post + b"\n")
    with pytest.raises(ContractError, match="pre-exec bytes"):
        publication.build_card(post, pre)


def test_all_committed_formats_reproduce_exactly_and_posts_fit() -> None:
    receipts = _receipts()
    first = publication.publication_artifacts(*receipts)
    assert tuple(first) == FILENAMES
    assert first == publication.publication_artifacts(*receipts)
    for name, data in first.items():
        assert data == (PUBLISHED / name).read_bytes(), name
        assert b"\r" not in data
        assert data.endswith(b"\n") == (not name.endswith(".json"))
    card_bytes = first[FILENAMES[0]]
    assert canonical_json(load_json_bytes(card_bytes)) == card_bytes
    article = first["a-path-is-not-a-pin.md"].decode()
    prose, posts = article.split("## Ready-to-share X drafts\n", 1)
    assert 600 <= len(prose.split()) <= 900
    assert len(article.split()) <= 900
    drafts = [line.partition(". ")[2] for line in posts.splitlines() if line[:1].isdigit()]
    assert len(drafts) == 5
    assert all(0 < len(post) <= 280 for post in drafts)
    for name in ("native-evidence-card.md", "a-path-is-not-a-pin.md"):
        text = first[name].decode()
        assert "12 matched / 2 unmet / 1 unknown" in text
        assert "Runtime authority" in text
        assert "NOT MEASURED" in text
        assert "runtime gate is ungranted" in text
        assert 'width="1200"' in text and "height=" not in text
        assert publication.SOURCE_COMMIT in text
        assert "SIGABRT; no result" in text
    for name in ("native-evidence-card.svg", "native-evidence-card-mobile.svg"):
        svg = ET.fromstring(first[name])  # noqa: S314
        texts = svg.findall(".//{http://www.w3.org/2000/svg}text")
        assert all(int(item.attrib["font-size"]) >= 16 for item in texts)
        combined = " ".join(item.text or "" for item in texts)
        assert "AFTER-STARTUP NATIVE HELPER" in combined
        assert "NOT AN MLX BENCHMARK" in combined
        assert "NOT GRANTED" in combined
        assert "NOT MEASURED" in combined
        assert "14 later UNTESTED" in combined


def test_command_writes_only_requested_outputs_and_refuses_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "card"
    assert publication.main(_args(output)) == 0
    assert capsys.readouterr().out == "\n".join(FILENAMES) + "\n"
    assert sorted(path.name for path in output.iterdir()) == sorted(FILENAMES)
    before = {name: (output / name).read_bytes() for name in FILENAMES}
    assert publication.main(_args(output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "output already exists" in captured.err
    assert before == {name: (output / name).read_bytes() for name in FILENAMES}


@pytest.mark.parametrize("ancestor", [False, True])
def test_output_directory_and_ancestor_symlinks_refuse_without_redirected_writes(
    *, ancestor: bool, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    sentinel = real / "sentinel"
    sentinel.write_bytes(b"preserve")
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    output = link / "new-subdir" if ancestor else link
    assert publication.main(_args(output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unsafe directory component" in captured.err
    assert "/Users/" not in captured.err
    assert sentinel.read_bytes() == b"preserve"
    assert sorted(item.name for item in real.iterdir()) == ["sentinel"]
    assert link.is_symlink()


def test_dangling_output_filename_symlink_is_not_overwritten_or_deleted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "card"
    output.mkdir()
    sentinel = output / FILENAMES[-1]
    target = tmp_path / "absent"
    sentinel.symlink_to(target)
    assert publication.main(_args(output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "output already exists" in captured.err
    assert sentinel.is_symlink() and not target.exists()
    assert sorted(item.name for item in output.iterdir()) == [FILENAMES[-1]]


@pytest.mark.parametrize("mode", [0o775, 0o777, 0o1777])
def test_writable_output_directory_refuses_and_preserves_sentinel(
    mode: int, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "card"
    output.mkdir()
    sentinel = output / "sentinel"
    sentinel.write_bytes(b"preserve")
    output.chmod(mode)
    assert publication.main(_args(output)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unsafe directory component" in captured.err
    assert sentinel.read_bytes() == b"preserve"
    assert sorted(item.name for item in output.iterdir()) == ["sentinel"]


@pytest.mark.parametrize(("owner", "target"), [(0, "/caller/redirect"), (1, "/private/tmp")])
def test_system_alias_exception_rejects_nonliteral_target_or_nonroot_owner(
    owner: int, target: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    actual_stat = os.stat

    def alias_stat(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if path == "tmp" and dir_fd is not None and not follow_symlinks:
            return os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, owner, 0, 0, 0, 0, 0))
        return actual_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", alias_stat)
    monkeypatch.setattr(os, "readlink", lambda *_args, **_kwargs: target)
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        with pytest.raises(ContractError, match="unsafe system alias"):
            publication._output_parts(Path("/tmp/publication"), descriptor)  # noqa: SLF001, S108
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("timing", ["before_open", "after_open"])
@pytest.mark.parametrize("replacement", ["symlink", "directory"])
def test_output_directory_replacement_refuses_and_preserves_both_sentinels(
    timing: str,
    replacement: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output, moved, redirected = (tmp_path / name for name in ("card", "moved", "redirected"))
    output.mkdir()
    redirected.mkdir()
    (output / "original-sentinel").write_bytes(b"original")
    (redirected / "redirected-sentinel").write_bytes(b"redirected")
    actual_open = os.open
    replaced = False

    def replace() -> None:
        output.rename(moved)
        if replacement == "symlink":
            output.symlink_to(redirected, target_is_directory=True)
        else:
            output.mkdir()
            (output / "replacement-sentinel").write_bytes(b"replacement")

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == "card" and flags & os.O_DIRECTORY and not replaced:
            replaced = True
            if timing == "before_open":
                replace()
            descriptor = actual_open(path, flags, mode, dir_fd=dir_fd)
            if timing == "after_open":
                replace()
            return descriptor
        return actual_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    assert publication.main(_args(output)) == 2
    captured = capsys.readouterr()
    assert replaced and captured.out == "" and "native card" in captured.err
    assert (moved / "original-sentinel").read_bytes() == b"original"
    assert (redirected / "redirected-sentinel").read_bytes() == b"redirected"
    assert sorted(item.name for item in moved.iterdir()) == ["original-sentinel"]
    assert sorted(item.name for item in redirected.iterdir()) == ["redirected-sentinel"]
    if replacement == "directory":
        assert sorted(item.name for item in output.iterdir()) == ["replacement-sentinel"]


def test_ancestor_replacement_during_write_cannot_redirect_bound_file_creation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    parent, moved, redirected = (tmp_path / name for name in ("parent", "moved", "redirected"))
    parent.mkdir()
    redirected.mkdir()
    output = parent / "card"
    output.mkdir()
    (output / "sentinel").write_bytes(b"original")
    (redirected / "sentinel").write_bytes(b"redirected")
    actual_open = os.open
    replaced = False

    def racing_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        if path == FILENAMES[0] and flags & os.O_WRONLY and not replaced:
            replaced = True
            parent.rename(moved)
            parent.symlink_to(redirected, target_is_directory=True)
        return actual_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", racing_open)
    assert publication.main(_args(output)) == 2
    captured = capsys.readouterr()
    assert replaced and captured.out == ""
    assert "directory binding changed" in captured.err
    assert sorted(item.name for item in redirected.iterdir()) == ["sentinel"]
    assert (redirected / "sentinel").read_bytes() == b"redirected"
    bound = moved / "card"
    assert (bound / "sentinel").read_bytes() == b"original"
    assert (bound / FILENAMES[0]).read_bytes() == (PUBLISHED / FILENAMES[0]).read_bytes()
    assert sorted(item.name for item in bound.iterdir()) == [FILENAMES[0], "sentinel"]


@pytest.mark.parametrize("location", ["system_tmp", "relative_repo"])
def test_valid_system_tmp_alias_and_relative_repo_output_reproduce_exact_bytes(
    location: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    with tempfile.TemporaryDirectory(
        prefix="publication-destination-",
        dir="/tmp" if location == "system_tmp" else ROOT,  # noqa: S108
    ) as temporary:
        directory = Path(temporary)
        output = directory / "new" / "card"
        if location == "relative_repo":
            monkeypatch.chdir(ROOT)
            output = output.relative_to(ROOT)
        assert publication.main(_args(output)) == 0
        assert capsys.readouterr().out == "\n".join(FILENAMES) + "\n"
        for name in FILENAMES:
            assert (output / name).read_bytes() == (PUBLISHED / name).read_bytes()
        assert stat.S_IMODE(output.stat().st_mode) == 0o700


@pytest.mark.parametrize("kind", ["missing", "directory", "oversized", "symlink", "mutated"])
def test_input_errors_never_write_success_outputs(
    kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source, output = tmp_path / "input", tmp_path / "output"
    if kind == "directory":
        source.mkdir()
    elif kind == "oversized":
        source.write_bytes(b"x" * (MAX_REPORT_BYTES + 1))
    elif kind == "symlink":
        source.symlink_to(ROOT / "docs/evidence" / publication.PRE_EXEC_FILENAME)
    elif kind == "mutated":
        source.write_bytes(_receipts()[0] + b"\n")
    assert publication.main(_args(output, pre_exec=source)) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "native card" in captured.err
    assert not output.exists()


def test_import_help_and_complete_export_never_observe_or_execute_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        pytest.fail("publication attempted a runtime or host observation")

    actual_read = native._read_regular  # noqa: SLF001
    paths = {
        ROOT / "docs/evidence" / publication.PRE_EXEC_FILENAME,
        ROOT / "docs/evidence" / publication.AFTER_STARTUP_FILENAME,
    }
    observed_reads: list[Path] = []

    def explicit_read(path: Path, maximum: int) -> bytes:
        assert path in paths
        observed_reads.append(path)
        return actual_read(path, maximum)

    with monkeypatch.context() as guarded:
        for module, name in (
            (subprocess, "Popen"),
            (socket, "socket"),
            (socket, "getaddrinfo"),
            (time, "monotonic_ns"),
            (time, "time"),
            (os, "uname"),
            (os, "getpid"),
            (os, "getuid"),
            (os, "urandom"),
            (native, "run_probes"),
            (native, "source_identities"),
            (diagnostic, "run_diagnostic"),
        ):
            guarded.setattr(module, name, forbidden)
        guarded.setattr(native, "_read_regular", explicit_read)
        importlib.reload(publication)
        with pytest.raises(SystemExit) as exited:
            publication.main(["--help"])
        assert exited.value.code == 0
        assert observed_reads == []
        capsys.readouterr()
        assert publication.main(_args(tmp_path / "card")) == 0
        assert set(observed_reads) == paths
        assert len(observed_reads) == 2
        assert not any(
            name in {"mlx", "mlx_lm"} or name.startswith(("mlx.", "mlx_lm."))
            for name in sys.modules
        )
    importlib.reload(publication)
