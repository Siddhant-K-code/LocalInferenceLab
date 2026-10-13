"""Offline mutations and bounded collection; native probing requires a separate opt-in."""

# ruff: noqa: SLF001
from __future__ import annotations

import importlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, Self, cast

import pytest

import localinferencelab.native_confinement as harness
import localinferencelab.native_confinement_after_startup as diagnostic
import localinferencelab.native_confinement_contract as contract
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
)
from localinferencelab.native_confinement_contract import Capture


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _identities() -> dict[str, JsonValue]:
    identities: dict[str, JsonValue] = {
        name: digest_bytes(name.encode()) for name in contract.IDENTITY_FIELDS
    }
    identities["profile_template_id"] = canonical_identity(contract.PROFILE_TEMPLATE)
    return identities


def _native(operation: str, *, ok: bool = True, error: int = 0) -> Capture:
    detail = (66 if operation == "read_replacement" else 65) if operation.startswith("read_") else 0
    return Capture(
        "may_have_run",
        "complete",
        100,
        0,
        canonical_json(
            {"operation": operation, "ok": ok, "errno": error, "detail": detail if ok else 0}
        ),
        pid=124,
    )


def _report() -> dict[str, JsonValue]:
    pin: dict[str, JsonValue] = {"device": 1, "inode": 2, "mode": 0o700}
    return contract.build_report(
        identities=_identities(),
        host={
            "system": "Darwin",
            "release": "26.0.0",
            "machine": "arm64",
            "parent_pid": 123,
            "started_ns": 1000,
            "finished_ns": 100_000,
        },
        fixture={
            "root": pin,
            "read_initial": {**pin, "inode": 3},
            "read_replacement": {**pin, "inode": 4},
        },
        compilation=Capture("may_have_run", "complete", 100, 0, pid=122),
        observations=tuple(
            (
                _native(operation),
                _native(
                    operation, ok=expectation == "allow", error=0 if expectation == "allow" else 1
                ),
            )
            for operation, expectation in contract.PROBES
        ),
    )


def _rehash(report: dict[str, JsonValue]) -> None:
    report["record_id"] = canonical_identity(
        {key: value for key, value in report.items() if key != "record_id"}
    )


def test_canonical_roundtrip_is_non_authority_even_with_all_matching_results() -> None:
    report = _report()
    assert contract.replay_bytes(canonical_json(report)) == report
    assert report["disposition"] == "enforced"
    assert report["runtime_authority"] is False
    assert report["physical_launch_approved"] is False
    assert report["production_bindings"] is None
    assert "real_mlx_metal_compatibility_untested" in cast("list[str]", report["untested"])


def test_committed_native_failure_replays_inertly() -> None:
    path = (
        Path(__file__).parents[1] / "docs/evidence/native-confinement-darwin-27.0.0-arm64-v1.json"
    )
    report = contract.replay_bytes(path.read_bytes())
    assert report["record_id"] == (
        "sha256:94c12b835ac785f86a3b166837b67a5f7cf5a8457ce4ad4aa34f62afc7f873da"
    )
    assert (
        report["reason"] == "candidate_startup_unavailable" and report["disposition"] == "unknown"
    )
    rows = cast("list[dict[str, JsonValue]]", report["observations"])
    assert _object(rows[0]["candidate"])["returncode"] == -6
    assert {row["disposition"] for row in rows[1:]} == {"untested"}
    assert _object(report["identities"])["implementation_id"] == (
        "sha256:e53764779e3a61e239b1b4bbfd090ec89833ab0e062da3b5663640e146554b6b"
    )
    assert (
        _object(report["identities"])["probe_source_id"]
        == harness.source_identities()["probe_source_id"]
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", "2.0"),
        ("runtime_authority", 0),
        ("physical_launch_approved", True),
        ("production_bindings", {}),
        ("untested", []),
        ("reason", "success"),
        ("specification_id", "sha256:" + "0" * 64),
        ("disposition", "accepted"),
    ],
)
def test_rehashed_top_level_mutations_refuse(field: str, value: JsonValue) -> None:
    report = _report()
    report[field] = value
    _rehash(report)
    with pytest.raises(ContractError):
        contract.verify_report(report)


@pytest.mark.parametrize("value", [True, False, -1, 2**63])
def test_integer_aliases_and_out_of_range_host_values_refuse(value: object) -> None:
    report = _report()
    _object(report["host"])["parent_pid"] = cast("JsonValue", value)
    _rehash(report)
    with pytest.raises(ContractError, match=r"^native evidence integer$"):
        contract.verify_report(report)


def test_float_host_pid_refuses_canonical_rehash() -> None:
    report = _report()
    _object(report["host"])["parent_pid"] = cast("JsonValue", 1.0)
    with pytest.raises(ContractError, match="floating-point values are forbidden"):
        _rehash(report)


@pytest.mark.parametrize("span", [0, 100, 3099])
def test_rehashed_serial_capture_sum_must_fit_host_span(span: int) -> None:
    report = _report()
    host = _object(report["host"])
    host["finished_ns"] = cast("int", host["started_ns"]) + span
    _rehash(report)
    with pytest.raises(ContractError, match=r"^native serial capture durations exceed host span$"):
        contract.verify_report(report)


def test_exact_serial_duration_sum_and_reused_child_pid_remain_valid() -> None:
    report = _report()
    host = _object(report["host"])
    host["finished_ns"] = cast("int", host["started_ns"]) + 3100
    rows = cast("list[dict[str, JsonValue]]", report["observations"])
    for row in rows:
        for direction in ("baseline", "candidate"):
            _object(row[direction])["pid"] = 124
    _object(report["compilation"])["pid"] = 124
    _rehash(report)
    assert contract.verify_report(report)["disposition"] == "enforced"


@pytest.mark.parametrize("direction", ["compilation", "baseline", "candidate"])
def test_rehashed_spawned_pid_cannot_equal_live_parent(direction: str) -> None:
    report = _report()
    capture = (
        _object(report["compilation"])
        if direction == "compilation"
        else _object(cast("list[dict[str, JsonValue]]", report["observations"])[0][direction])
    )
    capture["pid"] = _object(report["host"])["parent_pid"]
    _rehash(report)
    with pytest.raises(ContractError, match=r"^native child pid equals parent pid$"):
        contract.verify_report(report)


@pytest.mark.parametrize("terminal", ["deadline", "output_limit"])
@pytest.mark.parametrize("code", [None, 0, -9])
def test_rehashed_unknown_terminal_requires_reaped_wait_code(
    terminal: str,
    code: int | None,
) -> None:
    report = _report()
    row = cast("list[dict[str, JsonValue]]", report["observations"])[0]
    candidate = _object(row["candidate"])
    candidate["terminal"], candidate["returncode"] = terminal, code
    row["disposition"] = report["disposition"] = "unknown"
    _rehash(report)
    if code is None:
        with pytest.raises(ContractError, match=r"^native reaped child wait code missing$"):
            contract.verify_report(report)
    else:
        assert contract.verify_report(report)["disposition"] == "unknown"


def test_exposed_compilation_requires_host_even_without_probe_launch() -> None:
    report = contract.build_report(
        identities=harness.source_identities(), reason="unsupported_host"
    )
    report["compilation"] = Capture("may_have_run", "exit_error", 100, 1, pid=124).to_dict()
    report["reason"] = "compilation_failed"
    _rehash(report)
    with pytest.raises(ContractError, match=r"^native captures lack host lifetime$"):
        contract.verify_report(report)


def test_integer_subclass_is_not_a_scalar_integer() -> None:
    class IntegerAlias(int):
        pass

    report = _report()
    _object(_object(report["fixture"])["root"])["inode"] = IntegerAlias(2)
    with pytest.raises(ContractError, match="integer"):
        contract.verify_report(report)


def test_duplicate_noncanonical_nested_oversized_and_extra_json_refuse() -> None:
    raw = canonical_json(_report())
    duplicate = raw.replace(
        b'"schema_version":"1.0"', b'"schema_version":"1.0","schema_version":"1.0"'
    )
    for data in (duplicate, raw + b"\n", b"[" * 1500, b" " * (contract.MAX_REPORT_BYTES + 1)):
        with pytest.raises(ContractError):
            contract.replay_bytes(data)
    report = _report()
    report["extra"] = "field"
    _rehash(report)
    with pytest.raises(ContractError, match="fields"):
        contract.verify_report(report)


def test_identity_operation_order_and_capture_projection_mutations_refuse() -> None:
    report = _report()
    rows = cast("list[dict[str, JsonValue]]", report["observations"])
    rows[0], rows[1] = rows[1], rows[0]
    _rehash(report)
    with pytest.raises(ContractError, match="order"):
        contract.verify_report(report)
    report = _report()
    rows = cast("list[dict[str, JsonValue]]", report["observations"])
    _object(rows[0]["candidate"])["elapsed_ns"] = contract.COMMAND_TIMEOUT_NS + 1
    _rehash(report)
    with pytest.raises(ContractError, match="deadline"):
        contract.verify_report(report)
    _object(rows[0]["candidate"])["terminal"] = "deadline"
    rows[0]["disposition"] = "enforced"
    _rehash(report)
    with pytest.raises(ContractError, match="projection"):
        contract.verify_report(report)


def test_capture_and_observation_bounds_and_aliases() -> None:
    data = _native("environment").to_dict()
    data["returncode"] = False
    with pytest.raises(ContractError, match="integer"):
        contract.parse_capture(data, contract.COMMAND_TIMEOUT_NS)
    data = Capture(stdout=b"x" * (contract.MAX_CAPTURE_BYTES + 1)).to_dict()
    with pytest.raises(ContractError, match="bound"):
        contract.parse_capture(data, contract.COMMAND_TIMEOUT_NS)
    for raw in (
        b'{"ok":true,"ok":false}',
        b"{}",
        b"\xff",
        b'{"detail":0,"errno":false,"ok":true,"operation":"environment"}',
        b'{"detail":1,"errno":0,"ok":true,"operation":"environment"}',
    ):
        capture = Capture("may_have_run", "complete", 1, 0, raw)
        assert contract.syscall_observation(capture, "environment") is None
    assert (
        contract.syscall_observation(
            Capture("may_have_run", "complete", 1, 0, _native("environment").stdout, b"diagnostic"),
            "environment",
        )
        is None
    )


def test_measured_permit_denial_baseline_failure_and_missing_completion() -> None:
    baseline = _native("exec_self")
    assert contract.assess("exec_self", "deny", baseline, baseline) == "refused"
    assert (
        contract.assess("exec_self", "deny", baseline, _native("exec_self", ok=False, error=13))
        == "enforced"
    )
    assert (
        contract.assess("exec_self", "deny", baseline, _native("exec_self", ok=False, error=2))
        == "unknown"
    )
    assert (
        contract.assess("exec_self", "deny", _native("exec_self", ok=False, error=2), baseline)
        == "unavailable"
    )
    for terminal in ("deadline", "output_limit", "exit_error", "spawn_failed"):
        assert (
            contract.assess("exec_self", "deny", baseline, Capture("may_have_run", terminal))
            == "unknown"
        )
    assert contract.assess("exec_self", "deny", Capture(), Capture()) == "untested"


def test_help_import_spec_and_replay_are_inert(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        pytest.fail("offline route attempted native probing")

    monkeypatch.setattr(harness.subprocess, "Popen", forbidden)
    monkeypatch.setattr(harness.socket, "socket", forbidden)
    monkeypatch.setattr(harness.tempfile, "TemporaryDirectory", forbidden)
    monkeypatch.setattr(harness.os, "uname", forbidden)
    importlib.reload(harness)
    assert harness.main(["spec"]) == 0
    capsys.readouterr()
    with pytest.raises(SystemExit) as exit_info:
        harness.main(["--help"])
    assert exit_info.value.code == 0
    capsys.readouterr()
    path = tmp_path / "report.json"
    path.write_bytes(canonical_json(_report()))
    assert harness.main(["replay", str(path)]) == 0


@pytest.mark.parametrize("reason", ["unsupported_host", "sandbox_exec_missing", "compiler_missing"])
def test_unavailable_platform_or_tool_never_spawns(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    reason: str,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        pytest.fail("unavailable route attempted OS execution")

    monkeypatch.setattr(harness.subprocess, "Popen", forbidden)
    monkeypatch.setattr(harness.socket, "socket", forbidden)
    monkeypatch.setattr(harness, "_is_darwin", lambda: reason != "unsupported_host")
    sandbox, compiler = tmp_path / "sandbox", tmp_path / "compiler"
    for name, path in (("sandbox_exec_missing", sandbox), ("compiler_missing", compiler)):
        if reason != name:
            path.write_bytes(b"fixture-tool")
            path.chmod(0o700)
    monkeypatch.setattr(harness, "_TOOLS", {"sandbox_exec_id": sandbox, "compiler_id": compiler})
    report = harness.run_probes()
    assert report["reason"] == reason
    assert report["disposition"] == "unavailable"


def test_nonregular_and_symlink_input_refuse(tmp_path: Path) -> None:
    file = tmp_path / "regular"
    file.write_bytes(b"abc")
    link = tmp_path / "link"
    link.symlink_to(file)
    assert harness._read_regular(file, 3) == b"abc"
    with pytest.raises(ContractError, match="size"):
        harness._read_regular(file, 2)
    with pytest.raises(OSError, match="Too many levels"):
        harness._read_regular(link, 3)
    with pytest.raises(ContractError, match="type"):
        harness._read_regular(tmp_path, 100)


def test_profile_paths_escape_literal_quotes_slashes_and_parentheses() -> None:
    path = Path('/controlled/quote"\\(allow default)')
    escaped = harness._literal(path)
    assert escaped == '"\\/controlled\\/quote\\"\\\\(allow default)"'.replace("\\/", "/")
    profile = harness._profile(path, path, path, path, path)
    assert "(deny default)" in profile
    assert profile.count(escaped) == 7
    assert "(allow default)" not in contract.PROFILE_TEMPLATE
    for refused in (Path("relative"), Path("/controlled/\n"), Path("/controlled/é")):
        with pytest.raises(ContractError, match="refused"):
            harness._literal(refused)


class FakePipe:
    """In-memory descriptor stand-in, with no actual native descriptor."""

    def __init__(self, descriptor: int) -> None:
        """Assign a fictional descriptor for selector tests."""
        self.descriptor = descriptor
        self.closed = False

    def fileno(self) -> int:
        return self.descriptor

    def close(self) -> None:
        self.closed = True


class FakeProcess:
    """Owned-child stand-in; never starts a process."""

    def __init__(self) -> None:
        """Provide fictional pipes and an initially running state."""
        self.stdout, self.stderr = FakePipe(10), FakePipe(11)
        self.returncode: int | None = None
        self.killed = False
        self.pid = 456

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9

    def wait(self, *, timeout: float) -> int:
        assert 0 < timeout <= 2
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakeSelector:
    """Deterministic selector stand-in, optionally delivering beyond the deadline."""

    def __init__(self, clock: list[int], *, late: bool) -> None:
        """Bind a test clock and fictional registrations."""
        self.clock, self.late = clock, late
        self.keys: dict[FakePipe, SimpleNamespace] = {}

    def __enter__(self) -> Self:
        """Return the fictional selector."""
        return self

    def __exit__(self, *_args: object) -> None:
        """No native resource is owned."""

    def register(self, stream: FakePipe, _events: int, index: int) -> None:
        self.keys[stream] = SimpleNamespace(data=index, fd=stream.fileno(), fileobj=stream)

    def unregister(self, stream: FakePipe) -> None:
        del self.keys[stream]

    def get_map(self) -> dict[FakePipe, SimpleNamespace]:
        return self.keys

    def select(self, _timeout: float) -> list[tuple[SimpleNamespace, int]]:
        if self.late:
            self.clock[0] = contract.COMMAND_TIMEOUT_NS + 2
        return [(key, 1) for key in self.keys.values()]


@pytest.mark.parametrize("mode", ["complete", "late", "overflow"])
def test_bounded_collection_retains_late_bytes_and_kills_only_owned_process(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
) -> None:
    clock = [1]
    process = FakeProcess()
    raw = _native("read_allowed").stdout if mode != "overflow" else b"x" * 8192
    streams = {10: io.BytesIO(raw), 11: io.BytesIO()}
    kwargs_seen: dict[str, object] = {}

    def spawn(_argv: list[str], **kwargs: object) -> FakeProcess:
        kwargs_seen.update(kwargs)
        return process

    monkeypatch.setattr(harness.subprocess, "Popen", spawn)
    monkeypatch.setattr(harness.time, "monotonic_ns", lambda: clock[0])
    monkeypatch.setattr(
        harness.selectors, "DefaultSelector", lambda: FakeSelector(clock, late=mode == "late")
    )
    monkeypatch.setattr(harness.os, "set_blocking", lambda *_args: None)
    monkeypatch.setattr(harness.os, "read", lambda fd, count: streams[fd].read(count))
    capture = harness._run_command(
        ["/controlled/helper"],
        cwd=tmp_path,
        deadline_ns=contract.RUN_TIMEOUT_NS,
        timeout_ns=contract.COMMAND_TIMEOUT_NS,
    )
    assert kwargs_seen["env"] == {}
    assert kwargs_seen["close_fds"] is True
    assert "shell" not in kwargs_seen and "pass_fds" not in kwargs_seen
    assert capture.exposure == "may_have_run"
    assert (
        capture.terminal
        == {"complete": "complete", "late": "deadline", "overflow": "output_limit"}[mode]
    )
    assert capture.stdout == raw[: contract.MAX_CAPTURE_BYTES]
    assert process.killed is (mode != "complete")
    assert process.stdout.closed and process.stderr.closed
    if mode == "late":
        assert (
            contract.assess("read_allowed", "allow", _native("read_allowed"), capture) == "unknown"
        )
    contract.parse_capture(capture.to_dict(), contract.COMMAND_TIMEOUT_NS)


def test_no_launch_after_deadline_and_spawn_error_is_not_zero_action_proof(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    def fail_spawn(*_args: object, **_kwargs: object) -> object:
        raise OSError("controlled fixture failure")

    monkeypatch.setattr(harness.subprocess, "Popen", fail_spawn)
    monkeypatch.setattr(harness.time, "monotonic_ns", lambda: 100)
    assert harness._run_command([], cwd=tmp_path, deadline_ns=99, timeout_ns=10) == Capture()
    capture = harness._run_command([], cwd=tmp_path, deadline_ns=1000, timeout_ns=100)
    assert capture.terminal == "spawn_failed" and capture.exposure == "may_have_run"


class FixtureListener:
    """Loopback fixture stand-in; never creates a socket."""

    def __enter__(self) -> Self:
        """Return the inert listener."""
        return self

    def __exit__(self, *_args: object) -> None:
        """No socket is owned."""

    def bind(self, address: tuple[str, int]) -> None:
        assert address == ("127.0.0.1", 0)

    def listen(self, backlog: int) -> None:
        assert backlog == 4

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 12345)


@pytest.mark.parametrize("mode", ["observed", "startup_crash", "compilation_failed"])
@pytest.mark.parametrize("candidate", ["pre_exec", "after_startup"])
def test_fixture_experiment_without_any_native_execution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    candidate: Literal["pre_exec", "after_startup"],
) -> None:
    calls: list[list[str]] = []

    def command(argv: list[str], **_kwargs: object) -> Capture:
        calls.append(argv)
        if "-std=c11" in argv:
            if mode == "compilation_failed":
                return Capture("may_have_run", "exit_error", 1, 1, pid=122)
            (tmp_path / "helper").write_bytes(b"fixture-not-native-executable")
            return Capture("may_have_run", "complete", 1, 0, pid=122)
        confined = "-p" in argv or "--apply-profile-after-startup" in argv
        operation = argv[-2]
        if confined and mode == "startup_crash":
            return Capture("may_have_run", "exit_error", 1, -6, pid=124)
        if confined and operation in {
            "read_denied",
            "write_denied",
            "read_prefix_sibling",
            "read_symlink",
            "write_symlink",
            "connect_loopback",
            "fork",
            "exec_other",
        }:
            return _native(operation, ok=False, error=1)
        return _native(operation)

    monkeypatch.setattr(harness, "_run_command", command)
    monkeypatch.setattr(harness.socket, "socket", lambda *_args: FixtureListener())
    monkeypatch.setattr(harness.time, "monotonic_ns", lambda: 10_000)
    identities = _identities()
    host: dict[str, JsonValue] = {
        "system": "Darwin",
        "release": "26.0.0",
        "machine": "arm64",
        "parent_pid": 123,
        "started_ns": 1,
        "finished_ns": 1,
    }
    report = harness._experiment(tmp_path, identities, host, contract.RUN_TIMEOUT_NS, candidate)
    assert contract.replay_bytes(canonical_json(report)) == report
    rows = cast("list[dict[str, JsonValue]]", report["observations"])
    if mode == "startup_crash":
        assert len(calls) == 3
        assert report["reason"] == "candidate_startup_unavailable"
        assert rows[0]["disposition"] == "unknown"
        assert {row["disposition"] for row in rows[1:]} == {"untested"}
        assert _object(report["fixture"])["read_replacement"] is None
    elif mode == "compilation_failed":
        assert len(calls) == 1
        assert report["reason"] == "compilation_failed" and report["disposition"] == "unavailable"
    else:
        assert len(calls) == 1 + 2 * len(contract.PROBES)
        assert report["disposition"] == "refused"
        states = {row["operation"]: row["disposition"] for row in rows}
        assert (
            states["socket_loopback"]
            == states["exec_self"]
            == states["read_replacement"]
            == "refused"
        )
        assert states["read_denied"] == states["connect_loopback"] == states["fork"] == "enforced"
        assert all(
            row["candidate"] != row["baseline"]
            for row in rows
            if row["expectation"] == "deny" and row["disposition"] == "enforced"
        )


def test_unobserved_preparation_and_replacement_mutations_refuse() -> None:
    report = _report()
    report["fixture"] = None
    _rehash(report)
    with pytest.raises(ContractError, match="preparation"):
        contract.verify_report(report)
    report = _report()
    fixture = _object(report["fixture"])
    fixture["read_replacement"] = fixture["read_initial"]
    _rehash(report)
    with pytest.raises(ContractError, match="unchanged"):
        contract.verify_report(report)


def test_separate_post_startup_receipt_and_immutable_pre_exec_failure() -> None:
    root = Path(__file__).parents[1] / "docs/evidence"
    before = contract.replay_bytes(
        (root / "native-confinement-darwin-27.0.0-arm64-v1.json").read_bytes()
    )
    after = diagnostic.replay_bytes(
        (root / "native-confinement-after-startup-darwin-27.0.0-arm64-v1.json").read_bytes()
    )
    assert before["record_id"] == (
        "sha256:94c12b835ac785f86a3b166837b67a5f7cf5a8457ce4ad4aa34f62afc7f873da"
    )
    assert after["record_id"] == (
        "sha256:be031b62bc65c7fe68e937e78a85f288d9ea871003aec3c4ce4a802ce0f29312"
    )
    assert after["startup_confinement_proven"] is False and after["runtime_authority"] is False
    record = _object(after["test_record"])
    identities = _object(record["identities"])
    assert identities["implementation_id"] == (
        "sha256:af459854fedf83746e1317cf4e0643dba92ebb5e489baa6d23fe49e6be454e6a"
    )
    for field in ("probe_source_id", "profile_template_id"):
        assert identities[field] == harness._variant_identities("after_startup")[field]
    states = {
        row["operation"]: row["disposition"]
        for row in cast("list[dict[str, JsonValue]]", record["observations"])
    }
    assert states["socket_loopback"] == states["read_replacement"] == "refused"
    assert states["exec_self"] == "unknown"
    assert states["read_denied"] == states["connect_loopback"] == states["fork"] == "enforced"


@pytest.mark.parametrize(
    ("name", "serial_ns", "span_ns"),
    [
        ("native-confinement-darwin-27.0.0-arm64-v1.json", 601_133_042, 602_767_584),
        ("native-confinement-after-startup-darwin-27.0.0-arm64-v1.json", 684_274_919, 687_192_458),
    ],
)
def test_preserved_receipts_have_producer_consistent_serial_lifetimes(
    name: str,
    serial_ns: int,
    span_ns: int,
) -> None:
    raw = (Path(__file__).parents[1] / "docs/evidence" / name).read_bytes()
    report = (
        _object(diagnostic.replay_bytes(raw)["test_record"])
        if "after-startup" in name
        else contract.replay_bytes(raw)
    )
    captures = [_object(report["compilation"])]
    for row in cast("list[dict[str, JsonValue]]", report["observations"]):
        captures.extend((_object(row["baseline"]), _object(row["candidate"])))
    host = _object(report["host"])
    assert sum(cast("int", capture["elapsed_ns"]) for capture in captures) == serial_ns
    assert cast("int", host["finished_ns"]) - cast("int", host["started_ns"]) == span_ns
    assert serial_ns <= span_ns
    for capture in captures:
        if capture["pid"] is not None:
            assert capture["pid"] != host["parent_pid"]
            assert type(capture["returncode"]) is int


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("startup_confinement_proven", True),
        ("startup_confinement_proven", 0),
        ("runtime_authority", True),
        ("application_stage", "before_exec"),
        ("schema_version", "2.0"),
    ],
)
def test_post_startup_rehash_cannot_promote_or_change_application_stage(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: JsonValue,
) -> None:
    monkeypatch.setattr(diagnostic, "_run_variant", lambda _candidate: _report())
    report = diagnostic.run_diagnostic()
    report[field] = value
    _rehash(report)
    with pytest.raises(ContractError):
        diagnostic.verify_diagnostic(report)


def test_post_startup_help_replay_and_run_routes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fake(candidate: str) -> dict[str, JsonValue]:
        assert candidate == "after_startup"
        return _report()

    monkeypatch.setattr(diagnostic, "_run_variant", fake)
    report = diagnostic.run_diagnostic()
    path = tmp_path / "diagnostic.json"
    path.write_bytes(canonical_json(report))
    assert diagnostic.main(["run"]) == 2
    capsys.readouterr()
    monkeypatch.setattr(diagnostic, "_run_variant", lambda _candidate: pytest.fail("replay probed"))
    assert diagnostic.main(["replay", str(path)]) == 0
    capsys.readouterr()
    with pytest.raises(SystemExit) as exit_info:
        diagnostic.main(["--help"])
    assert exit_info.value.code == 0
    assert diagnostic.main(["replay", str(tmp_path / "missing")]) == 2
    capsys.readouterr()
    for raw in (
        canonical_json(report) + b"\n",
        canonical_json(report).replace(
            b'"runtime_authority":false', b'"runtime_authority":false,"runtime_authority":true', 1
        ),
        b" " * (contract.MAX_REPORT_BYTES + 1),
        b"[" * 1500,
    ):
        with pytest.raises(ContractError):
            diagnostic.replay_bytes(raw)


@pytest.mark.skipif(
    os.environ.get("LOCALINFERENCELAB_NATIVE_PROBE") != "1",
    reason="Native execution is opt-in; default CI never invokes the OS experiment",
)
def test_explicit_native_probe() -> None:
    report = harness.run_probes()
    assert contract.replay_bytes(canonical_json(report)) == report
    assert report["runtime_authority"] is False and report["physical_launch_approved"] is False
    assert report["disposition"] in contract.DISPOSITIONS
    if report["reason"] == "none":
        for row in cast("list[dict[str, JsonValue]]", report["observations"]):
            assert _object(row["baseline"])["terminal"] != "not_run"


@pytest.mark.skipif(
    os.environ.get("LOCALINFERENCELAB_NATIVE_PROBE") != "1",
    reason="Post-startup native diagnostic is separately opt-in, never default CI",
)
def test_explicit_native_after_startup_probe() -> None:
    report = diagnostic.run_diagnostic()
    assert diagnostic.replay_bytes(canonical_json(report)) == report
    assert report["startup_confinement_proven"] is False and report["runtime_authority"] is False
    assert _object(report["test_record"])["physical_launch_approved"] is False
