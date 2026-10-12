"""Inert-only transport, worker-stub, refusal, retention and offline report tests."""

# ruff: noqa: SLF001
from __future__ import annotations

import ast
import importlib
import os
import signal
import socket
import struct
import sys
import time
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import cast

import pytest

import localinferencelab.mlx_preflight_execution as parent
import localinferencelab.mlx_preflight_report as reports
import localinferencelab.mlx_preflight_worker as worker
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_json,
    decode_bytes,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.cli import main
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_custody import _read_launch_target
from localinferencelab.mlx_manifest import _scan_open_tree
from localinferencelab.mlx_preflight_protocol import (
    MAX_RETAINED_OVERSIZE_BYTES,
    AcquisitionError,
    Capture,
    RetainingChannel,
    decode_frame,
    encode_frame,
)


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _fixture_frames() -> list[dict[str, JsonValue]]:
    return [decode_frame(capture.wire) for capture in reports.synthetic_fixture().captures]


class InertRuntime:
    """Invented values only: no imported runtime, backend/device or synchronization."""

    def __init__(self, hello: dict[str, object], fail: str | None = None) -> None:
        """Bind invented identities, and optionally throw before returning an observation."""
        self.hello = hello
        self.fail = fail
        self.calls: list[str] = []

    def _call(self, action: str, value: object) -> object:
        self.calls.append(action)
        if self.fail == action:
            raise RuntimeError("private /do/not/publish secret-token")
        return value

    def distributions(self) -> object:
        return self._call(worker.ACTIONS[0], self.hello["distributions"])

    def import_mlx(self) -> object:
        imports = cast("dict[str, dict[str, object]]", self.hello["import_files"])
        return self._call("import_mlx", {"module": "mlx.core", **imports["mlx.core"]})

    def import_mlx_lm(self) -> object:
        imports = cast("dict[str, dict[str, object]]", self.hello["import_files"])
        return self._call("import_mlx_lm", {"module": "mlx_lm", **imports["mlx_lm"]})

    def default_device(self) -> object:
        return self._call("default_device", "Device(gpu, 0)")

    def default_stream(self) -> object:
        return self._call("default_stream", "Stream(0)")

    def metal_is_available(self) -> object:
        return self._call("metal_is_available", True)

    def synchronize(self) -> object:
        return self._call(
            "synchronize",
            {
                "completed": True,
                "scope": "mlx_default_streams",
                "kernel_execution_proven": False,
            },
        )


@pytest.fixture(autouse=True)
def forbid_native_imports(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test execution never resolves/imports MLX or MLX-LM, including accidentally."""
    original = importlib.import_module

    def guard(name: str, package: str | None = None) -> ModuleType:
        if name == "mlx" or name.startswith(("mlx.", "mlx_lm")):
            pytest.fail("real MLX import attempted")
        return original(name, package)

    monkeypatch.setattr(importlib, "import_module", guard)


def test_physical_gates_have_no_test_or_caller_bypass(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> object:
        pytest.fail("gate performed an action")

    monkeypatch.setattr(socket, "socketpair", forbidden)
    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(parent, "_create_worker_snapshot_at", forbidden)
    monkeypatch.setattr(parent, "_open_private_output_root", forbidden)
    refusal = parent.request_preflight()
    assert refusal["disposition"] == "refused_before_root_socket_process_import_or_consumption"
    assert set(_object(refusal["real_action_counters"]).values()) == {0}
    assert reports.verify_gate_refusal(refusal) == refusal
    with pytest.raises(AcquisitionError, match="physical_launch_closed"):
        parent.require_physical_launch()
    with pytest.raises(AcquisitionError, match="physical_launch_closed"):
        parent._acquire_prepared(cast("parent._PreparedLaunch", object()))
    with pytest.raises(AcquisitionError, match="physical_launch_closed"):
        parent._spawn_owned(Path("/not/an/executable"), 0, 0, 0, cast("socket.socket", object()))
    with pytest.raises(AcquisitionError, match="physical_launch_closed"):
        reports.compile_physical_acquisition(reports.synthetic_fixture())
    assert worker.main() == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",
        b"{",
        b'{"a":1,"a":2}',
        b'{"a":1.0}',
        b'{"a":NaN}',
        b'{"a": 1}',
        b"[]",
        b'{"a":"\\ud800"}',
    ],
)
def test_malformed_frame_bytes_are_retained_before_parse(raw: bytes) -> None:
    left, right = socket.socketpair()
    with left, right:
        channel = RetainingChannel(left, time.monotonic_ns() + 1_000_000_000)
        wire = struct.pack(">I", len(raw)) + raw
        right.sendall(wire)
        with pytest.raises(AcquisitionError, match="invalid_frame"):
            channel.receive()
        capture = channel.captures[-1]
        assert capture.wire == wire
        assert capture.complete is True
        assert capture.rejection == "invalid_frame_json"
        assert capture.public_record()["retained_sha256"] == digest_bytes(wire)


@pytest.mark.parametrize("header", [0, worker.MAX_FRAME_BYTES + 1, 0xFFFFFFFF])
def test_oversize_and_empty_header_never_drain_claimed_frame(header: int) -> None:
    left, right = socket.socketpair()
    with left, right:
        channel = RetainingChannel(left, time.monotonic_ns() + 1_000_000_000)
        right.sendall(struct.pack(">I", header) + b"\xff" * 8000)
        with pytest.raises(AcquisitionError, match="frame_size"):
            channel.receive()
        capture = channel.captures[-1]
        assert capture.declared_bytes == header
        assert len(capture.wire) <= 4 + MAX_RETAINED_OVERSIZE_BYTES
        assert capture.complete is False
        assert capture.public_record()["unread_bytes"] == "unknown_not_claimed_observed"


@pytest.mark.parametrize("raw", [b"", b"\0", b"\0\0\0", struct.pack(">I", 10) + b"abc"])
def test_partial_eof_retains_exact_received_bytes(raw: bytes) -> None:
    left, right = socket.socketpair()
    with left, right:
        channel = RetainingChannel(left, time.monotonic_ns() + 1_000_000_000)
        right.sendall(raw)
        right.shutdown(socket.SHUT_WR)
        with pytest.raises(AcquisitionError, match="eof"):
            channel.receive()
        assert channel.captures[-1].wire == raw
        assert channel.captures[-1].complete is False


def test_deadline_and_extra_output_are_retained() -> None:
    left, right = socket.socketpair()
    with left, right:
        channel = RetainingChannel(left, time.monotonic_ns() - 1)
        with pytest.raises(AcquisitionError, match="deadline"):
            channel.receive()
        assert channel.captures[-1].wire == b""
        channel = RetainingChannel(left, time.monotonic_ns() + 1_000_000_000)
        right.sendall(b"secret /private/path \xff")
        with pytest.raises(AcquisitionError, match="extra_output"):
            channel.expect_eof()
        assert channel.captures[-1].wire == b"secret /private/path \xff"


@pytest.mark.parametrize(
    ("index", "field", "value", "reason"),
    [
        (1, "unknown", 0, "frame_fields"),
        (1, "pid", 999, "worker_identity_mismatch"),
        (1, "interpreter_sha256", "sha256:" + "0" * 64, "worker_identity_mismatch"),
        (1, "runtime_root", {"device": 999, "inode": 2, "mode": 0o555}, "worker_identity_mismatch"),
        (1, "worker_program_id", "sha256:" + "0" * 64, "worker_identity_mismatch"),
        (2, "action", "model_load", "action_order"),
        (3, "action", "import_mlx", "action_order"),
        (3, "sequence", 99, "frame_order_or_binding"),
        (4, "observation", [{"name": "not-reviewed"}], "distribution_identity_mismatch"),
        (
            7,
            "observation",
            {"module": "mlx.core", "relative_file": "/private/root", "sha256": "x"},
            "import_observation_identity",
        ),
        (13, "observation", "/private/device/path", "unsafe_representation"),
        (19, "observation", "yes", "nonboolean_metal"),
        (22, "observation", {"completed": False}, "synchronization_observation"),
    ],
)
def test_strict_sequence_action_identity_fields_and_observations(
    index: int,
    field: str,
    value: JsonValue,
    reason: str,
) -> None:
    acquisition = reports.synthetic_fixture()
    capture = acquisition.captures[index]
    frame = decode_frame(capture.wire)
    frame[field] = value
    capture.wire = encode_frame(frame)
    capture.declared_bytes = len(capture.wire) - 4
    capture.rejection = reason
    acquisition.captures = acquisition.captures[: index + 1]
    acquisition.rejection = reason
    validator, rejection = parent.replay_captures(
        acquisition.hello,
        acquisition.identity,
        acquisition.captures,
        acquisition.started_ns,
        acquisition.deadline_ns,
    )
    assert rejection == reason
    assert validator.stage != "closed"


def test_missing_duplicate_extra_and_reordered_actions_fail() -> None:
    fixture = reports.synthetic_fixture()
    for index in (2, 3, 4):
        validator = parent.SessionValidator(fixture.hello, fixture.identity)
        frames = _fixture_frames()
        for position in range(index):
            validator.accept(fixture.captures[position].direction, frames[position])
        with pytest.raises(AcquisitionError):
            validator.accept(fixture.captures[index + 1].direction, frames[index + 1])
        if index > 2:
            with pytest.raises(AcquisitionError):
                validator.accept(fixture.captures[index - 1].direction, frames[index - 1])
    validator, rejection = parent.replay_captures(
        fixture.hello, fixture.identity, fixture.captures, fixture.started_ns, fixture.deadline_ns
    )
    assert rejection is None
    with pytest.raises(AcquisitionError, match="extra_frame"):
        validator.accept("worker_to_parent", frames[-1])
    partial = reports.synthetic_fixture()
    partial.captures = partial.captures[:4]
    partial.rejection = "eof"
    report = reports._derive_report(partial)
    state = _object(_object(report["action_accounting"])[worker.ACTIONS[0]])
    assert state["attempted"] is True and state["completed"] is None


def test_compile_replay_determinism_nonpromotion_and_private_report(
    tmp_path: Path,
) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    path_a, report_a = reports.compile_acquisition(reports.synthetic_fixture(), a)
    path_b, report_b = reports.compile_acquisition(reports.synthetic_fixture(), b)
    assert report_a == report_b
    assert read_closed_bundle(path_a) == read_closed_bundle(path_b)
    assert reports.replay_bundle(path_a) == report_a
    assert report_a["accepted_physical_evidence"] is False
    assert report_a["promotable"] is False
    assert "Synthetic / non-promotable" in reports.human_report(report_a)
    _, files = read_closed_bundle(path_a)
    for field in ("accepted_physical_evidence", "promotable", "evidence_kind"):
        changed = _object(load_json_bytes(files["report.json"]))
        changed[field] = True if field != "evidence_kind" else "accepted_physical"
        tampered = dict(files)
        tampered.pop("index.json")
        tampered.pop("receipt.json")
        tampered["report.json"] = canonical_json(changed)
        destination = tmp_path / field
        destination.mkdir()
        republished = publish_bundle(tampered, destination, name_prefix="tampered")
        with pytest.raises(AcquisitionError, match="mismatch"):
            reports.replay_bundle(republished)


def test_rejection_private_nonutf8_and_no_secret_in_public_report(tmp_path: Path) -> None:
    acquisition = reports.synthetic_fixture()
    wire = b"\0\0\0\x10/private/secret\xff"
    acquisition.captures = acquisition.captures[:2] + [
        Capture("worker_to_parent", wire, acquisition.started_ns + 3, 16, False, "eof")
    ]
    acquisition.rejection = "eof"
    path, report = reports.compile_acquisition(acquisition, tmp_path)
    _, files = read_closed_bundle(path)
    private = _object(load_json_bytes(files["private/acquisition.json"]))
    captures = cast("list[JsonValue]", private["captures"])
    assert decode_bytes(cast("str", _object(captures[-1])["wire_base64"])) == wire
    assert b"/private/" not in files["report.json"] + files["report.md"]
    assert reports.replay_bundle(path) == report


def _prepared(tmp_path: Path) -> parent._PreparedLaunch:
    roots = [tmp_path / name for name in ("runtime", "output", "custody")]
    for root in roots:
        root.mkdir(mode=0o700)
    roots[0].chmod(0o555)
    descriptors = [os.open(root, os.O_RDONLY | os.O_DIRECTORY) for root in roots]
    root_record, files = _scan_open_tree(descriptors[0])
    interpreter, data = _read_launch_target(
        Path(sys.executable),
        "inert interpreter",
        executable=True,
        trusted_ancestors=False,
        trusted_source=False,
    )
    fixture = reports.synthetic_fixture()
    return parent._PreparedLaunch(
        data,
        interpreter,
        Path(worker.__file__).read_bytes(),
        *descriptors,
        roots[1],
        parent._root(descriptors[0]),
        [],
        "sha256:" + "c" * 64,
        _object(fixture.hello["import_files"]),
        {"package_root": root_record, "files": files},
    )


def _install_inert_spawn(
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure: str | None = None,
    anomaly: str | None = None,
) -> None:
    def spawn(
        _executable: Path,
        _interpreter: int,
        _source: int,
        _runtime: int,
        endpoint: socket.socket,
    ) -> int:
        pid = os.fork()
        if pid:
            return pid
        try:
            hello = worker._receive(endpoint, time.monotonic_ns() + worker.MAX_LIFETIME_NS)
            if anomaly == "crash":
                os._exit(17)
            if anomaly == "signal":
                os.kill(os.getpid(), signal.SIGTERM)
            if anomaly in {"timeout", "late"}:
                time.sleep(1)
            identity: dict[str, object] = {
                "pid": os.getpid(),
                "parent_pid": os.getppid(),
                "interpreter_sha256": hello["interpreter_sha256"],
                "runtime_root": hello["runtime_root"],
                "worker_program_id": hello["worker_program_id"],
            }
            if anomaly == "identity":
                identity["interpreter_sha256"] = "sha256:" + "0" * 64
            if anomaly == "malformed":
                endpoint.sendall(struct.pack(">I", 1) + b"\xff")
            else:
                worker._serve(endpoint, hello, InertRuntime(hello, failure), identity)
        except (worker.WorkerError, OSError):
            os._exit(18)
        os._exit(0)

    monkeypatch.setattr(parent, "_spawn_owned", spawn)
    monkeypatch.setattr(
        parent,
        "_parent_process_evidence",
        lambda *_args: {"method": "inert_test_stub_not_physical", "available": False},
    )
    deadline = 250_000_000 if anomaly in {"timeout", "late"} else 5_000_000_000
    monkeypatch.setattr(parent, "MAX_LIFETIME_NS", deadline)


@pytest.mark.parametrize("failure", [None, *worker.ACTIONS])
def test_parent_owned_process_socket_worker_stub_failures_and_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str | None,
) -> None:
    launch = _prepared(tmp_path)
    _install_inert_spawn(monkeypatch, failure=failure)
    try:
        acquisition = parent._collect_owned_session(launch)
        assert acquisition.cleanup_complete is True
        assert acquisition.processes_started == 1 and acquisition.socketpairs_created == 1
        assert acquisition.child_wait is not None
        assert not list((tmp_path / "custody").glob(".localinferencelab-mlx-*"))
        retained = list((tmp_path / "custody").glob(".mlx-preflight-*/event-*.json"))
        assert retained
        path, report = reports.compile_acquisition(
            acquisition, tmp_path / "output", output_descriptor=launch.output_descriptor
        )
        assert reports.replay_bundle(path) == report
        assert report["real_mlx_actions_observed"] == 0
        if failure is None:
            assert report["status"] == "synthetic_sequence_completed"
        else:
            assert report["status"] == "synthetic_rejected"
            states = _object(report["action_accounting"])
            state = _object(states[failure])
            assert state["attempted"] is True and state["completed"] is None
            _, files = read_closed_bundle(path)
            assert b"secret-token" not in files["report.json"] + files["report.md"]
    finally:
        for descriptor in (
            launch.runtime_descriptor,
            launch.output_descriptor,
            launch.custody_descriptor,
        ):
            os.close(descriptor)


@pytest.mark.parametrize("anomaly", ["crash", "signal", "timeout", "late", "identity", "malformed"])
def test_parent_crash_signal_deadline_identity_and_rejection_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    anomaly: str,
) -> None:
    launch = _prepared(tmp_path)
    _install_inert_spawn(monkeypatch, anomaly=anomaly)
    try:
        acquisition = parent._collect_owned_session(launch)
        assert acquisition.rejection is not None
        assert acquisition.child_wait is not None
        path, report = reports.compile_acquisition(
            acquisition, tmp_path / "output", output_descriptor=launch.output_descriptor
        )
        assert reports.replay_bundle(path) == report
        assert report["status"] == "synthetic_rejected"
        if anomaly == "malformed":
            assert acquisition.captures[-1].wire.endswith(b"\xff")
            retained = list((tmp_path / "custody").glob(".mlx-preflight-*/event-*.json"))
            assert any(b"invalid_frame_json" in item.read_bytes() for item in retained)
    finally:
        for descriptor in (
            launch.runtime_descriptor,
            launch.output_descriptor,
            launch.custody_descriptor,
        ):
            os.close(descriptor)


def test_worker_installed_operations_use_fake_modules_and_no_forbidden_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_core = tmp_path / "mlx" / "core.fake.so"
    fake_lm = tmp_path / "mlx_lm" / "__init__.py"
    for path in (fake_core, fake_lm):
        path.parent.mkdir()
        path.write_bytes(b"inert fake module")
    fake = SimpleNamespace(
        __file__=str(fake_core),
        default_device=lambda: "gpu",
        default_stream=lambda _device: "stream",
        metal=SimpleNamespace(is_available=lambda: True),
        synchronize=lambda: None,
    )
    modules = {"mlx.core": fake, "mlx_lm": SimpleNamespace(__file__=str(fake_lm))}
    calls: list[str] = []

    def importer(name: str) -> object:
        calls.append(name)
        return modules[name]

    monkeypatch.setattr(worker.importlib, "import_module", importer)
    imports = {
        "mlx.core": ("mlx/core.fake.so", digest_bytes(fake_core.read_bytes())),
        "mlx_lm": ("mlx_lm/__init__.py", digest_bytes(fake_lm.read_bytes())),
    }
    runtime = worker._InstalledRuntime(tmp_path, {}, imports)
    original_path = list(sys.path)
    try:
        assert runtime.import_mlx() == {
            "module": "mlx.core",
            "relative_file": "mlx/core.fake.so",
            "sha256": imports["mlx.core"][1],
        }
        runtime.import_mlx_lm()
        assert calls == ["mlx.core", "mlx_lm"]
        with pytest.raises(worker.WorkerError, match="unsafe_representation"):
            runtime.default_device()
        with pytest.raises(worker.WorkerError, match="unsafe_representation"):
            runtime.default_stream()
    finally:
        sys.path[:] = original_path
    assert runtime.metal_is_available() is True
    assert runtime.synchronize() == {
        "completed": True,
        "scope": "mlx_default_streams",
        "kernel_execution_proven": False,
    }
    fake.metal.is_available = lambda: "bad"
    with pytest.raises(worker.WorkerError, match="nonboolean"):
        runtime.metal_is_available()
    fake.synchronize = lambda: 1
    with pytest.raises(worker.WorkerError, match="synchronization_return"):
        runtime.synchronize()
    tree = ast.parse(Path(worker.__file__).read_text())
    assert not any(
        isinstance(node, ast.Import)
        and any(
            alias.name == "mlx" or alias.name.startswith(("mlx.", "mlx_lm")) for alias in node.names
        )
        for node in ast.walk(tree)
    )


def test_exact_fake_distribution_set_and_metadata_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "mlx-0.30.4.dist-info" / "METADATA"
    path.parent.mkdir()
    path.write_bytes(b"Name: mlx\nVersion: 0.30.4\n")
    distribution = SimpleNamespace(
        metadata={"Name": "mlx"},
        version="0.30.4",
        files=["mlx-0.30.4.dist-info/METADATA"],
        locate_file=lambda _file: path,
    )
    monkeypatch.setattr(
        worker.importlib.metadata, "distributions", lambda **_kwargs: [distribution]
    )
    expected = {"mlx": ("0.30.4", digest_bytes(path.read_bytes()))}
    runtime = worker._InstalledRuntime(tmp_path, expected, {})
    assert runtime.distributions() == [
        {"name": "mlx", "version": "0.30.4", "metadata_sha256": expected["mlx"][1]},
    ]
    distribution.version = "0.29.3"
    with pytest.raises(worker.WorkerError, match="distribution_identity"):
        runtime.distributions()
    distribution.version = "0.30.4"
    path.write_bytes(b"modified")
    with pytest.raises(worker.WorkerError, match="distribution_identity"):
        runtime.distributions()


def test_cli_request_help_compile_replay_and_reports(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["localinferencelab", "mlx", "runtime-preflight-1-2-request"])
    assert main() == 2
    assert '"physical_launch_enabled":false' in capsys.readouterr().out
    monkeypatch.setattr(
        sys,
        "argv",
        ["localinferencelab", "mlx", "runtime-preflight-1-2-fixture-compile", str(tmp_path)],
    )
    assert main() == 0
    capsys.readouterr()
    bundle = next(tmp_path.glob("localinferencelab-mlx-preflight-*"))
    for command in ("evidence-replay", "report"):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "localinferencelab",
                "mlx",
                f"runtime-preflight-1-2-{command}",
                str(bundle),
            ],
        )
        assert main() == 0
        output = capsys.readouterr().out
        assert "synthetic" in output.lower()
    monkeypatch.setattr(sys, "argv", ["localinferencelab", "mlx", "--help"])
    with pytest.raises(SystemExit) as exit_error:
        main()
    assert exit_error.value.code == 0


@pytest.mark.parametrize(
    "mismatch",
    [
        None,
        "interpreter",
        "worker",
        "distribution",
        "python",
        "roots",
        "retained_root",
        "rescan",
    ],
)
def test_preparation_checks_exact_target_closure_source_and_distinct_roots_with_stubs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str | None,
) -> None:
    runtime, output, custody = [tmp_path / name for name in ("runtime", "output", "custody")]
    for root in (runtime, output, custody):
        root.mkdir(mode=0o700)
    for relative in ("mlx/core.cpython-313-darwin.so", "mlx_lm/__init__.py"):
        file = runtime / relative
        file.parent.mkdir()
        file.write_bytes(b"inert source stub, never import")
        file.chmod(0o444)
        file.parent.chmod(0o555)
    runtime.chmod(0o555)
    descriptor = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY)
    try:
        root_record, files = _scan_open_tree(descriptor)
    finally:
        os.close(descriptor)
    selection = cast("list[str]", parent.custody_bridge_spec_1_1()["selected_distributions"])
    distributions: list[JsonValue] = [
        {"name": pin.split("==")[0], "version": pin.split("==")[1]} for pin in selection
    ]
    spec: dict[str, JsonValue] = {
        "expected_distributions": distributions,
        "python": {
            "implementation": "cpython",
            "version": "3.13.15",
            "abi": "cp313",
            "platform": "macosx-11.0-arm64",
        },
    }
    manifest: dict[str, JsonValue] = {
        "manifest_id": "sha256:" + "b" * 64,
        "package_root": root_record,
        "files": files,
        "distributions": [
            {**_object(item), "metadata_sha256": "sha256:" + "c" * 64} for item in distributions
        ],
    }
    target = _object(_object(parent.runtime_target_anchor()["prospective_target"])["interpreter"])

    def read(_path: Path, label: str, **_kwargs: object) -> tuple[dict[str, JsonValue], bytes]:
        identity = (
            target["executable_sha256"]
            if "interpreter" in label
            else (parent.EXPECTED_WORKER_SOURCE_ID)
        )
        if mismatch is not None and mismatch in label:
            identity = "sha256:" + "0" * 64
        return {"sha256": identity}, b"inert snapshot"

    monkeypatch.setattr(parent, "_read_launch_target", read)
    monkeypatch.setattr(parent, "verify_runtime_manifest", lambda value: _object(value))
    monkeypatch.setattr(
        parent,
        "compile_runtime_manifest",
        lambda *_args: manifest if mismatch != "rescan" else {"different": True},
    )
    if mismatch == "distribution":
        _object(distributions[0])["version"] = "not-reviewed"
    if mismatch == "python":
        _object(spec["python"])["version"] = "3.13.0"
    if mismatch == "roots":
        custody = output
    if mismatch == "retained_root":
        _object(manifest["package_root"])["inode"] = 999
    if mismatch is not None:
        with pytest.raises(AcquisitionError):
            parent._prepare_launch(
                runtime, tmp_path / "inert-python", output, custody, manifest, spec
            )
    else:
        prepared = parent._prepare_launch(
            runtime, tmp_path / "inert-python", output, custody, manifest, spec
        )
        assert len(prepared.distributions) == 34
        for retained in (
            prepared.runtime_descriptor,
            prepared.output_descriptor,
            prepared.custody_descriptor,
        ):
            os.close(retained)


def test_runtime_descriptor_drift_refuses_before_process_and_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch = _prepared(tmp_path)
    launch.runtime_manifest["package_root"] = {}
    monkeypatch.setattr(parent, "_spawn_owned", lambda *_args: pytest.fail("drift spawned child"))
    try:
        acquisition = parent._collect_owned_session(launch)
        assert acquisition.rejection == "retained_runtime_root_mismatch"
        assert acquisition.processes_started == 0
        assert acquisition.socketpairs_created == 0
        assert not list((tmp_path / "custody").iterdir())
    finally:
        for descriptor in (
            launch.runtime_descriptor,
            launch.output_descriptor,
            launch.custody_descriptor,
        ):
            os.close(descriptor)


def test_boolean_sequence_and_late_complete_frame_fail_with_retention() -> None:
    fixture = reports.synthetic_fixture()
    identity = decode_frame(fixture.captures[1].wire)
    identity["sequence"] = True
    validator = parent.SessionValidator(fixture.hello, fixture.identity)
    validator.accept("parent_to_worker", fixture.hello)
    with pytest.raises(AcquisitionError, match="frame_order_or_binding"):
        validator.accept("worker_to_parent", identity)
    late = fixture.captures[1]
    late.observed_ns = fixture.deadline_ns + 1
    late.rejection = "deadline"
    fixture.captures = fixture.captures[:2]
    fixture.rejection = "deadline"
    report = reports._derive_report(fixture)
    assert report["status"] == "synthetic_rejected"
    assert _object(_object(report["action_accounting"])[worker.ACTIONS[0]])["attempted"] is False


def test_snapshot_cleanup_even_when_child_cannot_be_reaped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launch = _prepared(tmp_path)
    _install_inert_spawn(monkeypatch, anomaly="malformed")
    real_terminate = parent._terminate_and_wait

    def terminate(pid: int) -> dict[str, JsonValue]:
        real_terminate(pid)
        raise ContractError("inert simulated wait custody unavailable")

    monkeypatch.setattr(parent, "_terminate_and_wait", terminate)
    try:
        with pytest.raises(ContractError, match="wait custody"):
            parent._collect_owned_session(launch)
        assert not list((tmp_path / "custody").glob(".localinferencelab-mlx-*"))
        assert list((tmp_path / "custody").glob(".mlx-preflight-*/event-*.json"))
    finally:
        for descriptor in (
            launch.runtime_descriptor,
            launch.output_descriptor,
            launch.custody_descriptor,
        ):
            os.close(descriptor)


def test_target_platform_check_uses_only_inert_supplied_stubs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(worker.sys, "platform", "linux")
    with pytest.raises(worker.WorkerError, match="target_platform_mismatch"):
        worker._verify_target_platform()
    monkeypatch.setattr(worker.sys, "platform", "darwin")
    monkeypatch.setattr(worker.os, "uname", lambda: SimpleNamespace(machine="x86_64"))
    with pytest.raises(worker.WorkerError, match="target_platform_mismatch"):
        worker._verify_target_platform()
    monkeypatch.setattr(worker.os, "uname", lambda: SimpleNamespace(machine="arm64"))
    worker._verify_target_platform()
