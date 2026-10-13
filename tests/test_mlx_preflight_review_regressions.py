"""Frozen-review regressions: inert sockets and invented custody only."""

# ruff: noqa: SLF001
from __future__ import annotations

import socket
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_preflight_execution as parent
import localinferencelab.mlx_preflight_protocol as protocol
import localinferencelab.mlx_preflight_report as reports
import localinferencelab.mlx_preflight_worker as worker
from localinferencelab.canonical import JsonValue, canonical_identity, canonical_json
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_preflight_protocol import AcquisitionError, decode_frame, encode_frame


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def test_actual_send_crossing_deadline_records_exposure_unknown_not_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = reports.synthetic_fixture()
    command = decode_frame(fixture.captures[2].wire)
    left, right = socket.socketpair()
    deadline = fixture.deadline_ns
    clock = iter((fixture.started_ns + 10, fixture.started_ns + 11, deadline + 1, deadline + 2))
    with left, right, monkeypatch.context() as scoped:
        scoped.setattr(protocol.time, "monotonic_ns", lambda: next(clock))
        channel = protocol.RetainingChannel(left, deadline)
        with pytest.raises(AcquisitionError, match="deadline"):
            channel.send(command)
        assert right.recv(worker.MAX_FRAME_BYTES) == encode_frame(command)
    capture = channel.captures[0]
    assert capture.complete is True and capture.rejection == "deadline"
    fixture.captures = fixture.captures[:2] + [capture]
    fixture.rejection = "deadline"
    validator, reason = parent.replay_captures(
        fixture.hello, fixture.identity, fixture.captures, fixture.started_ns, deadline
    )
    assert reason == "deadline" and validator.stage == "command"
    state = _object(validator.accounting()[worker.ACTIONS[0]])
    assert state["attempted"] is None and state["completed"] is None
    assert state["delivery"] == "complete_parent_command_exposed"
    path, report = reports.compile_acquisition(fixture, tmp_path)
    assert reports.replay_bundle(path) == report
    assert _object(_object(report["action_accounting"])[worker.ACTIONS[0]]) == state
    assert report["status"] == "synthetic_rejected"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("exit_code", "/private/path-secret"),
        ("signal", "secret-token"),
        ("exit_code", False),
        ("exit_code", -1),
        ("exit_code", 256),
        ("pid", False),
        ("pid", 999),
        ("wait_owned", False),
        ("wait_owned", 1),
        ("exited", 1),
        ("exited", False),
        ("signal", 15),
        ("signal", []),
        ("extra", "/private/path-secret"),
    ],
)
@pytest.mark.parametrize("rejected", [True, False])
def test_wait_evidence_shape_privacy_pid_ownership_and_exit_state(
    tmp_path: Path,
    field: str,
    value: JsonValue,
    *,
    rejected: bool,
) -> None:
    fixture = reports.synthetic_fixture()
    assert fixture.child_wait is not None
    fixture.child_wait[field] = value
    if rejected:
        fixture.captures = fixture.captures[:2]
        fixture.rejection = "eof"
    with pytest.raises(AcquisitionError) as error:
        reports.compile_acquisition(fixture, tmp_path)
    assert "secret" not in str(error.value) and "/private/" not in str(error.value)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("signal", [None, False, 0, -1, 128, [], {}])
def test_signaled_wait_requires_exact_coherent_terminal_state(signal: JsonValue) -> None:
    fixture = reports.synthetic_fixture()
    fixture.rejection = "child_exit_or_signal"
    fixture.child_wait = {
        "pid": 123,
        "wait_owned": True,
        "exited": False,
        "exit_code": None,
        "signal": signal,
    }
    with pytest.raises(AcquisitionError):
        reports._derive_report(fixture)


def test_valid_owned_signal_is_rejected_not_sequence_completed() -> None:
    fixture = reports.synthetic_fixture()
    fixture.rejection = "child_exit_or_signal"
    fixture.child_wait = {
        "pid": 123,
        "wait_owned": True,
        "exited": False,
        "exit_code": None,
        "signal": 15,
    }
    report = reports._derive_report(fixture)
    assert report["status"] == "synthetic_rejected" and report["child_signal"] == 15
    fixture.child_wait = None
    with pytest.raises(AcquisitionError, match="cleanup_without_owned_wait"):
        reports._derive_report(fixture)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("kind", {}, "action_terminal_kind"),
        ("kind", [], "action_terminal_kind"),
        ("error_category", {}, "error_category"),
        ("error_category", [], "error_category"),
    ],
)
def test_malformed_enum_frame_retained_as_canonical_rejection(
    tmp_path: Path,
    field: str,
    value: JsonValue,
    reason: str,
) -> None:
    fixture = reports.synthetic_fixture()
    capture = fixture.captures[4]
    frame = decode_frame(capture.wire)
    if field == "error_category":
        frame["kind"] = "action_failed"
        frame.pop("observation")
    frame[field] = value
    capture.wire = encode_frame(frame)
    capture.declared_bytes = len(capture.wire) - 4
    capture.rejection = reason
    fixture.captures = fixture.captures[:5]
    fixture.rejection = reason
    path, report = reports.compile_acquisition(fixture, tmp_path)
    assert reports.replay_bundle(path) == report
    assert report["rejection"] == reason
    state = _object(_object(report["action_accounting"])[worker.ACTIONS[0]])
    assert state["attempted"] is True and state["completed"] is None


@pytest.mark.parametrize("field", ["direction", "rejection"])
@pytest.mark.parametrize("value", [{}, []])
def test_capture_enums_do_not_raise_typeerror(field: str, value: JsonValue) -> None:
    fixture = reports.synthetic_fixture()
    record = fixture.captures[0].private_record()
    record[field] = value
    with pytest.raises(AcquisitionError):
        reports._capture(record)
    capture = fixture.captures[0]
    setattr(capture, field, value)
    with pytest.raises(AcquisitionError):
        parent.replay_captures(
            fixture.hello,
            fixture.identity,
            fixture.captures,
            fixture.started_ns,
            fixture.deadline_ns,
        )


@pytest.mark.parametrize("value", [{}, []])
def test_acquisition_rejection_enums_do_not_raise_typeerror(value: JsonValue) -> None:
    fixture = reports.synthetic_fixture()
    record = fixture.private_record()
    record["rejection"] = value
    with pytest.raises(AcquisitionError, match="terminal_rejection_code"):
        reports._acquisition(record)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "not_hello"),
        ("kind", {}),
        ("sequence", -100),
        ("sequence", False),
        ("sequence", []),
        ("challenge", "invalid-token"),
        ("challenge", []),
        ("nonce", "a" * 64),
        ("session_id", "sha256:" + "0" * 64),
        ("deadline_ns", False),
        ("deadline_ns", 0),
        ("interpreter_sha256", "/private/path-secret"),
        ("worker_program_id", {}),
        ("runtime_root", {"device": 1, "inode": 2, "mode": True}),
        ("runtime_root", {"device": 1, "inode": 0, "mode": 0o555}),
        ("runtime_root", {"device": 1, "inode": 2, "mode": 0o777}),
        ("distributions", []),
        (
            "import_files",
            {
                "mlx.core": {
                    "relative_file": "/private/path-secret",
                    "sha256": "sha256:" + "c" * 64,
                },
                "mlx_lm": {"relative_file": "mlx_lm/__init__.py", "sha256": "sha256:" + "c" * 64},
            },
        ),
    ],
)
def test_coordinated_hello_and_frame_mutation_fails_shared_schema(
    tmp_path: Path,
    field: str,
    value: JsonValue,
) -> None:
    fixture = reports.synthetic_fixture()
    fixture.hello[field] = value
    for capture in fixture.captures:
        frame = decode_frame(capture.wire)
        if frame["kind"] == "hello":
            frame = dict(fixture.hello)
        if frame["kind"] == "identity" and field in {"nonce", "challenge"}:
            frame[field] = value
        capture.wire = encode_frame(frame)
        capture.declared_bytes = len(capture.wire) - 4
    with pytest.raises(worker.WorkerError):
        worker.validate_hello(fixture.hello)
    with pytest.raises(AcquisitionError, match="hello_invalid"):
        reports.compile_acquisition(fixture, tmp_path)
    assert not list(tmp_path.iterdir())


def test_valid_hello_session_and_identity_cannot_be_replaced_by_coordinated_claims() -> None:
    fixture = reports.synthetic_fixture()
    worker.validate_hello(fixture.hello)
    assert fixture.hello["session_id"] == canonical_identity(
        {
            "challenge": fixture.hello["challenge"],
            "nonce": fixture.hello["nonce"],
        }
    )
    fixture.identity["interpreter_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(AcquisitionError, match="worker_identity_mismatch"):
        reports._acquisition(fixture.private_record())
    fixture = reports.synthetic_fixture()
    fixture.identity["pid"] = False
    with pytest.raises(AcquisitionError, match="worker_identity_mismatch"):
        reports._acquisition(fixture.private_record())


def test_distribution_type_probe_cannot_leak_into_hello_identity() -> None:
    fixture = reports.synthetic_fixture()
    distributions = cast("list[JsonValue]", fixture.hello["distributions"])
    _object(distributions[0])["version"] = []
    with pytest.raises(worker.WorkerError, match="hello_distribution_identity"):
        worker.validate_hello(fixture.hello)


@pytest.mark.parametrize(
    "mutation",
    [
        "supplied_root_device_boolean",
        "received_root_device_boolean",
        "received_pid_boolean",
        "supplied_pid_boolean",
        "synchronize_completed_integer",
        "synchronize_kernel_integer",
        "received_hello_sequence_boolean",
    ],
)
def test_bool_integer_identity_and_observation_aliases_fail_compile_and_offline_replay(
    tmp_path: Path, mutation: str
) -> None:
    fixture = reports.synthetic_fixture()
    fixture.identity["pid"] = 1
    assert fixture.child_wait is not None
    fixture.child_wait["pid"] = 1
    identity_frame = decode_frame(fixture.captures[1].wire)
    identity_frame["pid"] = 1
    fixture.captures[1].wire = encode_frame(identity_frame)
    fixture.captures[1].declared_bytes = len(fixture.captures[1].wire) - 4
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    path, _ = reports.compile_acquisition(fixture, baseline)
    _, files = read_closed_bundle(path)
    if mutation.startswith("supplied"):
        if mutation == "supplied_pid_boolean":
            fixture.identity["pid"] = True
        else:
            fixture.identity["runtime_root"] = {
                **_object(fixture.identity["runtime_root"]),
                "device": True,
            }
    else:
        index = 0 if mutation.startswith("received_hello") else 1
        if mutation.startswith("synchronize"):
            index = 22
        frame = decode_frame(fixture.captures[index].wire)
        if mutation == "received_root_device_boolean":
            _object(frame["runtime_root"])["device"] = True
        elif mutation == "received_pid_boolean":
            frame["pid"] = True
        elif mutation == "received_hello_sequence_boolean":
            frame["sequence"] = False
        elif mutation == "synchronize_completed_integer":
            _object(frame["observation"])["completed"] = 1
        else:
            _object(frame["observation"])["kernel_execution_proven"] = 0
        fixture.captures[index].wire = encode_frame(frame)
        fixture.captures[index].declared_bytes = len(fixture.captures[index].wire) - 4
    with pytest.raises(AcquisitionError):
        reports.compile_acquisition(fixture, tmp_path)
    changed = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    changed["private/acquisition.json"] = canonical_json(fixture.private_record())
    republished = publish_bundle(changed, tmp_path, name_prefix="coordinated-typed-mutation")
    with pytest.raises(AcquisitionError):
        reports.replay_bundle(republished)


@pytest.mark.parametrize("field", ["device", "inode", "mode"])
@pytest.mark.parametrize("value", [True, False, -1, 1 << 64, [], {}])
def test_shared_runtime_root_schema_rejects_invalid_scalar_types_and_ranges(
    field: str, value: JsonValue
) -> None:
    fixture = reports.synthetic_fixture()
    root = {**_object(fixture.identity["runtime_root"]), field: value}
    fixture.identity["runtime_root"] = root
    with pytest.raises(AcquisitionError, match="worker_identity_mismatch"):
        parent.require_identity(fixture.identity, fixture.hello)
    with pytest.raises(worker.WorkerError):
        worker.validate_root(root)
