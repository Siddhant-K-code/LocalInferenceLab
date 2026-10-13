"""Offline evidence compilation/replay, with no unsigned physical acceptance path."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

from localinferencelab.canonical import (
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle, publish_bundle_at, read_closed_bundle
from localinferencelab.mlx_preflight_attempt import (
    consumed_attempt_id,
    verify_synthetic_attempt_record,
)
from localinferencelab.mlx_preflight_execution import (
    BLOCKERS,
    EXPECTED_WORKER_SOURCE_ID,
    Acquisition,
    _object,
    replay_captures,
    request_preflight,
    require_hello,
    require_identity,
    require_physical_launch,
)
from localinferencelab.mlx_preflight_protocol import (
    MAX_CAPTURES,
    MAX_RETAINED_OVERSIZE_BYTES,
    AcquisitionError,
    Capture,
    encode_frame,
    expected_frame,
    protocol_record,
)
from localinferencelab.mlx_preflight_worker import (
    ACTIONS,
    MAX_FRAME_BYTES,
    PROTOCOL_ID,
    SCHEMA_VERSION,
)

_CONTENT_FILES = {
    "private/acquisition.json",
    "source/worker.py",
    "protocol.json",
    "report.json",
    "report.md",
}
_MAX_PRIVATE_BYTES = 1_048_576
_MAX_WIRE_SIZE = 0xFFFFFFFF
_HEADER_BYTES = 4
_MAX_EXIT_CODE = 255
_MAX_WAIT_SIGNAL = 127
_FAILURE_CODES = {
    "deadline",
    "eof",
    "frame_size",
    "socket_error",
    "send_failed",
    "extra_output",
    "invalid_frame_json",
    "invalid_frame_object",
    "frame_fields",
    "frame_order_or_binding",
    "worker_identity_mismatch",
    "action_order",
    "action_terminal_kind",
    "error_category",
    "distribution_identity_mismatch",
    "import_observation_fields",
    "import_observation_identity",
    "unsafe_representation",
    "nonboolean_metal",
    "synchronization_observation",
    "extra_frame",
    "hello_binding",
    "frame_direction",
    "parent_io_failure",
    "child_exit_or_signal",
    "worker_reported_failure",
    "capture_bound",
    "physical_launch_closed",
    "retained_runtime_root_mismatch",
    "runtime_changed_during_attempt",
    "hello_invalid",
}


def _integer(value: JsonValue) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AcquisitionError("invalid_integer")
    return value


def _capture(value: JsonValue) -> Capture:
    item = _object(value)
    fields = {
        "direction",
        "observed_ns",
        "declared_payload_bytes",
        "retained_wire_bytes",
        "retained_sha256",
        "complete_frame_retained",
        "rejection",
        "unread_bytes",
        "wire_base64",
    }
    if item.keys() != fields or not isinstance(item["wire_base64"], str):
        raise AcquisitionError("capture_fields")
    raw = decode_bytes(item["wire_base64"])
    if len(raw) > MAX_FRAME_BYTES + 4:
        raise AcquisitionError("capture_bound")
    _integer(item["retained_wire_bytes"])
    direction = item["direction"]
    if not isinstance(direction, str) or direction not in {"parent_to_worker", "worker_to_parent"}:
        raise AcquisitionError("capture_direction")
    complete = item["complete_frame_retained"]
    if not isinstance(complete, bool):
        raise AcquisitionError("capture_completeness")
    declared = item["declared_payload_bytes"]
    if declared is not None:
        declared = _integer(declared)
        if declared > _MAX_WIRE_SIZE:
            raise AcquisitionError("capture_declared_size")
    rejection = item["rejection"]
    if rejection is not None and (
        not isinstance(rejection, str) or rejection not in _FAILURE_CODES
    ):
        raise AcquisitionError("capture_rejection_code")
    capture = Capture(
        direction,
        raw,
        _integer(item["observed_ns"]),
        declared,
        complete,
        rejection,
    )
    if capture.private_record() != item:
        raise AcquisitionError("capture_digest_or_shape")
    if (
        len(raw) >= _HEADER_BYTES
        and declared is not None
        and int.from_bytes(raw[:_HEADER_BYTES], "big") != declared
    ):
        raise AcquisitionError("capture_header_mismatch")
    if complete and (declared is None or len(raw) != 4 + declared):
        raise AcquisitionError("capture_completeness")
    if rejection == "frame_size" and len(raw) > 4 + MAX_RETAINED_OVERSIZE_BYTES:
        raise AcquisitionError("oversize_retention_bound")
    return capture


def _child_wait(
    value: JsonValue, identity: dict[str, JsonValue], processes: int
) -> dict[str, JsonValue] | None:
    if value is None:
        return None
    wait = _object(value)
    if wait.keys() != {"pid", "wait_owned", "exited", "exit_code", "signal"} or processes != 1:
        raise AcquisitionError("child_wait_fields_or_lifetime")
    pid = _integer(wait["pid"])
    if pid == 0 or pid != identity.get("pid"):
        raise AcquisitionError("child_wait_pid")
    if (
        not isinstance(wait["wait_owned"], bool)
        or wait["wait_owned"] is not True
        or not isinstance(wait["exited"], bool)
    ):
        raise AcquisitionError("child_wait_ownership")
    if wait["exited"]:
        code = _integer(wait["exit_code"])
        if code > _MAX_EXIT_CODE or wait["signal"] is not None:
            raise AcquisitionError("child_wait_exit_state")
    else:
        signal = _integer(wait["signal"])
        if not 0 < signal <= _MAX_WAIT_SIGNAL or wait["exit_code"] is not None:
            raise AcquisitionError("child_wait_signal_state")
    return wait


def _acquisition(value: JsonValue) -> Acquisition:
    item = _object(value)
    fields = {
        "schema_version",
        "hello",
        "identity",
        "captures",
        "started_ns",
        "deadline_ns",
        "process_evidence",
        "child_wait",
        "rejection",
        "cleanup_complete",
        "socketpairs_created",
        "processes_started",
        "worker_source_id",
        "authority",
        "consumed_attempt_identity",
        "synthetic_ledger_attempt",
    }
    if item.keys() != fields or item["schema_version"] != SCHEMA_VERSION:
        raise AcquisitionError("acquisition_fields")
    if item["authority"] != "unsigned_not_physical_acceptance_evidence":
        raise AcquisitionError("caller_claims_not_authority")
    if item["worker_source_id"] != EXPECTED_WORKER_SOURCE_ID:
        raise AcquisitionError("worker_source_identity")
    captures = item["captures"]
    if not isinstance(captures, list) or len(captures) > MAX_CAPTURES:
        raise AcquisitionError("captures_bound")
    rejection = item["rejection"]
    if rejection is not None and (
        not isinstance(rejection, str) or rejection not in _FAILURE_CODES
    ):
        raise AcquisitionError("terminal_rejection_code")
    if not isinstance(item["cleanup_complete"], bool):
        raise AcquisitionError("cleanup_shape")
    process = None if item["process_evidence"] is None else _object(item["process_evidence"])
    sockets, processes = _integer(item["socketpairs_created"]), _integer(item["processes_started"])
    if not 0 <= processes <= sockets <= 1:
        raise AcquisitionError("lifetime_counts")
    hello = _object(item["hello"])
    require_hello(hello)
    if hello["worker_program_id"] != EXPECTED_WORKER_SOURCE_ID:
        raise AcquisitionError("hello_worker_identity")
    if hello["deadline_ns"] != item["deadline_ns"]:
        raise AcquisitionError("hello_deadline")
    synthetic_record = (
        None
        if item["synthetic_ledger_attempt"] is None
        else verify_synthetic_attempt_record(item["synthetic_ledger_attempt"], hello)
    )
    if item["consumed_attempt_identity"] != consumed_attempt_id(synthetic_record):
        raise AcquisitionError("synthetic_attempt_consumption_binding")
    if synthetic_record is not None:
        context = _object(synthetic_record["context"])
        if canonical_json(item["started_ns"]) != canonical_json(context["started_ns"]):
            raise AcquisitionError("synthetic_attempt_time_binding")
    identity = _object(item["identity"])
    if processes:
        require_identity(identity, hello)
    elif identity:
        raise AcquisitionError("identity_without_process")
    wait = _child_wait(item["child_wait"], identity, processes)
    if processes and item["cleanup_complete"] and wait is None:
        raise AcquisitionError("cleanup_without_owned_wait")
    return Acquisition(
        hello,
        identity,
        [_capture(entry) for entry in captures],
        _integer(item["started_ns"]),
        _integer(item["deadline_ns"]),
        process,
        wait,
        rejection,
        item["cleanup_complete"],
        sockets,
        processes,
        EXPECTED_WORKER_SOURCE_ID,
        synthetic_record,
    )


def _derive_report(acquisition: Acquisition) -> dict[str, JsonValue]:
    acquisition = _acquisition(acquisition.private_record())
    validator, retained_rejection = replay_captures(
        acquisition.hello,
        acquisition.identity,
        acquisition.captures,
        acquisition.started_ns,
        acquisition.deadline_ns,
    )
    if retained_rejection is not None and acquisition.rejection != retained_rejection:
        raise AcquisitionError("terminal_retained_rejection_mismatch")
    success = (
        validator.stage == "closed"
        and retained_rejection is None
        and acquisition.rejection is None
        and acquisition.cleanup_complete
    )
    if success:
        wait = acquisition.child_wait
        if wait is None or wait.get("exit_code") != 0 or wait.get("signal") is not None:
            raise AcquisitionError("successful_sequence_without_parent_wait")
        if acquisition.processes_started != 1 or acquisition.socketpairs_created != 1:
            raise AcquisitionError("successful_sequence_without_lifetime")
    if not success and acquisition.rejection is None:
        raise AcquisitionError("incomplete_without_failure")
    value: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_evidence_report",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "synthetic_non_promotable",
        "accepted_physical_evidence": False,
        "promotable": False,
        "status": "synthetic_sequence_completed" if success else "synthetic_rejected",
        "protocol_id": PROTOCOL_ID,
        "worker_program_id": acquisition.worker_source_id,
        "private_acquisition_id": canonical_identity(acquisition.private_record()),
        "action_accounting": validator.accounting(),
        "observations": {
            action: canonical_identity(observation)
            for action, observation in validator.observations.items()
        },
        "retained_captures": [capture.public_record() for capture in acquisition.captures],
        "rejection": acquisition.rejection,
        "parent_cleanup_complete": acquisition.cleanup_complete,
        "child_exit_code": None
        if acquisition.child_wait is None
        else acquisition.child_wait.get("exit_code"),
        "child_signal": None
        if acquisition.child_wait is None
        else acquisition.child_wait.get("signal"),
        "inert_lifetime_counts": {
            "socketpairs_created": acquisition.socketpairs_created,
            "processes_started": acquisition.processes_started,
        },
        "real_mlx_actions_observed": 0,
        "native_forbidden_actions_proven_absent": False,
        "unretained_events": "unknown_no_nonaction_claim",
        "consumed_attempt_identity": consumed_attempt_id(acquisition.synthetic_ledger_attempt),
        "synthetic_parent_attempt_id": None
        if acquisition.synthetic_ledger_attempt is None
        else acquisition.synthetic_ledger_attempt["attempt_id"],
        "synthetic_durable_consumptions": 0 if acquisition.synthetic_ledger_attempt is None else 1,
        "physical_acceptance_blockers": list(BLOCKERS),
        "schema_1_0_state": "permanently_disabled",
        "atlas_accepted_physical_records": 0,
    }
    value["record_id"] = canonical_identity(value)
    return value


def human_report(value: dict[str, JsonValue]) -> str:
    """Render only fixed/sanitized summaries, never raw frames or private strings."""
    counts = _object(value["inert_lifetime_counts"])
    accounting = _object(value["action_accounting"])
    lines = [
        "# MLX model-free preflight",
        "",
        "**Synthetic / non-promotable. No accepted physical MLX evidence.**",
        "",
        f"Status: `{value['status']}`. Rejection: `{value['rejection'] or 'none'}`.",
        f"Record: `{value['record_id']}`.",
        f"Inert children: {counts['processes_started']}; "
        f"socketpairs: {counts['socketpairs_created']}.",
        f"Cleanup complete: `{value['parent_cleanup_complete']}`.",
        f"Synthetic durable consumptions: {value['synthetic_durable_consumptions']}; "
        f"audit identity: `{value['consumed_attempt_identity'] or 'none'}` (not authority).",
        "",
        "| Action | Attempted | Completed | Scope |",
        "|---|---|---|---|",
    ]
    for action in ACTIONS:
        state = _object(accounting[action])
        attempted = "unknown" if state["attempted"] is None else str(state["attempted"]).lower()
        completed = "unknown" if state["completed"] is None else str(state["completed"]).lower()
        lines.append(f"| {action} | {attempted} | {completed} | worker-reported synthetic |")
    lines.extend(
        [
            "",
            "Rejected bytes are retained only in private custody; public custody includes",
            "their retained-prefix digest, length, completeness and fixed failure code.",
            "Unread bytes and native side effects remain unknown. No automatic retry;",
            "failed consumption is never refunded.",
            "A deadline-rejected command may still have been delivered; without a trusted",
            "start/terminal acknowledgment, exposed actions remain unknown, not refused/zero.",
            "",
            "Physical launch remains closed pending independent ledger/authority/approval,",
            "exact provisioned",
            "runtime, worker review, trustworthy observations and reviewed OS/native enforcement.",
            "Python auditing is not a sandbox. Atlas accepted physical records remain **0**.",
            "",
        ]
    )
    return "\n".join(lines)


def compile_acquisition(
    acquisition: Acquisition, output_root: Path, *, output_descriptor: int | None = None
) -> tuple[Path, dict[str, JsonValue]]:
    """Seal unsigned acquisitions as irreversibly synthetic, receipt-last private bundles."""
    checked = _acquisition(acquisition.private_record())
    report = _derive_report(checked)
    worker = Path(__file__).with_name("mlx_preflight_worker.py").read_bytes()
    if digest_bytes(worker) != EXPECTED_WORKER_SOURCE_ID:
        raise AcquisitionError("worker_source_identity")
    files = {
        "private/acquisition.json": canonical_json(checked.private_record()),
        "source/worker.py": worker,
        "protocol.json": canonical_json(protocol_record()),
        "report.json": canonical_json(report),
        "report.md": human_report(report).encode("utf-8"),
    }
    if output_descriptor is None:
        path = publish_bundle(
            files, output_root, name_prefix="localinferencelab-mlx-preflight-synthetic-v1-2"
        )
    else:
        path = publish_bundle_at(
            files,
            output_root,
            output_descriptor,
            name_prefix="localinferencelab-mlx-preflight-synthetic-v1-2",
        )
    return path, report


def compile_physical_acquisition(acquisition: Acquisition) -> NoReturn:
    """Reject unsigned caller acquisitions; reviewed custody verification is not integrated."""
    del acquisition
    require_physical_launch()
    raise AcquisitionError("authentic_parent_custody_verifier_unavailable")


def replay_bundle(bundle: Path) -> dict[str, JsonValue]:
    """Verify exact source, private bytes, transcript, accounting, JSON and Markdown offline."""
    _, files = read_closed_bundle(bundle)
    content = set(files) - {"index.json", "receipt.json"}
    if content != _CONTENT_FILES:
        raise AcquisitionError("bundle_content_set")
    raw = files["private/acquisition.json"]
    if len(raw) > _MAX_PRIVATE_BYTES:
        raise AcquisitionError("private_acquisition_bound")
    parsed = load_json_bytes(raw)
    if canonical_json(parsed) != raw:
        raise AcquisitionError("private_acquisition_noncanonical")
    report = _derive_report(_acquisition(parsed))
    if (
        digest_bytes(files["source/worker.py"]) != EXPECTED_WORKER_SOURCE_ID
        or files["protocol.json"] != canonical_json(protocol_record())
        or files["report.json"] != canonical_json(report)
        or files["report.md"] != human_report(report).encode("utf-8")
    ):
        raise AcquisitionError("bundle_source_report_or_protocol_mismatch")
    return report


def verify_gate_refusal(value: JsonValue) -> dict[str, JsonValue]:
    """Verify static physical refusal without installed-distribution or host observations."""
    expected = request_preflight()
    if canonical_json(value) != canonical_json(expected):
        raise AcquisitionError("gate_refusal_mismatch")
    return expected


def synthetic_fixture() -> Acquisition:
    """Deterministic invented events, not a worker/process launch or runtime observation."""
    started, deadline = 1_000_000, 2_000_000
    identity: dict[str, JsonValue] = {
        "pid": 123,
        "parent_pid": 122,
        "interpreter_sha256": "sha256:" + "d" * 64,
        "runtime_root": {"device": 1, "inode": 2, "mode": 0o555},
        "worker_program_id": EXPECTED_WORKER_SOURCE_ID,
    }
    session = canonical_identity({"challenge": "a" * 64, "nonce": "b" * 64})
    hello = expected_frame(
        "hello",
        0,
        session,
        challenge="a" * 64,
        nonce="b" * 64,
        deadline_ns=deadline,
        interpreter_sha256=identity["interpreter_sha256"],
        runtime_root=identity["runtime_root"],
        distributions=[
            {"name": "mlx", "version": "0.30.4", "metadata_sha256": "sha256:" + "c" * 64},
            {"name": "mlx-lm", "version": "0.30.6", "metadata_sha256": "sha256:" + "c" * 64},
        ],
        worker_program_id=EXPECTED_WORKER_SOURCE_ID,
        import_files={
            "mlx.core": {"relative_file": "mlx/core.fake.so", "sha256": "sha256:" + "c" * 64},
            "mlx_lm": {"relative_file": "mlx_lm/__init__.py", "sha256": "sha256:" + "c" * 64},
        },
    )
    observations: tuple[JsonValue, ...] = (
        hello["distributions"],
        {"module": "mlx.core", "relative_file": "mlx/core.fake.so", "sha256": "sha256:" + "c" * 64},
        {"module": "mlx_lm", "relative_file": "mlx_lm/__init__.py", "sha256": "sha256:" + "c" * 64},
        "Device(gpu, 0)",
        "Stream(0)",
        True,
        {"completed": True, "scope": "mlx_default_streams", "kernel_execution_proven": False},
    )
    captures: list[Capture] = []

    def append(direction: str, frame: dict[str, JsonValue]) -> None:
        wire = encode_frame(frame)
        captures.append(Capture(direction, wire, started + len(captures) + 1, len(wire) - 4, True))

    append("parent_to_worker", hello)
    append(
        "worker_to_parent",
        expected_frame(
            "identity", 1, session, **identity, challenge=hello["challenge"], nonce=hello["nonce"]
        ),
    )
    sequence = 2
    for action, observation in zip(ACTIONS, observations, strict=True):
        append("parent_to_worker", expected_frame("run_action", sequence, session, action=action))
        append(
            "worker_to_parent",
            expected_frame("action_started", sequence + 1, session, action=action),
        )
        append(
            "worker_to_parent",
            expected_frame(
                "action_completed", sequence + 2, session, action=action, observation=observation
            ),
        )
        sequence += 3
    append("parent_to_worker", expected_frame("shutdown", sequence, session))
    append("worker_to_parent", expected_frame("shutdown_ack", sequence + 1, session))
    return Acquisition(
        hello,
        identity,
        captures,
        started,
        deadline,
        {
            "method": "synthetic_fixture_only",
            "available": False,
            "matched": None,
        },
        {"pid": 123, "wait_owned": True, "exited": True, "exit_code": 0, "signal": None},
        None,
        True,
        1,
        1,
        EXPECTED_WORKER_SOURCE_ID,
    )
