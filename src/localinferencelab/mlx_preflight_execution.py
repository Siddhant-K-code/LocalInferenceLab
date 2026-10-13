"""Parent acquisition machinery, with an unconditional physical pre-launch gate."""

from __future__ import annotations

import fcntl
import os
import socket
import stat
import threading
import time
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
)
from localinferencelab.mlx_custody import (
    _create_interpreter_snapshot_at,
    _create_worker_snapshot_at,
    _open_descriptors,
    _open_directory_no_follow,
    _open_private_output_root,
    _parent_process_evidence,
    _read_launch_target,
    _revalidate_output_root_path,
    _terminate_and_wait,
    _wait_child,
    _write_exclusive_at,
)
from localinferencelab.mlx_manifest import (
    _scan_open_tree,
    compile_runtime_manifest,
    verify_runtime_manifest,
)
from localinferencelab.mlx_preflight_attempt import (
    SyntheticParentAttempt,
    consumed_attempt_id,
    parent_bindings_for_attempt,
    revalidate_synthetic_attempt,
    synthetic_attempt_record,
)
from localinferencelab.mlx_preflight_custody import custody_bridge_spec_1_1
from localinferencelab.mlx_preflight_ledger import (
    ParentBindings,
    SyntheticAttemptPermit,
    SyntheticAuthorizationLedger,
)
from localinferencelab.mlx_preflight_protocol import (
    AcquisitionError,
    Capture,
    RetainingChannel,
    decode_frame,
    expected_frame,
    require_frame,
)
from localinferencelab.mlx_preflight_worker import (
    ACTIONS,
    ENVIRONMENT,
    IDENTITY_FIELDS,
    INTERPRETER_FD,
    MAX_LIFETIME_NS,
    PROTOCOL_ID,
    RUNTIME_FD,
    SCHEMA_VERSION,
    WORKER_FD,
    WorkerError,
    validate_hello,
    validate_identity,
)
from localinferencelab.mlx_qualification_publication import (
    EXPECTED_QUALIFICATION_RECORD_ID,
    EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
)
from localinferencelab.mlx_runtime_target import runtime_target_anchor

# This is a NEW implementation identity, not the old reviewed source/API approval.
EXPECTED_WORKER_SOURCE_ID = (
    "sha256:063f357df20b2b58be6b1b8b68c6321a33fdd15ba169e3c6173838524fee694a"
)
BLOCKERS = (
    "schema_1_2_production_ledger_binding_and_dispatch_not_reviewed_and_integrated",
    "reviewed_authorization_authority_unavailable",
    "fresh_explicit_human_runtime_approval_unavailable",
    "independent_trustworthy_current_time_and_host_provenance_unavailable",
    "exact_provisioned_runtime_and_native_loader_closure_unavailable",
    "new_schema_1_2_worker_source_and_protocol_not_independently_reviewed",
    "darwin_parent_observed_child_executable_identity_unavailable",
    "reviewed_os_native_network_and_forbidden_action_enforcement_unavailable",
)
_IDENTITY_FIELDS = {
    "pid",
    "parent_pid",
    "interpreter_sha256",
    "runtime_root",
    "worker_program_id",
    "challenge",
    "nonce",
}
_STANDARD_FDS = 2
_REPRESENTATION_BOUND = 256
_SYNTHETIC_DISPATCH_PID = os.getpid()
_SYNTHETIC_DISPATCH_LOCK = threading.Lock()
_SYNTHETIC_DISPATCHED: weakref.WeakKeyDictionary[SyntheticAuthorizationLedger, str] = (
    weakref.WeakKeyDictionary()
)


def require_hello(value: dict[str, JsonValue]) -> None:
    """Translate shared worker schema rejection to one privacy-safe parent code."""
    try:
        validate_hello(value)
    except WorkerError as error:
        raise AcquisitionError("hello_invalid") from error


def require_identity(value: dict[str, JsonValue], hello: dict[str, JsonValue]) -> None:
    """Validate observed process identities before comparison or public projection."""
    try:
        validate_identity(value, hello)
    except WorkerError as error:
        raise AcquisitionError("worker_identity_mismatch") from error


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise AcquisitionError("expected_object")
    return value


def _root(descriptor: int) -> dict[str, JsonValue]:
    metadata = os.fstat(descriptor)
    return {"device": metadata.st_dev, "inode": metadata.st_ino, "mode": metadata.st_mode & 0o777}


def capability_report() -> dict[str, JsonValue]:
    """Observe committed static contracts only; never inspect the runtime host."""
    spec = custody_bridge_spec_1_1()
    return {
        "record_type": "mlx_preflight_implementation_capability",
        "schema_version": SCHEMA_VERSION,
        "qualification_record_id": EXPECTED_QUALIFICATION_RECORD_ID,
        "qualification_bindings": spec["identity_bindings"],
        "worker_program_id": EXPECTED_WORKER_SOURCE_ID,
        "protocol_id": PROTOCOL_ID,
        "old_worker_api_anchor_id": EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
        "old_api_anchor_approves_new_worker": False,
        "worker_operations_implemented": True,
        "parent_transport_and_rejection_retention_implemented": True,
        "offline_compiler_verifier_report_implemented": True,
        "merged_ledger_synthetic_parent_integration_implemented": True,
        "physical_launch_enabled": False,
        "accepted_physical_evidence": False,
        "schema_1_0_state": "permanently_disabled",
        "blockers": list(BLOCKERS),
        "real_action_counters": {
            "provisioning": 0,
            "authorization_consumptions": 0,
            "process_starts": 0,
            "socket_creations": 0,
            "mlx_imports": 0,
            "device_queries": 0,
            "synchronizations": 0,
        },
    }


def require_physical_launch() -> None:
    """No path, receipt, object, boolean, synthetic permit or callback opens this gate."""
    raise AcquisitionError("physical_launch_closed")


def request_preflight() -> dict[str, JsonValue]:
    """Return a canonical pre-spawn refusal without acquiring any runtime inputs."""
    report = capability_report()
    report["record_type"] = "mlx_preflight_gate_refusal"
    report["disposition"] = "refused_before_root_socket_process_import_or_consumption"
    report["record_id"] = canonical_identity(report)
    return report


class SessionValidator:
    """Shared online/offline state machine for exact parent commands and worker events."""

    def __init__(self, hello: dict[str, JsonValue], identity: dict[str, JsonValue]) -> None:
        """Start with parent-observed identities, not worker-selected input claims."""
        require_hello(hello)
        if identity:
            require_identity(identity, hello)
        self.hello = hello
        self.identity = identity
        self.sequence = 0
        self.stage = "hello"
        self.action_index = 0
        self.terminal = False
        self.states = dict.fromkeys(ACTIONS, "refused_not_requested")
        self.observations: dict[str, JsonValue] = {}
        self.delivery = dict.fromkeys(ACTIONS, "not_exposed")

    def note_exposure(self, capture: Capture) -> None:
        """Retained parent delivery is distinct from protocol/deadline acceptance."""
        if (
            capture.direction != "parent_to_worker"
            or not capture.wire
            or self.stage not in {"command", "started", "completed"}
        ):
            return
        action = ACTIONS[self.action_index]
        if capture.complete:
            try:
                frame = decode_frame(capture.wire)
            except AcquisitionError:
                frame = {}
            candidate = frame.get("action")
            if (
                frame.get("kind") == "run_action"
                and isinstance(candidate, str)
                and candidate in ACTIONS
            ):
                action = candidate
            self.delivery[action] = "complete_parent_command_exposed"
        else:
            self.delivery[action] = "partial_parent_command_exposure"
        if self.states[action] == "refused_not_requested":
            self.states[action] = "command_exposed_acceptance_unknown"

    def _verify_observation(self, action: str, value: JsonValue) -> None:
        if action == ACTIONS[0]:
            if value != self.hello["distributions"]:
                raise AcquisitionError("distribution_identity_mismatch")
        elif action in {"import_mlx", "import_mlx_lm"}:
            item = _object(value)
            if item.keys() != {"module", "relative_file", "sha256"}:
                raise AcquisitionError("import_observation_fields")
            expected = "mlx.core" if action == "import_mlx" else "mlx_lm"
            files = _object(self.hello["import_files"])
            if item != {"module": expected, **_object(files[expected])}:
                raise AcquisitionError("import_observation_identity")
        elif action in {"default_device", "default_stream"}:
            if (
                not isinstance(value, str)
                or not value
                or len(value.encode("utf-8")) > _REPRESENTATION_BOUND
                or any(
                    character
                    not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_(), .=:-"
                    for character in value
                )
            ):
                raise AcquisitionError("unsafe_representation")
        elif action == "metal_is_available":
            if not isinstance(value, bool):
                raise AcquisitionError("nonboolean_metal")
        else:
            item = _object(value)
            if (
                item.keys() != {"completed", "scope", "kernel_execution_proven"}
                or item["completed"] is not True
                or item["scope"] != "mlx_default_streams"
                or item["kernel_execution_proven"] is not False
            ):
                raise AcquisitionError("synchronization_observation")

    def accept(self, direction: str, value: dict[str, JsonValue]) -> None:
        session = cast("str", self.hello["session_id"])
        if self.stage == "hello":
            require_hello(value)
            if direction != "parent_to_worker" or value != self.hello:
                raise AcquisitionError("hello_binding")
            self.stage = "identity"
        elif self.stage == "identity":
            require_frame(value, "identity", self.sequence, session, _IDENTITY_FIELDS)
            require_identity({field: value[field] for field in IDENTITY_FIELDS}, self.hello)
            expected = expected_frame(
                "identity",
                self.sequence,
                session,
                **self.identity,
                challenge=self.hello["challenge"],
                nonce=self.hello["nonce"],
            )
            if direction != "worker_to_parent" or value != expected:
                raise AcquisitionError("worker_identity_mismatch")
            self.stage = "command"
        elif self.stage in {"command", "started", "completed"}:
            action = ACTIONS[self.action_index]
            if self.stage == "command":
                require_frame(value, "run_action", self.sequence, session, {"action"})
                if direction != "parent_to_worker" or value["action"] != action:
                    raise AcquisitionError("action_order")
                self.states[action] = "command_sent_attempt_unknown"
                self.stage = "started"
            elif self.stage == "started":
                require_frame(value, "action_started", self.sequence, session, {"action"})
                if direction != "worker_to_parent" or value["action"] != action:
                    raise AcquisitionError("action_order")
                self.states[action] = "attempted_completion_unknown"
                self.stage = "completed"
            else:
                kind = value.get("kind")
                if not isinstance(kind, str) or kind not in {"action_completed", "action_failed"}:
                    raise AcquisitionError("action_terminal_kind")
                fields = {
                    "action",
                    "observation" if kind == "action_completed" else "error_category",
                }
                require_frame(value, kind, self.sequence, session, fields)
                if direction != "worker_to_parent" or value["action"] != action:
                    raise AcquisitionError("action_order")
                if kind == "action_failed":
                    category = value["error_category"]
                    if not isinstance(category, str) or category not in {
                        "WorkerError",
                        "ImportError",
                        "ModuleNotFoundError",
                        "AttributeError",
                        "OSError",
                        "RuntimeError",
                        "TypeError",
                        "ValueError",
                        "PermissionError",
                        "FileNotFoundError",
                    }:
                        raise AcquisitionError("error_category")
                    self.states[action] = "attempted_reported_failed_completion_unknown"
                    self.stage = "failed"
                    self.terminal = True
                else:
                    self._verify_observation(action, value["observation"])
                    self.states[action] = "worker_reported_completed"
                    self.observations[action] = value["observation"]
                    self.action_index += 1
                    self.stage = "shutdown" if self.action_index == len(ACTIONS) else "command"
        elif self.stage in {"shutdown", "shutdown_ack"}:
            kind = self.stage
            require_frame(value, kind, self.sequence, session, set())
            expected_direction = "parent_to_worker" if kind == "shutdown" else "worker_to_parent"
            if direction != expected_direction:
                raise AcquisitionError("frame_direction")
            self.stage = "shutdown_ack" if kind == "shutdown" else "closed"
            self.terminal = self.stage == "closed"
        else:
            raise AcquisitionError("extra_frame")
        self.sequence += 1

    def accounting(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for action, state in self.states.items():
            attempted: JsonValue = (
                None
                if state in {"command_sent_attempt_unknown", "command_exposed_acceptance_unknown"}
                else (state != "refused_not_requested")
            )
            completed: JsonValue = (
                True
                if state == "worker_reported_completed"
                else (False if state == "refused_not_requested" else None)
            )
            result[action] = {
                "state": state,
                "attempted": attempted,
                "completed": completed,
                "delivery": self.delivery[action],
                "observation_scope": "worker_report_not_native_nonaction_proof",
            }
        return result


@dataclass(slots=True)
class _PreparedLaunch:
    interpreter_bytes: bytes
    interpreter_identity: dict[str, JsonValue]
    worker_bytes: bytes
    runtime_descriptor: int
    output_descriptor: int
    custody_descriptor: int
    output_path: Path
    runtime_root: dict[str, JsonValue]
    distributions: list[JsonValue]
    manifest_id: str
    import_files: dict[str, JsonValue]
    runtime_manifest: dict[str, JsonValue]


def _prepare_launch(
    runtime_root: Path,
    interpreter_path: Path,
    output_root: Path,
    custody_root: Path,
    runtime_manifest_value: JsonValue,
    scan_spec: JsonValue,
) -> _PreparedLaunch:
    """Observe/revalidate supplied provisioned bytes; production never reaches this yet."""
    manifest = verify_runtime_manifest(runtime_manifest_value)
    target = _object(_object(runtime_target_anchor()["prospective_target"])["interpreter"])
    worker_path = Path(__file__).with_name("mlx_preflight_worker.py")
    interpreter_identity, interpreter_bytes = _read_launch_target(
        interpreter_path, "preflight interpreter", executable=True
    )
    worker_identity, worker_bytes = _read_launch_target(
        worker_path, "preflight worker", executable=False
    )
    if interpreter_identity["sha256"] != target["executable_sha256"]:
        raise AcquisitionError("exact_interpreter_mismatch")
    if worker_identity["sha256"] != EXPECTED_WORKER_SOURCE_ID:
        raise AcquisitionError("worker_source_mismatch")
    spec = _object(scan_spec)
    expected_selected = custody_bridge_spec_1_1()["selected_distributions"]
    distributions = spec.get("expected_distributions")
    if not isinstance(distributions, list):
        raise AcquisitionError("distribution_spec")
    selected = sorted(
        (f"{_object(item)['name']}=={_object(item)['version']}" for item in distributions),
        key=lambda pin: pin.split("==")[0],
    )
    if selected != expected_selected:
        raise AcquisitionError("exact_distribution_closure_mismatch")
    if spec.get("python") != {
        "implementation": "cpython",
        "version": "3.13.15",
        "abi": "cp313",
        "platform": "macosx-11.0-arm64",
    }:
        raise AcquisitionError("exact_interpreter_target_spec_mismatch")
    rescanned = compile_runtime_manifest(spec, runtime_root, interpreter_path, worker_path)
    if canonical_json(rescanned) != canonical_json(manifest):
        raise AcquisitionError("runtime_interpreter_worker_or_root_mismatch")
    descriptors: list[int] = []
    try:
        runtime_descriptor = _open_directory_no_follow(runtime_root, "runtime root")
        descriptors.append(runtime_descriptor)
        output_descriptor = _open_private_output_root(output_root)
        descriptors.append(output_descriptor)
        custody_descriptor = _open_private_output_root(custody_root)
        descriptors.append(custody_descriptor)
        objects = [_root(descriptor) for descriptor in descriptors]
        if len({(item["device"], item["inode"]) for item in objects}) != len(objects):
            raise AcquisitionError("roots_not_distinct")
        manifest_distributions = cast("list[JsonValue]", manifest["distributions"])
        identities: list[JsonValue] = []
        for item in manifest_distributions:
            record = _object(item)
            identities.append(
                {
                    "name": record["name"],
                    "version": record["version"],
                    "metadata_sha256": record["metadata_sha256"],
                }
            )
        records = {
            _object(item)["path"]: _object(item)
            for item in cast("list[JsonValue]", manifest["files"])
        }
        imports: dict[str, JsonValue] = {}
        for module, path in (
            ("mlx.core", "mlx/core.cpython-313-darwin.so"),
            ("mlx_lm", "mlx_lm/__init__.py"),
        ):
            imports[module] = {"relative_file": path, "sha256": records[path]["sha256"]}
        observed_root, observed_files = _scan_open_tree(runtime_descriptor)
        if observed_root != manifest["package_root"] or observed_files != manifest["files"]:
            raise AcquisitionError("retained_runtime_root_mismatch")
        return _PreparedLaunch(
            interpreter_bytes,
            interpreter_identity,
            worker_bytes,
            runtime_descriptor,
            output_descriptor,
            custody_descriptor,
            output_root.absolute(),
            objects[0],
            identities,
            cast("str", manifest["manifest_id"]),
            imports,
            manifest,
        )
    except (ContractError, OSError, KeyError):
        for descriptor in descriptors:
            os.close(descriptor)
        raise


def _spawn_owned(
    executable: Path,
    interpreter_descriptor: int,
    source_descriptor: int,
    runtime_descriptor: int,
    child_endpoint: socket.socket,
) -> int:
    # A second gate protects direct calls to this private helper, not just CLI dispatch.
    require_physical_launch()
    originals = [
        source_descriptor,
        child_endpoint.fileno(),
        interpreter_descriptor,
        runtime_descriptor,
    ]
    copies: list[int] = []
    try:
        minimum = max(_open_descriptors() | {RUNTIME_FD}) + 1
        for descriptor in originals:
            duplicate = fcntl.fcntl(descriptor, fcntl.F_DUPFD_CLOEXEC, minimum)
            copies.append(duplicate)
            minimum = duplicate + 1
        targets = [0, WORKER_FD, INTERPRETER_FD, RUNTIME_FD]
        actions: list[tuple[int, ...] | tuple[int, int, str, int, int]] = [
            (os.POSIX_SPAWN_DUP2, source, destination)
            for source, destination in zip(copies, targets, strict=True)
        ]
        actions.extend(
            [
                (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
                (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
            ]
        )
        actions.extend(
            (os.POSIX_SPAWN_CLOSE, descriptor)
            for descriptor in sorted(_open_descriptors())
            if descriptor > _STANDARD_FDS and descriptor not in targets
        )
        return os.posix_spawn(
            str(executable),
            [str(executable), "-I", "-S", "-E", "-s", "-B", "-"],
            ENVIRONMENT,
            file_actions=actions,
        )
    finally:
        for descriptor in copies:
            os.close(descriptor)


@dataclass(slots=True)
class Acquisition:
    """Parent observations only; these unsigned inputs cannot establish physical authority."""

    hello: dict[str, JsonValue]
    identity: dict[str, JsonValue]
    captures: list[Capture]
    started_ns: int
    deadline_ns: int
    process_evidence: dict[str, JsonValue] | None
    child_wait: dict[str, JsonValue] | None
    rejection: str | None
    cleanup_complete: bool
    socketpairs_created: int
    processes_started: int
    worker_source_id: str
    synthetic_ledger_attempt: dict[str, JsonValue] | None = None

    def private_record(self) -> dict[str, JsonValue]:
        return {
            "schema_version": SCHEMA_VERSION,
            "hello": self.hello,
            "identity": self.identity,
            "captures": [capture.private_record() for capture in self.captures],
            "started_ns": self.started_ns,
            "deadline_ns": self.deadline_ns,
            "process_evidence": self.process_evidence,
            "child_wait": self.child_wait,
            "rejection": self.rejection,
            "cleanup_complete": self.cleanup_complete,
            "socketpairs_created": self.socketpairs_created,
            "processes_started": self.processes_started,
            "worker_source_id": self.worker_source_id,
            "authority": "unsigned_not_physical_acceptance_evidence",
            "consumed_attempt_identity": consumed_attempt_id(self.synthetic_ledger_attempt),
            "synthetic_ledger_attempt": self.synthetic_ledger_attempt,
        }


def _claim_synthetic_dispatch(ledger: SyntheticAuthorizationLedger) -> str:
    if os.getpid() != _SYNTHETIC_DISPATCH_PID:
        raise AcquisitionError("synthetic_parent_dispatch_fork")
    with _SYNTHETIC_DISPATCH_LOCK:
        if ledger in _SYNTHETIC_DISPATCHED:
            raise AcquisitionError("synthetic_parent_dispatch_terminal")
        dispatch_id = digest_bytes(os.urandom(32))
        _SYNTHETIC_DISPATCHED[ledger] = dispatch_id
        return dispatch_id


def _retain_synthetic_dispatch_refusal(
    launch: _PreparedLaunch,
    attempt: SyntheticParentAttempt,
    bindings: ParentBindings,
    dispatch_id: str,
) -> None:
    metadata = os.fstat(launch.custody_descriptor)
    pin = {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "owner": metadata.st_uid,
        "mode": stat.S_IMODE(metadata.st_mode),
    }
    if not stat.S_ISDIR(metadata.st_mode) or canonical_json(pin) != canonical_json(
        bindings.roots[0].to_dict()
    ):
        raise AcquisitionError("synthetic_dispatch_refusal_custody_unavailable")
    hello = attempt.hello()
    require_hello(hello)
    record: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_synthetic_terminal_dispatch_refusal",
        "schema_version": "1.0",
        "evidence_scope": "synthetic_non_promotable",
        "session_id": hello["session_id"],
        "parent_dispatch_id": dispatch_id,
        "context_id": digest_bytes(attempt.context_bytes),
        "parent_bindings_id": canonical_identity(bindings.to_dict()),
        "authorization_id": _object(bindings.to_dict()["authorization"])["authorization_id"],
        "parent_dispatch_state": "terminal_refused_before_callback",
        "callback_invoked": False,
        "durable_consumption_audit": "unavailable_without_validated_ledger_callback",
        "action_attempts_and_completions": "unknown_no_native_nonaction_claim",
        "permit_scope": "parent_adapter_only_not_raw_ledger_revocation",
        "retry_refund_or_remint": False,
        "accepted_physical_evidence": False,
        "promotable": False,
    }
    record["record_id"] = canonical_identity(record)
    name = ".mlx-preflight-dispatch-refused-" + dispatch_id[7:] + ".json"
    _write_exclusive_at(launch.custody_descriptor, name, canonical_json(record))
    os.fsync(launch.custody_descriptor)


def dispatch_synthetic_attempt(
    launch: _PreparedLaunch,
    attempt: SyntheticParentAttempt,
    ledger: SyntheticAuthorizationLedger,
    bindings: ParentBindings,
    permit: SyntheticAttemptPermit,
) -> Acquisition:
    """Use only a live merged-ledger synthetic permit; no callback or native-gate bypass."""
    if type(ledger) is not SyntheticAuthorizationLedger:
        raise AcquisitionError("synthetic_ledger_origin")
    dispatch_id = _claim_synthetic_dispatch(ledger)
    callback_invoked = False

    def collect(consumption: dict[str, JsonValue]) -> Acquisition:
        nonlocal callback_invoked
        callback_invoked = True
        revalidate_synthetic_attempt(attempt, launch)
        record = synthetic_attempt_record(attempt, bindings, consumption)
        return _collect_owned_session(launch, synthetic_attempt=attempt, synthetic_record=record)

    try:
        expected = parent_bindings_for_attempt(
            _object(bindings.to_dict()["authorization"]), attempt
        )
        if canonical_json(expected.to_dict()) != canonical_json(bindings.to_dict()):
            raise AcquisitionError("synthetic_attempt_parent_bindings")
        return ledger.dispatch_synthetic_once(permit, bindings, collect)
    except (ContractError, OSError):
        if not callback_invoked:
            _retain_synthetic_dispatch_refusal(launch, attempt, bindings, dispatch_id)
        raise


def consume_synthetic_attempt(
    launch: _PreparedLaunch,
    attempt: SyntheticParentAttempt,
    ledger: SyntheticAuthorizationLedger,
    authorization: JsonValue,
) -> Acquisition:
    """Consume durably once, then acquire inert test evidence; never refund or auto-retry."""
    if type(ledger) is not SyntheticAuthorizationLedger:
        raise AcquisitionError("synthetic_ledger_origin")
    bindings = parent_bindings_for_attempt(authorization, attempt)
    revalidate_synthetic_attempt(attempt, launch)
    permit = ledger.consume_once(authorization, bindings)
    return dispatch_synthetic_attempt(launch, attempt, ledger, bindings, permit)


def _acquire_prepared(launch: _PreparedLaunch) -> Acquisition:
    """Refuse before snapshots or sockets; no synthetic production dispatch option."""
    require_physical_launch()
    return _collect_owned_session(launch)


def _collect_owned_session(
    launch: _PreparedLaunch,
    *,
    synthetic_attempt: SyntheticParentAttempt | None = None,
    synthetic_record: dict[str, JsonValue] | None = None,
) -> Acquisition:
    """Parent lifetime/framing implementation; tests replace spawn with an inert child."""
    started = time.monotonic_ns()
    deadline = started + MAX_LIFETIME_NS
    challenge, nonce = os.urandom(32).hex(), os.urandom(32).hex()
    hello = expected_frame(
        "hello",
        0,
        canonical_identity({"challenge": challenge, "nonce": nonce}),
        challenge=challenge,
        nonce=nonce,
        deadline_ns=deadline,
        interpreter_sha256=launch.interpreter_identity["sha256"],
        runtime_root=launch.runtime_root,
        distributions=launch.distributions,
        worker_program_id=digest_bytes(launch.worker_bytes),
        import_files=launch.import_files,
    )
    if synthetic_attempt is not None:
        if synthetic_record is None:
            raise AcquisitionError("synthetic_attempt_consumption")
        context = synthetic_attempt.context()
        started, deadline = cast("int", context["started_ns"]), cast("int", context["deadline_ns"])
        hello = synthetic_attempt.hello()
    elif synthetic_record is not None:
        raise AcquisitionError("synthetic_attempt_context")
    result = Acquisition(
        hello,
        {},
        [],
        started,
        deadline,
        None,
        None,
        None,
        False,
        0,
        0,
        digest_bytes(launch.worker_bytes),
        synthetic_record,
    )
    snapshot_name: str | None = None
    owned_descriptors: list[int] = []
    endpoints: list[socket.socket] = []
    child_pid: int | None = None
    channel: RetainingChannel | None = None
    retention_descriptor: int | None = None
    try:
        observed_root, observed_files = _scan_open_tree(launch.runtime_descriptor)
        if (
            observed_root != launch.runtime_manifest["package_root"]
            or observed_files != launch.runtime_manifest["files"]
        ):
            raise AcquisitionError("retained_runtime_root_mismatch")
        retention_name = ".mlx-preflight-" + cast("str", hello["session_id"])[7:]
        os.mkdir(retention_name, 0o700, dir_fd=launch.custody_descriptor)
        os.fsync(launch.custody_descriptor)
        retention_descriptor = os.open(
            retention_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=launch.custody_descriptor,
        )
        if synthetic_record is not None:
            _write_exclusive_at(
                retention_descriptor, "attempt.json", canonical_json(synthetic_record)
            )
            os.fsync(retention_descriptor)
        retention_index = 0
        last_capture_bytes: bytes | None = None

        def retain(capture: Capture) -> None:
            nonlocal retention_index, last_capture_bytes
            if retention_descriptor is None:
                raise AcquisitionError("retention_descriptor_unavailable")
            capture_bytes = canonical_json(capture.private_record())
            if capture_bytes == last_capture_bytes:
                return
            content = canonical_json(
                {
                    "session_id": hello["session_id"],
                    "event": retention_index,
                    "capture": capture.private_record(),
                    "scope": "unsigned_parent_retention_not_authorization",
                    "consumed_attempt_identity": consumed_attempt_id(synthetic_record),
                    "synthetic_attempt_id": None
                    if synthetic_record is None
                    else synthetic_record["attempt_id"],
                }
            )
            _write_exclusive_at(retention_descriptor, f"event-{retention_index:03d}.json", content)
            os.fsync(retention_descriptor)
            last_capture_bytes = capture_bytes
            retention_index += 1

        source_descriptor, _source = _create_worker_snapshot_at(
            launch.custody_descriptor, launch.worker_bytes, "mlx_preflight_worker.py"
        )
        owned_descriptors.append(source_descriptor)
        interpreter_descriptor, interpreter, snapshot_name = _create_interpreter_snapshot_at(
            launch.custody_descriptor, launch.interpreter_bytes
        )
        owned_descriptors.append(interpreter_descriptor)
        parent_endpoint, child_endpoint = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        result.socketpairs_created = 1
        endpoints.extend([parent_endpoint, child_endpoint])
        _revalidate_output_root_path(launch.output_path, launch.output_descriptor)
        # The executable pathname is parent-created, never caller/worker selected.
        executable = Path(f"/dev/fd/{launch.custody_descriptor}") / snapshot_name
        child_pid = _spawn_owned(
            executable,
            interpreter_descriptor,
            source_descriptor,
            launch.runtime_descriptor,
            child_endpoint,
        )
        result.processes_started = 1
        child_endpoint.close()
        result.identity = {
            "pid": child_pid,
            "parent_pid": os.getpid(),
            "interpreter_sha256": interpreter["sha256"],
            "runtime_root": launch.runtime_root,
            "worker_program_id": result.worker_source_id,
        }
        result.process_evidence = _parent_process_evidence(child_pid, os.getpid(), interpreter)
        channel = RetainingChannel(parent_endpoint, deadline, retain)
        result.captures = channel.captures
        validator = SessionValidator(hello, result.identity)

        def send(value: dict[str, JsonValue]) -> None:
            channel.send(value)
            validator.accept("parent_to_worker", value)

        def receive() -> None:
            value = channel.receive()
            if time.monotonic_ns() > deadline:
                channel.reject_latest("deadline")
                raise AcquisitionError("deadline")
            try:
                validator.accept("worker_to_parent", value)
            except AcquisitionError as error:
                channel.reject_latest(str(error))
                raise

        send(hello)
        receive()
        for action in ACTIONS:
            send(
                expected_frame(
                    "run_action",
                    validator.sequence,
                    cast("str", hello["session_id"]),
                    action=action,
                )
            )
            receive()
            receive()
            if validator.stage == "failed":
                result.rejection = "worker_reported_failure"
                break
        if result.rejection is None:
            send(expected_frame("shutdown", validator.sequence, cast("str", hello["session_id"])))
            receive()
        channel.expect_eof()
        result.child_wait = _wait_child(child_pid, deadline)
        child_pid = None
        if result.child_wait["exit_code"] != 0 or result.child_wait["signal"] is not None:
            result.rejection = "child_exit_or_signal"
        final_root, final_files = _scan_open_tree(launch.runtime_descriptor)
        if final_root != observed_root or final_files != observed_files:
            result.rejection = "runtime_changed_during_attempt"
    except (ContractError, OSError) as error:
        result.rejection = (
            str(error) if isinstance(error, AcquisitionError) else "parent_io_failure"
        )
    finally:
        endpoints_closed = False
        try:
            for endpoint in endpoints:
                endpoint.close()
            endpoints_closed = True
            if child_pid is not None:
                result.child_wait = _terminate_and_wait(child_pid)
                child_pid = None
        finally:
            try:
                for descriptor in owned_descriptors:
                    os.close(descriptor)
                if snapshot_name is not None:
                    os.unlink(snapshot_name, dir_fd=launch.custody_descriptor)
                    os.fsync(launch.custody_descriptor)
                result.cleanup_complete = endpoints_closed and child_pid is None
            finally:
                if retention_descriptor is not None:
                    try:
                        _write_exclusive_at(
                            retention_descriptor,
                            "terminal.json",
                            canonical_json(result.private_record()),
                        )
                        os.fsync(retention_descriptor)
                    finally:
                        os.close(retention_descriptor)
    return result


def replay_captures(
    hello: dict[str, JsonValue],
    identity: dict[str, JsonValue],
    captures: list[Capture],
    started_ns: int,
    deadline_ns: int,
) -> tuple[SessionValidator, str | None]:
    """Reconstruct all retained actions, stopping at the first retained rejection."""
    if not 0 < deadline_ns - started_ns <= MAX_LIFETIME_NS:
        raise AcquisitionError("invalid_deadline")
    validator = SessionValidator(hello, identity)
    prior = started_ns
    rejection: str | None = None
    for capture in captures:
        if (
            not isinstance(capture.direction, str)
            or capture.direction not in {"parent_to_worker", "worker_to_parent"}
            or (capture.rejection is not None and not isinstance(capture.rejection, str))
        ):
            raise AcquisitionError("capture_enum_fields")
        if capture.observed_ns < prior:
            raise AcquisitionError("nonmonotonic_capture")
        prior = capture.observed_ns
        if rejection is not None:
            raise AcquisitionError("captures_after_rejection")
        validator.note_exposure(capture)
        if capture.observed_ns > deadline_ns:
            rejection = "deadline"
        elif not capture.complete:
            rejection = capture.rejection
            if rejection is None:
                raise AcquisitionError("unexplained_partial_capture")
        else:
            try:
                value = decode_frame(capture.wire)
                validator.accept(capture.direction, value)
            except AcquisitionError as error:
                rejection = str(error)
        if rejection != capture.rejection:
            raise AcquisitionError("capture_rejection_mismatch")
    return validator, rejection
