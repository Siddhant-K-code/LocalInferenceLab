"""Retained OpenSSH signed-request evidence; no signing, enrollment or production dispatch."""

from __future__ import annotations

import base64
import binascii
import contextlib
import os
import secrets
import selectors
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle_at
from localinferencelab.mlx_custody import (
    _open_directory_no_follow,
    _write_exclusive_at,
)
from localinferencelab.mlx_preflight_authorization import _digest, _exact, _integer, _object
from localinferencelab.mlx_preflight_trusted_lab import (
    CLOCK_TOLERANCE_NS,
    MAX_PAYLOAD_BYTES,
    MAX_TOOL_OUTPUT_BYTES,
    NAMESPACE,
    NON_AUTHORITY_FIXTURE_KEY_ID,
    PRINCIPAL,
    SCHEMA_VERSION,
    SYSTEM_TOOL,
    TOOL_TIMEOUT_SECONDS,
    trusted_lab_request_spec,
    verification_mechanism_spec,
    verify_approval_payload_bytes,
)

_MAX_TRUST_BYTES = 8192
_MAX_SIGNATURE_BYTES = 8192
_MAX_TOOL_BYTES = 16 * 1024 * 1024
_MAX_TIME = (1 << 64) - 1
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600
_MAX_PRINCIPAL_LENGTH = 64
_MAX_PUBLIC_KEY_LENGTH = 256
_KEY_PARTS = 2
_ED25519_WIRE_LENGTH = 51
_TRUST_FIELDS = {
    "record_type",
    "schema_version",
    "trust_id",
    "policy_id",
    "spec_id",
    "mechanism_id",
    "mechanism_approval",
    "tool_sha256",
    "principal",
    "namespace",
    "public_key",
    "state",
    "scope",
}


class _Refusal(ContractError):  # noqa: N818
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ApprovalRetentionError(ContractError):
    """No verification result can be claimed when private evidence retention fails."""

    def __init__(self) -> None:
        """Expose no private paths, exception details or success-shaped fallback."""
        super().__init__("signed_request_evidence_retention_unavailable")


class ApprovalVerificationError(ContractError):
    """Explicit refusal with retained privacy-safe immutable outcome bytes."""

    def __init__(self, report: dict[str, JsonValue]) -> None:
        """Retain evidence of refusal, not permission or a child wait structure."""
        super().__init__("retained_signed_request_verification_refused")
        self.report_bytes = canonical_json(report)


@dataclass(frozen=True, slots=True)
class SignedRequestEvidence:
    """Detached audit bytes; no issuer, permit, ledger handle or executable capability."""

    report_bytes: bytes
    bundle_name: str

    def report(self) -> dict[str, JsonValue]:
        """Return a detached copy whose mutation cannot alter retained verification facts."""
        value = load_json_bytes(self.report_bytes)
        if not isinstance(value, dict):
            raise ContractError("signed request outcome object unavailable")
        return value


def _directory_pin(metadata: os.stat_result) -> tuple[int, ...]:
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode


def _file_pin(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        *_directory_pin(metadata),
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@dataclass(frozen=True, slots=True)
class _Directory:
    path: Path
    descriptor: int
    pin: tuple[int, ...]
    system: bool = False

    def recheck(self) -> None:
        with _directory(self.path, system=self.system) as observed:
            if self.pin != observed.pin or self.pin != _directory_pin(os.fstat(self.descriptor)):
                raise _Refusal("retained_directory_replaced_or_changed")


@contextlib.contextmanager
def _directory(path: Path, *, system: bool = False) -> Iterator[_Directory]:
    if not path.is_absolute() or ".." in path.parts:
        raise _Refusal("absolute_no_follow_custody_path_required")
    descriptor = _open_directory_no_follow(
        path, "retained approval custody", trusted_launch_path=True
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != (0 if system else os.geteuid())
            or (
                bool(metadata.st_mode & 0o022)
                if system
                else stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
            )
        ):
            raise _Refusal("retained_directory_owner_or_mode")
        yield _Directory(path, descriptor, _directory_pin(metadata), system)
    finally:
        os.close(descriptor)


@dataclass(frozen=True, slots=True)
class _File:
    directory: _Directory
    name: str
    descriptor: int
    pin: tuple[int, ...]
    data: bytes

    def recheck(self) -> None:
        self.directory.recheck()
        if (
            _file_pin(os.fstat(self.descriptor)) != self.pin
            or _file_pin(
                os.stat(self.name, dir_fd=self.directory.descriptor, follow_symlinks=False)
            )
            != self.pin
            or os.pread(self.descriptor, len(self.data) + 1, 0) != self.data
            or _file_pin(os.fstat(self.descriptor)) != self.pin
        ):
            raise _Refusal("retained_file_drift_or_replacement")


@contextlib.contextmanager
def _file(directory: _Directory, name: str, maximum: int) -> Iterator[_File]:
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=directory.descriptor,
    )
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != (0 if directory.system else os.geteuid())
            or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= maximum
            or (
                bool(metadata.st_mode & 0o022) or not metadata.st_mode & 0o111
                if directory.system
                else stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            )
        ):
            raise _Refusal("retained_file_type_owner_mode_links_or_bound")
        data = os.pread(descriptor, maximum + 1, 0)
        if len(data) != metadata.st_size:
            raise _Refusal("retained_file_short_or_unstable_read")
        retained = _File(directory, name, descriptor, _file_pin(metadata), data)
        retained.recheck()
        yield retained
    finally:
        os.close(descriptor)


def _trust(data: bytes, expected_id: str, request: dict[str, JsonValue]) -> dict[str, JsonValue]:
    value = load_json_bytes(data)
    trust = _object(value, _TRUST_FIELDS, "retained trust")
    if canonical_json(trust) != data:
        raise _Refusal("retained_trust_noncanonical")
    spec = trusted_lab_request_spec()
    policy = spec["policy"]
    if not isinstance(policy, dict):
        raise _Refusal("candidate_policy_unavailable")
    for field, expected in (
        ("record_type", "mlx_trusted_lab_retained_public_trust"),
        ("schema_version", "1.0"),
        ("policy_id", policy["policy_id"]),
        ("spec_id", spec["spec_id"]),
        ("mechanism_id", verification_mechanism_spec()["mechanism_id"]),
        ("mechanism_approval", "human_configured_approved_for_evidence_verification_only"),
        ("namespace", NAMESPACE),
        ("principal", PRINCIPAL),
        ("state", "enabled"),
        ("scope", "signed_request_evidence_only_no_runtime_authority"),
    ):
        _exact(trust[field], expected, "retained trust selection")
    identity = canonical_identity({key: item for key, item in trust.items() if key != "trust_id"})
    if _digest(trust["trust_id"], "trust id") != identity or identity != expected_id:
        raise _Refusal("independently_retained_trust_identity_mismatch")
    _digest(trust["tool_sha256"], "tool identity")
    principal = trust["principal"]
    if (
        type(principal) is not str
        or not 1 <= len(principal) <= _MAX_PRINCIPAL_LENGTH
        or principal[0] not in "abcdefghijklmnopqrstuvwxyz0123456789"
        or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_.-" for c in principal)
    ):
        raise _Refusal("retained_principal_not_literal")
    key = trust["public_key"]
    if type(key) is not str or len(key) > _MAX_PUBLIC_KEY_LENGTH:
        raise _Refusal("retained_public_key_invalid")
    parts = key.split(" ")
    if len(parts) != _KEY_PARTS or parts[0] != "ssh-ed25519":
        raise _Refusal("retained_public_key_invalid")
    try:
        wire = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        raise _Refusal("retained_public_key_invalid") from None
    if (
        len(wire) != _ED25519_WIRE_LENGTH
        or wire[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
        or base64.b64encode(wire).decode("ascii") != parts[1]
    ):
        raise _Refusal("retained_public_key_invalid")
    context = request["context"]
    if digest_bytes(wire) == NON_AUTHORITY_FIXTURE_KEY_ID and (
        not isinstance(context, dict) or context["evidence_scope"] != "synthetic_non_promotable"
    ):
        raise _Refusal("published_fixture_key_not_operator_authority")
    return trust


@dataclass(frozen=True, slots=True)
class _Sample:
    unix_ns: int
    monotonic_ns: int


class _ClockSession:
    """Observe real host clocks per call; no public clock/callback injection surface."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self.identity = digest_bytes(secrets.token_bytes(32))
        self.samples: list[_Sample] = []
        self.poisoned = False

    def observe(self) -> _Sample:
        if self.poisoned or os.getpid() != self.pid:
            raise _Refusal("clock_session_restart_or_poisoned")
        before = time.monotonic_ns()
        wall = time.time_ns()
        after = time.monotonic_ns()
        for value in (before, wall, after):
            _integer(value, "observed clock", minimum=1, maximum=_MAX_TIME)
        if not 0 <= after - before <= CLOCK_TOLERANCE_NS:
            self.poisoned = True
            raise _Refusal("clock_sample_uncertainty_or_rollback")
        sample = _Sample(wall, (before + after) // 2)
        if self.samples:
            first, last = self.samples[0], self.samples[-1]
            if sample.unix_ns < last.unix_ns or sample.monotonic_ns < last.monotonic_ns:
                self.poisoned = True
                raise _Refusal("clock_rollback")
            if (
                abs((sample.unix_ns - first.unix_ns) - (sample.monotonic_ns - first.monotonic_ns))
                > CLOCK_TOLERANCE_NS
            ):
                self.poisoned = True
                raise _Refusal("clock_wall_monotonic_disagreement")
        self.samples.append(sample)
        return sample

    def window(self, request: dict[str, JsonValue]) -> str:
        sample = self.observe()
        context = request["context"]
        validity = request["requested_validity"]
        if not isinstance(context, dict) or not isinstance(validity, dict):
            raise _Refusal("temporal_context_unavailable")
        session = context["session"]
        if not isinstance(session, dict):
            raise _Refusal("temporal_session_unavailable")
        start = _integer(session["started_monotonic_ns"], "start", maximum=_MAX_TIME)
        deadline = _integer(session["deadline_monotonic_ns"], "deadline", maximum=_MAX_TIME)
        not_before = _integer(validity["not_before_unix_ns"], "not before", maximum=_MAX_TIME)
        expiry = _integer(validity["expires_at_unix_ns"], "expiry", maximum=_MAX_TIME)
        if abs((sample.unix_ns - not_before) - (sample.monotonic_ns - start)) > CLOCK_TOLERANCE_NS:
            raise _Refusal("request_clock_binding_disagreement")
        if sample.unix_ns < not_before or sample.monotonic_ns < start:
            raise _Refusal("request_not_yet_valid")
        if sample.unix_ns >= expiry or sample.monotonic_ns >= deadline:
            raise _Refusal("request_expired")
        return "within_observed_trusted_host_window_not_consumption"


@dataclass(frozen=True, slots=True)
class _ToolOutcome:
    status: str = "unavailable_not_invoked"
    process_exposure: str = "not_started"
    termination: str = "not_started"
    output_size: int = 0


def _run_openssh(
    payload: bytes, signature: bytes, trust: dict[str, JsonValue], output: _Directory
) -> _ToolOutcome:
    principal, key = trust["principal"], trust["public_key"]
    if not isinstance(principal, str) or not isinstance(key, str):
        raise _Refusal("retained_trust_unavailable")
    output.recheck()
    with (
        tempfile.TemporaryDirectory(prefix=".approval-tool-", dir=output.path) as scratch,
        _directory(Path(scratch)) as directory,
    ):
        allowed = f'{principal} namespaces="{NAMESPACE}" {key}\n'.encode("ascii")
        _write_exclusive_at(directory.descriptor, "allowed-signers", allowed)
        _write_exclusive_at(directory.descriptor, "signature", signature)
        argv = [
            SYSTEM_TOOL,
            "-Y",
            "verify",
            "-f",
            str(Path(scratch) / "allowed-signers"),
            "-I",
            principal,
            "-n",
            NAMESPACE,
            "-s",
            str(Path(scratch) / "signature"),
        ]
        with (
            _file(directory, "allowed-signers", _MAX_TRUST_BYTES) as retained_allowed,
            _file(directory, "signature", _MAX_SIGNATURE_BYTES) as retained_signature,
        ):
            result = _bounded_tool(argv, payload, Path(scratch))
            try:
                retained_allowed.recheck()
                retained_signature.recheck()
            except (OSError, ContractError):
                return _ToolOutcome(
                    "unknown_verifier_input_custody",
                    result.process_exposure,
                    result.termination,
                    result.output_size,
                )
            return result


def _bounded_tool(argv: list[str], payload: bytes, cwd: Path) -> _ToolOutcome:
    """Use only internal fixed verify argv; drain bounded pipes without a shell or inherited FDs."""
    deadline = time.monotonic() + TOOL_TIMEOUT_SECONDS
    try:
        child = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env={"LC_ALL": "C", "TZ": "UTC"},
            close_fds=True,
            shell=False,
        )
    except OSError:
        return _ToolOutcome(status="unavailable_spawn")
    total = 0
    status = "unknown_deadline"
    try:
        if child.stdin is None or child.stdout is None or child.stderr is None:
            raise _Refusal("verification_pipe_unavailable")  # noqa: TRY301
        with selectors.DefaultSelector() as selector:
            for stream, event in (
                (child.stdin, selectors.EVENT_WRITE),
                (child.stdout, selectors.EVENT_READ),
                (child.stderr, selectors.EVENT_READ),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, event)
            offset = 0
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                for selected, event in selector.select(min(remaining, 0.05)):
                    descriptor = selected.fd
                    if event == selectors.EVENT_WRITE:
                        try:
                            offset += os.write(descriptor, payload[offset : offset + 4096])
                        except BrokenPipeError:
                            selector.unregister(descriptor)
                            child.stdin.close()
                        else:
                            if offset == len(payload):
                                selector.unregister(descriptor)
                                child.stdin.close()
                    else:
                        chunk = os.read(descriptor, min(4096, MAX_TOOL_OUTPUT_BYTES - total + 1))
                        total += len(chunk)
                        if not chunk:
                            selector.unregister(descriptor)
                        if total > MAX_TOOL_OUTPUT_BYTES:
                            status = "unknown_output_bound"
                            break
                if total > MAX_TOOL_OUTPUT_BYTES:
                    break
            else:
                try:
                    code = child.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    code = None
                if type(code) is int and time.monotonic() < deadline:
                    status = (
                        "verified"
                        if code == 0 and offset == len(payload)
                        else "unknown_signal"
                        if code < 0
                        else "rejected"
                    )
                elif code is not None and type(code) is not int:
                    status = "unknown_wait_type"
    except (OSError, _Refusal):
        status = "unknown_io_failure"
    finally:
        if child.poll() is None:
            try:
                child.kill()
            except ProcessLookupError:
                pass
            except OSError:
                status = "unknown_termination"
        try:
            child.wait(timeout=0.5)
        except (subprocess.TimeoutExpired, OSError):
            status = "unknown_termination"
        for cleanup_stream in (child.stdin, child.stdout, child.stderr):
            if cleanup_stream is not None:
                try:
                    cleanup_stream.close()
                except OSError:
                    status = "unknown_io_failure"
    code = child.returncode
    if type(code) is not int:
        status = "unknown_termination"
    elif status == "verified" and code != 0:
        status = "unknown_wait_disagreement"
    termination = (
        "unknown" if type(code) is not int else "reaped_signal" if code < 0 else "reaped_exit"
    )
    return _ToolOutcome(status, "started", termination, total)


def _report(
    code: str,
    tool: _ToolOutcome,
    clock: _ClockSession,
    files: dict[str, bytes],
    request: dict[str, JsonValue] | None,
    spec: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    policy = spec["policy"]
    if not isinstance(policy, dict):
        raise _Refusal("candidate_policy_unavailable")
    report: dict[str, JsonValue] = {
        "record_type": "mlx_trusted_lab_retained_signature_verification_outcome",
        "schema_version": SCHEMA_VERSION,
        "disposition": code,
        "verification_scope": "signed_request_bytes_against_independently_retained_public_key",
        "trust_scope": "human_configured_anchor_under_trusted_host_and_parent_assumptions",
        "configuration_is_independent_review_or_live_authority_proof": False,
        "candidate_review_status": "UNREVIEWED",
        "spec_id": spec["spec_id"],
        "policy_id": policy["policy_id"],
        "source_candidate_bindings": spec["source_bindings"],
        "request_id": None if request is None else request["request_id"],
        "request_evidence_scope": (
            None
            if request is None or not isinstance(request["context"], dict)
            else request["context"]["evidence_scope"]
        ),
        "attempt_id": None if request is None else request["attempt_id"],
        "retained_byte_identities": {name: digest_bytes(data) for name, data in files.items()},
        "signature_verification": tool.status,
        "tool_process_exposure": tool.process_exposure,
        "tool_termination": tool.termination,
        "bounded_tool_output_size_bytes": tool.output_size,
        "clock_verification_session_id": clock.identity,
        "freshness_scope": "observed_interval_only_fresh_verification_required_after_return",
        "consumption_expiry_and_custody_recheck": "required_not_implemented",
        "parent_restart_requires_fresh_session": True,
        "runtime_authorized": False,
        "consumable": False,
        "physical_launch_enabled": False,
        "accepted_physical_evidence": False,
        "ledger_permit_created": False,
        "live_ledger": "not_opened_or_consumed",
        "environment_root_process_installation_authority": "not_observed_or_authenticated",
        "model_free_claim": "scoped_application_operations_not_library_internal_nonaction",
        "requested_action_outcomes": "UNKNOWN_not_executed_or_observed",
        "unapproved_production_prerequisites": spec["unapproved_prerequisites"],
    }
    report["report_id"] = canonical_identity(report)
    return report


def _clock_bytes(clock: _ClockSession) -> bytes:
    return canonical_json(
        {
            "scope": "trusted_host_observations_not_external_time",
            "session_id": clock.identity,
            "samples": [
                {"unix_ns": sample.unix_ns, "monotonic_ns": sample.monotonic_ns}
                for sample in clock.samples
            ],
            "poisoned": clock.poisoned,
            "restart_or_later_consumption_requires_fresh_verification": True,
        }
    )


def _recheck_candidates(spec: dict[str, JsonValue]) -> None:
    if trusted_lab_request_spec()["spec_id"] != spec["spec_id"]:
        raise _Refusal("candidate_source_or_spec_drift")


def _retain(
    output: _Directory,
    files: dict[str, bytes],
    report: dict[str, JsonValue],
) -> Path:
    try:
        output.recheck()
        content = {f"private/{name}": data for name, data in files.items()}
        content["report.json"] = canonical_json(report)
        return publish_bundle_at(
            content,
            output.path,
            output.descriptor,
            name_prefix="localinferencelab-trusted-lab-signature-evidence-v2",
        )
    except (OSError, ContractError):
        raise ApprovalRetentionError from None


def verify_retained_approval(
    trust_root: Path,
    approval_root: Path,
    output_root: Path,
    *,
    retained_trust_id: str,
) -> SignedRequestEvidence:
    """Observe and retain evidence only; a caller digest is never an enrollment ceremony."""
    clock = _ClockSession()
    spec = trusted_lab_request_spec()
    files: dict[str, bytes] = {}
    request: dict[str, JsonValue] | None = None
    tool = _ToolOutcome()
    code = "custody_or_contract_refused"
    with contextlib.ExitStack() as stack:
        try:
            output = stack.enter_context(_directory(output_root))
        except (OSError, ContractError):
            raise ApprovalRetentionError from None
        retained: list[_File] = []
        try:
            _digest(retained_trust_id, "independently retained trust id")
            trust_directory = stack.enter_context(_directory(trust_root))
            approval_directory = stack.enter_context(_directory(approval_root))
            roots = (trust_directory, approval_directory, output)
            if len({root.pin[:2] for root in roots}) != len(roots) or any(
                left.path == right.path or left.path in right.path.parents
                for left in roots
                for right in roots
                if left is not right
            ):
                raise _Refusal("separately_retained_non_nested_roots_required")  # noqa: TRY301
            for directory, name, maximum in (
                (trust_directory, "trust.json", _MAX_TRUST_BYTES),
                (approval_directory, "signed-request.json", MAX_PAYLOAD_BYTES),
                (approval_directory, "signed-request.sig", _MAX_SIGNATURE_BYTES),
            ):
                item = stack.enter_context(_file(directory, name, maximum))
                retained.append(item)
                files[name] = item.data
            payload = verify_approval_payload_bytes(files["signed-request.json"])
            value = payload["request"]
            if not isinstance(value, dict):
                raise _Refusal("signed_request_unavailable")  # noqa: TRY301
            request = value
            trust = _trust(files["trust.json"], retained_trust_id, request)
            _recheck_candidates(spec)
            clock.window(request)
            system_directory = stack.enter_context(
                _directory(Path(SYSTEM_TOOL).parent, system=True)
            )
            measured_tool = stack.enter_context(
                _file(system_directory, Path(SYSTEM_TOOL).name, _MAX_TOOL_BYTES)
            )
            retained.append(measured_tool)
            if digest_bytes(measured_tool.data) != trust["tool_sha256"]:
                raise _Refusal("approved_system_tool_identity_mismatch")  # noqa: TRY301
            for item in retained:
                item.recheck()
            _recheck_candidates(spec)
            tool = _ToolOutcome(
                "unknown_verifier_invocation", "unknown_may_have_started", "unknown"
            )
            tool = _run_openssh(
                files["signed-request.json"], files["signed-request.sig"], trust, output
            )
            for item in retained:
                item.recheck()
            _recheck_candidates(spec)
            clock.window(request)
            if tool.status != "verified":
                raise _Refusal("signature_not_verified")  # noqa: TRY301
            code = "verified_signed_request_evidence_only"
        except _Refusal as error:
            code = error.code
        except (OSError, ContractError, RecursionError):
            code = "custody_or_contract_refused"
        files["observed-clock.json"] = _clock_bytes(clock)
        report = _report(code, tool, clock, files, request, spec)
        prior_report_id = report["report_id"]
        bundle = _retain(output, files, report)
        if code == "verified_signed_request_evidence_only":
            try:
                for item in retained:
                    item.recheck()
                if request is None:
                    raise _Refusal("signed_request_unavailable")
                clock.window(request)
                _recheck_candidates(spec)
                output.recheck()
            except (OSError, ContractError) as error:
                code = (
                    error.code if isinstance(error, _Refusal) else "postretention_custody_refused"
                )
            files["observed-clock.json"] = _clock_bytes(clock)
            report = _report(code, tool, clock, files, request, spec)
            report["prior_observation_report_id"] = prior_report_id
            report["retention_postcheck_scope"] = "prior_bundle_only_not_permanent_custody"
            report.pop("report_id")
            report["report_id"] = canonical_identity(report)
            bundle = _retain(output, files, report)
        if code != "verified_signed_request_evidence_only":
            raise ApprovalVerificationError(report)
        return SignedRequestEvidence(canonical_json(report), bundle.name)
