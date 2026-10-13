"""Strict, non-authoritative evidence for the harmless native boundary experiment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from localinferencelab.canonical import (
    SHA256_ID_LENGTH,
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    encode_bytes,
    load_json_bytes,
)

SCHEMA_VERSION = "1.0"
PRIVATE_ROOT_MODE = 0o700
MAX_CAPTURE_BYTES = 4096
MAX_REPORT_BYTES = 262_144
RUN_TIMEOUT_NS = 30_000_000_000
COMMAND_TIMEOUT_NS = 1_000_000_000
COMPILE_TIMEOUT_NS = 10_000_000_000
CLEANUP_TIMEOUT_NS = 2_000_000_000
PROBES = (
    ("read_allowed", "allow"),
    ("write_allowed", "allow"),
    ("read_denied", "deny"),
    ("write_denied", "deny"),
    ("read_prefix_sibling", "deny"),
    ("read_symlink", "deny"),
    ("write_symlink", "deny"),
    ("socket_loopback", "deny"),
    ("connect_loopback", "deny"),
    ("fork", "deny"),
    ("exec_other", "deny"),
    ("exec_self", "deny"),
    ("descriptors", "allow"),
    ("environment", "allow"),
    ("read_replacement", "deny"),
)
DISPOSITIONS = ("enforced", "refused", "unavailable", "untested", "unknown")
LIMITATIONS = (
    "deprecated_unsupported_seatbelt_infrastructure",
    "path_rules_not_object_pins_or_immutable_execution_lifetime",
    "replacement_measured_not_concurrent_race_exclusion",
    "hostile_parent_and_complete_native_dependency_snapshot_untested",
    "inherited_resource_use_not_proven_by_acquisition_rules",
    "permitted_library_internal_math_tensor_cache_activity_unobservable",
    "real_mlx_metal_compatibility_untested",
    "no_production_target_interpreter_runtime_or_native_closure_binding",
    "worker_syscall_reports_not_independent_kernel_audit_or_authority",
    "loader_path_grants_not_exact_native_closure",
    "child_pid_observed_final_executable_identity_untested",
)
PROFILE_TEMPLATE = """(version 1)
(deny default)
(allow process-exec (literal {helper}))
(allow file-read* (literal {helper}) (literal {read}) (literal {read_link}))
(allow file-write-data (literal {write}) (literal {write_link}))
(allow file-read* (literal "/usr/lib/dyld") (subpath "/System/Library/dyld"))
(allow file-map-executable (literal {helper}) (literal "/usr/lib/dyld")
    (subpath "/System/Library/dyld"))
"""


def specification() -> dict[str, JsonValue]:
    """Return static experiment semantics without observing tools or the host."""
    result: dict[str, JsonValue] = {
        "record_type": "native_confinement_specification",
        "schema_version": SCHEMA_VERSION,
        "profile_template": PROFILE_TEMPLATE,
        "probes": [{"operation": name, "expectation": rule} for name, rule in PROBES],
        "limits": {
            "run_ns": RUN_TIMEOUT_NS,
            "command_ns": COMMAND_TIMEOUT_NS,
            "compile_ns": COMPILE_TIMEOUT_NS,
            "cleanup_ns": CLEANUP_TIMEOUT_NS,
            "capture_bytes_per_stream": MAX_CAPTURE_BYTES,
            "report_bytes": MAX_REPORT_BYTES,
        },
        "limitations": list(LIMITATIONS),
        "runtime_authority": False,
        "physical_launch_approved": False,
    }
    result["specification_id"] = canonical_identity(result)
    return result


def _object(value: JsonValue, fields: set[str]) -> dict[str, JsonValue]:
    if type(value) is not dict or value.keys() != fields:
        raise ContractError("native evidence object fields")
    return value


def _integer(value: JsonValue, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError("native evidence integer")
    return value


def _text(value: JsonValue, *, maximum: int = 128) -> str:
    if type(value) is not str or not 0 < len(value) <= maximum or not value.isascii():
        raise ContractError("native evidence text")
    return value


def _identity(value: JsonValue) -> str:
    text = _text(value)
    if len(text) != SHA256_ID_LENGTH or not text.startswith("sha256:"):
        raise ContractError("native evidence identity")
    if any(character not in "0123456789abcdef" for character in text[7:]):
        raise ContractError("native evidence identity")
    return text


@dataclass(frozen=True)
class Capture:
    """Bounded parent observation; exposure is never a zero-native-action claim."""

    exposure: str = "not_started"
    terminal: str = "not_run"
    elapsed_ns: int = 0
    returncode: int | None = None
    stdout: bytes = b""
    stderr: bytes = b""
    pid: int | None = None

    def to_dict(self) -> dict[str, JsonValue]:
        """Encode retained bytes without publishing raw private paths."""
        return {
            "exposure": self.exposure,
            "terminal": self.terminal,
            "elapsed_ns": self.elapsed_ns,
            "returncode": self.returncode,
            "stdout": encode_bytes(self.stdout),
            "stderr": encode_bytes(self.stderr),
            "pid": self.pid,
        }


def parse_capture(value: JsonValue, timeout_ns: int) -> Capture:
    """Reject equal-valued aliases, oversized bytes and contradictory terminal claims."""
    item = _object(
        value, {"exposure", "terminal", "elapsed_ns", "returncode", "stdout", "stderr", "pid"}
    )
    exposure, terminal = _text(item["exposure"]), _text(item["terminal"])
    elapsed = _integer(item["elapsed_ns"])
    code = item["returncode"]
    pid = item["pid"]
    if pid is not None:
        _integer(pid, minimum=1)
    if code is not None:
        _integer(code, minimum=-127, maximum=255)
    if exposure not in {"not_started", "may_have_run"} or terminal not in {
        "not_run",
        "complete",
        "deadline",
        "output_limit",
        "exit_error",
        "spawn_failed",
    }:
        raise ContractError("native capture enum")
    streams = []
    for field in ("stdout", "stderr"):
        encoded = item[field]
        if type(encoded) is not str or len(encoded) > MAX_CAPTURE_BYTES * 2:
            raise ContractError("native capture byte bound")
        stream = decode_bytes(encoded)
        if len(stream) > MAX_CAPTURE_BYTES:
            raise ContractError("native capture byte bound")
        streams.append(stream)
    if terminal == "not_run":
        if (
            exposure != "not_started"
            or elapsed != 0
            or code is not None
            or pid is not None
            or any(streams)
        ):
            raise ContractError("native not-run capture")
    elif exposure != "may_have_run":
        raise ContractError("native exposure missing")
    if terminal not in {"not_run", "spawn_failed"} and pid is None:
        raise ContractError("native owned child pid missing")
    if terminal not in {"not_run", "spawn_failed"} and code is None:
        raise ContractError("native reaped child wait code missing")
    if terminal == "spawn_failed" and (pid is not None or code is not None or any(streams)):
        raise ContractError("native spawn failure evidence")
    if terminal == "complete" and (code != 0 or elapsed > timeout_ns):
        raise ContractError("native completion past deadline or unsuccessful")
    if terminal == "exit_error" and (code is None or code == 0 or elapsed > timeout_ns):
        raise ContractError("native exit evidence")
    return Capture(
        exposure,
        terminal,
        elapsed,
        cast("int | None", code),
        streams[0],
        streams[1],
        pid=cast("int | None", pid),
    )


def syscall_observation(capture: Capture, operation: str) -> dict[str, JsonValue] | None:
    """Accept only a complete, exact native helper result, never diagnostic text."""
    if capture.terminal != "complete" or capture.stderr:
        return None
    try:
        value = load_json_bytes(capture.stdout)
        item = _object(value, {"operation", "ok", "errno", "detail"})
        if type(item["ok"]) is not bool or _text(item["operation"]) != operation:
            return None
        error = _integer(item["errno"], maximum=4095)
        _integer(item["detail"], maximum=65535)
        if (item["ok"] is True and error != 0) or (item["ok"] is False and error == 0):
            return None
    except (ContractError, RecursionError):
        return None
    expected_detail = 66 if operation == "read_replacement" else 65
    if item["ok"] is True and (
        (operation.startswith("read_") and item["detail"] != expected_detail)
        or (not operation.startswith("read_") and item["detail"] != 0)
    ):
        return None
    return item


def assess(  # noqa: PLR0911
    operation: str, expectation: str, baseline: Capture, candidate: Capture
) -> str:
    """Recompute per-operation disposition from retained observations, not caller labels."""
    if candidate.terminal == "not_run":
        return "untested"
    if candidate.terminal != "complete":
        return "unknown"
    control = syscall_observation(baseline, operation)
    observed = syscall_observation(candidate, operation)
    if observed is None:
        return "unknown"
    if control is None or control["ok"] is not True:
        return "unavailable"
    if expectation == "allow":
        return "enforced" if observed["ok"] is True else "refused"
    if observed["ok"] is True:
        return "refused"
    return "enforced" if observed["errno"] in {1, 13} else "unknown"


def overall(dispositions: list[str]) -> str:
    """Prioritize measured blockers, then uncertainty and absence."""
    for state in ("refused", "unknown", "unavailable"):
        if state in dispositions:
            return state
    return "unavailable" if "untested" in dispositions else "enforced"


def build_report(
    *,
    identities: dict[str, JsonValue],
    host: dict[str, JsonValue] | None = None,
    fixture: dict[str, JsonValue] | None = None,
    compilation: Capture | None = None,
    observations: tuple[tuple[Capture, Capture], ...] = (),
    reason: str = "none",
) -> dict[str, JsonValue]:
    """Seal a replayable observation record, explicitly not a production capability."""
    if not observations:
        observations = tuple((Capture(), Capture()) for _ in PROBES)
    if len(observations) != len(PROBES):
        raise ContractError("native observation count")
    rows: list[JsonValue] = []
    dispositions = []
    for (operation, expectation), (baseline, candidate) in zip(PROBES, observations, strict=True):
        state = assess(operation, expectation, baseline, candidate)
        dispositions.append(state)
        rows.append(
            {
                "operation": operation,
                "expectation": expectation,
                "baseline": baseline.to_dict(),
                "candidate": candidate.to_dict(),
                "disposition": state,
            }
        )
    result: dict[str, JsonValue] = {
        "record_type": "native_confinement_feasibility",
        "schema_version": SCHEMA_VERSION,
        "specification_id": specification()["specification_id"],
        "identities": identities,
        "host": host,
        "fixture": fixture,
        "compilation": (Capture() if compilation is None else compilation).to_dict(),
        "observations": rows,
        "disposition": overall(dispositions),
        "reason": reason,
        "untested": list(LIMITATIONS),
        "runtime_authority": False,
        "physical_launch_approved": False,
        "production_bindings": None,
    }
    result["record_id"] = canonical_identity(result)
    return verify_report(result)


IDENTITY_FIELDS = {
    "implementation_id",
    "probe_source_id",
    "profile_template_id",
    "profile_id",
    "helper_id",
    "sandbox_exec_id",
    "compiler_id",
}
REPORT_FIELDS = {
    "record_type",
    "schema_version",
    "specification_id",
    "identities",
    "host",
    "fixture",
    "compilation",
    "observations",
    "disposition",
    "reason",
    "untested",
    "runtime_authority",
    "physical_launch_approved",
    "production_bindings",
    "record_id",
}
REASONS = {
    "none",
    "unsupported_host",
    "sandbox_exec_missing",
    "compiler_missing",
    "tool_identity_unavailable",
    "compilation_failed",
    "fixture_failed",
    "path_refused",
    "candidate_startup_unavailable",
}


def _pin(value: JsonValue) -> None:
    pin = _object(value, {"device", "inode", "mode"})
    _integer(pin["device"])
    _integer(pin["inode"], minimum=1)
    _integer(pin["mode"], maximum=0o777)


def verify_report(value: JsonValue) -> dict[str, JsonValue]:
    """Offline structural replay only; rehashing never authenticates OS observations."""
    item = _object(value, REPORT_FIELDS)
    if (
        type(item["runtime_authority"]) is not bool
        or item["runtime_authority"] is not False
        or type(item["physical_launch_approved"]) is not bool
        or item["physical_launch_approved"] is not False
        or item["production_bindings"] is not None
        or _text(item["record_type"]) != "native_confinement_feasibility"
        or _text(item["schema_version"]) != SCHEMA_VERSION
        or _identity(item["specification_id"]) != specification()["specification_id"]
        or type(item["untested"]) is not list
        or [_text(entry) for entry in item["untested"]] != list(LIMITATIONS)
        or _text(item["reason"]) not in REASONS
    ):
        raise ContractError("native report contract")
    identities = _object(item["identities"], IDENTITY_FIELDS)
    for name, identity in identities.items():
        if identity is None and name not in {
            "implementation_id",
            "probe_source_id",
            "profile_template_id",
        }:
            continue
        _identity(identity)
    if identities["profile_template_id"] != canonical_identity(PROFILE_TEMPLATE):
        raise ContractError("native profile template identity")
    host = item["host"]
    if host is not None:
        h = _object(
            host, {"system", "release", "machine", "parent_pid", "started_ns", "finished_ns"}
        )
        for name in ("system", "release", "machine"):
            _text(h[name])
        _integer(h["parent_pid"], minimum=1)
        start, finish = _integer(h["started_ns"]), _integer(h["finished_ns"])
        if finish < start or finish - start > RUN_TIMEOUT_NS + CLEANUP_TIMEOUT_NS:
            raise ContractError("native host lifetime")
    fixture = item["fixture"]
    if fixture is not None:
        pins = _object(fixture, {"root", "read_initial", "read_replacement"})
        for name, pin in pins.items():
            if name == "read_replacement" and pin is None:
                continue
            _pin(pin)
        if cast("dict[str, JsonValue]", pins["root"])["mode"] != PRIVATE_ROOT_MODE:
            raise ContractError("native fixture root not private")
    compilation = parse_capture(item["compilation"], COMPILE_TIMEOUT_NS)
    captures = [compilation]
    rows = item["observations"]
    if type(rows) is not list or len(rows) != len(PROBES):
        raise ContractError("native observation count")
    dispositions = []
    exposed = False
    for (operation, expectation), row in zip(PROBES, rows, strict=True):
        r = _object(row, {"operation", "expectation", "baseline", "candidate", "disposition"})
        if _text(r["operation"]) != operation or _text(r["expectation"]) != expectation:
            raise ContractError("native operation order or expectation")
        baseline = parse_capture(r["baseline"], COMMAND_TIMEOUT_NS)
        candidate = parse_capture(r["candidate"], COMMAND_TIMEOUT_NS)
        captures.extend((baseline, candidate))
        state = assess(operation, expectation, baseline, candidate)
        if _text(r["disposition"]) != state or state not in DISPOSITIONS:
            raise ContractError("native disposition projection")
        dispositions.append(state)
        exposed |= baseline.exposure != "not_started" or candidate.exposure != "not_started"
    if exposed and (
        host is None
        or fixture is None
        or compilation.terminal != "complete"
        or any(identity is None for identity in identities.values())
        or item["reason"] not in {"none", "candidate_startup_unavailable"}
    ):
        raise ContractError("native exposed observations lack preparation")
    if exposed and cast("dict[str, JsonValue]", host)["system"] != "Darwin":
        raise ContractError("native exposed host is not Darwin")
    if any(capture.exposure != "not_started" for capture in captures):
        if host is None:
            raise ContractError("native captures lack host lifetime")
        h = cast("dict[str, JsonValue]", host)
        if sum(capture.elapsed_ns for capture in captures) > (
            cast("int", h["finished_ns"]) - cast("int", h["started_ns"])
        ):
            raise ContractError("native serial capture durations exceed host span")
        if any(capture.pid == h["parent_pid"] for capture in captures if capture.pid is not None):
            raise ContractError("native child pid equals parent pid")
    replacement_row = _object(
        rows[-1], {"operation", "expectation", "baseline", "candidate", "disposition"}
    )
    replacement_capture = parse_capture(replacement_row["baseline"], COMMAND_TIMEOUT_NS)
    if replacement_capture.exposure != "not_started":
        pins = cast("dict[str, JsonValue]", fixture)
        initial, replacement = pins["read_initial"], pins["read_replacement"]
        if (
            replacement is None
            or not isinstance(initial, dict)
            or not isinstance(replacement, dict)
        ):
            raise ContractError("native replacement pin missing")
        if (initial["device"], initial["inode"]) == (replacement["device"], replacement["inode"]):
            raise ContractError("native replacement object unchanged")
    if _text(item["disposition"]) != overall(dispositions):
        raise ContractError("native overall projection")
    identity = _identity(item["record_id"])
    if identity != canonical_identity(
        {key: val for key, val in item.items() if key != "record_id"}
    ):
        raise ContractError("native report identity")
    if len(canonical_json(item)) > MAX_REPORT_BYTES:
        raise ContractError("native report byte bound")
    return item


def replay_bytes(data: bytes) -> dict[str, JsonValue]:
    """Reject oversized/duplicate/noncanonical records without any native activity."""
    if len(data) > MAX_REPORT_BYTES:
        raise ContractError("native report byte bound")
    try:
        report = verify_report(load_json_bytes(data))
    except RecursionError as error:
        raise ContractError("native report nesting") from error
    if canonical_json(report) != data:
        raise ContractError("native report noncanonical")
    return report
