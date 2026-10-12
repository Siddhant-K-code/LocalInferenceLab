"""Bounded byte-retaining parent transport for the additive schema-1.2 worker."""

from __future__ import annotations

import contextlib
import socket
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    encode_bytes,
    validate_json_value,
)
from localinferencelab.mlx_preflight_worker import (
    ACTIONS,
    MAX_FRAME_BYTES,
    PROTOCOL_ID,
    SCHEMA_VERSION,
    WorkerError,
    _canonical,
    _parse,
)

MAX_RETAINED_OVERSIZE_BYTES = 4096
MAX_CAPTURES = 32
_HEADER_BYTES = 4


class AcquisitionError(ContractError):
    """A fixed, privacy-safe failure code, never an echoed worker payload."""


def encode_frame(value: dict[str, JsonValue]) -> bytes:
    """Encode the isolated worker's ASCII canonical JSON dialect."""
    payload = _canonical(value)
    if not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise AcquisitionError("frame_size")
    return struct.pack(">I", len(payload)) + payload


def decode_frame(wire: bytes) -> dict[str, JsonValue]:
    """Reject malformed UTF-8/JSON, duplicates, noncanonical or oversized frames."""
    if len(wire) < _HEADER_BYTES:
        raise AcquisitionError("truncated_header")
    length = struct.unpack(">I", wire[:_HEADER_BYTES])[0]
    if not 0 < length <= MAX_FRAME_BYTES or len(wire) != _HEADER_BYTES + length:
        raise AcquisitionError("frame_size")
    try:
        value = validate_json_value(_parse(wire[_HEADER_BYTES:]))
    except (WorkerError, ContractError, RecursionError, ValueError) as error:
        raise AcquisitionError("invalid_frame_json") from error
    if not isinstance(value, dict):
        raise AcquisitionError("invalid_frame_object")
    return value


@dataclass(slots=True)
class Capture:
    """Private exact received bytes, including rejected prefixes and partial headers."""

    direction: str
    wire: bytes
    observed_ns: int
    declared_bytes: int | None
    complete: bool
    rejection: str | None = None

    def private_record(self) -> dict[str, JsonValue]:
        return {**self.public_record(), "wire_base64": encode_bytes(self.wire)}

    def public_record(self) -> dict[str, JsonValue]:
        return {
            "direction": self.direction,
            "observed_ns": self.observed_ns,
            "declared_payload_bytes": self.declared_bytes,
            "retained_wire_bytes": len(self.wire),
            "retained_sha256": digest_bytes(self.wire),
            "complete_frame_retained": self.complete,
            "rejection": self.rejection,
            "unread_bytes": "none" if self.complete else "unknown_not_claimed_observed",
        }


class RetainingChannel:
    """One absolute deadline; retain before decode or semantic validation."""

    def __init__(
        self,
        endpoint: socket.socket,
        deadline_ns: int,
        persist: Callable[[Capture], None] | None = None,
    ) -> None:
        """Bind the existing parent socket and one monotonic absolute deadline."""
        self.endpoint = endpoint
        self.deadline_ns = deadline_ns
        self.captures: list[Capture] = []
        self.persist = persist

    def _persist(self, capture: Capture) -> None:
        if self.persist is not None:
            self.persist(capture)

    def _remaining(self) -> float:
        remaining = self.deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            raise AcquisitionError("deadline")
        return remaining / 1_000_000_000

    def _read(self, count: int, retained: bytearray) -> None:
        goal = len(retained) + count
        while len(retained) < goal:
            self.endpoint.settimeout(self._remaining())
            try:
                block = self.endpoint.recv(goal - len(retained))
            except TimeoutError as error:
                raise AcquisitionError("deadline") from error
            except OSError as error:
                raise AcquisitionError("socket_error") from error
            if not block:
                raise AcquisitionError("eof")
            retained.extend(block)

    def _retain(self, capture: Capture) -> None:
        if len(self.captures) >= MAX_CAPTURES:
            raise AcquisitionError("capture_bound")
        self.captures.append(capture)

    def send(self, value: dict[str, JsonValue]) -> None:
        wire = encode_frame(value)
        capture = Capture("parent_to_worker", b"", time.monotonic_ns(), len(wire) - 4, False)
        self._retain(capture)
        sent = 0
        try:
            while sent < len(wire):
                self.endpoint.settimeout(self._remaining())
                count = self.endpoint.send(wire[sent:])
                if count <= 0:
                    raise AcquisitionError("send_eof")  # noqa: TRY301
                sent += count
                capture.wire = wire[:sent]
            capture.complete = True
            if time.monotonic_ns() > self.deadline_ns:
                raise AcquisitionError("deadline")  # noqa: TRY301
        except (TimeoutError, OSError, AcquisitionError) as error:
            capture.rejection = (
                "deadline"
                if isinstance(error, AcquisitionError) and str(error) == "deadline"
                else "send_failed"
            )
            raise AcquisitionError(capture.rejection) from error
        finally:
            capture.observed_ns = time.monotonic_ns()
            self._persist(capture)

    def receive(self) -> dict[str, JsonValue]:
        raw = bytearray()
        capture = Capture("worker_to_parent", b"", time.monotonic_ns(), None, False)
        self._retain(capture)
        try:
            self._read(_HEADER_BYTES, raw)
            length = struct.unpack(">I", raw)[0]
            capture.declared_bytes = length
            if not 0 < length <= MAX_FRAME_BYTES:
                # Retain only already available bytes: never drain a claimed 4-GiB frame.
                self.endpoint.setblocking(False)
                with contextlib.suppress(BlockingIOError):
                    raw.extend(self.endpoint.recv(MAX_RETAINED_OVERSIZE_BYTES))
                raise AcquisitionError("frame_size")  # noqa: TRY301
            self._read(length, raw)
            capture.complete = True
            capture.wire = bytes(raw)
            capture.observed_ns = time.monotonic_ns()
            self._persist(capture)
            if capture.observed_ns > self.deadline_ns:
                raise AcquisitionError("deadline")  # noqa: TRY301
            return decode_frame(capture.wire)
        except AcquisitionError as error:
            capture.rejection = str(error)
            raise
        except OSError as error:
            capture.rejection = "socket_error"
            raise AcquisitionError("socket_error") from error
        finally:
            capture.wire = bytes(raw)
            if not capture.complete:
                capture.observed_ns = time.monotonic_ns()
            self._persist(capture)

    def reject_latest(self, code: str) -> None:
        self.captures[-1].rejection = code
        self._persist(self.captures[-1])

    def expect_eof(self) -> None:
        raw = bytearray()
        try:
            self.endpoint.settimeout(self._remaining())
            raw.extend(self.endpoint.recv(MAX_RETAINED_OVERSIZE_BYTES))
            if not raw:
                return
            code = "extra_output"
        except (TimeoutError, AcquisitionError):
            code = "deadline"
        except OSError:
            code = "socket_error"
        self._retain(
            Capture("worker_to_parent", bytes(raw), time.monotonic_ns(), None, False, code)
        )
        self._persist(self.captures[-1])
        raise AcquisitionError(code)


def expected_frame(
    kind: str, sequence: int, session_id: str, **content: JsonValue
) -> dict[str, JsonValue]:
    """Construct only a protocol-bound frame, without any executable/path fields."""
    return {
        "kind": kind,
        "sequence": sequence,
        "session_id": session_id,
        "protocol_id": PROTOCOL_ID,
        **content,
    }


def require_frame(
    value: dict[str, JsonValue], kind: str, sequence: int, session_id: str, fields: set[str]
) -> None:
    """Strict sequence and field validation without echoing untrusted strings."""
    common = expected_frame(kind, sequence, session_id)
    if value.keys() != common.keys() | fields:
        raise AcquisitionError("frame_fields")
    if isinstance(value["sequence"], bool):
        raise AcquisitionError("frame_order_or_binding")
    if any(value[key] != expected for key, expected in common.items()):
        raise AcquisitionError("frame_order_or_binding")


def protocol_record() -> dict[str, JsonValue]:
    """Return the new versioned implementation boundary, not a reviewed worker anchor."""
    value: dict[str, JsonValue] = {
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "actions": list(ACTIONS),
        "maximum_frame_bytes": MAX_FRAME_BYTES,
        "maximum_captures": MAX_CAPTURES,
        "maximum_oversize_prefix_bytes": MAX_RETAINED_OVERSIZE_BYTES,
        "raw_bytes_private_only": True,
        "accepted_physical_evidence": False,
        "python_audit_is_sandbox": False,
    }
    value["record_id"] = canonical_identity(value)
    return value


def canonical_private_record(value: dict[str, JsonValue]) -> bytes:
    """Use repository canonical JSON for bundle files, not the wire dialect."""
    return canonical_json(value)
