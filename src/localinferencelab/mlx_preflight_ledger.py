"""Private durable one-shot custody, exercisable only with synthetic authority."""

from __future__ import annotations

import fcntl
import os
import stat
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import NoReturn, TypeVar, cast

from localinferencelab.canonical import (
    SHA256_ID_LENGTH,
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_json_bytes,
)
from localinferencelab.mlx_preflight_custody import (
    _build_consumption,
    _verify_authorization,
    _verify_authorization_at,
)

_MAX_JOURNAL_BYTES = 64 * 1024
_JOURNAL_NAME = "authorization.journal"
_SCOPE = "synthetic_non_promotable"
_ROOT_ROLES = ("custody", "output", "runtime")
_T = TypeVar("_T")


@dataclass(frozen=True, slots=True)
class ObjectPin:
    """Parent-retained object identity, not an authority or rollback-proof anchor."""

    device: int
    inode: int
    owner: int
    mode: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "device": self.device,
            "inode": self.inode,
            "owner": self.owner,
            "mode": self.mode,
        }


def _pin(descriptor: int, *, directory: bool) -> ObjectPin:
    metadata = os.fstat(descriptor)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    expected_mode = 0o700 if directory else 0o600
    if (
        not expected_type(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != expected_mode
        or metadata.st_nlink < 1
        or (not directory and metadata.st_nlink != 1)
    ):
        raise ContractError("ledger requires private owned directories and single-link files")
    return ObjectPin(metadata.st_dev, metadata.st_ino, metadata.st_uid, expected_mode)


def _flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ContractError("ledger requires POSIX no-follow directory operations")
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    return flags | (os.O_RDONLY | os.O_DIRECTORY if directory else os.O_RDWR | os.O_APPEND)


def _ledger_name(authorization_bytes: bytes) -> str:
    identity = _digest(
        cast("str", _canonical_object(authorization_bytes)["authorization_id"]), "authorization"
    )
    return "authorization-" + identity[7:]


def _digest(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != SHA256_ID_LENGTH
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ContractError(f"invalid {label} digest")
    return value


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError("ledger record must be an object")
    return value


def _canonical_object(data: bytes) -> dict[str, JsonValue]:
    value = _object(load_json_bytes(data))
    if canonical_json(value) != data:
        raise ContractError("ledger record must be canonical JSON")
    return value


@dataclass(slots=True)
class SyntheticClock:
    """Explicit test clock; never a source of production freshness or human approval."""

    unix_ns: int
    monotonic_ns: int

    def sample(self) -> dict[str, JsonValue]:
        if (
            type(self.unix_ns) is not int
            or type(self.monotonic_ns) is not int
            or self.unix_ns < 1
            or self.monotonic_ns < 1
        ):
            raise ContractError("invalid synthetic clock observation")
        return {"unix_ns": self.unix_ns, "monotonic_ns": self.monotonic_ns}


def synthetic_root_ids(root_descriptors: tuple[int, int, int]) -> tuple[str, str, str]:
    """Bind custody/output/runtime roots to observed private descriptor objects."""
    if len(root_descriptors) != len(_ROOT_ROLES):
        raise ContractError("exactly three parent-owned root descriptors are required")
    pins = tuple(_pin(descriptor, directory=True) for descriptor in root_descriptors)
    if len(set(pins)) != len(_ROOT_ROLES):
        raise ContractError("custody/output/runtime root objects must be distinct")
    return cast(
        "tuple[str, str, str]",
        tuple(
            canonical_identity({"scope": _SCOPE, "role": role, "object": pin.to_dict()})
            for role, pin in zip(_ROOT_ROLES, pins, strict=True)
        ),
    )


@dataclass(frozen=True, slots=True)
class ParentBindings:
    """Exact synthetic parent attempt inputs; audit identity is not a capability."""

    authorization_bytes: bytes
    session_id: str
    interpreter_sha256: str
    roots: tuple[ObjectPin, ObjectPin, ObjectPin]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "authorization": _canonical_object(self.authorization_bytes),
            "session_id": self.session_id,
            "interpreter_sha256": self.interpreter_sha256,
            "root_objects": [root.to_dict() for root in self.roots],
        }


def synthetic_parent_bindings(
    authorization: JsonValue,
    *,
    session_id: str,
    interpreter_sha256: str,
    root_descriptors: tuple[int, int, int],
) -> ParentBindings:
    """Observe roots and bind a strictly validated schema-1.1 synthetic attempt."""
    verified = _verify_authorization(authorization, allow_synthetic=True)
    if verified["evidence_kind"] != "synthetic_fixture_only":
        raise ContractError("ledger accepts synthetic fixtures only; production authority absent")
    root_ids = synthetic_root_ids(root_descriptors)
    roots = _object(verified["root_bindings"])
    if tuple(roots[name] for name in ("custody_root_id", "output_root_id", "runtime_root_id")) != (
        root_ids
    ):
        raise ContractError("authorization root identities differ from parent-observed objects")
    return ParentBindings(
        canonical_json(verified),
        _digest(session_id, "session"),
        _digest(interpreter_sha256, "interpreter"),
        cast(
            "tuple[ObjectPin, ObjectPin, ObjectPin]",
            tuple(_pin(descriptor, directory=True) for descriptor in root_descriptors),
        ),
    )


@dataclass(frozen=True, slots=True)
class LedgerAnchor:
    """Out-of-journal parent pin needed on reopen; never reconstruct it from storage."""

    parent: ObjectPin
    root: ObjectPin
    journal: ObjectPin
    initialization: ObjectPin
    header_bytes: bytes


class SyntheticAttemptPermit:
    """Opaque application-origin token, not authority, serializable evidence or sandbox."""

    __slots__ = ()

    def __init__(self) -> None:
        """Refuse caller construction; the ledger registers its own object identity."""
        raise ContractError("only a durable synthetic consumption can issue a permit")

    def __reduce__(self) -> NoReturn:
        """Refuse serialization rather than exporting a launch-shaped receipt."""
        raise ContractError("synthetic permits cannot be serialized")


def open_production_ledger() -> NoReturn:
    """Refuse until independently reviewed authority and explicit human approval exist."""
    raise ContractError(
        "production ledger blocked: independently reviewed authority material, "
        "fresh explicit human approval and reviewed launch integration are absent"
    )


def _write_once(descriptor: int, data: bytes) -> None:
    if os.write(descriptor, data) != len(data):
        raise ContractError("ambiguous partial ledger write; never reset or retry")


def _append_intent(descriptor: int, record: bytes) -> None:
    # Any incomplete intent suffix is permanently unusable, not an unused authorization.
    _write_once(descriptor, b"!")
    _write_once(descriptor, record + b"\n")
    os.fsync(descriptor)


def _initialization_bytes(header: bytes) -> bytes:
    return (
        canonical_json(
            {
                "record_type": "mlx_preflight_ledger_initialization",
                "schema_version": "1.0",
                "evidence_scope": _SCOPE,
                "header_id": canonical_identity(_canonical_object(header)),
            }
        )
        + b"\n"
    )


class SyntheticLedgerIssuer:
    """One exact fixture enrollment and clock, explicitly incapable of real issuance."""

    def __init__(self, authorization: JsonValue, clock: SyntheticClock) -> None:
        """Enroll exact synthetic bytes, without claiming current validity on inspection."""
        verified = _verify_authorization(authorization, allow_synthetic=True)
        _verify_authorization_at(
            verified,
            observed_at_unix_ns=cast("int", _object(verified["temporal"])["not_before_unix_ns"]),
            allow_synthetic=True,
        )
        clock.sample()
        self._authorization_bytes = canonical_json(verified)
        self._clock = clock
        self._pid = os.getpid()

    def _check(self, bindings: ParentBindings) -> None:
        if self._pid != os.getpid():
            raise ContractError("synthetic issuer cannot be inherited across fork")
        if bindings.authorization_bytes != self._authorization_bytes:
            raise ContractError("authorization differs from exact synthetic issuer enrollment")
        _digest(bindings.session_id, "session")
        _digest(bindings.interpreter_sha256, "interpreter")
        self._clock.sample()

    def initialize(
        self,
        parent_descriptor: int,
        bindings: ParentBindings,
        root_descriptors: tuple[int, int, int],
    ) -> LedgerAnchor:
        """Explicitly create a new synthetic journal; never replace or recover one."""
        self._check(bindings)
        parent_pin = _pin(parent_descriptor, directory=True)
        if parent_pin != bindings.roots[0]:
            raise ContractError("ledger must live under the bound custody root")
        name = _ledger_name(self._authorization_bytes)
        expected = synthetic_parent_bindings(
            _canonical_object(self._authorization_bytes),
            session_id=bindings.session_id,
            interpreter_sha256=bindings.interpreter_sha256,
            root_descriptors=root_descriptors,
        )
        if expected != bindings:
            raise ContractError("synthetic initialization parent bindings mismatch")
        header = canonical_json(
            {
                "record_type": "mlx_preflight_one_shot_ledger",
                "schema_version": "1.0",
                "evidence_scope": _SCOPE,
                "state": "unconsumed",
                "parent_bindings": bindings.to_dict(),
                "created_clock": self._clock.sample(),
            }
        )
        if len(header) > _MAX_JOURNAL_BYTES // 2:
            raise ContractError("ledger header exceeds bound")
        try:
            initialization = os.open(
                name + ".initialized",
                _flags(directory=False) | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_descriptor,
            )
            try:
                initialization_pin = _pin(initialization, directory=False)
                _write_once(initialization, _initialization_bytes(header))
                os.fsync(initialization)
                os.fsync(parent_descriptor)
            finally:
                os.close(initialization)
            os.mkdir(name, 0o700, dir_fd=parent_descriptor)
            root = os.open(name, _flags(directory=True), dir_fd=parent_descriptor)
            try:
                root_pin = _pin(root, directory=True)
                journal = os.open(
                    _JOURNAL_NAME,
                    _flags(directory=False) | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=root,
                )
                try:
                    journal_pin = _pin(journal, directory=False)
                    _write_once(journal, header + b"\n")
                    os.fsync(journal)
                    os.fsync(root)
                    os.fsync(parent_descriptor)
                finally:
                    os.close(journal)
            finally:
                os.close(root)
        except OSError as error:
            raise ContractError(
                "ledger initialization failed; no recovery or replacement"
            ) from error
        return LedgerAnchor(parent_pin, root_pin, journal_pin, initialization_pin, header)

    def open(
        self,
        parent_descriptor: int,
        anchor: LedgerAnchor,
        bindings: ParentBindings,
        root_descriptors: tuple[int, int, int],
    ) -> SyntheticAuthorizationLedger:
        """Reopen only an existing exact pinned fixture; opening never creates authority."""
        self._check(bindings)
        return SyntheticAuthorizationLedger(
            self, parent_descriptor, anchor, bindings, root_descriptors
        )


class SyntheticAuthorizationLedger:
    """Locked append-only durable transition plus one process-local synthetic dispatch."""

    def __init__(
        self,
        issuer: SyntheticLedgerIssuer,
        parent_descriptor: int,
        anchor: LedgerAnchor,
        bindings: ParentBindings,
        root_descriptors: tuple[int, int, int],
    ) -> None:
        """Validate an existing parent-pinned store without minting a permit."""
        self._issuer = issuer
        self._parent = parent_descriptor
        self._name = _ledger_name(bindings.authorization_bytes)
        self._anchor = anchor
        self._bindings = bindings
        self._roots = root_descriptors
        self._pid = os.getpid()
        self._mutex = threading.Lock()
        self._permits: dict[SyntheticAttemptPermit, bytes] = {}
        self._poisoned = False
        self._last_size = 0
        with self._locked() as descriptor:
            self._read(descriptor)

    def __copy__(self) -> NoReturn:
        """Reject cloned handles that could share the issuing instance's permit registry."""
        raise ContractError("synthetic ledger handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        """Reject deep copying without consulting or duplicating private origin state."""
        raise ContractError("synthetic ledger handles cannot be copied")

    def _check_context(self) -> None:
        if self._pid != os.getpid():
            raise ContractError("ledger/permit cannot be inherited across fork")
        if self._poisoned:
            raise ContractError("ledger handle poisoned by ambiguous storage failure")
        self._issuer._check(self._bindings)  # noqa: SLF001
        if _pin(self._parent, directory=True) != self._anchor.parent:
            raise ContractError("parent descriptor replacement")
        if self._anchor.parent != self._bindings.roots[0]:
            raise ContractError("ledger custody root mismatch")
        observed = synthetic_parent_bindings(
            _canonical_object(self._bindings.authorization_bytes),
            session_id=self._bindings.session_id,
            interpreter_sha256=self._bindings.interpreter_sha256,
            root_descriptors=self._roots,
        )
        if observed != self._bindings:
            raise ContractError("bound root descriptor replacement")

    def _check_names(self, root: int, journal: int) -> None:
        if (
            _pin(root, directory=True) != self._anchor.root
            or _pin(journal, directory=False) != self._anchor.journal
        ):
            raise ContractError("ledger root/file object replacement")
        initialization_name = self._name + ".initialized"
        initialization = os.open(initialization_name, _flags(directory=False), dir_fd=self._parent)
        try:
            if _pin(initialization, directory=False) != self._anchor.initialization:
                raise ContractError("ledger initialization object replacement")
            expected = _initialization_bytes(self._anchor.header_bytes)
            if (
                os.fstat(initialization).st_size != len(expected)
                or os.pread(initialization, len(expected) + 1, 0) != expected
            ):
                raise ContractError("partial or corrupt ledger initialization")
        finally:
            os.close(initialization)
        for parent, name, pin in (
            (self._parent, self._name, self._anchor.root),
            (root, _JOURNAL_NAME, self._anchor.journal),
            (self._parent, initialization_name, self._anchor.initialization),
        ):
            metadata = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (
                metadata.st_dev != pin.device
                or metadata.st_ino != pin.inode
                or stat.S_IMODE(metadata.st_mode) != pin.mode
                or metadata.st_uid != pin.owner
            ):
                raise ContractError("ledger pathname substitution")
        with os.scandir(root) as entries:
            first = next(entries, None)
            if first is None or first.name != _JOURNAL_NAME or next(entries, None) is not None:
                raise ContractError("ledger directory has unknown or missing entries")

    @contextmanager
    def _locked(self) -> Iterator[int]:
        self._check_context()
        if not self._mutex.acquire(timeout=1):
            raise ContractError("ledger busy; no permit issued")
        try:
            try:
                self._check_context()
                root = os.open(self._name, _flags(directory=True), dir_fd=self._parent)
                try:
                    journal = os.open(_JOURNAL_NAME, _flags(directory=False), dir_fd=root)
                    try:
                        self._check_names(root, journal)
                        try:
                            fcntl.flock(journal, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError as error:
                            raise ContractError("ledger busy; no permit issued") from error
                        self._check_names(root, journal)
                        yield journal
                        self._check_names(root, journal)
                    finally:
                        os.close(journal)
                finally:
                    os.close(root)
            except OSError as error:
                self._poisoned = True
                raise ContractError("ledger storage unavailable or ambiguous; refusing") from error
        finally:
            self._mutex.release()

    def _read(self, descriptor: int) -> dict[str, JsonValue] | None:
        metadata = os.fstat(descriptor)
        if not 1 <= metadata.st_size <= _MAX_JOURNAL_BYTES:
            raise ContractError("empty, truncated or oversized ledger")
        if metadata.st_size < self._last_size:
            raise ContractError("ledger truncation or rollback observed by live parent")
        self._last_size = metadata.st_size
        data = os.pread(descriptor, _MAX_JOURNAL_BYTES + 1, 0)
        if len(data) != metadata.st_size or os.fstat(descriptor).st_size != metadata.st_size:
            raise ContractError("ledger changed during bounded read")
        header = self._anchor.header_bytes
        header_value = _canonical_object(header)
        if set(header_value) != {
            "record_type",
            "schema_version",
            "evidence_scope",
            "state",
            "parent_bindings",
            "created_clock",
        } or (
            header_value["record_type"] != "mlx_preflight_one_shot_ledger"
            or header_value["schema_version"] != "1.0"
            or header_value["evidence_scope"] != _SCOPE
            or header_value["state"] != "unconsumed"
            or header_value["parent_bindings"] != self._bindings.to_dict()
        ):
            raise ContractError("unsupported ledger header or parent binding mismatch")
        self._clock_pair(header_value["created_clock"])
        prefix = header + b"\n"
        if not data.startswith(prefix):
            raise ContractError("ledger header corruption, truncation or rollback")
        suffix = data[len(prefix) :]
        if not suffix:
            return None
        if not suffix.startswith(b"!") or not suffix.endswith(b"\n"):
            raise ContractError("partial or corrupt consumed intent; never reset")
        record = _canonical_object(suffix[1:-1])
        clock = self._clock_pair(record.get("clock"))
        self._check_clock(clock)
        expected = self._consumed_record(clock)
        if record != expected:
            raise ContractError("consumed ledger record drift or unknown fields")
        return record

    @staticmethod
    def _clock_pair(value: JsonValue) -> dict[str, JsonValue]:
        pair = _object(value)
        if set(pair) != {"unix_ns", "monotonic_ns"} or any(
            type(pair[name]) is not int or cast("int", pair[name]) < 1
            for name in ("unix_ns", "monotonic_ns")
        ):
            raise ContractError("invalid ledger clock fields")
        return pair

    def _check_clock(self, sample: dict[str, JsonValue]) -> None:
        created = self._clock_pair(_canonical_object(self._anchor.header_bytes)["created_clock"])
        wall_delta = cast("int", sample["unix_ns"]) - cast("int", created["unix_ns"])
        mono_delta = cast("int", sample["monotonic_ns"]) - cast("int", created["monotonic_ns"])
        if wall_delta < 0 or mono_delta < 0 or wall_delta != mono_delta:
            raise ContractError("synthetic clock rollback or wall/monotonic inconsistency")

    def _consumed_record(self, clock: dict[str, JsonValue]) -> dict[str, JsonValue]:
        return {
            "record_type": "mlx_preflight_durable_consumption",
            "schema_version": "1.0",
            "evidence_scope": _SCOPE,
            "header_id": canonical_identity(_canonical_object(self._anchor.header_bytes)),
            "parent_bindings_id": canonical_identity(self._bindings.to_dict()),
            "clock": clock,
            "consumption": _build_consumption(
                _canonical_object(self._bindings.authorization_bytes),
                consumed_at_unix_ns=cast("int", clock["unix_ns"]),
                session_id=self._bindings.session_id,
            ),
        }

    def inspect(self) -> dict[str, JsonValue]:
        """Read audit state only; never consume, issue a permit or authorize replay."""
        with self._locked() as descriptor:
            record = self._read(descriptor)
        return {
            "evidence_scope": _SCOPE,
            "state": "unconsumed" if record is None else "consumed",
            "consumption": record,
            "production_authority": False,
        }

    def consume_once(
        self, authorization: JsonValue, parent_bindings: ParentBindings
    ) -> SyntheticAttemptPermit:
        """Commit exact launch intent durably before issuing a synthetic attempt token."""
        if (
            canonical_json(authorization) != self._bindings.authorization_bytes
            or parent_bindings != self._bindings
        ):
            raise ContractError("exact authorization/attempt binding mismatch")
        with self._locked() as descriptor:
            if self._read(descriptor) is not None:
                raise ContractError("authorization already consumed; no retry or refund")
            clock = self._issuer._clock.sample()  # noqa: SLF001
            self._check_clock(clock)
            record = canonical_json(self._consumed_record(clock))
            try:
                _append_intent(descriptor, record)
            except (OSError, ContractError):
                self._poisoned = True
                raise
            if canonical_json(self._read(descriptor)) != record:
                self._poisoned = True
                raise ContractError("consumption persistence mismatch; no permit issued")
        permit = object.__new__(SyntheticAttemptPermit)
        self._permits[permit] = record
        return permit

    def dispatch_synthetic_once(
        self,
        permit: SyntheticAttemptPermit,
        parent_bindings: ParentBindings,
        callback: Callable[[dict[str, JsonValue]], _T],
    ) -> _T:
        """Burn one live exact token before invoking an inert parent-owned test callback."""
        with self._locked() as descriptor:
            if parent_bindings != self._bindings or type(permit) is not SyntheticAttemptPermit:
                raise ContractError("synthetic permit or attempt binding mismatch")
            record = self._permits.pop(permit, None)
            if record is None:
                raise ContractError("unknown, foreign or already dispatched synthetic permit")
            clock = self._issuer._clock.sample()  # noqa: SLF001
            self._check_clock(clock)
            _verify_authorization_at(
                _canonical_object(self._bindings.authorization_bytes),
                observed_at_unix_ns=cast("int", clock["unix_ns"]),
                allow_synthetic=True,
            )
            consumed = self._read(descriptor)
            if canonical_json(consumed) != record:
                raise ContractError("permit does not match exact durable attempt")
            consumed_clock = self._clock_pair(_object(consumed)["clock"])
            if cast("int", clock["unix_ns"]) < cast("int", consumed_clock["unix_ns"]):
                raise ContractError("synthetic clock rolled back after consumption")
        return callback(_canonical_object(record))
