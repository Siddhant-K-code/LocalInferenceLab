"""Exercise real private storage and inert processes with synthetic authority only."""

from __future__ import annotations

import concurrent.futures
import copy
import errno
import json
import os
import pickle
import shutil
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_preflight_ledger as ledger_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    encode_bytes,
)
from localinferencelab.mlx_preflight_custody import (
    _synthetic_authorization,
    compile_custody_bridge_fixture_1_1,
    verify_consumption_1_1,
)
from localinferencelab.mlx_preflight_ledger import (
    LedgerAnchor,
    ObjectPin,
    ParentBindings,
    SyntheticAttemptPermit,
    SyntheticAuthorizationLedger,
    SyntheticClock,
    SyntheticLedgerIssuer,
    open_production_ledger,
    synthetic_parent_bindings,
    synthetic_root_ids,
)

_SESSION = "sha256:" + "d" * 64
_INTERPRETER = "sha256:" + "e" * 64
_CHILD_CODE = "from test_mlx_preflight_ledger import child_main; child_main()"


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _rehash(authorization: dict[str, JsonValue]) -> None:
    authorization.pop("authorization_id")
    authorization["authorization_id"] = canonical_identity(authorization)


def _open_roots(paths: tuple[Path, Path, Path]) -> tuple[int, int, int]:
    return cast(
        "tuple[int, int, int]",
        tuple(os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW) for path in paths),
    )


@dataclass
class Fixture:
    """Private parent fixture and its inert child-process inputs."""

    paths: tuple[Path, Path, Path]
    roots: tuple[int, int, int]
    authorization: dict[str, JsonValue]
    clock: SyntheticClock
    issuer: SyntheticLedgerIssuer
    bindings: ParentBindings
    anchor: LedgerAnchor
    store: SyntheticAuthorizationLedger

    @property
    def directory(self) -> Path:
        return self.paths[0] / (
            "authorization-" + cast("str", self.authorization["authorization_id"])[7:]
        )

    @property
    def journal(self) -> Path:
        return self.directory / "authorization.journal"

    def reopen(self) -> SyntheticAuthorizationLedger:
        issuer = SyntheticLedgerIssuer(self.authorization, self.clock)
        return issuer.open(self.roots[0], self.anchor, self.bindings, self.roots)

    def child_payload(self, mode: str) -> bytes:
        return (
            canonical_json(
                {
                    "paths": [str(path) for path in self.paths],
                    "authorization": self.authorization,
                    "clock": self.clock.sample(),
                    "anchor": {
                        "parent": self.anchor.parent.to_dict(),
                        "root": self.anchor.root.to_dict(),
                        "journal": self.anchor.journal.to_dict(),
                        "initialization": self.anchor.initialization.to_dict(),
                        "header": encode_bytes(self.anchor.header_bytes),
                    },
                    "mode": mode,
                }
            )
            + b"\n"
        )


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    paths = cast("tuple[Path, Path, Path]", tuple(tmp_path / name for name in ("c", "o", "r")))
    for path in paths:
        path.mkdir(mode=0o700)
    roots = _open_roots(paths)
    authorization = _synthetic_authorization(1)
    root_ids = synthetic_root_ids(roots)
    root_bindings = _object(authorization["root_bindings"])
    for name, identity in zip(
        ("custody_root_id", "output_root_id", "runtime_root_id"), root_ids, strict=True
    ):
        root_bindings[name] = identity
    _rehash(authorization)
    clock = SyntheticClock(1_000_000_001, 100)
    issuer = SyntheticLedgerIssuer(authorization, clock)
    bindings = synthetic_parent_bindings(
        authorization,
        session_id=_SESSION,
        interpreter_sha256=_INTERPRETER,
        root_descriptors=roots,
    )
    anchor = issuer.initialize(roots[0], bindings, roots)
    store = issuer.open(roots[0], anchor, bindings, roots)
    yield Fixture(paths, roots, authorization, clock, issuer, bindings, anchor, store)
    for descriptor in roots:
        os.close(descriptor)


def _start_child(fixture: Fixture, mode: str = "race") -> subprocess.Popen[bytes]:
    process = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", _CHILD_CODE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={
            "PATH": os.defpath,
            "PYTHONPATH": os.pathsep.join(
                (str(Path(__file__).parent), str(Path(__file__).parents[1] / "src"))
            ),
        },
    )
    assert process.stdin is not None
    process.stdin.write(fixture.child_payload(mode))
    process.stdin.flush()
    return process


def _pin_from_json(value: JsonValue) -> ObjectPin:
    item = _object(value)
    return ObjectPin(*(cast("int", item[key]) for key in ("device", "inode", "owner", "mode")))


def child_main() -> None:
    """Independent inert interpreter, with test-only fault injection at write boundaries."""
    payload = _object(json.loads(sys.stdin.buffer.readline()))
    paths = cast("tuple[Path, Path, Path]", tuple(Path(path) for path in payload["paths"]))
    roots = _open_roots(paths)
    authorization = _object(payload["authorization"])
    sample = _object(payload["clock"])
    clock = SyntheticClock(cast("int", sample["unix_ns"]), cast("int", sample["monotonic_ns"]))
    issuer = SyntheticLedgerIssuer(authorization, clock)
    bindings = synthetic_parent_bindings(
        authorization,
        session_id=_SESSION,
        interpreter_sha256=_INTERPRETER,
        root_descriptors=roots,
    )
    encoded_anchor = _object(payload["anchor"])
    anchor = LedgerAnchor(
        _pin_from_json(encoded_anchor["parent"]),
        _pin_from_json(encoded_anchor["root"]),
        _pin_from_json(encoded_anchor["journal"]),
        _pin_from_json(encoded_anchor["initialization"]),
        decode_bytes(cast("str", encoded_anchor["header"])),
    )
    mode = payload["mode"]
    try:
        store = issuer.open(roots[0], anchor, bindings, roots)
        print("ready", flush=True)
        assert sys.stdin.buffer.readline() == b"go\n"
        if mode != "race":

            def crash_append(descriptor: int, record: bytes) -> None:
                if mode == "before_intent":
                    os._exit(73)
                os.write(descriptor, b"!")
                if mode == "partial_intent":
                    os._exit(73)
                os.write(descriptor, record + b"\n")
                if mode == "before_fsync":
                    os._exit(73)
                os.fsync(descriptor)
                if mode == "after_fsync":
                    os._exit(73)

            ledger_module._append_intent = crash_append  # noqa: SLF001
        store.consume_once(authorization, bindings)
        if mode == "after_consume":
            os._exit(73)
        print("consumed", flush=True)
    except ContractError as error:
        print("refused:" + str(error), flush=True)
    finally:
        for descriptor in roots:
            os.close(descriptor)


def test_private_exact_binding_and_nonconsuming_inspection(fixture: Fixture) -> None:
    assert fixture.directory.stat().st_mode & 0o777 == 0o700
    assert fixture.journal.stat().st_mode & 0o777 == 0o600
    before = fixture.journal.read_bytes()
    assert fixture.store.inspect()["state"] == "unconsumed"
    assert fixture.store.inspect()["production_authority"] is False
    assert fixture.journal.read_bytes() == before
    permit = fixture.store.consume_once(fixture.authorization, fixture.bindings)
    record = fixture.store.inspect()["consumption"]
    consumption = _object(_object(record)["consumption"])
    assert verify_consumption_1_1(consumption, fixture.authorization) == consumption
    assert consumption["session_id"] == _SESSION
    assert (
        fixture.store.dispatch_synthetic_once(
            permit, fixture.bindings, lambda audit: audit["evidence_scope"]
        )
        == "synthetic_non_promotable"
    )
    with pytest.raises(ContractError, match="already dispatched"):
        fixture.store.dispatch_synthetic_once(permit, fixture.bindings, lambda _: None)
    with pytest.raises(ContractError, match="already consumed"):
        fixture.reopen().consume_once(fixture.authorization, fixture.bindings)
    with pytest.raises(ContractError, match="initialization failed"):
        fixture.issuer.initialize(fixture.roots[0], fixture.bindings, fixture.roots)


def test_independent_processes_compete_exactly_one_wins(fixture: Fixture) -> None:
    processes = []
    try:
        for _ in range(6):
            process = _start_child(fixture)
            processes.append(process)
            assert process.stdout is not None
            assert process.stdout.readline() == b"ready\n"
        for process in processes:
            assert process.stdin is not None
            process.stdin.write(b"go\n")
            process.stdin.flush()
        outputs = []
        for process in processes:
            stdout, stderr = process.communicate(timeout=30)
            assert process.returncode == 0, stderr.decode()
            outputs.append(stdout.decode().strip())
        assert outputs.count("consumed") == 1
        assert sum(output.startswith("refused:") for output in outputs) == 5
        assert all(
            output == "consumed" or "busy" in output or "already consumed" in output
            for output in outputs
        )
        assert fixture.reopen().inspect()["state"] == "consumed"
        restarted = _start_child(fixture)
        assert restarted.stdout is not None
        assert restarted.stdout.readline() == b"ready\n"
        stdout, stderr = restarted.communicate(b"go\n", timeout=30)
        assert restarted.returncode == 0, stderr.decode()
        assert b"already consumed" in stdout
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=30)


@pytest.mark.parametrize(
    ("mode", "state"),
    [
        ("before_intent", "unconsumed"),
        ("partial_intent", "corrupt"),
        ("before_fsync", "consumed"),
        ("after_fsync", "consumed"),
        ("after_consume", "consumed"),
    ],
)
def test_process_crash_boundaries_never_refund(fixture: Fixture, mode: str, state: str) -> None:
    process = _start_child(fixture, mode)
    assert process.stdout is not None
    assert process.stdout.readline() == b"ready\n"
    _, stderr = process.communicate(b"go\n", timeout=30)
    assert process.returncode == 73, stderr.decode()
    if state == "corrupt":
        with pytest.raises(ContractError, match="partial"):
            fixture.reopen()
    else:
        restarted = fixture.reopen()
        assert restarted.inspect()["state"] == state
        if state == "consumed":
            with pytest.raises(ContractError, match="already consumed"):
                restarted.consume_once(fixture.authorization, fixture.bindings)
        else:
            restarted.consume_once(fixture.authorization, fixture.bindings)


@pytest.mark.parametrize(
    "damage", ["remove", "copy", "symlink", "hardlink", "root", "extra", "removed_root"]
)
def test_missing_replaced_or_substituted_objects_refuse(fixture: Fixture, damage: str) -> None:
    fixture.store.consume_once(fixture.authorization, fixture.bindings)
    if damage == "remove":
        fixture.journal.unlink()
    elif damage == "copy":
        copied = fixture.directory / "copy"
        shutil.copyfile(fixture.journal, copied)
        copied.chmod(0o600)
        copied.replace(fixture.journal)
    elif damage == "symlink":
        target = fixture.directory / "saved"
        fixture.journal.rename(target)
        fixture.journal.symlink_to(target)
    elif damage == "hardlink":
        os.link(fixture.journal, fixture.directory / "linked")
    elif damage == "root":
        saved = fixture.directory.with_name("saved")
        fixture.directory.rename(saved)
        fixture.directory.mkdir(mode=0o700)
        shutil.copyfile(saved / "authorization.journal", fixture.journal)
        fixture.journal.chmod(0o600)
    elif damage == "removed_root":
        fixture.journal.unlink()
        fixture.directory.rmdir()
    else:
        (fixture.directory / "unexpected").write_bytes(b"")
    with pytest.raises(ContractError):
        fixture.reopen()
    with pytest.raises(ContractError):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)
    with pytest.raises(ContractError, match="initialization failed"):
        fixture.issuer.initialize(fixture.roots[0], fixture.bindings, fixture.roots)


@pytest.mark.parametrize("data", [b"", b"{", b"\n", b"!" * 65537])
def test_corrupt_partial_and_oversized_storage_refuses(fixture: Fixture, data: bytes) -> None:
    fixture.journal.write_bytes(data)
    with pytest.raises(ContractError):
        fixture.reopen()


def test_live_parent_detects_truncation_reset(fixture: Fixture) -> None:
    unused = fixture.journal.read_bytes()
    fixture.store.consume_once(fixture.authorization, fixture.bindings)
    fixture.journal.write_bytes(unused)
    with pytest.raises(ContractError, match="rollback"):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)


@pytest.mark.parametrize("damage", ["missing", "corrupt", "copy"])
def test_initialization_marker_cannot_be_missing_corrupt_or_replaced(
    fixture: Fixture, damage: str
) -> None:
    marker = fixture.directory.with_name(fixture.directory.name + ".initialized")
    if damage == "missing":
        marker.unlink()
    elif damage == "corrupt":
        marker.write_bytes(b"{")
    else:
        replacement = marker.with_name("replacement")
        shutil.copyfile(marker, replacement)
        replacement.chmod(0o600)
        replacement.replace(marker)
    with pytest.raises(ContractError):
        fixture.reopen()
    with pytest.raises(ContractError):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)


@pytest.mark.parametrize("boundary", [1, 2, 3, 4, 5])
def test_interrupted_initialization_never_returns_anchor_or_recreates(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, boundary: int
) -> None:
    authorization = _synthetic_authorization(2)
    authorization["root_bindings"] = fixture.authorization["root_bindings"]
    _rehash(authorization)
    clock = SyntheticClock(2_000_000_001, 200)
    issuer = SyntheticLedgerIssuer(authorization, clock)
    bindings = synthetic_parent_bindings(
        authorization,
        session_id=_SESSION,
        interpreter_sha256=_INTERPRETER,
        root_descriptors=fixture.roots,
    )
    original_fsync = os.fsync
    calls = 0

    def interrupt(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == boundary:
            raise OSError(errno.EIO, "synthetic initialization crash boundary")
        original_fsync(descriptor)

    monkeypatch.setattr(ledger_module.os, "fsync", interrupt)
    with pytest.raises(ContractError, match="initialization failed"):
        issuer.initialize(fixture.roots[0], bindings, fixture.roots)
    monkeypatch.setattr(ledger_module.os, "fsync", original_fsync)
    with pytest.raises(ContractError, match="initialization failed"):
        SyntheticLedgerIssuer(authorization, clock).initialize(
            fixture.roots[0], bindings, fixture.roots
        )


@pytest.mark.parametrize("target", ["parent", "root", "journal", "output"])
def test_nonprivate_permissions_refuse(fixture: Fixture, target: str) -> None:
    path = {
        "parent": fixture.paths[0],
        "root": fixture.directory,
        "journal": fixture.journal,
        "output": fixture.paths[1],
    }[target]
    previous = path.stat().st_mode & 0o777
    path.chmod(0o777)
    try:
        with pytest.raises(ContractError, match="private owned"):
            fixture.store.consume_once(fixture.authorization, fixture.bindings)
    finally:
        path.chmod(previous)


def test_fifo_state_refuses_without_blocking(fixture: Fixture) -> None:
    fixture.journal.unlink()
    os.mkfifo(fixture.journal, 0o600)
    with pytest.raises(ContractError):
        fixture.reopen()


def test_other_owner_refuses(fixture: Fixture, monkeypatch: pytest.MonkeyPatch) -> None:
    owner = os.geteuid()
    monkeypatch.setattr(ledger_module.os, "geteuid", lambda: owner + 1)
    with pytest.raises(ContractError, match="private owned"):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)


@pytest.mark.parametrize("field", ["schema_version", "unknown", "clock", "consumption"])
def test_rehashed_or_unknown_journal_fields_are_not_accepted(fixture: Fixture, field: str) -> None:
    fixture.store.consume_once(fixture.authorization, fixture.bindings)
    data = fixture.journal.read_bytes()
    header, suffix = data.split(b"\n!", 1)
    record = _object(json.loads(suffix))
    record[field] = {"unreviewed": True}
    fixture.journal.write_bytes(header + b"\n!" + canonical_json(record) + b"\n")
    with pytest.raises(ContractError):
        fixture.reopen()


@pytest.mark.parametrize(
    ("section", "field"),
    [
        ("identity_bindings", "qualification_record_id"),
        ("identity_bindings", "worker_program_id"),
        ("identity_bindings", "runtime_target_id"),
        ("authority_bindings", "authorization_review_id"),
        ("authority_bindings", "authorization_authority_id"),
        ("root_bindings", "output_root_id"),
        ("session_bindings", "nonce_sha256"),
        ("session_bindings", "challenge_sha256"),
        ("temporal", "expires_at_unix_ns"),
    ],
)
def test_exact_authorization_enrollment_cannot_be_rebound(
    fixture: Fixture, section: str, field: str
) -> None:
    altered = copy.deepcopy(fixture.authorization)
    _object(altered[section])[field] = "sha256:" + "f" * 64
    _rehash(altered)
    with pytest.raises(ContractError, match="exact authorization"):
        fixture.store.consume_once(altered, fixture.bindings)
    assert fixture.store.inspect()["state"] == "unconsumed"


@pytest.mark.parametrize(
    "mutation", ["unknown", "nested", "zero_actions", "external", "old_schema"]
)
def test_labels_unknown_fields_zero_actions_and_downgrade_never_authorize(
    fixture: Fixture, mutation: str
) -> None:
    altered = copy.deepcopy(fixture.authorization)
    if mutation == "unknown":
        altered["durable_consumed"] = False
    elif mutation == "nested":
        _object(altered["temporal"])["observed_at_unix_ns"] = fixture.clock.unix_ns
    elif mutation == "zero_actions":
        altered["allowed_actions"] = []
    elif mutation == "external":
        altered["evidence_kind"] = "external_independently_reviewed_authorization"
    else:
        altered["schema_version"] = "1.0"
    _rehash(altered)
    with pytest.raises(ContractError):
        SyntheticLedgerIssuer(altered, fixture.clock)
    with pytest.raises(ContractError, match="production ledger blocked"):
        open_production_ledger()


@pytest.mark.parametrize("field", ["session_id", "interpreter_sha256"])
def test_parent_attempt_and_interpreter_mismatch_refuse(fixture: Fixture, field: str) -> None:
    altered = replace(fixture.bindings, **{field: "sha256:" + "f" * 64})
    with pytest.raises(ContractError, match="binding mismatch"):
        fixture.store.consume_once(fixture.authorization, altered)
    assert fixture.store.inspect()["state"] == "unconsumed"


def test_replaced_root_descriptor_and_wrong_parent_refuse(fixture: Fixture) -> None:
    swapped = (fixture.roots[1], fixture.roots[0], fixture.roots[2])
    with pytest.raises(ContractError, match="root identities"):
        fixture.issuer.open(fixture.roots[0], fixture.anchor, fixture.bindings, swapped)
    with pytest.raises(ContractError, match="custody root"):
        fixture.issuer.initialize(fixture.roots[1], fixture.bindings, fixture.roots)


@pytest.mark.parametrize("phase", ["consume", "dispatch"])
def test_late_expiry_refuses_without_side_effect(fixture: Fixture, phase: str) -> None:
    permit = (
        fixture.store.consume_once(fixture.authorization, fixture.bindings)
        if phase == "dispatch"
        else None
    )
    fixture.clock.unix_ns += 30_000_000_000
    fixture.clock.monotonic_ns += 30_000_000_000
    calls: list[int] = []
    if permit is None:
        with pytest.raises(ContractError, match="expired"):
            fixture.store.consume_once(fixture.authorization, fixture.bindings)
    else:
        with pytest.raises(ContractError, match="expired"):
            fixture.store.dispatch_synthetic_once(
                permit, fixture.bindings, lambda _: calls.append(1)
            )
    assert not calls
    assert fixture.reopen().inspect()["state"] == (
        "consumed" if phase == "dispatch" else "unconsumed"
    )


@pytest.mark.parametrize("delta", [(-1, -1), (1, 0), (0, 1)])
def test_clock_rollback_or_inconsistency_refuses(fixture: Fixture, delta: tuple[int, int]) -> None:
    fixture.clock.unix_ns += delta[0]
    fixture.clock.monotonic_ns += delta[1]
    with pytest.raises(ContractError, match=r"clock rollback|inconsistency"):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)


def test_serialized_forged_foreign_and_concurrent_permits_refuse(fixture: Fixture) -> None:
    permit = fixture.store.consume_once(fixture.authorization, fixture.bindings)
    with pytest.raises(ContractError, match="cannot be serialized"):
        pickle.dumps(permit)
    with pytest.raises(ContractError, match="only a durable"):
        SyntheticAttemptPermit()
    for lookalike in (object.__new__(SyntheticAttemptPermit), True, fixture.store.inspect()):
        with pytest.raises(ContractError, match="permit"):
            fixture.store.dispatch_synthetic_once(
                cast("SyntheticAttemptPermit", lookalike), fixture.bindings, lambda _: None
            )
    with pytest.raises(ContractError, match="unknown, foreign"):
        fixture.reopen().dispatch_synthetic_once(permit, fixture.bindings, lambda _: None)

    def dispatch() -> str:
        try:
            return fixture.store.dispatch_synthetic_once(permit, fixture.bindings, lambda _: "once")
        except ContractError:
            return "refused"

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        outputs = list(pool.map(lambda _: dispatch(), range(8)))
    assert outputs.count("once") == 1
    assert outputs.count("refused") == 7


@pytest.mark.parametrize("kind", ["shallow", "deep"])
def test_copied_ledger_cannot_adopt_original_permit(fixture: Fixture, kind: str) -> None:
    permit = fixture.store.consume_once(fixture.authorization, fixture.bindings)
    copier = copy.copy if kind == "shallow" else copy.deepcopy
    with pytest.raises(ContractError, match="cannot be copied"):
        copier(fixture.store)
    assert (
        fixture.store.dispatch_synthetic_once(
            permit, fixture.bindings, lambda _: "exact issuing instance"
        )
        == "exact issuing instance"
    )
    with pytest.raises(ContractError, match="already dispatched"):
        fixture.store.dispatch_synthetic_once(permit, fixture.bindings, lambda _: None)


@pytest.mark.parametrize("fault", ["inspect_pread", "intent_write"])
def test_queued_calls_recheck_poison_under_mutex(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    permit = (
        fixture.store.consume_once(fixture.authorization, fixture.bindings)
        if fault == "inspect_pread"
        else None
    )
    fault_entered = threading.Event()
    queued_precheck_passed = threading.Event()
    release_fault = threading.Event()
    original_check = fixture.store._check_context  # noqa: SLF001
    original_pread = os.pread
    original_write = os.write
    errors: dict[str, ContractError] = {}
    successes: list[str] = []
    callbacks: list[str] = []

    def observe_precheck() -> None:
        original_check()
        if threading.current_thread().name == "ledger-queued":
            queued_precheck_passed.set()

    def fail_while_locked() -> None:
        fault_entered.set()
        assert release_fault.wait(timeout=10)
        raise OSError(errno.EIO, "synthetic queued-call poisoning")

    def faulting_pread(descriptor: int, count: int, offset: int) -> bytes:
        if threading.current_thread().name == "ledger-fault" and count == 65537:
            fail_while_locked()
        return original_pread(descriptor, count, offset)

    def faulting_write(descriptor: int, data: bytes) -> int:
        if threading.current_thread().name == "ledger-fault" and data == b"!":
            fail_while_locked()
        return original_write(descriptor, data)

    def fault_operation() -> None:
        if fault == "inspect_pread":
            fixture.store.inspect()
        else:
            fixture.store.consume_once(fixture.authorization, fixture.bindings)

    def queued_operation() -> None:
        if permit is None:
            fixture.store.consume_once(fixture.authorization, fixture.bindings)
        else:
            fixture.store.dispatch_synthetic_once(
                permit, fixture.bindings, lambda _: callbacks.append("launched")
            )

    def capture(label: str, operation: Callable[[], None]) -> None:
        try:
            operation()
        except ContractError as error:
            errors[label] = error
        else:
            successes.append(label)

    monkeypatch.setattr(fixture.store, "_check_context", observe_precheck)
    monkeypatch.setattr(ledger_module.os, "pread", faulting_pread)
    monkeypatch.setattr(ledger_module.os, "write", faulting_write)
    failing = threading.Thread(target=capture, args=("fault", fault_operation), name="ledger-fault")
    queued = threading.Thread(
        target=capture, args=("queued", queued_operation), name="ledger-queued"
    )
    failing.start()
    try:
        assert fault_entered.wait(timeout=10)
        queued.start()
        assert queued_precheck_passed.wait(timeout=10)
    finally:
        release_fault.set()
        failing.join(timeout=10)
        if queued.ident is not None:
            queued.join(timeout=10)
    assert not failing.is_alive() and not queued.is_alive()
    assert not successes
    assert not callbacks
    assert set(errors) == {"fault", "queued"}
    assert "storage unavailable" in str(errors["fault"])
    assert "poisoned" in str(errors["queued"])
    assert len(fixture.store._permits) == (1 if permit is not None else 0)  # noqa: SLF001
    with pytest.raises(ContractError, match="poisoned"):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)
    assert fixture.reopen().inspect()["state"] == (
        "consumed" if permit is not None else "unconsumed"
    )


def test_inherited_permit_and_issuer_refuse_after_fork(fixture: Fixture) -> None:
    permit = fixture.store.consume_once(fixture.authorization, fixture.bindings)
    pid = os.fork()
    if pid == 0:
        try:
            fixture.store.dispatch_synthetic_once(permit, fixture.bindings, lambda _: None)
        except ContractError:
            os._exit(0)
        os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0
    fixture.store.dispatch_synthetic_once(permit, fixture.bindings, lambda _: None)


def test_forked_issuer_cannot_open_fresh_handle(fixture: Fixture) -> None:
    pid = os.fork()
    if pid == 0:
        try:
            fixture.issuer.open(fixture.roots[0], fixture.anchor, fixture.bindings, fixture.roots)
        except ContractError:
            os._exit(0)
        os._exit(1)
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0


def test_failed_dispatch_never_refunds(fixture: Fixture) -> None:
    permit = fixture.store.consume_once(fixture.authorization, fixture.bindings)

    def fail(_record: dict[str, JsonValue]) -> None:
        raise TimeoutError("synthetic launch/timeout/rejected frame")

    with pytest.raises(TimeoutError):
        fixture.store.dispatch_synthetic_once(permit, fixture.bindings, fail)
    with pytest.raises(ContractError, match="already dispatched"):
        fixture.store.dispatch_synthetic_once(permit, fixture.bindings, lambda _: None)
    with pytest.raises(ContractError, match="already consumed"):
        fixture.reopen().consume_once(fixture.authorization, fixture.bindings)


@pytest.mark.parametrize("phase", ["short_write", "fsync", "path_race"])
def test_ambiguous_write_sync_and_substitution_never_issue_permit(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    original_write = os.write
    original_fsync = os.fsync
    original_append = ledger_module._append_intent  # noqa: SLF001

    def short_write(descriptor: int, data: bytes) -> int:
        return original_write(descriptor, data[:1])

    def bad_fsync(_descriptor: int) -> None:
        raise OSError(errno.EIO, "synthetic fsync failure")

    def raced_append(descriptor: int, data: bytes) -> None:
        saved = fixture.directory / "saved"
        fixture.journal.rename(saved)
        fixture.journal.write_bytes(fixture.anchor.header_bytes + b"\n")
        fixture.journal.chmod(0o600)
        original_append(descriptor, data)

    if phase == "short_write":
        monkeypatch.setattr(ledger_module.os, "write", short_write)
    elif phase == "fsync":
        monkeypatch.setattr(ledger_module.os, "fsync", bad_fsync)
    else:
        monkeypatch.setattr(ledger_module, "_append_intent", raced_append)
    with pytest.raises(ContractError):
        fixture.store.consume_once(fixture.authorization, fixture.bindings)
    monkeypatch.setattr(ledger_module.os, "write", original_write)
    monkeypatch.setattr(ledger_module.os, "fsync", original_fsync)
    assert not fixture.store._permits  # noqa: SLF001
    if phase == "fsync":
        assert fixture.reopen().inspect()["state"] == "consumed"
    else:
        with pytest.raises(ContractError):
            fixture.reopen()


def test_historical_custody_fixture_replays_byte_identically(tmp_path: Path) -> None:
    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    first, first_result = compile_custody_bridge_fixture_1_1(tmp_path / "a")
    second, second_result = compile_custody_bridge_fixture_1_1(tmp_path / "b")
    assert first_result == second_result
    assert first_result.real_authorizations_created == 0
    assert first_result.real_authorizations_consumed == 0
    assert first_result.physical_actions == 0
    assert {
        path.relative_to(first): path.read_bytes() for path in first.rglob("*") if path.is_file()
    } == {
        path.relative_to(second): path.read_bytes() for path in second.rglob("*") if path.is_file()
    }
