"""Merged-ledger end-to-end acquisition with synthetic authority and inert children only."""

# ruff: noqa: SLF001
from __future__ import annotations

import copy
import errno
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest
from test_mlx_preflight_execution import _install_inert_spawn, _prepared

import localinferencelab.mlx_preflight_attempt as attempts
import localinferencelab.mlx_preflight_execution as parent
import localinferencelab.mlx_preflight_ledger as ledger_module
import localinferencelab.mlx_preflight_report as reports
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.mlx_preflight_custody import _synthetic_authorization
from localinferencelab.mlx_preflight_ledger import (
    LedgerAnchor,
    ParentBindings,
    SyntheticAuthorizationLedger,
    SyntheticClock,
    SyntheticLedgerIssuer,
    synthetic_root_ids,
)
from localinferencelab.mlx_preflight_protocol import AcquisitionError


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


@dataclass
class IntegratedFixture:
    """Retained parent pins and explicitly synthetic ledger enrollment."""

    launch: parent._PreparedLaunch
    attempt: attempts.SyntheticParentAttempt
    authorization: dict[str, JsonValue]
    bindings: ParentBindings
    clock: SyntheticClock
    issuer: SyntheticLedgerIssuer
    anchor: LedgerAnchor
    ledger: SyntheticAuthorizationLedger
    root: Path

    def reopen(self) -> SyntheticAuthorizationLedger:
        return self.issuer.open(
            self.launch.custody_descriptor, self.anchor, self.bindings, self.attempt.roots
        )

    @property
    def journal(self) -> Path:
        return (
            self.root
            / "custody"
            / ("authorization-" + cast("str", self.authorization["authorization_id"])[7:])
            / "authorization.journal"
        )


@pytest.fixture
def integrated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> Iterator[IntegratedFixture]:
    container = tmp_path / "private-runtime"
    container.mkdir(mode=0o700)
    launch = _prepared(tmp_path, runtime_container=container)
    container_fd = os.open(container, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    timeout = "test_timeout_consumption" in request.node.name
    monkeypatch.setattr(attempts, "MAX_LIFETIME_NS", 250_000_000 if timeout else 5_000_000_000)
    attempt = attempts.prepare_synthetic_attempt(launch, runtime_container_descriptor=container_fd)
    authorization = _synthetic_authorization(1)
    root_ids = synthetic_root_ids(attempt.roots)
    for key, identity in zip(
        ("custody_root_id", "output_root_id", "runtime_root_id"), root_ids, strict=True
    ):
        _object(authorization["root_bindings"])[key] = identity
    hello = attempt.hello()
    authorization["session_bindings"] = {
        "challenge_sha256": digest_bytes(cast("str", hello["challenge"]).encode("ascii")),
        "nonce_sha256": digest_bytes(cast("str", hello["nonce"]).encode("ascii")),
    }
    authorization.pop("authorization_id")
    authorization["authorization_id"] = canonical_identity(authorization)
    bindings = attempts.parent_bindings_for_attempt(authorization, attempt)
    clock = SyntheticClock(1_000_000_001, 100)
    issuer = SyntheticLedgerIssuer(authorization, clock)
    anchor = issuer.initialize(launch.custody_descriptor, bindings, attempt.roots)
    ledger = issuer.open(launch.custody_descriptor, anchor, bindings, attempt.roots)
    yield IntegratedFixture(
        launch, attempt, authorization, bindings, clock, issuer, anchor, ledger, tmp_path
    )
    for descriptor in (*attempt.roots, launch.runtime_descriptor):
        os.close(descriptor)


def _assert_consumed_no_refund(fixture: IntegratedFixture) -> None:
    assert fixture.ledger.inspect()["state"] == "consumed"
    reopened = fixture.reopen()
    assert reopened.inspect()["state"] == "consumed"
    with pytest.raises(ContractError, match="already consumed"):
        reopened.consume_once(fixture.authorization, fixture.bindings)


def _assert_parent_binding(
    fixture: IntegratedFixture, acquisition: parent.Acquisition, tmp_path: Path
) -> None:
    path, report = reports.compile_acquisition(
        acquisition, fixture.root / "output", output_descriptor=fixture.launch.output_descriptor
    )
    assert reports.replay_bundle(path) == report
    assert report["evidence_kind"] == "synthetic_non_promotable"
    assert report["accepted_physical_evidence"] is False and report["promotable"] is False
    assert report["synthetic_durable_consumptions"] == 1
    assert report["real_mlx_actions_observed"] == 0
    record = acquisition.synthetic_ledger_attempt
    assert record is not None
    assert report["synthetic_parent_attempt_id"] == record["attempt_id"]
    consumption_id = attempts.consumed_attempt_id(record)
    assert report["consumed_attempt_identity"] == consumption_id
    session = cast("str", acquisition.hello["session_id"])
    retention = fixture.root / "custody" / (".mlx-preflight-" + session[7:])
    assert _object(load_json_bytes((retention / "attempt.json").read_bytes())) == record
    terminal = _object(load_json_bytes((retention / "terminal.json").read_bytes()))
    assert terminal == acquisition.private_record()
    events = list(retention.glob("event-*.json"))
    for event in events:
        item = _object(load_json_bytes(event.read_bytes()))
        assert item["consumed_attempt_identity"] == consumption_id
        assert (
            item["synthetic_attempt_id"] == record["attempt_id"] and item["session_id"] == session
        )
    assert not list((fixture.root / "custody").glob(".localinferencelab-mlx-*"))
    assert str(tmp_path).encode() not in canonical_json(report)


@pytest.mark.parametrize(
    "mode", ["completed", "worker_failure", "malformed", "crash", "signal", "native_gate"]
)
def test_consumed_before_callback_retention_report_and_failure_nonrefund(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    timeline: list[str] = []
    append = ledger_module._append_intent

    def durable_append(descriptor: int, record: bytes) -> None:
        append(descriptor, record)
        timeline.append("intent_fsynced")

    monkeypatch.setattr(ledger_module, "_append_intent", durable_append)
    if mode != "native_gate":
        _install_inert_spawn(
            monkeypatch,
            failure="import_mlx" if mode == "worker_failure" else None,
            anomaly=mode if mode in {"malformed", "crash", "signal"} else None,
        )
    spawn = parent._spawn_owned

    def checked_spawn(*args: object) -> int:
        assert timeline == ["intent_fsynced"]
        assert integrated.ledger.inspect()["state"] == "consumed"
        assert b"\n!" in integrated.journal.read_bytes()
        timeline.append("parent_dispatch")
        return spawn(*args)

    monkeypatch.setattr(parent, "_spawn_owned", checked_spawn)
    acquisition = parent.consume_synthetic_attempt(
        integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
    )
    assert timeline == ["intent_fsynced", "parent_dispatch"]
    assert (
        acquisition.rejection is None if mode == "completed" else acquisition.rejection is not None
    )
    if mode == "native_gate":
        assert acquisition.rejection == "physical_launch_closed"
        assert acquisition.processes_started == 0
    _assert_consumed_no_refund(integrated)
    _assert_parent_binding(integrated, acquisition, tmp_path)
    with pytest.raises(ContractError, match="already consumed"):
        parent.consume_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
        )


@pytest.mark.parametrize("mode", ["timeout", "late"])
def test_timeout_consumption_retention_no_retry_or_refund(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, mode: str
) -> None:
    _install_inert_spawn(monkeypatch, anomaly=mode)
    context = integrated.attempt.context()
    assert cast("int", context["deadline_ns"]) - cast("int", context["started_ns"]) == 250_000_000
    acquisition = parent.consume_synthetic_attempt(
        integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
    )
    assert acquisition.rejection == "deadline"
    _assert_consumed_no_refund(integrated)
    _assert_parent_binding(integrated, acquisition, tmp_path)


def test_dispatch_reuse_foreign_copied_and_forked_handles_never_collect(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> parent.Acquisition:
        calls.append("collected")
        raise AssertionError

    monkeypatch.setattr(parent, "_collect_owned_session", forbidden)
    permit = integrated.ledger.consume_once(integrated.authorization, integrated.bindings)
    foreign = integrated.reopen()
    with pytest.raises(ContractError, match="foreign"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, foreign, integrated.bindings, permit
        )
    for copier in (copy.copy, copy.deepcopy):
        with pytest.raises(ContractError, match="cannot be copied"):
            copier(integrated.ledger)
    child = os.fork()
    if child == 0:
        try:
            parent.dispatch_synthetic_attempt(
                integrated.launch,
                integrated.attempt,
                integrated.ledger,
                integrated.bindings,
                permit,
            )
        except ContractError:
            os._exit(0)
        os._exit(1)
    assert os.waitpid(child, 0)[1] == 0
    assert calls == []


def test_consumed_permit_retired_before_failed_callback_and_live_drift(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = integrated.ledger.consume_once(integrated.authorization, integrated.bindings)

    def failed(*_args: object, **_kwargs: object) -> parent.Acquisition:
        raise OSError(errno.EIO, "inert failed launch")

    monkeypatch.setattr(parent, "_collect_owned_session", failed)
    with pytest.raises(OSError, match="inert failed launch"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    with pytest.raises(ContractError, match="already dispatched"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    _assert_consumed_no_refund(integrated)


def test_poisoned_handle_never_invokes_parent_collection(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = integrated.ledger.consume_once(integrated.authorization, integrated.bindings)

    original_open = os.open

    def io_failure(name: str, *args: object, **kwargs: object) -> int:
        if isinstance(name, str) and name.startswith("authorization-"):
            raise OSError(errno.EIO, "inert injected storage failure")
        return original_open(name, *args, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(ledger_module.os, "open", io_failure)
        with pytest.raises(ContractError, match="storage unavailable"):
            integrated.ledger.inspect()
    called: list[str] = []
    monkeypatch.setattr(
        parent, "_collect_owned_session", lambda *_args, **_kwargs: called.append("bad")
    )
    with pytest.raises(ContractError, match="poisoned"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    assert called == [] and integrated.reopen().inspect()["state"] == "consumed"


def test_post_consumption_source_drift_burns_permit_without_collection_or_refund(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = integrated.ledger.consume_once(integrated.authorization, integrated.bindings)
    original = integrated.launch.worker_bytes
    integrated.launch.worker_bytes = b"unreviewed substituted inert bytes"
    called: list[str] = []
    monkeypatch.setattr(
        parent, "_collect_owned_session", lambda *_args, **_kwargs: called.append("bad")
    )
    with pytest.raises(AcquisitionError, match="source_or_interpreter"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    integrated.launch.worker_bytes = original
    with pytest.raises(ContractError, match="already dispatched"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    assert called == []
    _assert_consumed_no_refund(integrated)


def test_copied_journal_object_refuses_before_parent_collection(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = integrated.ledger.consume_once(integrated.authorization, integrated.bindings)
    contents = integrated.journal.read_bytes()
    saved = integrated.journal.with_name("original-retained.journal")
    integrated.journal.rename(saved)
    integrated.journal.write_bytes(contents)
    integrated.journal.chmod(0o600)
    called: list[str] = []
    monkeypatch.setattr(
        parent, "_collect_owned_session", lambda *_args, **_kwargs: called.append("bad")
    )
    with pytest.raises(ContractError, match="object replacement"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    assert called == []
    assert saved.read_bytes() == integrated.journal.read_bytes() == contents


def test_report_publication_failure_preserves_consumption_and_parent_retention(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_inert_spawn(monkeypatch, anomaly="malformed")
    acquisition = parent.consume_synthetic_attempt(
        integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
    )

    def failed_publish(*_args: object, **_kwargs: object) -> Path:
        raise ContractError("inert publication unavailable")

    monkeypatch.setattr(reports, "publish_bundle", failed_publish)
    with pytest.raises(ContractError, match="publication unavailable"):
        reports.compile_acquisition(acquisition, integrated.root / "output")
    _assert_consumed_no_refund(integrated)
    retained = next((integrated.root / "custody").glob(".mlx-preflight-*"))
    assert (retained / "attempt.json").is_file() and (retained / "terminal.json").is_file()
    assert any(
        b"invalid_frame_json" in event.read_bytes() for event in retained.glob("event-*.json")
    )


def test_late_synthetic_expiry_never_collects_or_refunds(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    permit = integrated.ledger.consume_once(integrated.authorization, integrated.bindings)
    elapsed = (
        cast("int", _object(integrated.authorization["temporal"])["expires_at_unix_ns"])
        - integrated.clock.unix_ns
    )
    integrated.clock.unix_ns += elapsed
    integrated.clock.monotonic_ns += elapsed
    called: list[str] = []
    monkeypatch.setattr(
        parent, "_collect_owned_session", lambda *_args, **_kwargs: called.append("bad")
    )
    with pytest.raises(ContractError, match="expired"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    with pytest.raises(ContractError, match="already dispatched"):
        parent.dispatch_synthetic_attempt(
            integrated.launch, integrated.attempt, integrated.ledger, integrated.bindings, permit
        )
    assert called == []
    _assert_consumed_no_refund(integrated)


def test_completed_bundle_replay_never_touches_or_consumes_ledger(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_inert_spawn(monkeypatch)
    acquisition = parent.consume_synthetic_attempt(
        integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
    )
    path, report = reports.compile_acquisition(acquisition, integrated.root / "output")
    before = integrated.journal.read_bytes()

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("offline replay touched live ledger dispatch")

    monkeypatch.setattr(SyntheticAuthorizationLedger, "consume_once", forbidden)
    monkeypatch.setattr(SyntheticAuthorizationLedger, "dispatch_synthetic_once", forbidden)
    monkeypatch.setattr(SyntheticAuthorizationLedger, "inspect", forbidden)
    assert reports.replay_bundle(path) == report
    assert integrated.journal.read_bytes() == before


def test_synthetic_record_and_json_are_not_production_or_dispatch_permission(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_inert_spawn(monkeypatch)
    acquisition = parent.consume_synthetic_attempt(
        integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
    )
    with pytest.raises(AcquisitionError, match="physical_launch_closed"):
        parent._acquire_prepared(integrated.launch)
    with pytest.raises(AcquisitionError, match="physical_launch_closed"):
        reports.compile_physical_acquisition(acquisition)
    with pytest.raises(ContractError):
        parent.dispatch_synthetic_attempt(
            integrated.launch,
            integrated.attempt,
            integrated.ledger,
            integrated.bindings,
            cast("ledger_module.SyntheticAttemptPermit", acquisition.private_record()),
        )
    _assert_consumed_no_refund(integrated)


@pytest.mark.parametrize(
    "field", ["worker_program_id", "protocol_id", "execution_root", "nonce", "started_ns"]
)
def test_coordinated_synthetic_attempt_drift_cannot_replay_as_original(
    integrated: IntegratedFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, field: str
) -> None:
    _install_inert_spawn(monkeypatch)
    acquisition = parent.consume_synthetic_attempt(
        integrated.launch, integrated.attempt, integrated.ledger, integrated.authorization
    )
    record = acquisition.synthetic_ledger_attempt
    assert record is not None
    context = _object(record["context"])
    context[field] = False if field == "started_ns" else "/private/secret"
    record.pop("attempt_id")
    record["attempt_id"] = canonical_identity(record)
    with pytest.raises(AcquisitionError):
        reports.compile_acquisition(acquisition, tmp_path)
