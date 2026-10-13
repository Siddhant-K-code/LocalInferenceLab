"""Structure-only requests and explicit blocked acquisition; no MLX or authority issuance."""

from __future__ import annotations

import concurrent.futures
import copy
import importlib
import os
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

import pytest
import test_mlx_preflight_integration as integration

import localinferencelab.mlx_preflight_execution as parent
import localinferencelab.mlx_preflight_ledger as ledger
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.cli import run
from localinferencelab.mlx_preflight_authorization import (
    MAX_REQUEST_BYTES,
    AuthorizationAcquisitionError,
    assess_authorization_request,
    authorization_request_spec,
    build_authorization_request,
    prepare_authorization_acquisition,
    verify_authorization_request_bytes,
    verify_authorization_request_structure,
)
from localinferencelab.mlx_preflight_execution import require_physical_launch
from localinferencelab.mlx_preflight_ledger import open_production_ledger
from localinferencelab.mlx_preflight_worker import MAX_LIFETIME_NS, PROTOCOL_ID, validate_hello

merged_ledger = integration.integrated


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    return _object(load_json_bytes(canonical_json(value)))


def _rehash(request: dict[str, JsonValue]) -> None:
    request.pop("request_id", None)
    request["request_id"] = canonical_identity(request)


def _inputs() -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    """Invent proposal fields only, conspicuously synthetic and never observed evidence."""
    spec = authorization_request_spec()
    root_objects: dict[str, JsonValue] = {
        role: {"device": 1, "inode": index, "owner": 501, "mode": 0o700}
        for index, role in enumerate(("custody", "output", "runtime_container"), 1)
    }
    context: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_prospective_attempt_context",
        "schema_version": "1.0",
        "evidence_scope": "synthetic_non_promotable",
        "candidate_bindings": spec["candidate_bindings"],
        "source_bindings": spec["source_bindings"],
        "policy_id": _object(spec["policy"])["policy_id"],
        "parent_process": {"pid": 123, "process_instance_id": "sha256:" + "1" * 64},
        "host_provenance_claim_id": None,
        "roots": root_objects,
        "execution_root": {
            "parent_role": "runtime_container",
            "relative_name": "preflight-runtime",
            "object": {"device": 1, "inode": 4, "owner": 501, "mode": 0o555},
            "tree_id": "sha256:" + "2" * 64,
        },
        "environment": {
            "interpreter_sha256": _object(_object(spec["runtime_target"])["interpreter"])[
                "executable_sha256"
            ],
            "runtime_manifest_id": "sha256:" + "3" * 64,
            "distributions": spec["expected_distributions"],
            "import_files": {
                "mlx.core": {
                    "relative_file": "mlx/core.cpython-313-darwin.so",
                    "sha256": "sha256:" + "4" * 64,
                },
                "mlx_lm": {
                    "relative_file": "mlx_lm/__init__.py",
                    "sha256": "sha256:" + "5" * 64,
                },
            },
            "fresh_wheel_verification_id": None,
            "installation_custody_id": None,
            "stdlib_closure_id": None,
            "native_loader_closure_id": None,
            "framework_closure_id": None,
        },
        "session": {
            "started_monotonic_ns": 1_000_000_000,
            "deadline_monotonic_ns": 1_000_000_000 + MAX_LIFETIME_NS,
            "nonce": "6" * 64,
        },
    }
    validity: dict[str, JsonValue] = {
        "requested_at_unix_ns": 2_000_000_000,
        "not_before_unix_ns": 2_000_000_000,
        "expires_at_unix_ns": 2_000_000_000 + MAX_LIFETIME_NS,
    }
    return context, validity


@pytest.fixture
def proposal() -> dict[str, JsonValue]:
    return build_authorization_request(*_inputs())


def test_spec_exact_candidates_and_separate_unapproved_prerequisites() -> None:
    spec = authorization_request_spec()
    assert spec["worker_schema_version"] == "1.2" and spec["protocol_id"] == PROTOCOL_ID
    target = _object(spec["runtime_target"])
    assert _object(target["interpreter"])["python_full_version"] == "3.13.15"
    assert _object(target["platform"])["macos_build_version"] == "26A434"
    assert _object(target["platform"])["macos_product_version"] == "27.0.1"
    assert spec["wheel_artifact_count"] == 34 and spec["wheel_total_size_bytes"] == 70_700_189
    assert set(_object(spec["unapproved_prerequisites"]).values()) == {"unavailable"}
    assert _object(spec["trust_policy"])["production_authority_id"] is None
    policy = _object(spec["policy"])
    assert _object(policy["native_enforcement"])["metal_compatibility"] == "untested"
    assert _object(policy["durable_consumption"])["production_adapter_state"] == "unavailable"
    sources = _object(spec["source_bindings"])
    source_root = Path(__file__).resolve().parents[1] / "src" / "localinferencelab"
    for component, identity in sources.items():
        assert (
            digest_bytes((source_root / f"mlx_preflight_{component}.py").read_bytes()) == identity
        )
    assert (
        canonical_identity({key: value for key, value in spec.items() if key != "spec_id"})
        == (spec["spec_id"])
    )


def test_deterministic_request_binds_full_context_and_valid_worker_hello(
    proposal: dict[str, JsonValue],
) -> None:
    assert build_authorization_request(*_inputs()) == proposal
    assert verify_authorization_request_structure(proposal) == proposal
    validate_hello(_object(proposal["hello"]))
    with pytest.raises(AuthorizationAcquisitionError) as caught:
        prepare_authorization_acquisition(proposal)
    refusal = _object(load_json_bytes(caught.value.refusal_bytes))
    assert refusal == assess_authorization_request(proposal)
    assert refusal["runtime_authorized"] is False and refusal["consumable"] is False
    assert refusal["authority_verification"] == "unavailable_not_performed"
    assert refusal["requested_action_outcomes"] == "unknown_not_executed_or_observed"
    assert set(_object(refusal["preparation_actions"]).values()) == {0}
    assert b'"challenge"' not in caught.value.refusal_bytes
    assert b'"roots"' not in caught.value.refusal_bytes


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("schema_version",), "1.1"),
        (("decision",), "authorize_once"),
        (("action",), "inference"),
        (("spec_id",), "sha256:" + "7" * 64),
        (("context", "evidence_scope"), "external_independently_reviewed_authorization"),
        (("context", "evidence_scope"), ["synthetic_non_promotable"]),
        (("context", "policy_id"), "sha256:" + "7" * 64),
        (("context", "source_bindings", "worker"), "sha256:" + "c" * 64),
        (("context", "candidate_bindings", "qualification_record_id"), "sha256:" + "7" * 64),
        (("context", "parent_process", "pid"), True),
        (("context", "parent_process", "pid"), 0),
        (("context", "parent_process", "pid"), 2**31),
        (("context", "parent_process", "process_instance_id"), "sha256:" + "A" * 64),
        (("context", "roots", "custody", "device"), True),
        (("context", "roots", "custody", "inode"), 0),
        (("context", "roots", "custody", "inode"), 2**64),
        (("context", "roots", "custody", "mode"), 0o555),
        (("context", "roots", "custody", "owner"), False),
        (("context", "roots", "output", "inode"), 1),
        (("context", "roots", "output", "owner"), 502),
        (("context", "execution_root", "object", "mode"), 0o700),
        (("context", "execution_root", "object", "device"), 2),
        (("context", "execution_root", "object", "inode"), 1),
        (("context", "execution_root", "object", "owner"), 502),
        (("context", "execution_root", "relative_name"), "../preflight-runtime"),
        (("context", "environment", "interpreter_sha256"), "sha256:" + "7" * 64),
        (("context", "environment", "fresh_wheel_verification_id"), False),
        (("context", "environment", "import_files", "mlx.core", "relative_file"), "mlx/fake.so"),
        (("context", "environment", "import_files", "mlx_lm", "sha256"), "sha256:" + "A" * 64),
        (("context", "session", "started_monotonic_ns"), True),
        (("context", "session", "deadline_monotonic_ns"), 2**64),
        (("context", "session", "nonce"), "short"),
        (("requested_validity", "requested_at_unix_ns"), True),
        (("requested_validity", "expires_at_unix_ns"), 2_000_000_000),
        (("requested_validity", "expires_at_unix_ns"), 2_000_000_001),
        (("hello", "sequence"), False),
        (("hello", "deadline_ns"), True),
        (("unapproved_prerequisites", "independently_retained_trust_root"), "approved"),
        (("unapproved_prerequisites", "independently_retained_trust_root"), True),
    ],
)
def test_coherent_request_rehash_cannot_bypass_pins_types_or_scope(
    proposal: dict[str, JsonValue], path: tuple[str, ...], replacement: JsonValue
) -> None:
    target = proposal
    for key in path[:-1]:
        target = _object(target[key])
    target[path[-1]] = replacement
    _rehash(proposal)
    with pytest.raises(ContractError):
        verify_authorization_request_structure(proposal)


@pytest.mark.parametrize("kind", ["duplicate", "wrong_version", "metadata", "unsorted", "untyped"])
def test_exact_distribution_closure_rejects_substitution(
    proposal: dict[str, JsonValue], kind: str
) -> None:
    distributions = _object(_object(proposal["context"])["environment"])["distributions"]
    assert isinstance(distributions, list)
    if kind == "duplicate":
        distributions.append(distributions[0])
    elif kind == "wrong_version":
        _object(distributions[0])["version"] = "0.0.0"
    elif kind == "metadata":
        _object(distributions[0])["metadata_sha256"] = "sha256:" + "7" * 64
    elif kind == "untyped":
        distributions[0] = False
    else:
        distributions.reverse()
    _rehash(proposal)
    with pytest.raises(ContractError, match="distribution closure"):
        verify_authorization_request_structure(proposal)


@pytest.mark.parametrize(
    "field",
    ["approved", "execute", "skip_checks", "authority", "approval_id", "consumption", "callback"],
)
def test_no_extra_permission_surface(proposal: dict[str, JsonValue], field: str) -> None:
    proposal[field] = True
    _rehash(proposal)
    with pytest.raises(ContractError, match="exact object fields"):
        prepare_authorization_acquisition(proposal)


def test_canonical_byte_limits_duplicates_and_identity(proposal: dict[str, JsonValue]) -> None:
    data = canonical_json(proposal)
    assert len(data) < MAX_REQUEST_BYTES
    assert verify_authorization_request_bytes(data) == proposal
    for invalid in (
        b"",
        data + b"\n",
        b" " * (MAX_REQUEST_BYTES + 1),
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b'{"float":1.0}',
        b"\xff",
        b"[" * 1500 + b"]" * 1500,
    ):
        with pytest.raises(ContractError):
            verify_authorization_request_bytes(invalid)
    proposal["request_id"] = "sha256:" + "7" * 64
    with pytest.raises(ContractError, match="request: pinned"):
        verify_authorization_request_structure(proposal)


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (-1, "not_yet_within_caller_claimed_window"),
        (0, "within_caller_claimed_window_not_trusted_freshness"),
        (MAX_LIFETIME_NS - 1, "within_caller_claimed_window_not_trusted_freshness"),
        (MAX_LIFETIME_NS, "expired_caller_claimed_window"),
    ],
)
def test_claimed_time_never_establishes_freshness(
    proposal: dict[str, JsonValue], offset: int, expected: str
) -> None:
    clock: dict[str, JsonValue] = {
        "unix_ns": 2_000_000_000 + offset,
        "monotonic_ns": 1_000_000_000 + offset,
    }
    refusal = assess_authorization_request(proposal, claimed_clock=clock)
    assert refusal["claimed_clock_window"] == expected
    assert refusal["trusted_freshness_verification"] == "unavailable_not_performed"
    with pytest.raises(AuthorizationAcquisitionError):
        prepare_authorization_acquisition(proposal, claimed_clock=clock)


@pytest.mark.parametrize(
    "clock",
    [
        {"unix_ns": True, "monotonic_ns": 1_000_000_000},
        {"unix_ns": 2_000_000_000, "monotonic_ns": False},
        {"unix_ns": 2_000_000_001, "monotonic_ns": 1_000_000_000},
        {"unix_ns": 2_000_000_000, "monotonic_ns": 2**64},
    ],
)
def test_clock_aliases_and_incoherence_refuse(
    proposal: dict[str, JsonValue], clock: JsonValue
) -> None:
    with pytest.raises(ContractError):
        assess_authorization_request(proposal, claimed_clock=clock)


def test_all_claimed_references_and_matching_hello_still_block() -> None:
    context, validity = _inputs()
    context["evidence_scope"] = "caller_supplied_unverified"
    context["host_provenance_claim_id"] = "sha256:" + "a" * 64
    environment = _object(context["environment"])
    for field in (
        "fresh_wheel_verification_id",
        "installation_custody_id",
        "stdlib_closure_id",
        "native_loader_closure_id",
        "framework_closure_id",
    ):
        environment[field] = "sha256:" + "b" * 64
    request = build_authorization_request(context, validity)
    report = assess_authorization_request(request)
    assert set(_object(report["evidence_reference_status"]).values()) == {
        "supplied_reference_not_authenticated"
    }
    assert report["runtime_authorized"] is False and report["accepted_physical_evidence"] is False
    assert report["wheel_bytes_verification"] == "not_performed"
    assert report["live_ledger_verification"] == "not_opened_or_consumed"


def test_context_changes_rebind_challenge_session_and_attempt(
    proposal: dict[str, JsonValue],
) -> None:
    context = _copy(proposal["context"])
    _object(context["parent_process"])["process_instance_id"] = "sha256:" + "7" * 64
    changed = build_authorization_request(context, proposal["requested_validity"])
    for field in ("request_id", "attempt_id"):
        assert changed[field] != proposal[field]
    assert _object(changed["hello"])["challenge"] != _object(proposal["hello"])["challenge"]
    assert _object(changed["hello"])["session_id"] != _object(proposal["hello"])["session_id"]
    for request in (changed, proposal, copy.deepcopy(proposal)):
        with pytest.raises(AuthorizationAcquisitionError):
            prepare_authorization_acquisition(request)
    _object(context["parent_process"])["pid"] = 456
    assert _object(changed["context"])["parent_process"] != context["parent_process"]


def test_no_runtime_roots_clock_socket_process_or_ledger_acquisition(
    proposal: dict[str, JsonValue],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("offline request machinery performed runtime acquisition")

    fstat = os.fstat

    def static_files_only(descriptor: int) -> os.stat_result:
        metadata = fstat(descriptor)
        assert stat.S_ISREG(metadata.st_mode), "offline request observed a runtime root"
        return metadata

    monkeypatch.setattr(os, "fstat", static_files_only)
    monkeypatch.setattr(os, "fork", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "socketpair", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(time, "monotonic_ns", forbidden)
    monkeypatch.setattr(time, "time_ns", forbidden)
    monkeypatch.setattr(parent, "_prepare_launch", forbidden)
    monkeypatch.setattr(parent, "_spawn_owned", forbidden)
    monkeypatch.setattr(ledger, "open_production_ledger", forbidden)
    monkeypatch.setattr(ledger.SyntheticAuthorizationLedger, "consume_once", forbidden)
    monkeypatch.setattr(ledger.SyntheticAuthorizationLedger, "dispatch_synthetic_once", forbidden)
    monkeypatch.setattr(ledger.SyntheticLedgerIssuer, "initialize", forbidden)
    assert verify_authorization_request_structure(proposal) == proposal
    with pytest.raises(AuthorizationAcquisitionError):
        prepare_authorization_acquisition(proposal)
    with pytest.raises(SystemExit) as help_exit:
        run(["--help"])
    assert help_exit.value.code == 0
    assert "runtime" not in capsys.readouterr().err
    assert run(["mlx", "runtime-preflight-1-2-request"]) == 2
    assert "physical_launch_enabled" in capsys.readouterr().out


def test_fresh_process_import_and_help_are_nonexecuting() -> None:
    script = """
import sys
def audit(event, args):
    if event in {'os.fork', 'subprocess.Popen', 'socket.__new__'}:
        raise AssertionError('import/help attempted acquisition')
    if event == 'import' and args[0].split('.')[0] in {'mlx', 'mlx_lm', 'Metal'}:
        raise AssertionError('runtime import attempted')
sys.addaudithook(audit)
from localinferencelab.mlx_preflight_authorization import authorization_request_spec
from localinferencelab.cli import run
assert authorization_request_spec()['trust_policy']['production_authority_id'] is None
try:
    run(['--help'])
except SystemExit as error:
    assert error.code == 0
else:
    raise AssertionError('help did not terminate normally')
assert not {'mlx', 'mlx_lm', 'Metal'} & sys.modules.keys()
"""
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script], capture_output=True, check=False, timeout=30
    )
    assert completed.returncode == 0, completed.stderr.decode()


def test_existing_production_gates_remain_closed() -> None:
    with pytest.raises(ContractError, match="production ledger blocked"):
        open_production_ledger()
    with pytest.raises(ContractError, match="physical_launch_closed"):
        require_physical_launch()


def test_real_merged_synthetic_journal_or_authorization_never_promotes_request(
    merged_ledger: integration.IntegratedFixture, proposal: dict[str, JsonValue]
) -> None:
    before = merged_ledger.journal.read_bytes()
    with pytest.raises(ContractError, match="exact object fields"):
        verify_authorization_request_structure(merged_ledger.authorization)
    context = _copy(proposal["context"])
    environment = _object(context["environment"])
    environment["installation_custody_id"] = digest_bytes(before)
    request = build_authorization_request(context, proposal["requested_validity"])
    report = assess_authorization_request(request)
    assert _object(report["evidence_reference_status"])["installation_custody_id"] == (
        "supplied_reference_not_authenticated"
    )
    with pytest.raises(AuthorizationAcquisitionError):
        prepare_authorization_acquisition(request)
    assert merged_ledger.journal.read_bytes() == before
    assert merged_ledger.ledger.inspect()["state"] == "unconsumed"


def test_queued_and_concurrent_preparations_never_issue_a_capability(
    proposal: dict[str, JsonValue],
) -> None:
    def refuse(_index: int) -> bytes:
        with pytest.raises(AuthorizationAcquisitionError) as caught:
            prepare_authorization_acquisition(proposal)
        return caught.value.refusal_bytes

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        reports = list(pool.map(refuse, range(6)))
    assert len(set(reports)) == 1
    assert "mlx" not in sys.modules and "mlx_lm" not in sys.modules
    module = importlib.import_module("localinferencelab.mlx_preflight_authorization")
    assert not hasattr(module, "open_production_ledger")
