"""Synthetic non-authority vectors; no key generation, signing or live trust enrollment."""

# ruff: noqa: SLF001

from __future__ import annotations

import base64
import copy
import importlib
import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

import pytest
import test_mlx_preflight_authorization as legacy

import localinferencelab.mlx_preflight_approval as adapter
import localinferencelab.mlx_preflight_trusted_lab as policy_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.custody import read_closed_bundle
from localinferencelab.mlx_preflight_authorization import (
    AuthorizationAcquisitionError,
    authorization_request_spec,
    prepare_authorization_acquisition,
    verify_authorization_request_bytes,
)
from localinferencelab.mlx_preflight_execution import require_physical_launch
from localinferencelab.mlx_preflight_ledger import open_production_ledger
from localinferencelab.mlx_preflight_trusted_lab import (
    CLOCK_TOLERANCE_NS,
    MAX_PAYLOAD_BYTES,
    NAMESPACE,
    PRINCIPAL,
    SYSTEM_TOOL,
    approval_payload_bytes,
    build_trusted_lab_request,
    trusted_lab_request_spec,
    verification_mechanism_spec,
    verify_approval_payload_bytes,
    verify_trusted_lab_request_bytes,
)

_VECTORS = Path(__file__).parent / "data" / "trusted-lab-openssh"
_WALL = 2_000_000_000
_MONOTONIC = 1_000_000_000
pytestmark = pytest.mark.usefixtures("observed_clock")


def _object(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _request() -> dict[str, JsonValue]:
    context, validity = legacy._inputs()
    spec = trusted_lab_request_spec()
    context["schema_version"] = "2.0"
    context["source_bindings"] = spec["source_bindings"]
    context["policy_id"] = _object(spec["policy"])["policy_id"]
    return build_trusted_lab_request(context, validity)


def _rehash(value: dict[str, JsonValue], field: str) -> None:
    value.pop(field, None)
    value[field] = canonical_identity(value)


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _config() -> dict[str, JsonValue]:
    spec = trusted_lab_request_spec()
    config: dict[str, JsonValue] = {
        "record_type": "mlx_trusted_lab_retained_public_trust",
        "schema_version": "1.0",
        "policy_id": _object(spec["policy"])["policy_id"],
        "spec_id": spec["spec_id"],
        "mechanism_id": verification_mechanism_spec()["mechanism_id"],
        "mechanism_approval": "human_configured_approved_for_evidence_verification_only",
        "tool_sha256": digest_bytes(Path(SYSTEM_TOOL).read_bytes()),
        "principal": PRINCIPAL,
        "namespace": NAMESPACE,
        "public_key": (_VECTORS / "published-test-key.pub").read_text().strip(),
        "state": "enabled",
        "scope": "signed_request_evidence_only_no_runtime_authority",
    }
    _rehash(config, "trust_id")
    return config


@pytest.fixture
def observed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Non-promotable instrumentation, absent from every production API."""
    monkeypatch.setattr(adapter.time, "time_ns", lambda: _WALL + 1_000_000)
    monkeypatch.setattr(adapter.time, "monotonic_ns", lambda: _MONOTONIC + 1_000_000)


@pytest.fixture
def retained(tmp_path: Path) -> tuple[Path, Path, Path, str]:
    # Resolve pytest's platform temp ancestor once; the verifier itself never follows symlinks.
    roots = tuple(tmp_path.resolve() / name for name in ("trust", "approval", "output"))
    for root in roots:
        root.mkdir(mode=0o700)
    config = _config()
    trust_id = config["trust_id"]
    assert isinstance(trust_id, str)
    _write(roots[0] / "trust.json", canonical_json(config))
    _write(roots[1] / "signed-request.json", (_VECTORS / "signed-request.json").read_bytes())
    _write(roots[1] / "signed-request.sig", (_VECTORS / "signed-request.sig").read_bytes())
    return *roots, trust_id


def _invoke(retained: tuple[Path, Path, Path, str]) -> adapter.SignedRequestEvidence:
    trust, approval, output, identity = retained
    return adapter.verify_retained_approval(
        trust,
        approval,
        output,
        retained_trust_id=identity,
    )


def _refuse(retained: tuple[Path, Path, Path, str]) -> dict[str, JsonValue]:
    with pytest.raises(adapter.ApprovalVerificationError) as caught:
        _invoke(retained)
    return _object(load_json_bytes(caught.value.report_bytes))


def test_distinct_version_and_preserved_v1_identities() -> None:
    old = authorization_request_spec()
    assert (
        old["spec_id"] == "sha256:8dde416f087e2b91b16cf32c02bb668129a9efc85f754bf0498bad4f337de7c8"
    )
    assert _object(old["policy"])["policy_id"] == (
        "sha256:7a2b124f4f69ec7bc8107a6a341291587d782fad2bbaf528447c8dbfdfea27ea"
    )
    new = trusted_lab_request_spec()
    assert new["schema_version"] == "2.0"
    assert new["spec_id"] != old["spec_id"]
    assert new["candidate_review_status"] == "UNREVIEWED"
    assert _object(new["policy"])["policy_id"] != _object(old["policy"])["policy_id"]
    assert _object(_object(new["policy"])["native_enforcement"])["socket_creation"] == (
        "succeeded_not_denied"
    )
    assert set(_object(new["unapproved_prerequisites"]).values()) == {"unavailable"}
    request = _request()
    assert verify_trusted_lab_request_bytes(canonical_json(request)) == request
    with pytest.raises(ContractError):
        verify_authorization_request_bytes(canonical_json(request))
    old_request = legacy.build_authorization_request(*legacy._inputs())
    with pytest.raises(ContractError):
        verify_trusted_lab_request_bytes(canonical_json(old_request))
    with pytest.raises(AuthorizationAcquisitionError):
        prepare_authorization_acquisition(old_request)


def test_exact_payload_and_detached_deep_mutation() -> None:
    request = _request()
    payload = approval_payload_bytes(request)
    assert len(payload) <= MAX_PAYLOAD_BYTES
    assert payload == (_VECTORS / "signed-request.json").read_bytes()
    checked = verify_approval_payload_bytes(payload)
    _object(_object(checked["request"])["context"])["policy_id"] = "sha256:" + "0" * 64
    assert verify_approval_payload_bytes(payload) != checked
    for invalid in (
        payload + b"\n",
        b"",
        b" " * (MAX_PAYLOAD_BYTES + 1),
        b'{"request":1,"request":2}',
        b'{"n":1.0}',
        b"\xff",
        b"[" * 1500 + b"]" * 1500,
    ):
        with pytest.raises(ContractError):
            verify_approval_payload_bytes(invalid)


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("schema_version",), "1.0"),
        (("spec", "policy", "attempts"), True),
        (("spec", "policy", "excluded_guarantees"), []),
        (("request", "context", "schema_version"), "1.0"),
        (("request", "context", "policy_id"), "sha256:" + "0" * 64),
        (("request", "context", "source_bindings", "worker"), "sha256:" + "0" * 64),
        (("request", "context", "session", "nonce"), "0" * 64),
        (("request", "context", "parent_process", "pid"), True),
        (("request", "context", "environment", "runtime_manifest_id"), "sha256:" + "0" * 64),
        (("request", "requested_validity", "expires_at_unix_ns"), True),
    ],
)
def test_full_signed_binding_refuses_coherent_envelope_rehash(
    path: tuple[str, ...],
    replacement: JsonValue,
) -> None:
    payload = _object(load_json_bytes(approval_payload_bytes(_request())))
    node = payload
    for part in path[:-1]:
        node = _object(node[part])
    node[path[-1]] = replacement
    _rehash(_object(payload["request"]), "request_id")
    _rehash(payload, "payload_id")
    with pytest.raises(ContractError):
        verify_approval_payload_bytes(canonical_json(payload))


def test_actual_openssh_positive_retains_full_bytes_without_authority(
    retained: tuple[Path, Path, Path, str],
) -> None:
    evidence = _invoke(retained)
    report = evidence.report()
    assert report["signature_verification"] == "verified"
    assert report["tool_process_exposure"] == "started"
    assert report["tool_termination"] == "reaped_exit"
    assert report["disposition"] == "verified_signed_request_evidence_only"
    for field in (
        "runtime_authorized",
        "consumable",
        "physical_launch_enabled",
        "accepted_physical_evidence",
        "ledger_permit_created",
    ):
        assert report[field] is False
    _, files = read_closed_bundle(retained[2] / evidence.bundle_name)
    assert (
        files["private/signed-request.json"] == (retained[1] / "signed-request.json").read_bytes()
    )
    assert files["private/signed-request.sig"] == (retained[1] / "signed-request.sig").read_bytes()
    assert files["private/trust.json"] == (retained[0] / "trust.json").read_bytes()
    assert files["report.json"] == evidence.report_bytes
    for path in (retained[2] / evidence.bundle_name).rglob("*"):
        assert path.stat().st_mode & 0o777 == (0o700 if path.is_dir() else 0o600)
    public = evidence.report_bytes
    for secret in (
        str(retained[0]).encode(),
        str(retained[1]).encode(),
        b"ssh-ed25519 ",
        b"test-only-non-authority",
        b'"nonce"',
        b'"challenge"',
        b'"pid"',
        b'"public_key"',
        b"Good",
        b"Signature verification",
    ):
        assert secret not in public
    copied = copy.deepcopy(report)
    copied["runtime_authorized"] = True
    assert evidence.report()["runtime_authorized"] is False
    for gate in (open_production_ledger, require_physical_launch):
        with pytest.raises(ContractError):
            gate()


@pytest.mark.parametrize("parent_status", ["normal", "ignored_sigchld", "other_reaper"])
@pytest.mark.parametrize("signature", ["signed-request.sig", "wrong-namespace.sig"])
def test_isolated_actual_openssh_requires_owned_os_status(
    retained: tuple[Path, Path, Path, str],
    parent_status: str,
    signature: str,
) -> None:
    _write(retained[1] / "signed-request.sig", (_VECTORS / signature).read_bytes())
    script = """
import os, signal, sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "src"))
sys.path.insert(0, str(Path(sys.argv[1]) / "tests"))
import test_mlx_preflight_approval as fixture
from localinferencelab.canonical import canonical_json
adapter = fixture.adapter
adapter.time.time_ns = lambda: fixture._WALL + 1_000_000
adapter.time.monotonic_ns = lambda: fixture._MONOTONIC + 1_000_000
mode = sys.argv[2]
if mode == "ignored_sigchld":
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
elif mode == "other_reaper":
    original = adapter._observe_child_status
    stolen = []
    def reap_first(pid):
        observed_pid, status = os.waitpid(pid, 0)
        assert observed_pid == pid and os.WIFEXITED(status)
        stolen.append(status)
        return original(pid)
    adapter._observe_child_status = reap_first
roots = tuple(Path(arg) for arg in sys.argv[3:6])
try:
    report = adapter.verify_retained_approval(
        *roots, retained_trust_id=sys.argv[6]).report()
except adapter.ApprovalVerificationError as error:
    report = fixture._object(fixture.load_json_bytes(error.report_bytes))
if mode == "other_reaper":
    assert len(stolen) == 1
assert all(report[field] is False for field in (
    "runtime_authorized", "consumable", "physical_launch_enabled",
    "accepted_physical_evidence", "ledger_permit_created"))
sys.stdout.buffer.write(canonical_json(report))
"""
    completed = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(Path(__file__).resolve().parents[1]),
            parent_status,
            *(str(path) for path in retained[:3]),
            retained[3],
        ],
        check=True,
        capture_output=True,
        timeout=15,
        env={"LC_ALL": "C", "TZ": "UTC"},
    )
    report = _object(load_json_bytes(completed.stdout))
    if parent_status == "normal":
        expected = "verified" if signature == "signed-request.sig" else "rejected"
        assert report["signature_verification"] == expected
        assert report["tool_termination"] == "reaped_exit"
    else:
        assert report["signature_verification"] == "unknown_child_status"
        assert report["tool_termination"] == "unknown"
        assert report["disposition"] == "signature_not_verified"
    assert report["tool_process_exposure"] == "started"
    bundles = [path for path in retained[2].iterdir() if path.is_dir()]
    assert bundles
    retained_reports = []
    for bundle in bundles:
        _, files = read_closed_bundle(bundle)
        assert files["private/signed-request.sig"] == (_VECTORS / signature).read_bytes()
        wait_evidence = _object(load_json_bytes(files["private/owned-tool-status.json"]))
        if parent_status == "normal":
            status = wait_evidence["raw_wait_status"]
            assert type(status) is int and os.WIFEXITED(status)
            if signature == "signed-request.sig":
                assert os.WEXITSTATUS(status) == 0
            else:
                assert os.WEXITSTATUS(status) != 0
            assert wait_evidence["terminal_status_available"] is True
        else:
            assert wait_evidence["raw_wait_status"] is None
            assert wait_evidence["terminal_status_available"] is False
            assert wait_evidence["reported_termination"] == "unknown"
        retained_reports.append(files["report.json"])
    assert completed.stdout in retained_reports


def test_popen_wait_and_returncode_are_not_status_authority(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_wait(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("Popen synthetic ECHILD status must not authorize verification")

    monkeypatch.setattr(subprocess.Popen, "wait", forbidden_wait)
    monkeypatch.setattr(subprocess.Popen, "poll", forbidden_wait)
    assert _invoke(retained).report()["signature_verification"] == "verified"


@pytest.mark.parametrize(
    "kind",
    ["namespace", "key", "signature", "coherent_changed_request", "coherent_changed_context"],
)
def test_actual_openssh_negative_vectors(
    retained: tuple[Path, Path, Path, str],
    kind: str,
) -> None:
    if kind in {"coherent_changed_request", "coherent_changed_context"}:
        request = _request()
        context = _object(request["context"])
        if kind == "coherent_changed_request":
            _object(context["session"])["nonce"] = "7" * 64
        else:
            _object(context["parent_process"])["process_instance_id"] = "sha256:" + "7" * 64
        changed = build_trusted_lab_request(context, request["requested_validity"])
        _write(retained[1] / "signed-request.json", approval_payload_bytes(changed))
    elif kind == "key":
        config = _config()
        wire = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"\x00" * 32
        config["public_key"] = "ssh-ed25519 " + base64.b64encode(wire).decode()
        _rehash(config, "trust_id")
        _write(retained[0] / "trust.json", canonical_json(config))
        identity = config["trust_id"]
        assert isinstance(identity, str)
        retained = *retained[:3], identity
    elif kind == "namespace":
        _write(retained[1] / "signed-request.sig", (_VECTORS / "wrong-namespace.sig").read_bytes())
    else:
        _write(retained[1] / "signed-request.sig", b"not a signature")
    report = _refuse(retained)
    assert report["signature_verification"] == "rejected"
    assert report["disposition"] == "signature_not_verified"
    assert report["tool_process_exposure"] == "started"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("namespace", "file"),
        ("mechanism_approval", "unapproved"),
        ("state", "revoked"),
        ("principal", "*"),
        ("principal", "name,attacker"),
        ("principal", True),
        ("public_key", "ssh-ed25519 malformed"),
        ("tool_sha256", "sha256:" + "0" * 64),
        ("policy_id", "sha256:" + "0" * 64),
    ],
)
def test_retained_configuration_not_artifact_or_metadata_enrollment(
    retained: tuple[Path, Path, Path, str],
    field: str,
    value: JsonValue,
) -> None:
    config = _config()
    config[field] = value
    _rehash(config, "trust_id")
    identity = config["trust_id"]
    assert isinstance(identity, str)
    _write(retained[0] / "trust.json", canonical_json(config))
    report = _refuse((*retained[:3], identity))
    assert report["signature_verification"] == "unavailable_not_invoked"
    assert report["tool_process_exposure"] == "not_started"


def test_wrong_principal_cannot_verify(
    retained: tuple[Path, Path, Path, str],
) -> None:
    # SSHSIG alone has no principal; this policy signs and pins the principal in the payload.
    config = _config()
    config["principal"] = "other-literal-principal"
    _rehash(config, "trust_id")
    identity = config["trust_id"]
    assert isinstance(identity, str)
    _write(retained[0] / "trust.json", canonical_json(config))
    assert _refuse((*retained[:3], identity))["tool_process_exposure"] == "not_started"


def test_artifact_key_and_favorable_subset_never_supply_trust(
    retained: tuple[Path, Path, Path, str],
) -> None:
    payload = _object(load_json_bytes((retained[1] / "signed-request.json").read_bytes()))
    payload["public_key"] = _config()["public_key"]
    _rehash(payload, "payload_id")
    _write(retained[1] / "signed-request.json", canonical_json(payload))
    assert _refuse(retained)["tool_process_exposure"] == "not_started"


def test_published_fixture_key_cannot_promote_to_operator_authority(
    retained: tuple[Path, Path, Path, str],
) -> None:
    request = _request()
    context = _object(request["context"])
    context["evidence_scope"] = "caller_supplied_unverified"
    changed = build_trusted_lab_request(context, request["requested_validity"])
    _write(retained[1] / "signed-request.json", approval_payload_bytes(changed))
    report = _refuse(retained)
    assert report["disposition"] == "published_fixture_key_not_operator_authority"
    assert report["tool_process_exposure"] == "not_started"
    assert report["runtime_authorized"] is False
    assert report["ledger_permit_created"] is False


@pytest.mark.parametrize("kind", ["missing", "mode", "symlink", "hardlink", "fifo", "directory"])
def test_private_file_custody_refusals(
    retained: tuple[Path, Path, Path, str],
    kind: str,
) -> None:
    path = retained[0] / "trust.json"
    if kind == "mode":
        path.chmod(0o644)
    elif kind == "hardlink":
        os.link(path, retained[0] / "copied-trust")
    else:
        path.unlink()
        if kind == "symlink":
            path.symlink_to(retained[1] / "signed-request.json")
        elif kind == "fifo":
            os.mkfifo(path, 0o600)
        elif kind == "directory":
            path.mkdir(mode=0o600)
    assert _refuse(retained)["tool_process_exposure"] == "not_started"


@pytest.mark.parametrize("role", [0, 1])
def test_private_root_mode_or_symlink_refuses(
    retained: tuple[Path, Path, Path, str],
    role: int,
) -> None:
    retained[role].chmod(0o755)
    assert _refuse(retained)["tool_process_exposure"] == "not_started"
    retained[role].chmod(0o700)
    link = retained[role].parent / "link"
    link.symlink_to(retained[role], target_is_directory=True)
    values = list(retained[:3])
    values[role] = link
    assert _refuse((values[0], values[1], values[2], retained[3]))["tool_process_exposure"] == (
        "not_started"
    )


def test_same_root_and_output_retention_fail_explicitly(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert _refuse((retained[0], retained[0], retained[2], retained[3]))["disposition"] == (
        "separately_retained_non_nested_roots_required"
    )
    retained[2].chmod(0o755)
    with pytest.raises(adapter.ApprovalRetentionError):
        _invoke(retained)
    retained[2].chmod(0o700)

    def fail(*_args: object, **_kwargs: object) -> NoReturn:
        raise OSError("private-path-must-not-escape")

    monkeypatch.setattr(adapter, "publish_bundle_at", fail)
    with pytest.raises(adapter.ApprovalRetentionError, match="retention_unavailable") as caught:
        _invoke(retained)
    assert "private-path" not in str(caught.value)


@pytest.mark.parametrize("alias", ["exact", "case", "unicode", "volume"])
def test_object_ancestors_reject_alias_hidden_nested_roots(
    retained: tuple[Path, Path, Path, str],
    alias: str,
) -> None:
    name = "Tr\u00fast" if alias == "unicode" else "Trust"
    trust = retained[0].with_name(name)
    retained[0].rename(trust)
    approval = trust / "Approval"
    retained[1].rename(approval)
    supplied_approval = approval
    if alias == "case":
        supplied_approval = trust.with_name("tRuSt") / "Approval"
    elif alias == "unicode":
        supplied_approval = trust.with_name("Tru\u0301st") / "Approval"
    elif alias == "volume":
        supplied_approval = Path("/System/Volumes/Data") / approval.relative_to("/")
    try:
        aliases_same_object = supplied_approval.samefile(approval)
    except FileNotFoundError:
        aliases_same_object = False
    if not aliases_same_object:
        pytest.skip("host filesystem does not expose this case/Unicode/volume alias")
    assert trust != supplied_approval and trust.stat().st_ino != supplied_approval.stat().st_ino
    report = _refuse((trust, supplied_approval, retained[2], retained[3]))
    assert report["disposition"] == "separately_retained_non_nested_roots_required"
    assert report["tool_process_exposure"] == "not_started"
    bundles = list(retained[2].iterdir())
    assert len(bundles) == 1
    _, files = read_closed_bundle(bundles[0])
    assert files["report.json"] == canonical_json(report)


def test_case_distinct_sibling_objects_are_not_conflated(
    retained: tuple[Path, Path, Path, str],
) -> None:
    trust = retained[0].with_name("Trust")
    retained[0].rename(trust)
    approval = trust.with_name("tRuSt")
    if approval.exists():
        pytest.skip("case-insensitive host does not support distinct case-only siblings")
    retained[1].rename(approval)
    assert not trust.samefile(approval)
    assert (
        _invoke((trust, approval, retained[2], retained[3])).report()["signature_verification"]
        == "verified"
    )


def test_object_ancestry_bound_is_explicit_retention_failure(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "_MAX_ANCESTORS", 1)
    with pytest.raises(adapter.ApprovalRetentionError, match="retention_unavailable"):
        _invoke(retained)
    assert not list(retained[2].iterdir())


def test_object_ancestor_replacement_refuses_after_verification(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = retained[0].with_name("TrustParent")
    parent.mkdir(mode=0o700)
    trust = parent / "Trust"
    retained[0].rename(trust)
    original = adapter._run_openssh

    def move_ancestor(
        payload: bytes,
        signature: bytes,
        config: dict[str, JsonValue],
        output: adapter._Directory,
    ) -> adapter._ToolOutcome:
        result = original(payload, signature, config, output)
        moved = parent.with_name("MovedParent")
        parent.rename(moved)
        parent.mkdir(mode=0o700)
        (moved / "Trust").rename(trust)
        return result

    monkeypatch.setattr(adapter, "_run_openssh", move_ancestor)
    report = _refuse((trust, retained[1], retained[2], retained[3]))
    assert report["signature_verification"] == "verified"
    assert report["disposition"] == "retained_directory_replaced_or_changed"
    assert report["runtime_authorized"] is False


@pytest.mark.parametrize("filename", ["trust.json", "signed-request.json"])
def test_integer_digit_limit_retains_exact_closed_refusal(
    retained: tuple[Path, Path, Path, str],
    filename: str,
) -> None:
    data = b'{"x":' + b"9" * 4301 + b"}"
    root = retained[0] if filename == "trust.json" else retained[1]
    _write(root / filename, data)
    report = _refuse(retained)
    assert report["disposition"] == "custody_or_contract_refused"
    assert report["tool_process_exposure"] == "not_started"
    assert report["signature_verification"] == "unavailable_not_invoked"
    for field in (
        "runtime_authorized",
        "consumable",
        "physical_launch_enabled",
        "accepted_physical_evidence",
        "ledger_permit_created",
    ):
        assert report[field] is False
    bundles = list(retained[2].iterdir())
    assert len(bundles) == 1
    _, files = read_closed_bundle(bundles[0])
    assert files[f"private/{filename}"] == data
    assert files["report.json"] == canonical_json(report)
    assert "integer string conversion" not in canonical_json(report).decode()
    assert b"9" * 100 not in canonical_json(report)


def test_public_payload_integer_bound_and_unrelated_exception_are_narrow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ContractError, match="integer exceeds bounded parsing limit"):
        verify_approval_payload_bytes(b'{"x":' + b"9" * 4301 + b"}")
    with pytest.raises(ContractError, match="integer exceeds bounded parsing limit"):
        verify_trusted_lab_request_bytes(b'{"x":' + b"9" * 4301 + b"}")

    def unrelated(_text: str) -> NoReturn:
        raise ValueError("unrelated programming failure")

    monkeypatch.setattr(policy_module, "_approval_integer", unrelated)
    with pytest.raises(ValueError, match="unrelated programming failure") as caught:
        verify_approval_payload_bytes(b'{"x":1}')
    assert not isinstance(caught.value, ContractError)


@pytest.mark.parametrize("when", ["tool", "retention"])
def test_config_replacement_before_or_after_retention_refuses(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    when: str,
) -> None:
    def replace() -> None:
        path = retained[0] / "trust.json"
        data = path.read_bytes()
        path.unlink()
        _write(path, data)

    if when == "tool":
        original = adapter._run_openssh

        def run(
            payload: bytes,
            signature: bytes,
            trust: dict[str, JsonValue],
            output: adapter._Directory,
        ) -> adapter._ToolOutcome:
            # Invoke the real verifier first; instrumentation affects custody, never crypto.
            result = original(payload, signature, trust, output)
            replace()
            return result

        monkeypatch.setattr(adapter, "_run_openssh", run)
    else:
        publish = adapter.publish_bundle_at
        replaced = False

        def retain(
            content: dict[str, bytes],
            output: Path,
            descriptor: int,
            *,
            name_prefix: str,
        ) -> Path:
            nonlocal replaced
            result = publish(content, output, descriptor, name_prefix=name_prefix)
            if not replaced:
                replaced = True
                replace()
            return result

        monkeypatch.setattr(adapter, "publish_bundle_at", retain)
    report = _refuse(retained)
    assert report["signature_verification"] == "verified"
    assert report["disposition"] == "retained_file_drift_or_replacement"
    assert report["runtime_authorized"] is False
    if when == "retention":
        assert "prior_observation_report_id" in report


@pytest.mark.parametrize(
    ("wall_delta", "mono_delta", "expected"),
    [
        (-1, -1, "request_not_yet_valid"),
        (30_000_000_000, 30_000_000_000, "request_expired"),
        (CLOCK_TOLERANCE_NS + 1, 0, "request_clock_binding_disagreement"),
    ],
)
def test_real_clock_binding_window_checks(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    wall_delta: int,
    mono_delta: int,
    expected: str,
) -> None:
    monkeypatch.setattr(adapter.time, "time_ns", lambda: _WALL + wall_delta)
    monkeypatch.setattr(adapter.time, "monotonic_ns", lambda: _MONOTONIC + mono_delta)
    assert _refuse(retained)["disposition"] == expected


@pytest.mark.parametrize("kind", ["rollback", "disagreement", "expiry"])
def test_clock_changed_during_actual_verification_refuses(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    original = adapter._run_openssh

    def run(
        payload: bytes,
        signature: bytes,
        trust: dict[str, JsonValue],
        output: adapter._Directory,
    ) -> adapter._ToolOutcome:
        result = original(payload, signature, trust, output)
        delta = -1 if kind == "rollback" else 30_000_000_000 if kind == "expiry" else 10_000_000
        monkeypatch.setattr(adapter.time, "time_ns", lambda: _WALL + delta)
        if kind == "expiry":
            monkeypatch.setattr(adapter.time, "monotonic_ns", lambda: _MONOTONIC + delta)
        return result

    monkeypatch.setattr(adapter, "_run_openssh", run)
    report = _refuse(retained)
    assert report["signature_verification"] == "verified"
    assert (
        report["disposition"]
        == {
            "rollback": "clock_rollback",
            "disagreement": "clock_wall_monotonic_disagreement",
            "expiry": "request_expired",
        }[kind]
    )


@pytest.mark.parametrize(
    ("script", "expected"),
    [
        ("import time; time.sleep(5)", "unknown_deadline"),
        ("import os; os.write(1, b'x' * 16384)", "unknown_output_bound"),
        ("import os, signal; os.kill(os.getpid(), signal.SIGTERM)", "unknown_signal"),
    ],
)
def test_bounded_tool_exposure_never_fabricates_zero_or_completion(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
    script: str,
    expected: str,
) -> None:
    real_popen = subprocess.Popen

    def instrument(
        argv: list[str],
        *,
        stdin: int,
        stdout: int,
        stderr: int,
        cwd: Path,
        env: dict[str, str],
        close_fds: bool,
        shell: bool,
    ) -> subprocess.Popen[bytes]:
        assert argv[0] == SYSTEM_TOOL
        assert argv[1:3] == ["-Y", "verify"]
        assert "-I" in argv and "-n" in argv and "-s" in argv
        assert env == {"LC_ALL": "C", "TZ": "UTC"}
        assert close_fds is True and shell is False
        return real_popen(
            [sys.executable, "-I", "-S", "-c", script],
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            cwd=cwd,
            env=env,
            close_fds=close_fds,
            shell=shell,
        )

    monkeypatch.setattr(adapter.subprocess, "Popen", instrument)
    report = _refuse(retained)
    assert report["signature_verification"] == expected
    assert report["tool_process_exposure"] == "started"
    assert report["tool_termination"] in {"reaped_signal", "reaped_exit"}
    assert report["requested_action_outcomes"] == "UNKNOWN_not_executed_or_observed"
    assert report["runtime_authorized"] is False


def test_missing_tool_spawn_is_unavailable_not_signature_success(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable(*_args: object, **_kwargs: object) -> NoReturn:
        raise FileNotFoundError("private tool detail")

    monkeypatch.setattr(adapter.subprocess, "Popen", unavailable)
    report = _refuse(retained)
    assert report["signature_verification"] == "unavailable_spawn"
    assert report["tool_process_exposure"] == "not_started"
    assert "private tool" not in canonical_json(report).decode()


def test_verifier_cleanup_failure_after_exposure_stays_unknown(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = adapter._run_openssh

    def fail_after_verification(
        payload: bytes,
        signature: bytes,
        trust: dict[str, JsonValue],
        output: adapter._Directory,
    ) -> NoReturn:
        original(payload, signature, trust, output)
        raise OSError("private cleanup path")

    monkeypatch.setattr(adapter, "_run_openssh", fail_after_verification)
    report = _refuse(retained)
    assert report["signature_verification"] == "unknown_verifier_invocation"
    assert report["tool_process_exposure"] == "unknown_may_have_started"
    assert report["tool_termination"] == "unknown"
    assert report["runtime_authorized"] is False


def test_owner_drift_refuses_before_verification(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = (retained[0] / "trust.json").stat().st_ino
    original = os.fstat

    def observed_owner(descriptor: int) -> os.stat_result:
        metadata = original(descriptor)
        if metadata.st_ino == target:
            fields = list(metadata)
            fields[4] = metadata.st_uid + 1
            return os.stat_result(fields)
        return metadata

    monkeypatch.setattr(adapter.os, "fstat", observed_owner)
    assert _refuse(retained)["tool_process_exposure"] == "not_started"


def test_short_stable_read_refuses_without_success_fallback(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = os.pread
    target = (retained[0] / "trust.json").stat().st_ino

    def short_read(descriptor: int, size: int, offset: int) -> bytes:
        result = original(descriptor, size, offset)
        return result[:-1] if os.fstat(descriptor).st_ino == target else result

    monkeypatch.setattr(adapter.os, "pread", short_read)
    report = _refuse(retained)
    assert report["disposition"] == "retained_file_short_or_unstable_read"
    assert report["tool_process_exposure"] == "not_started"


def test_candidate_source_drift_during_verification_is_not_rebound_as_approval(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = adapter._run_openssh
    spec = trusted_lab_request_spec()
    changed = copy.deepcopy(spec)
    changed["spec_id"] = "sha256:" + "0" * 64

    def drift(
        payload: bytes,
        signature: bytes,
        trust: dict[str, JsonValue],
        output: adapter._Directory,
    ) -> adapter._ToolOutcome:
        result = original(payload, signature, trust, output)
        monkeypatch.setattr(adapter, "trusted_lab_request_spec", lambda: changed)
        return result

    monkeypatch.setattr(adapter, "_run_openssh", drift)
    report = _refuse(retained)
    assert report["signature_verification"] == "verified"
    assert report["disposition"] == "candidate_source_or_spec_drift"
    assert report["spec_id"] == spec["spec_id"]
    assert report["runtime_authorized"] is False


def test_detached_forged_receipts_never_dispatch(
    retained: tuple[Path, Path, Path, str],
) -> None:
    evidence = _invoke(retained)
    forged = evidence.report()
    forged["runtime_authorized"] = True
    forged["consumable"] = True
    fake = adapter.SignedRequestEvidence(canonical_json(forged), evidence.bundle_name)
    assert fake.report()["runtime_authorized"] is True
    assert evidence.report()["runtime_authorized"] is False
    for gate in (open_production_ledger, require_physical_launch):
        with pytest.raises(ContractError):
            gate()
        with pytest.raises(TypeError):
            gate(fake)  # type: ignore[call-arg]


def test_expiry_during_retention_never_returns_verified_evidence(
    retained: tuple[Path, Path, Path, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    publish = adapter.publish_bundle_at

    def expire(
        content: dict[str, bytes],
        output: Path,
        descriptor: int,
        *,
        name_prefix: str,
    ) -> Path:
        result = publish(content, output, descriptor, name_prefix=name_prefix)
        monkeypatch.setattr(adapter.time, "time_ns", lambda: _WALL + 30_000_000_000)
        monkeypatch.setattr(adapter.time, "monotonic_ns", lambda: _MONOTONIC + 30_000_000_000)
        return result

    monkeypatch.setattr(adapter, "publish_bundle_at", expire)
    report = _refuse(retained)
    assert report["signature_verification"] == "verified"
    assert report["disposition"] == "request_expired"
    assert "prior_observation_report_id" in report


def test_restart_and_sampling_uncertainty_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = adapter._ClockSession()
    clock.observe()
    monkeypatch.setattr(adapter.os, "getpid", lambda: clock.pid + 1)
    with pytest.raises(ContractError, match="restart"):
        clock.observe()
    monkeypatch.undo()
    ticks = iter((1, CLOCK_TOLERANCE_NS + 2))
    monkeypatch.setattr(adapter.time, "monotonic_ns", lambda: next(ticks))
    with pytest.raises(ContractError, match="uncertainty"):
        adapter._ClockSession().observe()


def test_import_and_payload_replay_are_process_inert(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> NoReturn:
        raise AssertionError("offline imports and payload replay must not spawn")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    importlib.reload(adapter)
    assert verify_approval_payload_bytes(approval_payload_bytes(_request()))
    assert not any(name == "mlx" or name.startswith(("mlx.", "mlx_lm")) for name in sys.modules)
