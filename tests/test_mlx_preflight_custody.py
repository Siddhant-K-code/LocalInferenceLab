"""Adversarial tests for the inert schema-1.1 execution-custody bridge."""

from __future__ import annotations

import ast
import importlib
import json
import os
import socket
import subprocess
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_preflight_custody as custody
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_preflight_custody import (
    ALLOWED_ACTIONS,
    AUTHORIZATION_LIFETIME_NS,
    authorization_assessment_1_1,
    build_synthetic_custody_session_record_1_1,
    compile_custody_bridge_fixture_1_1,
    custody_bridge_capability_report_1_1,
    custody_bridge_protocol_1_1,
    custody_bridge_spec_1_1,
    decode_custody_frame_1_1,
    encode_custody_frame_1_1,
    replay_custody_bridge_fixture_1_1,
    verify_authorization_structure_1_1,
    verify_consumption_1_1,
    verify_one_shot_consumptions_1_1,
    verify_synthetic_custody_session_record_1_1,
)
from localinferencelab.mlx_qualification_publication import (
    EXPECTED_CANDIDATE_PACKAGE_ID,
    EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID,
    EXPECTED_QUALIFICATION_RECORD_ID,
    EXPECTED_QUALIFICATION_SPEC_ID,
    EXPECTED_REVIEW_APPROVAL_ID,
    EXPECTED_REVIEW_REGISTRY_SPEC_ID,
    EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
    EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
    EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
    EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID,
    EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
)
from localinferencelab.mlx_review_registry import EXPECTED_REVIEW_REGISTRY_ID


def _dict(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    copied = json.loads(canonical_json(value))
    assert isinstance(copied, dict)
    return cast("dict[str, JsonValue]", copied)


def _rehash(value: dict[str, JsonValue], identity_field: str) -> None:
    content = dict(value)
    content.pop(identity_field, None)
    value[identity_field] = canonical_identity(content)


def _external_authorization(seed: int = 1) -> dict[str, JsonValue]:
    authorization = _copy(custody._synthetic_authorization(seed))  # noqa: SLF001
    authorization["evidence_kind"] = "external_independently_reviewed_authorization"
    _rehash(authorization, "authorization_id")
    return authorization


def _frame_payload(entry: dict[str, JsonValue]) -> dict[str, JsonValue]:
    encoded = cast("str", entry["wire_bytes_base64"])
    return decode_custody_frame_1_1(decode_bytes(encoded))


def _replace_frame(
    transcript: dict[str, JsonValue],
    index: int,
    payload: dict[str, JsonValue],
    *,
    received_at: int | None = None,
) -> None:
    frames = _list(transcript["frames"])
    entry = _dict(frames[index])
    wire = encode_custody_frame_1_1(payload)
    entry["wire_bytes_base64"] = encode_bytes(wire)
    entry["wire_sha256"] = digest_bytes(wire)
    if received_at is not None:
        entry["received_at_monotonic_ns"] = received_at


def test_bridge_binds_current_publication_and_stays_unreachable() -> None:
    protocol = custody_bridge_protocol_1_1()
    spec = custody_bridge_spec_1_1()
    report = custody_bridge_capability_report_1_1()
    bindings = _dict(spec["identity_bindings"])

    assert protocol["implementation_state"] == "inert_control_plane_complete_execution_unreachable"
    assert protocol["allowed_actions"] == list(ALLOWED_ACTIONS)
    assert ALLOWED_ACTIONS == (
        "candidate_distribution_identity_checks",
        "import_mlx",
        "import_mlx_lm",
        "query_backend_device_metal_availability",
        "synchronize",
    )
    assert bindings == {
        "candidate_package_id": EXPECTED_CANDIDATE_PACKAGE_ID,
        "candidate_review_anchor_id": EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID,
        "qualification_closure_id": bindings["qualification_closure_id"],
        "qualification_record_id": EXPECTED_QUALIFICATION_RECORD_ID,
        "qualification_spec_id": EXPECTED_QUALIFICATION_SPEC_ID,
        "review_approval_id": EXPECTED_REVIEW_APPROVAL_ID,
        "review_registry_id": EXPECTED_REVIEW_REGISTRY_ID,
        "review_registry_spec_id": EXPECTED_REVIEW_REGISTRY_SPEC_ID,
        "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        "runtime_target_id": bindings["runtime_target_id"],
        "wheel_evidence_manifest_id": EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        "wheel_evidence_pack_receipt_id": EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
        "wheel_evidence_pack_spec_id": EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID,
        "worker_api_evidence_anchor_id": EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
    }
    assert cast("str", bindings["qualification_closure_id"]).startswith("sha256:")
    assert cast("str", bindings["runtime_target_id"]).startswith("sha256:")

    execution = _dict(spec["execution_gate"])
    assert execution["physical_execution_reachable"] is False
    assert execution["public_or_internal_execute_entrypoint_present"] is False
    assert execution["authorization_creator_present"] is False
    assert execution["approved_authorization_present"] is False
    assert execution["approved_authority_present"] is False
    assert execution["reviewed_worker_program_present"] is False
    assert report["control_plane_complete"] is True
    assert report["execution_reachable"] is False
    assert report["worker_entrypoint_present"] is False
    assert report["installer_resolver_or_downloader_present"] is False
    assert report["physical_actions"] == 0
    assert set(_dict(report["static_action_counters"]).values()) == {0}


def test_policy_is_preinstalled_only_parent_owned_and_model_free() -> None:
    protocol = custody_bridge_protocol_1_1()
    spec = custody_bridge_spec_1_1()
    launch = _dict(protocol["launch_policy"])
    parent = _dict(protocol["parent_owned"])
    preinstalled = _dict(spec["preinstalled_only_policy"])

    assert launch == {
        "arbitrary_executable_allowed": False,
        "environment": "empty_parent_constructed_allowlist_only",
        "environment_inheritance_allowed": False,
        "installer_resolver_or_downloader_present": False,
        "preinstalled_exact_distribution_checks_only": True,
        "worker_controlled_output_path_allowed": False,
        "worker_implementation_present": False,
    }
    assert all(value is True or value == "receipt_last_closed_bundle" for value in parent.values())
    assert preinstalled["installer_present"] is False
    assert preinstalled["resolver_present"] is False
    assert preinstalled["download_present"] is False
    assert preinstalled["development_or_fixture_checks_performed"] is False
    forbidden = set(cast("list[str]", protocol["forbidden_actions"]))
    assert {
        "model_load",
        "tokenizer_discovery_or_load",
        "prompt_or_token_processing",
        "cache_construction_or_mutation",
        "tensor_allocation_or_operation",
        "inference",
        "generation",
        "benchmark",
        "network_access",
    }.issubset(forbidden)


def test_caller_structure_hash_and_labels_never_establish_authority() -> None:
    authorization = _external_authorization()
    assert verify_authorization_structure_1_1(authorization) == authorization
    temporal = _dict(authorization["temporal"])
    observed = cast("int", temporal["not_before_unix_ns"]) + 1
    assessment = authorization_assessment_1_1(
        authorization,
        observed_at_unix_ns=observed,
    )
    assert assessment["structure_valid"] is True
    assert assessment["time_window_current"] is True
    assert assessment["authoritative"] is False
    assert assessment["consumable"] is False
    assert assessment["caller_labels_or_self_hashes_accepted_as_authority"] is False
    assert set(_list(assessment["blockers"])) >= {
        "approved_authorization_authority_not_committed",
        "independently_reviewed_authorization_not_committed",
        "reviewed_worker_program_not_committed",
        "physical_execution_entrypoint_absent",
    }

    without_clock = authorization_assessment_1_1(authorization)
    assert without_clock["time_window_current"] is False
    assert "parent_current_time_observation_missing" in _list(without_clock["blockers"])


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: _dict(value["identity_bindings"]).__setitem__(
                "qualification_record_id", "sha256:" + ("0" * 64)
            ),
            "qualification_record_id",
        ),
        (
            lambda value: _dict(value["root_bindings"]).__setitem__(
                "worker_supplied_paths_accepted", True
            ),
            "root ownership",
        ),
        (
            lambda value: value.__setitem__("allowed_actions", [*ALLOWED_ACTIONS, "model_load"]),
            "allowlist",
        ),
        (
            lambda value: _dict(value["session_bindings"]).__setitem__(
                "challenge_sha256",
                _dict(value["session_bindings"])["nonce_sha256"],
            ),
            "distinct",
        ),
        (
            lambda value: _dict(value["temporal"]).__setitem__(
                "expires_at_unix_ns",
                cast("int", _dict(value["temporal"])["issued_at_unix_ns"])
                + AUTHORIZATION_LIFETIME_NS
                + 1,
            ),
            "maximum lifetime",
        ),
    ],
)
def test_authorization_identity_root_action_nonce_and_time_drift_fail_closed(
    mutate: Callable[[dict[str, JsonValue]], None],
    message: str,
) -> None:
    authorization = _external_authorization()
    mutate(authorization)
    _rehash(authorization, "authorization_id")
    with pytest.raises(ContractError, match=message):
        verify_authorization_structure_1_1(authorization)


def test_stale_expired_and_non_authoritative_authorizations_cannot_be_consumed() -> None:
    synthetic = custody._synthetic_authorization(1)  # noqa: SLF001
    temporal = _dict(synthetic["temporal"])
    not_before = cast("int", temporal["not_before_unix_ns"])
    expires = cast("int", temporal["expires_at_unix_ns"])
    with pytest.raises(ContractError, match="stale, expired, or not yet valid"):
        custody._verify_authorization_at(  # noqa: SLF001
            synthetic,
            observed_at_unix_ns=not_before - 1,
            allow_synthetic=True,
        )
    with pytest.raises(ContractError, match="stale, expired, or not yet valid"):
        custody._verify_authorization_at(  # noqa: SLF001
            synthetic,
            observed_at_unix_ns=expires,
            allow_synthetic=True,
        )

    external = _external_authorization()
    with pytest.raises(ContractError, match="no independently reviewed authorization"):
        custody._verify_authorization_at(  # noqa: SLF001
            external,
            observed_at_unix_ns=not_before + 1,
            allow_synthetic=False,
        )


def test_consumption_binds_every_session_fact_and_replay_is_rejected() -> None:
    transcript = custody._synthetic_transcript(1, extra_action=False)  # noqa: SLF001
    authorization = _dict(transcript["authorization"])
    consumption = _dict(transcript["consumption"])
    assert verify_consumption_1_1(consumption, authorization) == consumption

    tampered = _copy(consumption)
    tampered["nonce_sha256"] = "sha256:" + ("0" * 64)
    _rehash(tampered, "consumption_id")
    with pytest.raises(ContractError, match="binding mismatch"):
        verify_consumption_1_1(tampered, authorization)

    with pytest.raises(ContractError, match="replay or duplicate"):
        verify_one_shot_consumptions_1_1(
            [
                (authorization, consumption),
                (authorization, consumption),
            ]
        )


@pytest.mark.parametrize(
    ("wire", "message"),
    [
        (b"\x00\x00\x00\x02\xff\xff", "valid UTF-8"),
        (b"\x00\x00\x00\x01{", "malformed JSON"),
        (
            len(b'{"a":1,"a":2}').to_bytes(4, "big") + b'{"a":1,"a":2}',
            "duplicate JSON key",
        ),
        (b"\x00\x00\x00\x03{}", "length mismatch"),
        (b"\x00\x00\x00\x00", "outside its bound"),
    ],
)
def test_frame_decoder_rejects_malformed_utf8_json_duplicates_and_lengths(
    wire: bytes,
    message: str,
) -> None:
    with pytest.raises(ContractError, match=message):
        decode_custody_frame_1_1(wire)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "missing or extra frame"),
        ("duplicate", "frame sequence or session binding mismatch"),
        ("wrong_sequence", "frame sequence or session binding mismatch"),
        ("unknown_field", "unknown keys"),
        ("late", "after the parent deadline"),
        ("extra_action", "missing, duplicate, or extra action"),
        ("socket_anomaly", "process, socket, or cleanup anomaly"),
        ("process_anomaly", "process, socket, or cleanup anomaly"),
    ],
)
def test_sequence_timeout_extra_action_and_lifecycle_anomalies_are_retained(
    mutation: str,
    message: str,
) -> None:
    transcript = _copy(custody._synthetic_transcript(3, extra_action=False))  # noqa: SLF001
    frames = _list(transcript["frames"])
    if mutation == "missing":
        frames.pop()
    elif mutation == "duplicate":
        frames[1] = _copy(frames[0])
    elif mutation == "wrong_sequence":
        payload = _frame_payload(_dict(frames[1]))
        payload["sequence"] = 9
        _replace_frame(transcript, 1, payload)
    elif mutation == "unknown_field":
        payload = _frame_payload(_dict(frames[0]))
        payload["worker_output_path"] = "worker-controlled-path"
        _replace_frame(transcript, 0, payload)
    elif mutation == "late":
        _dict(frames[2])["received_at_monotonic_ns"] = transcript["deadline_monotonic_ns"]
        _dict(frames[2])["received_at_monotonic_ns"] = (
            cast("int", transcript["deadline_monotonic_ns"]) + 1
        )
    elif mutation == "extra_action":
        payload = _frame_payload(_dict(frames[2]))
        _list(payload["attempted_actions"]).append("model_load")
        _replace_frame(transcript, 2, payload)
    elif mutation == "socket_anomaly":
        _dict(transcript["synthetic_lifecycle"])["socket_anomaly"] = True
    elif mutation == "process_anomaly":
        _dict(transcript["synthetic_lifecycle"])["process_anomaly"] = True

    record = build_synthetic_custody_session_record_1_1(transcript)
    assert record["outcome"] == "rejected"
    rejection = _dict(record["rejection"])
    assert rejection["rejected_evidence_retained"] is True
    assert rejection["retained_transcript_id"] == canonical_identity(transcript)
    assert _list(rejection["retained_frame_digests"])
    error_digest = cast("str", rejection["error_message_sha256"])
    assert error_digest.startswith("sha256:")
    with pytest.raises(ContractError, match=message):
        custody._verify_transcript(transcript)  # noqa: SLF001
    assert verify_synthetic_custody_session_record_1_1(record) == record


def test_unretained_rejection_and_coordinated_rehash_fail_closed() -> None:
    transcript = custody._synthetic_transcript(4, extra_action=True)  # noqa: SLF001
    record = build_synthetic_custody_session_record_1_1(transcript)
    rejection = _dict(record["rejection"])
    rejection["rejected_evidence_retained"] = False
    rejection["retained_frame_digests"] = []
    _rehash(record, "record_id")
    with pytest.raises(ContractError, match="reconstruction mismatch"):
        verify_synthetic_custody_session_record_1_1(record)


def test_fixture_is_deterministic_replayable_and_zero_action(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_result = compile_custody_bridge_fixture_1_1(first_root)
    second, second_result = compile_custody_bridge_fixture_1_1(second_root)
    assert first.name == second.name
    assert first_result.to_dict() == second_result.to_dict()
    assert replay_custody_bridge_fixture_1_1(first).to_dict() == first_result.to_dict()
    assert first_result.rejected_evidence_retained is True
    assert first_result.real_authorizations_created == 0
    assert first_result.real_authorizations_consumed == 0
    assert first_result.process_starts == 0
    assert first_result.socketpair_creations == 0
    assert first_result.mlx_imports == 0
    assert first_result.metal_queries == 0
    assert first_result.synchronizations == 0
    assert first_result.physical_actions == 0
    published = b"".join(read_closed_bundle(first)[1].values()).decode("utf-8", errors="ignore")
    assert "/Users/" not in published
    assert "worker-controlled-path" not in published


def test_fixture_replay_rejects_extra_content_and_coordinated_tamper(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    bundle, _result = compile_custody_bridge_fixture_1_1(source_root)
    _root, files = read_closed_bundle(bundle)
    content = {
        name: data for name, data in files.items() if name not in {"index.json", "receipt.json"}
    }
    content["private/rejected-frame.json"] = canonical_json({"forbidden": True})
    extra_root = tmp_path / "extra"
    extra_root.mkdir()
    extra = publish_bundle(content, extra_root, name_prefix="extra-custody")
    with pytest.raises(ContractError, match="invalid content set"):
        replay_custody_bridge_fixture_1_1(extra)

    content.pop("private/rejected-frame.json")
    rejected = json.loads(content["sessions/rejected-record.json"])
    assert isinstance(rejected, dict)
    rejected["outcome"] = "synthetic_sequence_validated_not_physical_evidence"
    _rehash(cast("dict[str, JsonValue]", rejected), "record_id")
    content["sessions/rejected-record.json"] = canonical_json(rejected)
    tampered_root = tmp_path / "tampered"
    tampered_root.mkdir()
    tampered = publish_bundle(content, tampered_root, name_prefix="tampered-custody")
    with pytest.raises(ContractError, match="reconstruction mismatch"):
        replay_custody_bridge_fixture_1_1(tampered)


def test_module_and_fixture_touch_no_physical_or_mlx_boundary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module_path = Path(custody.__file__).resolve(strict=True)
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        (node.module or "").split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert not imported_roots & {
        "importlib",
        "mlx",
        "mlx_lm",
        "requests",
        "socket",
        "subprocess",
        "urllib",
    }
    called_attributes = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not called_attributes & {
        "default_device",
        "default_stream",
        "import_module",
        "metal",
        "posix_spawn",
        "socketpair",
        "synchronize",
    }

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("physical boundary touched")

    monkeypatch.setattr(os, "posix_spawn", forbidden)
    monkeypatch.setattr(socket, "socketpair", forbidden)
    monkeypatch.setattr(importlib, "import_module", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)

    root = tmp_path / "fixture"
    root.mkdir()
    bundle, result = compile_custody_bridge_fixture_1_1(root)
    assert result.physical_actions == 0
    assert replay_custody_bridge_fixture_1_1(bundle).physical_actions == 0
