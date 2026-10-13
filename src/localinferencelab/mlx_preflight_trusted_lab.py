"""Distinct trusted-code research policy; unsigned requests are never runtime authority."""

from __future__ import annotations

import json
from pathlib import Path

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    _reject_constant,
    _reject_float,
    _unique_object,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
    validate_json_value,
)
from localinferencelab.mlx_preflight_authorization import (
    MAX_REQUEST_BYTES,
    _build_request,
    _exact,
    _object,
    _verify,
    authorization_request_spec,
)

SCHEMA_VERSION = "2.0"
NAMESPACE = "localinferencelab-trusted-code-research-approval-v2"
PRINCIPAL = "localinferencelab-human"
MAX_PAYLOAD_BYTES = 65_536
SYSTEM_TOOL = "/usr/bin/ssh-keygen"
TOOL_TIMEOUT_SECONDS = 2
MAX_TOOL_OUTPUT_BYTES = 8192
CLOCK_TOLERANCE_NS = 5_000_000
NON_AUTHORITY_FIXTURE_KEY_ID = (
    "sha256:2f793fa09b9b6e5498d2507d525b25ede98332744f2a6ffcb9d7f671cc24e7ad"
)
_MAX_INTEGER_DIGITS = 20


def _approval_integer(text: str) -> int:
    if len(text.removeprefix("-")) > _MAX_INTEGER_DIGITS:
        raise ContractError("approval JSON integer exceeds bounded parsing limit")
    return int(text)


def _load_approval_json(data: bytes) -> JsonValue:
    if type(data) is not bytes or not 0 < len(data) <= MAX_PAYLOAD_BYTES:
        raise ContractError("approval JSON byte bound")
    try:
        value: object = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_int=_approval_integer,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
        return validate_json_value(value)
    except UnicodeDecodeError:
        raise ContractError("approval JSON must be UTF-8") from None
    except json.JSONDecodeError:
        raise ContractError("approval JSON malformed") from None
    except RecursionError:
        raise ContractError("approval JSON nesting bound") from None


def verification_mechanism_spec() -> dict[str, JsonValue]:
    """Describe measured OpenSSH verification, not a reviewed installation or trust root."""
    spec: dict[str, JsonValue] = {
        "record_type": "mlx_trusted_lab_openssh_verification_mechanism",
        "schema_version": "1.0",
        "system_tool": SYSTEM_TOOL,
        "operation": "OpenSSH_sshsig_Y_verify",
        "namespace": NAMESPACE,
        "principal": PRINCIPAL,
        "public_key_algorithm": "ssh-ed25519",
        "tool_identity_source": "separately_retained_human_controlled_trust_configuration",
        "tool_owner": "root",
        "tool_group_world_writable_allowed": False,
        "signature_covers": "full_canonical_spec_and_request_payload",
        "tool_timeout_seconds": TOOL_TIMEOUT_SECONDS,
        "maximum_combined_output_bytes": MAX_TOOL_OUTPUT_BYTES,
        "loader_and_complete_native_lifetime_immutability_proven": False,
        "approval_or_key_issuance_implemented": False,
    }
    spec["mechanism_id"] = canonical_identity(spec)
    return spec


def trusted_lab_request_spec() -> dict[str, JsonValue]:
    """Return a NEW candidate policy, never reinterpret v1.0 signatures or reviews."""
    spec = authorization_request_spec()
    spec.pop("spec_id")
    spec["schema_version"] = SCHEMA_VERSION
    sources = spec["source_bindings"]
    if not isinstance(sources, dict):
        raise ContractError("candidate sources unavailable")
    for name, filename in (
        ("request_validation", "mlx_preflight_authorization.py"),
        ("trusted_lab_policy", "mlx_preflight_trusted_lab.py"),
        ("retained_approval_verifier", "mlx_preflight_approval.py"),
    ):
        sources[name] = digest_bytes(Path(__file__).with_name(filename).read_bytes())
    policy = spec["policy"]
    if not isinstance(policy, dict):
        raise ContractError("candidate policy unavailable")
    policy.pop("policy_id")
    policy["policy_kind"] = "trusted_code_research_lab_not_malicious_native_containment"
    policy["model_free_scope"] = "scoped_application_operations_not_library_internal_nonaction"
    policy["trusted_assumptions"] = [
        "host_OS_wall_clock_and_monotonic_clock",
        "current_human_user_and_parent_process",
        "independently_reviewed_exact_pinned_Python_MLX_transitive_and_native_code",
        "human_controlled_separately_retained_public_trust_configuration",
        "dedicated_passphrase_protected_SSH_signing_key_outside_worker_accessible_files",
    ]
    policy["excluded_guarantees"] = [
        "hostile_parent_root_OS_or_native_library_containment",
        "complete_immutable_native_library_or_tool_lifetime",
        "full_machine_or_filesystem_snapshot_rollback_resistance",
        "exhaustive_absence_of_hidden_internal_tensor_cache_or_native_actions",
        "external_time_or_malicious_OS_resistant_freshness",
    ]
    policy["native_enforcement"] = {
        "reviewed_contract_id": None,
        "startup_confinement": "unestablished_pre_exec_candidate_SIGABRT",
        "after_startup_benign_helper": "partial_controls_only_not_MLX_process_evidence",
        "socket_creation": "succeeded_not_denied",
        "same_path_inode_replacement": "replacement_bytes_exposed",
        "self_exec": "SIGABRT_no_result_UNKNOWN",
        "metal_compatibility": "untested",
        "exact_MLX_native_controls_established": False,
        "audit_hooks_or_offline_environment_is_enforcement": False,
        "benign_probe_receipt_is_production_enforcement": False,
        "historical_failures_reclassified_as_pass": False,
    }
    policy["approval"] = {
        "mechanism": verification_mechanism_spec(),
        "retention": "separate_user_controlled_trust_and_signed_artifact_private_objects",
        "artifact_supplied_key_is_trust": False,
        "automatic_enrollment_or_revocation_change": False,
        "signature_evidence_is_runtime_authority": False,
        "published_non_secret_fixture_key_id": NON_AUTHORITY_FIXTURE_KEY_ID,
        "published_fixture_key_is_operator_authority": False,
        "key_passphrase_and_worker_inaccessibility_measured_by_verifier": False,
    }
    policy["clock"] = {
        "scope": "trusted_host_wall_clock_with_monotonic_continuity",
        "maximum_sample_uncertainty_and_elapsed_disagreement_ns": CLOCK_TOLERANCE_NS,
        "rollback_or_disagreement": "refuse",
        "parent_restart": "fresh_verification_session_required",
        "consumption": "fresh_custody_and_expiry_recheck_required_not_implemented",
    }
    policy["policy_id"] = canonical_identity(policy)
    spec["trust_policy"] = {
        "production_authority_id": None,
        "retained_trust_root_id": None,
        "signed_request_evidence_verification_implemented": True,
        "production_authority_verification_implemented": False,
        "static_review_grants_runtime_authority": False,
        "request_self_hash_grants_runtime_authority": False,
    }
    spec["candidate_review_status"] = "UNREVIEWED"
    spec["claim_scope"] = "trusted_lab_signed_request_evidence_only_not_permission"
    prerequisites = spec["unapproved_prerequisites"]
    if not isinstance(prerequisites, dict):
        raise ContractError("candidate prerequisites unavailable")
    prerequisites.pop("reviewed_exact_environment_os_enforcement_and_child_identity")
    prerequisites["reviewed_trusted_lab_exact_code_isolation_limits_and_child_identity"] = (
        "unavailable"
    )
    spec["spec_id"] = canonical_identity(spec)
    return spec


def build_trusted_lab_request(
    context: JsonValue, requested_validity: JsonValue
) -> dict[str, JsonValue]:
    """Build only a v2 proposal; supplied hashes remain unauthenticated claims."""
    return _build_request(
        context, requested_validity, trusted_lab_request_spec(), schema_version=SCHEMA_VERSION
    )


def verify_trusted_lab_request_bytes(data: bytes) -> dict[str, JsonValue]:
    """Validate exact v2 candidate bindings; no v1.0 migration or policy selection."""
    if type(data) is not bytes or not 0 < len(data) <= MAX_REQUEST_BYTES:
        raise ContractError("trusted lab request byte bound")
    try:
        value = _load_approval_json(data)
        if canonical_json(value) != data:
            raise ContractError("trusted lab request must use canonical JSON bytes")
        return _verify(value, trusted_lab_request_spec(), schema_version=SCHEMA_VERSION)
    except RecursionError:
        raise ContractError("trusted lab request nesting bound") from None


def approval_payload_bytes(request: JsonValue) -> bytes:
    """Encode all exact policy/spec/request bytes for external human signing, without signing."""
    checked = verify_trusted_lab_request_bytes(canonical_json(request))
    payload: dict[str, JsonValue] = {
        "record_type": "mlx_trusted_lab_signed_request_payload",
        "schema_version": SCHEMA_VERSION,
        "scope": "signed_request_evidence_only",
        "principal": PRINCIPAL,
        "spec": trusted_lab_request_spec(),
        "request": checked,
    }
    payload["payload_id"] = canonical_identity(payload)
    data = canonical_json(payload)
    if len(data) > MAX_PAYLOAD_BYTES:
        raise ContractError("signed payload exceeds byte bound")
    return data


def verify_approval_payload_bytes(data: bytes) -> dict[str, JsonValue]:
    """Reject editable favorable subsets, extra keys, old policies and coherent rehashes."""
    if type(data) is not bytes or not 0 < len(data) <= MAX_PAYLOAD_BYTES:
        raise ContractError("signed payload byte bound")
    try:
        value = _load_approval_json(data)
        payload = _object(
            value,
            {
                "record_type",
                "schema_version",
                "scope",
                "principal",
                "spec",
                "request",
                "payload_id",
            },
            "signed payload",
        )
        expected = approval_payload_bytes(payload["request"])
        _exact(payload, load_json_bytes(expected), "full signed payload")
        if data != expected:
            raise ContractError("signed payload must use canonical bytes")
    except RecursionError as error:
        raise ContractError("signed payload nesting bound") from error
    return payload
