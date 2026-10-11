"""Inert execution-custody bridge for a future schema-1.1 MLX preflight."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_qualification_publication import (
    COMMITTED_CANDIDATE_PATH,
    COMMITTED_MANIFEST_PATH,
    COMMITTED_QUALIFICATION_RECORD_PATH,
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
    committed_qualification_publication_record,
)
from localinferencelab.mlx_review_registry import (
    COMMITTED_REVIEW_REGISTRY_PATH,
    EXPECTED_REVIEW_REGISTRY_ID,
)
from localinferencelab.mlx_runtime_target import runtime_target_anchor

SCHEMA_VERSION = "1.1"
ACTION = "mlx_runtime_preflight_model_free"
AUTHORIZATION_LIFETIME_NS = 30_000_000_000
MAX_FRAME_BYTES = 1024 * 1024
_CONTROL_LIMIT = 32
_DIGEST_LENGTH = 71
_FRAME_HEADER_BYTES = 4
_FRAME_SEQUENCE = (
    "worker_hello",
    "authorization_ack",
    "preflight_result",
    "shutdown_ack",
)
ALLOWED_ACTIONS = (
    "candidate_distribution_identity_checks",
    "import_mlx",
    "import_mlx_lm",
    "query_backend_device_metal_availability",
    "synchronize",
)
_IMPORTED_MODULES = ("mlx.core", "mlx_lm")
_FORBIDDEN_ACTIONS = (
    "arbitrary_executable",
    "benchmark",
    "cache_construction_or_mutation",
    "environment_inheritance",
    "generation",
    "inference",
    "model_discovery_or_download",
    "model_load",
    "network_access",
    "package_installation",
    "package_resolution",
    "package_retrieval_or_download",
    "prompt_or_token_processing",
    "tensor_allocation_or_operation",
    "tokenizer_discovery_or_load",
    "worker_controlled_path",
)
_EXECUTION_BLOCKERS = (
    "approved_authorization_authority_not_committed",
    "authoritative_runtime_observer_not_available",
    "independently_reviewed_authorization_not_committed",
    "physical_execution_entrypoint_absent",
    "reviewed_worker_program_not_committed",
)
_ZERO_PHYSICAL_ACTIONS: dict[str, int] = {
    "authorization_consumptions": 0,
    "backend_device_metal_queries": 0,
    "candidate_distribution_identity_checks": 0,
    "mlx_imports": 0,
    "mlx_lm_imports": 0,
    "network_actions": 0,
    "package_installations": 0,
    "package_resolutions": 0,
    "process_starts": 0,
    "socketpair_creations": 0,
    "synchronizations": 0,
    "worker_launches": 0,
}
_CURRENT_CONTEXT_PATHS = (
    ("committed MLX candidate", COMMITTED_CANDIDATE_PATH),
    ("committed wheel closure manifest", COMMITTED_MANIFEST_PATH),
    ("committed qualification publication", COMMITTED_QUALIFICATION_RECORD_PATH),
    ("committed review registry", COMMITTED_REVIEW_REGISTRY_PATH),
)
_AUTHORIZATION_FIELDS = {
    "action",
    "allowed_actions",
    "authority_bindings",
    "authorization_id",
    "bridge_protocol_id",
    "bridge_spec_id",
    "decision",
    "evidence_kind",
    "identity_bindings",
    "one_shot",
    "record_type",
    "root_bindings",
    "schema_version",
    "session_bindings",
    "temporal",
}
_IDENTITY_BINDING_FIELDS = {
    "candidate_package_id",
    "candidate_review_anchor_id",
    "qualification_closure_id",
    "qualification_record_id",
    "qualification_spec_id",
    "review_approval_id",
    "review_registry_id",
    "review_registry_spec_id",
    "runtime_target_anchor_id",
    "runtime_target_id",
    "wheel_evidence_manifest_id",
    "wheel_evidence_pack_receipt_id",
    "wheel_evidence_pack_spec_id",
    "worker_api_evidence_anchor_id",
    "worker_program_id",
}
_ROOT_BINDING_FIELDS = {
    "custody_root_id",
    "output_root_id",
    "paths_parent_owned",
    "runtime_root_id",
    "worker_supplied_paths_accepted",
}
_BOUND_ROOT_FIELDS = ("custody_root_id", "output_root_id", "runtime_root_id")
_CONSUMPTION_FIELDS = {
    "authorization_id",
    "bridge_protocol_id",
    "bridge_spec_id",
    "challenge_sha256",
    "consumed_at_unix_ns",
    "consumption_id",
    "custody_root_id",
    "nonce_sha256",
    "one_shot",
    "output_root_id",
    "prior_state",
    "record_type",
    "resulting_state",
    "runtime_root_id",
    "schema_version",
    "session_id",
    "worker_program_id",
}
_COMMON_FRAME_FIELDS = {
    "bridge_protocol_id",
    "bridge_spec_id",
    "frame_type",
    "sequence",
    "session_id",
}
_TRANSCRIPT_FIELDS = {
    "authorization",
    "consumption",
    "deadline_monotonic_ns",
    "evidence_scope",
    "frames",
    "parent_policy",
    "physical_action_counters",
    "record_type",
    "schema_version",
    "session_id",
    "started_monotonic_ns",
    "synthetic_lifecycle",
}
_SESSION_RECORD_FIELDS = {
    "accepted_physical_evidence",
    "evidence_scope",
    "execution_reachable",
    "outcome",
    "physical_action_counters",
    "record_id",
    "record_type",
    "rejection",
    "schema_1_0_state",
    "schema_version",
    "transcript",
}
_SYNTHETIC_AUTHORITY_ID = "sha256:" + ("a" * 64)
_SYNTHETIC_AUTHORIZATION_REVIEW_ID = "sha256:" + ("b" * 64)
_SYNTHETIC_WORKER_PROGRAM_ID = "sha256:" + ("c" * 64)


@dataclass(frozen=True, slots=True)
class CustodyBridgeReplayResult:
    """Verified summary of the inert custody-bridge fixture."""

    bundle_root: str
    protocol_id: str
    spec_id: str
    validated_record_id: str
    rejected_record_id: str
    rejected_evidence_retained: bool
    real_authorizations_created: int
    real_authorizations_consumed: int
    process_starts: int
    socketpair_creations: int
    mlx_imports: int
    metal_queries: int
    synchronizations: int
    physical_actions: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "protocol_id": self.protocol_id,
            "spec_id": self.spec_id,
            "validated_record_id": self.validated_record_id,
            "rejected_record_id": self.rejected_record_id,
            "rejected_evidence_retained": self.rejected_evidence_retained,
            "real_authorizations_created": self.real_authorizations_created,
            "real_authorizations_consumed": self.real_authorizations_consumed,
            "process_starts": self.process_starts,
            "socketpair_creations": self.socketpair_creations,
            "mlx_imports": self.mlx_imports,
            "metal_queries": self.metal_queries,
            "synchronizations": self.synchronizations,
            "physical_actions": self.physical_actions,
        }


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = 256) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum count {maximum}")
    return value


def _keys(value: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(
    value: JsonValue,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ContractError(f"{label} must be <= {maximum}")
    return value


def _boolean(value: JsonValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _sha256(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _verify_zero_physical_actions(value: JsonValue, label: str) -> None:
    counters = _mapping(value, label)
    _keys(counters, set(_ZERO_PHYSICAL_ACTIONS), label)
    for name in sorted(_ZERO_PHYSICAL_ACTIONS):
        if _integer(counters[name], f"{label}.{name}") != 0:
            raise ContractError(f"{label}.{name} must remain zero")


def _regular_file_fingerprint(path: Path, label: str) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{label} must be a regular file")
        blocks: list[bytes] = []
        while block := os.read(descriptor, 1024 * 1024):
            blocks.append(block)
        data = b"".join(blocks)
        if len(data) != metadata.st_size:
            raise ContractError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    return digest_bytes(data)


def _current_context_fingerprints() -> tuple[str, ...]:
    return tuple(_regular_file_fingerprint(path, label) for label, path in _CURRENT_CONTEXT_PATHS)


@lru_cache(maxsize=2)
def _current_context_bytes(*_fingerprints: str) -> bytes:
    qualification = committed_qualification_publication_record()
    assessment = _mapping(qualification["assessment"], "committed qualification assessment")
    closure = _mapping(assessment["closure"], "committed qualification closure")
    target = runtime_target_anchor()
    prospective_target = _mapping(target["prospective_target"], "prospective runtime target")
    bindings = _mapping(qualification["evidence_bindings"], "qualification evidence bindings")
    if (
        qualification["record_id"] != EXPECTED_QUALIFICATION_RECORD_ID
        or target["anchor_id"] != EXPECTED_RUNTIME_TARGET_ANCHOR_ID
    ):
        raise ContractError("committed custody-bridge prerequisite identity drift")
    return canonical_json(
        {
            "qualification": qualification,
            "closure": closure,
            "qualification_closure_id": canonical_identity(closure),
            "selected_distributions": closure["selected_distributions"],
            "runtime_target": prospective_target,
            "runtime_target_id": canonical_identity(prospective_target),
            "evidence_bindings": bindings,
        }
    )


def _current_context() -> dict[str, JsonValue]:
    return _mapping(
        load_json_bytes(_current_context_bytes(*_current_context_fingerprints())),
        "current custody context",
    )


def custody_bridge_protocol_1_1() -> dict[str, JsonValue]:
    """Return the implemented inert parent protocol with no physical entrypoint."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_custody_protocol",
        "schema_version": SCHEMA_VERSION,
        "action": ACTION,
        "implementation_state": "inert_control_plane_complete_execution_unreachable",
        "transport": {
            "future_transport": "parent_created_inherited_private_af_unix_socketpair",
            "current_socket_creation_present": False,
            "network_allowed": False,
            "worker_selected_address_or_path_allowed": False,
        },
        "framing": {
            "encoding": "uint32_be_length_then_canonical_json_utf8",
            "maximum_frame_bytes": MAX_FRAME_BYTES,
            "duplicate_json_keys_allowed": False,
            "unknown_fields_allowed": False,
            "frame_sequence": list(_FRAME_SEQUENCE),
            "unexpected_missing_duplicate_or_extra_frame_policy": "reject_and_retain",
        },
        "parent_owned": {
            "authorization_consumption": True,
            "challenge_and_nonce": True,
            "counters_and_deadlines": True,
            "custody_output_and_runtime_roots": True,
            "executable_and_worker_identity": True,
            "final_evidence_publication": "receipt_last_closed_bundle",
            "process_and_socket_lifecycle": True,
            "rejected_evidence_retention": True,
            "shutdown_cleanup_and_child_wait": True,
        },
        "launch_policy": {
            "arbitrary_executable_allowed": False,
            "environment": "empty_parent_constructed_allowlist_only",
            "environment_inheritance_allowed": False,
            "installer_resolver_or_downloader_present": False,
            "preinstalled_exact_distribution_checks_only": True,
            "worker_controlled_output_path_allowed": False,
            "worker_implementation_present": False,
        },
        "allowed_actions": list(ALLOWED_ACTIONS),
        "action_limits": dict.fromkeys(ALLOWED_ACTIONS, 1),
        "forbidden_actions": list(_FORBIDDEN_ACTIONS),
        "model_free": True,
        "attempts": 1,
        "retries": 0,
        "warmups": 0,
        "concurrency": 1,
        "execution_command_present": False,
    }
    content["protocol_id"] = canonical_identity(content)
    return content


def custody_bridge_spec_1_1() -> dict[str, JsonValue]:
    """Return the exact current-qualification custody bridge specification."""
    context = _current_context()
    protocol = custody_bridge_protocol_1_1()
    bindings = _mapping(context["evidence_bindings"], "qualification evidence bindings")
    expected_bindings: dict[str, JsonValue] = {
        "candidate_package_id": EXPECTED_CANDIDATE_PACKAGE_ID,
        "candidate_review_anchor_id": EXPECTED_CANDIDATE_REVIEW_ANCHOR_ID,
        "qualification_closure_id": context["qualification_closure_id"],
        "qualification_record_id": EXPECTED_QUALIFICATION_RECORD_ID,
        "qualification_spec_id": EXPECTED_QUALIFICATION_SPEC_ID,
        "review_approval_id": EXPECTED_REVIEW_APPROVAL_ID,
        "review_registry_id": EXPECTED_REVIEW_REGISTRY_ID,
        "review_registry_spec_id": EXPECTED_REVIEW_REGISTRY_SPEC_ID,
        "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        "runtime_target_id": context["runtime_target_id"],
        "wheel_evidence_manifest_id": EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
        "wheel_evidence_pack_receipt_id": EXPECTED_WHEEL_EVIDENCE_PACK_RECEIPT_ID,
        "wheel_evidence_pack_spec_id": EXPECTED_WHEEL_EVIDENCE_PACK_SPEC_ID,
        "worker_api_evidence_anchor_id": EXPECTED_WORKER_API_EVIDENCE_ANCHOR_ID,
    }
    for name, expected in expected_bindings.items():
        if name in bindings and bindings[name] != expected:
            raise ContractError(f"qualification custody binding drift: {name}")
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_custody_spec",
        "schema_version": SCHEMA_VERSION,
        "action": ACTION,
        "protocol_id": protocol["protocol_id"],
        "identity_bindings": expected_bindings,
        "runtime_target": context["runtime_target"],
        "selected_distributions": context["selected_distributions"],
        "authorization_policy": {
            "maximum_lifetime_ns": AUTHORIZATION_LIFETIME_NS,
            "one_shot": True,
            "exclusive_consumption_required_before_worker_action": True,
            "nonce_and_challenge_required": True,
            "current_time_observation_parent_owned": True,
            "committed_authorization_ids": [],
            "committed_authority_ids": [],
            "committed_authorization_review_ids": [],
            "caller_label_or_self_hash_establishes_authority": False,
            "caller_time_establishes_freshness": False,
            "caller_root_id_establishes_independent_binding": False,
            "caller_consumption_state_establishes_nonreuse": False,
        },
        "root_policy": {
            "custody_output_and_runtime_roots_bound_separately": True,
            "root_identifiers_are_parent_observed": True,
            "absolute_private_paths_published": False,
            "worker_path_fields_allowed": False,
        },
        "preinstalled_only_policy": {
            "distribution_identity_checks": "exact_selected_distribution_name_and_version_set",
            "installer_present": False,
            "resolver_present": False,
            "download_present": False,
            "development_or_fixture_checks_performed": False,
        },
        "allowed_actions": list(ALLOWED_ACTIONS),
        "forbidden_actions": list(_FORBIDDEN_ACTIONS),
        "control_plane": {
            "authorization_structure_validator_present": True,
            "current_expiry_validator_present": True,
            "exclusive_consumption_record_contract_present": True,
            "strict_frame_validator_present": True,
            "deadline_validator_present": True,
            "process_socket_anomaly_validator_present": True,
            "rejected_evidence_retention_present": True,
            "final_closed_evidence_publication_present": True,
        },
        "execution_gate": {
            "physical_execution_reachable": False,
            "public_or_internal_execute_entrypoint_present": False,
            "authorization_creator_present": False,
            "approved_authorization_present": False,
            "approved_authority_present": False,
            "reviewed_worker_program_present": False,
            "worker_or_installer_entrypoint_present": False,
            "blockers": list(_EXECUTION_BLOCKERS),
        },
        "claim_scope": (
            "control_plane_contract_and_synthetic_inert_replay_only_no_host_or_runtime_evidence"
        ),
        "schema_1_0_state": "permanently_disabled",
        "historical_records_rewritten": False,
        "static_action_counters": dict(_ZERO_PHYSICAL_ACTIONS),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def custody_bridge_capability_report_1_1() -> dict[str, JsonValue]:
    """Report implemented inert controls and the deliberately absent execution gate."""
    spec = custody_bridge_spec_1_1()
    protocol = custody_bridge_protocol_1_1()
    return {
        "record_type": "mlx_runtime_preflight_custody_capability_report",
        "schema_version": SCHEMA_VERSION,
        "action": ACTION,
        "spec_id": spec["spec_id"],
        "protocol_id": protocol["protocol_id"],
        "control_plane_complete": True,
        "execution_reachable": False,
        "execute_command_present": False,
        "worker_entrypoint_present": False,
        "installer_resolver_or_downloader_present": False,
        "authorization_creator_present": False,
        "approved_authorization_present": False,
        "approved_authority_present": False,
        "synthetic_fixture_only": True,
        "blockers": list(_EXECUTION_BLOCKERS),
        "physical_actions": 0,
        "static_action_counters": dict(_ZERO_PHYSICAL_ACTIONS),
    }


def _verify_authorization(
    value: JsonValue,
    *,
    allow_synthetic: bool,
) -> dict[str, JsonValue]:
    authorization = _mapping(value, "custody authorization")
    _keys(authorization, _AUTHORIZATION_FIELDS, "custody authorization")
    spec = custody_bridge_spec_1_1()
    protocol = custody_bridge_protocol_1_1()
    evidence_kind = authorization["evidence_kind"]
    allowed_evidence_kinds = {"external_independently_reviewed_authorization"}
    if allow_synthetic:
        allowed_evidence_kinds.add("synthetic_fixture_only")
    if (
        authorization["record_type"] != "mlx_runtime_preflight_execution_authorization"
        or authorization["schema_version"] != SCHEMA_VERSION
        or authorization["action"] != ACTION
        or authorization["decision"] != "authorize_once"
        or authorization["one_shot"] is not True
        or authorization["bridge_spec_id"] != spec["spec_id"]
        or authorization["bridge_protocol_id"] != protocol["protocol_id"]
        or evidence_kind not in allowed_evidence_kinds
    ):
        raise ContractError("unsupported custody authorization")
    if authorization["allowed_actions"] != list(ALLOWED_ACTIONS):
        raise ContractError("custody authorization action allowlist mismatch")

    expected = _mapping(spec["identity_bindings"], "custody spec identity bindings")
    bindings = _mapping(authorization["identity_bindings"], "authorization identity bindings")
    _keys(bindings, _IDENTITY_BINDING_FIELDS, "authorization identity bindings")
    for name in sorted(_IDENTITY_BINDING_FIELDS):
        _sha256(bindings[name], f"authorization identity bindings.{name}")
        if name != "worker_program_id" and bindings[name] != expected[name]:
            raise ContractError(f"authorization identity binding mismatch: {name}")

    authority = _mapping(authorization["authority_bindings"], "authorization authority bindings")
    _keys(
        authority,
        {"authorization_authority_id", "authorization_review_id"},
        "authorization authority bindings",
    )
    _sha256(
        authority["authorization_authority_id"],
        "authorization authority bindings.authorization_authority_id",
    )
    _sha256(
        authority["authorization_review_id"],
        "authorization authority bindings.authorization_review_id",
    )

    roots = _mapping(authorization["root_bindings"], "authorization root bindings")
    _keys(roots, _ROOT_BINDING_FIELDS, "authorization root bindings")
    for name in _BOUND_ROOT_FIELDS:
        _sha256(roots[name], f"authorization root bindings.{name}")
    if (
        roots["paths_parent_owned"] is not True
        or roots["worker_supplied_paths_accepted"] is not False
    ):
        raise ContractError("authorization root ownership policy mismatch")
    if len({roots[name] for name in _BOUND_ROOT_FIELDS}) != len(_BOUND_ROOT_FIELDS):
        raise ContractError("authorization root bindings must be distinct")

    session = _mapping(authorization["session_bindings"], "authorization session bindings")
    _keys(session, {"challenge_sha256", "nonce_sha256"}, "authorization session bindings")
    challenge = _sha256(
        session["challenge_sha256"],
        "authorization session bindings.challenge_sha256",
    )
    nonce = _sha256(session["nonce_sha256"], "authorization session bindings.nonce_sha256")
    if challenge == nonce:
        raise ContractError("authorization challenge and nonce must be distinct")

    temporal = _mapping(authorization["temporal"], "authorization temporal")
    _keys(
        temporal,
        {
            "consumption_state",
            "expires_at_unix_ns",
            "issued_at_unix_ns",
            "not_before_unix_ns",
        },
        "authorization temporal",
    )
    issued = _integer(temporal["issued_at_unix_ns"], "authorization issued_at", minimum=1)
    not_before = _integer(
        temporal["not_before_unix_ns"],
        "authorization not_before",
        minimum=issued,
    )
    expires = _integer(
        temporal["expires_at_unix_ns"],
        "authorization expires_at",
        minimum=not_before + 1,
    )
    if expires - issued > AUTHORIZATION_LIFETIME_NS:
        raise ContractError("authorization exceeds maximum lifetime")
    if temporal["consumption_state"] != "unconsumed":
        raise ContractError("authorization must enter custody unconsumed")

    identity = _sha256(authorization["authorization_id"], "authorization authorization_id")
    content = dict(authorization)
    del content["authorization_id"]
    if canonical_identity(content) != identity:
        raise ContractError("authorization identity mismatch")
    return dict(authorization)


def verify_authorization_structure_1_1(value: JsonValue) -> dict[str, JsonValue]:
    """Validate structure without treating caller content as authority or freshness."""
    return _verify_authorization(value, allow_synthetic=False)


def authorization_assessment_1_1(
    value: JsonValue,
    *,
    observed_at_unix_ns: int | None = None,
) -> dict[str, JsonValue]:
    """Return a fail-closed assessment; no committed authorization can pass it."""
    authorization = verify_authorization_structure_1_1(value)
    temporal = _mapping(authorization["temporal"], "authorization temporal")
    blockers = list(_EXECUTION_BLOCKERS)
    time_window_current = False
    if observed_at_unix_ns is None:
        blockers.append("parent_current_time_observation_missing")
    else:
        observed = _integer(observed_at_unix_ns, "observed_at_unix_ns", minimum=1)
        not_before = cast("int", temporal["not_before_unix_ns"])
        expires = cast("int", temporal["expires_at_unix_ns"])
        time_window_current = not_before <= observed < expires
        if observed < not_before:
            blockers.append("authorization_not_yet_valid")
        if observed >= expires:
            blockers.append("authorization_expired")
    assessment: dict[str, JsonValue] = {
        "authorization_id": authorization["authorization_id"],
        "structure_valid": True,
        "time_window_current": time_window_current,
        "authoritative": False,
        "consumable": False,
        "caller_labels_or_self_hashes_accepted_as_authority": False,
        "blockers": cast("list[JsonValue]", sorted(set(blockers))),
    }
    return assessment


def _verify_authorization_at(
    value: JsonValue,
    *,
    observed_at_unix_ns: int,
    allow_synthetic: bool,
) -> dict[str, JsonValue]:
    authorization = _verify_authorization(value, allow_synthetic=allow_synthetic)
    temporal = _mapping(authorization["temporal"], "authorization temporal")
    observed = _integer(observed_at_unix_ns, "observed_at_unix_ns", minimum=1)
    if not (
        cast("int", temporal["not_before_unix_ns"])
        <= observed
        < cast("int", temporal["expires_at_unix_ns"])
    ):
        raise ContractError("authorization is stale, expired, or not yet valid")
    if authorization["evidence_kind"] != "synthetic_fixture_only":
        raise ContractError("no independently reviewed authorization is committed")
    if not allow_synthetic:
        raise ContractError("synthetic authorization cannot cross the physical execution gate")
    authority = _mapping(authorization["authority_bindings"], "authorization authority bindings")
    bindings = _mapping(authorization["identity_bindings"], "authorization identity bindings")
    if (
        authority["authorization_authority_id"] != _SYNTHETIC_AUTHORITY_ID
        or authority["authorization_review_id"] != _SYNTHETIC_AUTHORIZATION_REVIEW_ID
        or bindings["worker_program_id"] != _SYNTHETIC_WORKER_PROGRAM_ID
    ):
        raise ContractError("synthetic fixture authority or worker binding mismatch")
    return authorization


def _build_consumption(
    authorization_value: JsonValue,
    *,
    consumed_at_unix_ns: int,
    session_id: str,
) -> dict[str, JsonValue]:
    authorization = _verify_authorization_at(
        authorization_value,
        observed_at_unix_ns=consumed_at_unix_ns,
        allow_synthetic=True,
    )
    roots = _mapping(authorization["root_bindings"], "authorization root bindings")
    session = _mapping(authorization["session_bindings"], "authorization session bindings")
    bindings = _mapping(authorization["identity_bindings"], "authorization identity bindings")
    consumption: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_authorization_consumption",
        "schema_version": SCHEMA_VERSION,
        "bridge_spec_id": authorization["bridge_spec_id"],
        "bridge_protocol_id": authorization["bridge_protocol_id"],
        "authorization_id": authorization["authorization_id"],
        "session_id": _sha256(session_id, "session_id"),
        "worker_program_id": bindings["worker_program_id"],
        "custody_root_id": roots["custody_root_id"],
        "output_root_id": roots["output_root_id"],
        "runtime_root_id": roots["runtime_root_id"],
        "nonce_sha256": session["nonce_sha256"],
        "challenge_sha256": session["challenge_sha256"],
        "consumed_at_unix_ns": consumed_at_unix_ns,
        "prior_state": "unconsumed",
        "resulting_state": "consumed",
        "one_shot": True,
    }
    consumption["consumption_id"] = canonical_identity(consumption)
    return consumption


def verify_consumption_1_1(
    value: JsonValue,
    authorization_value: JsonValue,
) -> dict[str, JsonValue]:
    """Verify exact one-time state transition bindings without performing consumption."""
    consumption = _mapping(value, "authorization consumption")
    _keys(consumption, _CONSUMPTION_FIELDS, "authorization consumption")
    authorization = _verify_authorization(authorization_value, allow_synthetic=True)
    roots = _mapping(authorization["root_bindings"], "authorization root bindings")
    session = _mapping(authorization["session_bindings"], "authorization session bindings")
    bindings = _mapping(authorization["identity_bindings"], "authorization identity bindings")
    if (
        consumption["record_type"] != "mlx_runtime_preflight_authorization_consumption"
        or consumption["schema_version"] != SCHEMA_VERSION
        or consumption["bridge_spec_id"] != authorization["bridge_spec_id"]
        or consumption["bridge_protocol_id"] != authorization["bridge_protocol_id"]
        or consumption["authorization_id"] != authorization["authorization_id"]
        or consumption["worker_program_id"] != bindings["worker_program_id"]
        or consumption["custody_root_id"] != roots["custody_root_id"]
        or consumption["output_root_id"] != roots["output_root_id"]
        or consumption["runtime_root_id"] != roots["runtime_root_id"]
        or consumption["nonce_sha256"] != session["nonce_sha256"]
        or consumption["challenge_sha256"] != session["challenge_sha256"]
        or consumption["prior_state"] != "unconsumed"
        or consumption["resulting_state"] != "consumed"
        or consumption["one_shot"] is not True
    ):
        raise ContractError("authorization consumption binding mismatch")
    consumed = _integer(
        consumption["consumed_at_unix_ns"],
        "authorization consumption consumed_at_unix_ns",
        minimum=1,
    )
    temporal = _mapping(authorization["temporal"], "authorization temporal")
    if not (
        cast("int", temporal["not_before_unix_ns"])
        <= consumed
        < cast("int", temporal["expires_at_unix_ns"])
    ):
        raise ContractError("authorization consumption occurred outside the valid window")
    _sha256(consumption["session_id"], "authorization consumption session_id")
    identity = _sha256(consumption["consumption_id"], "authorization consumption_id")
    content = dict(consumption)
    del content["consumption_id"]
    if canonical_identity(content) != identity:
        raise ContractError("authorization consumption identity mismatch")
    return dict(consumption)


def verify_one_shot_consumptions_1_1(
    pairs: list[tuple[JsonValue, JsonValue]],
) -> list[dict[str, JsonValue]]:
    """Reject authorization or consumption replay across a parent-owned session set."""
    verified: list[dict[str, JsonValue]] = []
    authorization_ids: set[str] = set()
    consumption_ids: set[str] = set()
    for authorization_value, consumption_value in pairs:
        authorization = _verify_authorization(authorization_value, allow_synthetic=True)
        consumption = verify_consumption_1_1(consumption_value, authorization)
        authorization_id = cast("str", authorization["authorization_id"])
        consumption_id = cast("str", consumption["consumption_id"])
        if authorization_id in authorization_ids or consumption_id in consumption_ids:
            raise ContractError("authorization replay or duplicate consumption detected")
        authorization_ids.add(authorization_id)
        consumption_ids.add(consumption_id)
        verified.append(consumption)
    return verified


def encode_custody_frame_1_1(value: JsonValue) -> bytes:
    """Encode one bounded canonical frame; this performs no I/O."""
    payload = canonical_json(value)
    if not payload or len(payload) > MAX_FRAME_BYTES:
        raise ContractError("custody frame payload exceeds its bound")
    return len(payload).to_bytes(_FRAME_HEADER_BYTES, "big") + payload


def decode_custody_frame_1_1(data: bytes) -> dict[str, JsonValue]:
    """Decode one complete canonical frame and reject malformed or trailing bytes."""
    if len(data) < _FRAME_HEADER_BYTES:
        raise ContractError("custody frame is missing its length prefix")
    length = int.from_bytes(data[:_FRAME_HEADER_BYTES], "big")
    if length < 1 or length > MAX_FRAME_BYTES:
        raise ContractError("custody frame length is outside its bound")
    payload = data[_FRAME_HEADER_BYTES:]
    if len(payload) != length:
        raise ContractError("custody frame length mismatch or trailing bytes")
    value = load_json_bytes(payload)
    if canonical_json(value) != payload:
        raise ContractError("custody frame payload must use canonical JSON")
    return _mapping(value, "custody frame payload")


def _wire_entry(
    message: dict[str, JsonValue], received_at_monotonic_ns: int
) -> dict[str, JsonValue]:
    wire = encode_custody_frame_1_1(message)
    return {
        "direction": "worker_to_parent",
        "received_at_monotonic_ns": received_at_monotonic_ns,
        "wire_bytes_base64": encode_bytes(wire),
        "wire_sha256": digest_bytes(wire),
    }


def _decode_wire_entry(value: JsonValue, index: int) -> tuple[int, dict[str, JsonValue], str]:
    label = f"custody transcript frames[{index}]"
    entry = _mapping(value, label)
    _keys(
        entry,
        {
            "direction",
            "received_at_monotonic_ns",
            "wire_bytes_base64",
            "wire_sha256",
        },
        label,
    )
    if entry["direction"] != "worker_to_parent":
        raise ContractError(f"{label} direction mismatch")
    received = _integer(entry["received_at_monotonic_ns"], f"{label}.received_at_monotonic_ns")
    encoded = _text(entry["wire_bytes_base64"], f"{label}.wire_bytes_base64")
    wire = decode_bytes(encoded)
    digest = _sha256(entry["wire_sha256"], f"{label}.wire_sha256")
    if digest_bytes(wire) != digest:
        raise ContractError(f"{label} wire digest mismatch")
    return received, decode_custody_frame_1_1(wire), digest


def _verify_common_frame(
    frame: dict[str, JsonValue],
    *,
    expected_type: str,
    expected_sequence: int,
    expected_fields: set[str],
    spec: dict[str, JsonValue],
    session_id: str,
) -> None:
    if (
        frame.get("frame_type") != expected_type
        or _integer(frame.get("sequence"), f"{expected_type}.sequence", minimum=1)
        != expected_sequence
        or frame.get("bridge_protocol_id") != spec["protocol_id"]
        or frame.get("bridge_spec_id") != spec["spec_id"]
        or frame.get("session_id") != session_id
    ):
        raise ContractError(f"{expected_type} frame sequence or session binding mismatch")
    _keys(frame, _COMMON_FRAME_FIELDS | expected_fields, f"{expected_type} frame")


def _verify_worker_frames(
    frames_value: JsonValue,
    *,
    authorization: dict[str, JsonValue],
    consumption: dict[str, JsonValue],
    started_monotonic_ns: int,
    deadline_monotonic_ns: int,
) -> list[str]:
    frames = _array(frames_value, "custody transcript frames", maximum=len(_FRAME_SEQUENCE))
    if len(frames) != len(_FRAME_SEQUENCE):
        raise ContractError("custody transcript has a missing or extra frame")
    spec = custody_bridge_spec_1_1()
    bindings = _mapping(authorization["identity_bindings"], "authorization identity bindings")
    roots = _mapping(authorization["root_bindings"], "authorization root bindings")
    session = _mapping(authorization["session_bindings"], "authorization session bindings")
    session_id = cast("str", consumption["session_id"])
    decoded: list[dict[str, JsonValue]] = []
    digests: list[str] = []
    prior_received = started_monotonic_ns
    for index, entry in enumerate(frames):
        received, frame, digest = _decode_wire_entry(entry, index)
        if received < prior_received:
            raise ContractError("custody frame receive times must be monotonic")
        if received > deadline_monotonic_ns:
            raise ContractError("custody frame arrived after the parent deadline")
        prior_received = received
        decoded.append(frame)
        digests.append(digest)

    hello, ack, result, shutdown = decoded
    _verify_common_frame(
        hello,
        expected_type="worker_hello",
        expected_sequence=1,
        expected_fields={
            "challenge_sha256",
            "environment",
            "executable_selection",
            "network_enabled",
            "worker_program_id",
        },
        spec=spec,
        session_id=session_id,
    )
    if (
        hello["worker_program_id"] != bindings["worker_program_id"]
        or hello["challenge_sha256"] != session["challenge_sha256"]
        or hello["environment"] != {}
        or hello["network_enabled"] is not False
        or hello["executable_selection"] != "parent_owned_reviewed_program_id"
    ):
        raise ContractError("worker hello identity, environment, or network policy mismatch")

    _verify_common_frame(
        ack,
        expected_type="authorization_ack",
        expected_sequence=2,
        expected_fields={
            "authorization_id",
            "challenge_sha256",
            "consumption_id",
            "consumption_state",
            "custody_root_id",
            "nonce_sha256",
            "output_root_id",
            "runtime_root_id",
        },
        spec=spec,
        session_id=session_id,
    )
    if (
        ack["authorization_id"] != authorization["authorization_id"]
        or ack["consumption_id"] != consumption["consumption_id"]
        or ack["consumption_state"] != "consumed"
        or ack["challenge_sha256"] != session["challenge_sha256"]
        or ack["nonce_sha256"] != session["nonce_sha256"]
        or ack["custody_root_id"] != roots["custody_root_id"]
        or ack["output_root_id"] != roots["output_root_id"]
        or ack["runtime_root_id"] != roots["runtime_root_id"]
    ):
        raise ContractError("authorization acknowledgement binding mismatch")

    _verify_common_frame(
        result,
        expected_type="preflight_result",
        expected_sequence=3,
        expected_fields={
            "accepted_evidence",
            "attempted_actions",
            "authorization_id",
            "completed_actions",
            "consumption_id",
            "forbidden_actions_completed",
            "observations",
        },
        spec=spec,
        session_id=session_id,
    )
    if (
        result["authorization_id"] != authorization["authorization_id"]
        or result["consumption_id"] != consumption["consumption_id"]
        or result["attempted_actions"] != list(ALLOWED_ACTIONS)
        or result["completed_actions"] != list(ALLOWED_ACTIONS)
        or result["accepted_evidence"] != list(ALLOWED_ACTIONS)
        or result["forbidden_actions_completed"] != []
    ):
        raise ContractError("preflight result contains a missing, duplicate, or extra action")
    observations = _mapping(result["observations"], "preflight result observations")
    _keys(
        observations,
        {
            "backend",
            "candidate_distributions",
            "device",
            "imported_modules",
            "metal_available",
            "model_actions",
            "synchronized",
        },
        "preflight result observations",
    )
    context = _current_context()
    if (
        observations["candidate_distributions"] != context["selected_distributions"]
        or observations["imported_modules"] != list(_IMPORTED_MODULES)
        or _text(observations["backend"], "preflight result backend", maximum=256) == ""
        or _text(observations["device"], "preflight result device", maximum=256) == ""
        or not isinstance(observations["metal_available"], bool)
        or observations["synchronized"] is not True
        or _integer(observations["model_actions"], "preflight result model_actions") != 0
    ):
        raise ContractError("preflight result observation shape or identity mismatch")

    _verify_common_frame(
        shutdown,
        expected_type="shutdown_ack",
        expected_sequence=4,
        expected_fields={"cleanup_ready", "consumption_id"},
        spec=spec,
        session_id=session_id,
    )
    if (
        shutdown["consumption_id"] != consumption["consumption_id"]
        or shutdown["cleanup_ready"] is not True
    ):
        raise ContractError("shutdown acknowledgement binding mismatch")
    return digests


def _verify_parent_policy(value: JsonValue) -> None:
    policy = _mapping(value, "custody parent policy")
    expected: dict[str, JsonValue] = {
        "arbitrary_executable_allowed": False,
        "authorization_consumption_parent_owned": True,
        "cleanup_and_child_wait_parent_owned": True,
        "counters_and_deadlines_parent_owned": True,
        "environment_inherited": False,
        "final_evidence_publication_parent_owned": True,
        "network_enabled": False,
        "paths_parent_owned": True,
        "process_and_socket_lifecycle_parent_owned": True,
        "rejected_evidence_retention_required": True,
        "worker_controlled_output_path_allowed": False,
    }
    if canonical_json(policy) != canonical_json(expected):
        raise ContractError("custody parent ownership policy mismatch")


def _verify_synthetic_lifecycle(value: JsonValue) -> None:
    lifecycle = _mapping(value, "custody synthetic lifecycle")
    expected: dict[str, JsonValue] = {
        "cleanup_completed": True,
        "fake_processes_simulated": 1,
        "fake_socketpairs_simulated": 1,
        "physical_process_started": False,
        "physical_socket_created": False,
        "process_anomaly": False,
        "socket_anomaly": False,
    }
    if canonical_json(lifecycle) != canonical_json(expected):
        raise ContractError("custody process, socket, or cleanup anomaly")


def _verify_transcript(value: JsonValue) -> tuple[dict[str, JsonValue], list[str]]:
    transcript = _mapping(value, "custody transcript")
    _keys(transcript, _TRANSCRIPT_FIELDS, "custody transcript")
    if (
        transcript["record_type"] != "mlx_runtime_preflight_synthetic_custody_transcript"
        or transcript["schema_version"] != SCHEMA_VERSION
        or transcript["evidence_scope"] != "synthetic_inert_fixture_only"
    ):
        raise ContractError("unsupported custody transcript")
    _verify_zero_physical_actions(
        transcript["physical_action_counters"],
        "custody transcript physical_action_counters",
    )
    _verify_parent_policy(transcript["parent_policy"])
    _verify_synthetic_lifecycle(transcript["synthetic_lifecycle"])
    authorization = _verify_authorization(transcript["authorization"], allow_synthetic=True)
    consumption = verify_consumption_1_1(transcript["consumption"], authorization)
    session_id = _sha256(transcript["session_id"], "custody transcript session_id")
    if session_id != consumption["session_id"]:
        raise ContractError("custody transcript session identity mismatch")
    started = _integer(
        transcript["started_monotonic_ns"],
        "custody transcript started_monotonic_ns",
        minimum=1,
    )
    deadline = _integer(
        transcript["deadline_monotonic_ns"],
        "custody transcript deadline_monotonic_ns",
        minimum=started + 1,
    )
    if deadline - started > AUTHORIZATION_LIFETIME_NS:
        raise ContractError("custody transcript deadline exceeds authorization lifetime")
    digests = _verify_worker_frames(
        transcript["frames"],
        authorization=authorization,
        consumption=consumption,
        started_monotonic_ns=started,
        deadline_monotonic_ns=deadline,
    )
    return dict(transcript), digests


def build_synthetic_custody_session_record_1_1(value: JsonValue) -> dict[str, JsonValue]:
    """Build explicit synthetic validation or retained-rejection evidence."""
    transcript = _mapping(value, "custody transcript")
    frame_values = transcript.get("frames")
    retained_digests: list[JsonValue] = []
    if isinstance(frame_values, list):
        for index, item in enumerate(frame_values[: len(_FRAME_SEQUENCE)]):
            try:
                _received, _frame, digest = _decode_wire_entry(item, index)
            except ContractError:
                entry = item if isinstance(item, dict) else {}
                raw_digest = entry.get("wire_sha256")
                if isinstance(raw_digest, str):
                    retained_digests.append(raw_digest)
            else:
                retained_digests.append(digest)
    try:
        verified, retained_digests_text = _verify_transcript(transcript)
    except ContractError as error:
        outcome = "rejected"
        rejection: JsonValue = {
            "error_category": type(error).__name__,
            "error_message_sha256": digest_bytes(str(error).encode("utf-8")),
            "rejected_evidence_retained": True,
            "retained_frame_digests": retained_digests,
            "retained_transcript_id": canonical_identity(transcript),
        }
        retained_transcript = dict(transcript)
    else:
        outcome = "synthetic_sequence_validated_not_physical_evidence"
        rejection = None
        retained_transcript = verified
        retained_digests = cast("list[JsonValue]", retained_digests_text)
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_custody_session_record",
        "schema_version": SCHEMA_VERSION,
        "evidence_scope": "synthetic_inert_fixture_only",
        "transcript": retained_transcript,
        "outcome": outcome,
        "rejection": rejection,
        "execution_reachable": False,
        "accepted_physical_evidence": [],
        "schema_1_0_state": "permanently_disabled",
        "physical_action_counters": dict(_ZERO_PHYSICAL_ACTIONS),
    }
    record["record_id"] = canonical_identity(record)
    return record


def verify_synthetic_custody_session_record_1_1(value: JsonValue) -> dict[str, JsonValue]:
    """Reconstruct one synthetic session and require retained failure evidence."""
    record = _mapping(value, "custody session record")
    _keys(record, _SESSION_RECORD_FIELDS, "custody session record")
    if (
        record["record_type"] != "mlx_runtime_preflight_custody_session_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["evidence_scope"] != "synthetic_inert_fixture_only"
        or record["execution_reachable"] is not False
        or record["accepted_physical_evidence"] != []
        or record["schema_1_0_state"] != "permanently_disabled"
    ):
        raise ContractError("unsupported custody session record")
    _verify_zero_physical_actions(
        record["physical_action_counters"],
        "custody session physical_action_counters",
    )
    rebuilt = build_synthetic_custody_session_record_1_1(record["transcript"])
    if canonical_json(rebuilt) != canonical_json(record):
        raise ContractError("custody session record reconstruction mismatch")
    if record["outcome"] == "rejected":
        rejection = _mapping(record["rejection"], "custody session rejection")
        if rejection["rejected_evidence_retained"] is not True or not _array(
            rejection["retained_frame_digests"],
            "custody session retained frame digests",
            maximum=len(_FRAME_SEQUENCE),
        ):
            raise ContractError("rejected custody evidence was not retained")
    identity = _sha256(record["record_id"], "custody session record_id")
    content = dict(record)
    del content["record_id"]
    if canonical_identity(content) != identity:
        raise ContractError("custody session record identity mismatch")
    return dict(record)


def _synthetic_authorization(seed: int) -> dict[str, JsonValue]:
    spec = custody_bridge_spec_1_1()
    protocol = custody_bridge_protocol_1_1()
    identity_bindings = dict(cast("dict[str, JsonValue]", spec["identity_bindings"]))
    identity_bindings["worker_program_id"] = _SYNTHETIC_WORKER_PROGRAM_ID
    authorization: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_execution_authorization",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "synthetic_fixture_only",
        "action": ACTION,
        "decision": "authorize_once",
        "one_shot": True,
        "bridge_spec_id": spec["spec_id"],
        "bridge_protocol_id": protocol["protocol_id"],
        "identity_bindings": identity_bindings,
        "authority_bindings": {
            "authorization_authority_id": _SYNTHETIC_AUTHORITY_ID,
            "authorization_review_id": _SYNTHETIC_AUTHORIZATION_REVIEW_ID,
        },
        "root_bindings": {
            "custody_root_id": "sha256:" + (f"{seed + 1:x}"[-1] * 64),
            "output_root_id": "sha256:" + (f"{seed + 2:x}"[-1] * 64),
            "runtime_root_id": "sha256:" + (f"{seed + 3:x}"[-1] * 64),
            "paths_parent_owned": True,
            "worker_supplied_paths_accepted": False,
        },
        "session_bindings": {
            "nonce_sha256": "sha256:" + (f"{seed + 4:x}"[-1] * 64),
            "challenge_sha256": "sha256:" + (f"{seed + 5:x}"[-1] * 64),
        },
        "temporal": {
            "issued_at_unix_ns": seed * 1_000_000_000,
            "not_before_unix_ns": seed * 1_000_000_000,
            "expires_at_unix_ns": (seed * 1_000_000_000) + AUTHORIZATION_LIFETIME_NS,
            "consumption_state": "unconsumed",
        },
        "allowed_actions": list(ALLOWED_ACTIONS),
    }
    authorization["authorization_id"] = canonical_identity(authorization)
    return authorization


def _synthetic_transcript(seed: int, *, extra_action: bool) -> dict[str, JsonValue]:
    authorization = _synthetic_authorization(seed)
    consumed_at = (seed * 1_000_000_000) + 1
    session_id = canonical_identity(
        {
            "authorization_id": authorization["authorization_id"],
            "seed": seed,
            "scope": "synthetic_fixture_only",
        }
    )
    consumption = _build_consumption(
        authorization,
        consumed_at_unix_ns=consumed_at,
        session_id=session_id,
    )
    spec = custody_bridge_spec_1_1()
    bindings = _mapping(authorization["identity_bindings"], "authorization identity bindings")
    roots = _mapping(authorization["root_bindings"], "authorization root bindings")
    session = _mapping(authorization["session_bindings"], "authorization session bindings")
    common: dict[str, JsonValue] = {
        "bridge_protocol_id": spec["protocol_id"],
        "bridge_spec_id": spec["spec_id"],
        "session_id": session_id,
    }
    attempted = cast("list[JsonValue]", list(ALLOWED_ACTIONS))
    if extra_action:
        attempted.append("model_load")
    context = _current_context()
    frames: list[dict[str, JsonValue]] = [
        {
            **common,
            "frame_type": "worker_hello",
            "sequence": 1,
            "worker_program_id": bindings["worker_program_id"],
            "challenge_sha256": session["challenge_sha256"],
            "environment": {},
            "network_enabled": False,
            "executable_selection": "parent_owned_reviewed_program_id",
        },
        {
            **common,
            "frame_type": "authorization_ack",
            "sequence": 2,
            "authorization_id": authorization["authorization_id"],
            "consumption_id": consumption["consumption_id"],
            "consumption_state": "consumed",
            "nonce_sha256": session["nonce_sha256"],
            "challenge_sha256": session["challenge_sha256"],
            "custody_root_id": roots["custody_root_id"],
            "output_root_id": roots["output_root_id"],
            "runtime_root_id": roots["runtime_root_id"],
        },
        {
            **common,
            "frame_type": "preflight_result",
            "sequence": 3,
            "authorization_id": authorization["authorization_id"],
            "consumption_id": consumption["consumption_id"],
            "attempted_actions": attempted,
            "completed_actions": cast("list[JsonValue]", list(ALLOWED_ACTIONS)),
            "accepted_evidence": cast("list[JsonValue]", list(ALLOWED_ACTIONS)),
            "forbidden_actions_completed": [],
            "observations": {
                "candidate_distributions": context["selected_distributions"],
                "imported_modules": cast("list[JsonValue]", list(_IMPORTED_MODULES)),
                "backend": "synthetic-metal",
                "device": "synthetic-gpu",
                "metal_available": True,
                "synchronized": True,
                "model_actions": 0,
            },
        },
        {
            **common,
            "frame_type": "shutdown_ack",
            "sequence": 4,
            "consumption_id": consumption["consumption_id"],
            "cleanup_ready": True,
        },
    ]
    started = seed * 10_000_000_000
    return {
        "record_type": "mlx_runtime_preflight_synthetic_custody_transcript",
        "schema_version": SCHEMA_VERSION,
        "evidence_scope": "synthetic_inert_fixture_only",
        "session_id": session_id,
        "authorization": authorization,
        "consumption": consumption,
        "started_monotonic_ns": started,
        "deadline_monotonic_ns": started + AUTHORIZATION_LIFETIME_NS,
        "frames": [_wire_entry(frame, started + index + 1) for index, frame in enumerate(frames)],
        "parent_policy": {
            "arbitrary_executable_allowed": False,
            "authorization_consumption_parent_owned": True,
            "cleanup_and_child_wait_parent_owned": True,
            "counters_and_deadlines_parent_owned": True,
            "environment_inherited": False,
            "final_evidence_publication_parent_owned": True,
            "network_enabled": False,
            "paths_parent_owned": True,
            "process_and_socket_lifecycle_parent_owned": True,
            "rejected_evidence_retention_required": True,
            "worker_controlled_output_path_allowed": False,
        },
        "synthetic_lifecycle": {
            "cleanup_completed": True,
            "fake_processes_simulated": 1,
            "fake_socketpairs_simulated": 1,
            "physical_process_started": False,
            "physical_socket_created": False,
            "process_anomaly": False,
            "socket_anomaly": False,
        },
        "physical_action_counters": dict(_ZERO_PHYSICAL_ACTIONS),
    }


def _fixture_source() -> dict[str, JsonValue]:
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_custody_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_scope": "synthetic_inert_fixture_only",
        "real_authorization_present": False,
        "real_authorization_consumed": False,
        "real_worker_present": False,
        "physical_execution_reachable": False,
        "historical_records_rewritten": False,
        "schema_1_0_state": "permanently_disabled",
        "private_paths_published": False,
        "physical_action_counters": dict(_ZERO_PHYSICAL_ACTIONS),
    }
    content["fixture_id"] = canonical_identity(content)
    return content


def compile_custody_bridge_fixture_1_1(
    output_root: Path,
) -> tuple[Path, CustodyBridgeReplayResult]:
    """Publish deterministic valid/rejected fake-worker sessions and replay them."""
    validated_transcript = _synthetic_transcript(1, extra_action=False)
    rejected_transcript = _synthetic_transcript(2, extra_action=True)
    validated_record = build_synthetic_custody_session_record_1_1(validated_transcript)
    rejected_record = build_synthetic_custody_session_record_1_1(rejected_transcript)
    destination = publish_bundle(
        {
            "source/fixture.json": canonical_json(_fixture_source()),
            "source/protocol.json": canonical_json(custody_bridge_protocol_1_1()),
            "source/spec.json": canonical_json(custody_bridge_spec_1_1()),
            "sessions/validated-transcript.json": canonical_json(validated_transcript),
            "sessions/validated-record.json": canonical_json(validated_record),
            "sessions/rejected-transcript.json": canonical_json(rejected_transcript),
            "sessions/rejected-record.json": canonical_json(rejected_record),
        },
        output_root,
        name_prefix="localinferencelab-mlx-runtime-preflight-custody-synthetic-v1-1",
    )
    return destination, replay_custody_bridge_fixture_1_1(destination)


def _canonical_value(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def replay_custody_bridge_fixture_1_1(bundle: Path) -> CustodyBridgeReplayResult:
    """Replay the closed fake-worker fixture without process, socket, MLX, or Metal action."""
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/fixture.json",
        "source/protocol.json",
        "source/spec.json",
        "sessions/validated-transcript.json",
        "sessions/validated-record.json",
        "sessions/rejected-transcript.json",
        "sessions/rejected-record.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("custody bridge fixture has an invalid content set")
    source = _mapping(
        _canonical_value(files["source/fixture.json"], "custody fixture source"),
        "custody fixture source",
    )
    _verify_zero_physical_actions(
        source["physical_action_counters"],
        "custody fixture physical_action_counters",
    )
    if canonical_json(source) != canonical_json(_fixture_source()):
        raise ContractError("custody bridge fixture source drift")
    protocol = _mapping(
        _canonical_value(files["source/protocol.json"], "custody bridge protocol"),
        "custody bridge protocol",
    )
    spec = _mapping(
        _canonical_value(files["source/spec.json"], "custody bridge spec"),
        "custody bridge spec",
    )
    if canonical_json(protocol) != canonical_json(custody_bridge_protocol_1_1()) or canonical_json(
        spec
    ) != canonical_json(custody_bridge_spec_1_1()):
        raise ContractError("custody bridge protocol or specification drift")
    validated_transcript = _canonical_value(
        files["sessions/validated-transcript.json"],
        "validated custody transcript",
    )
    rejected_transcript = _canonical_value(
        files["sessions/rejected-transcript.json"],
        "rejected custody transcript",
    )
    validated_record = verify_synthetic_custody_session_record_1_1(
        _canonical_value(
            files["sessions/validated-record.json"],
            "validated custody record",
        )
    )
    rejected_record = verify_synthetic_custody_session_record_1_1(
        _canonical_value(
            files["sessions/rejected-record.json"],
            "rejected custody record",
        )
    )
    if (
        canonical_json(validated_record)
        != canonical_json(build_synthetic_custody_session_record_1_1(validated_transcript))
        or canonical_json(rejected_record)
        != canonical_json(build_synthetic_custody_session_record_1_1(rejected_transcript))
        or validated_record["outcome"] != "synthetic_sequence_validated_not_physical_evidence"
        or rejected_record["outcome"] != "rejected"
    ):
        raise ContractError("custody bridge fixture session reconstruction mismatch")
    validated_authorization = _mapping(
        _mapping(validated_record["transcript"], "validated transcript")["authorization"],
        "validated authorization",
    )
    rejected_authorization = _mapping(
        _mapping(rejected_record["transcript"], "rejected transcript")["authorization"],
        "rejected authorization",
    )
    validated_consumption = _mapping(
        _mapping(validated_record["transcript"], "validated transcript")["consumption"],
        "validated consumption",
    )
    rejected_consumption = _mapping(
        _mapping(rejected_record["transcript"], "rejected transcript")["consumption"],
        "rejected consumption",
    )
    verify_one_shot_consumptions_1_1(
        [
            (validated_authorization, validated_consumption),
            (rejected_authorization, rejected_consumption),
        ]
    )
    rejection = _mapping(rejected_record["rejection"], "rejected custody evidence")
    return CustodyBridgeReplayResult(
        bundle_root=content_root,
        protocol_id=cast("str", protocol["protocol_id"]),
        spec_id=cast("str", spec["spec_id"]),
        validated_record_id=cast("str", validated_record["record_id"]),
        rejected_record_id=cast("str", rejected_record["record_id"]),
        rejected_evidence_retained=cast("bool", rejection["rejected_evidence_retained"]),
        real_authorizations_created=0,
        real_authorizations_consumed=0,
        process_starts=0,
        socketpair_creations=0,
        mlx_imports=0,
        metal_queries=0,
        synchronizations=0,
        physical_actions=0,
    )
