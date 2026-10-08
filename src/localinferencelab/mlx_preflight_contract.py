"""Prospective schema-1.1 contract for a model-free MLX runtime preflight."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_canonical_json_file,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_qualification import (
    ELIGIBLE,
    build_qualification_record,
    historical_incompatible_qualification_package,
    qualification_spec,
    synthetic_eligible_qualification_package,
    verify_qualification_record,
)
from localinferencelab.mlx_runtime_target import EXPECTED_RUNTIME_TARGET_ANCHOR_ID

SCHEMA_VERSION = "1.1"
ACTION = "mlx_runtime_preflight_model_free"
AUTHORIZATION_LIFETIME_NS = 30_000_000_000
_CONTROL_LIMIT = 32
_DIGEST_LENGTH = 71
_ATTEMPTED_ACTIONS = (
    "default_device_metadata_query",
    "default_stream_metadata_query",
    "distribution_version_query",
    "isolated_runtime_closure_verification",
    "metal_availability_metadata_query",
    "mlx_core_import",
    "mlx_lm_import",
)
_CONDITIONAL_SYNCHRONIZATION_ACTION = "single_default_stream_synchronization_canary"
_UNRESOLVED_AUTHORIZATION_BLOCKERS = (
    "authoritative_authorization_acquisition_custody_unimplemented",
    "authoritative_authorization_current_expiry_observation_unimplemented",
    "authoritative_authorization_exclusive_consumption_and_nonreuse_custody_unimplemented",
    "independent_authorization_nonce_binding_unimplemented",
    "independent_output_root_identity_binding_unimplemented",
)
_FORBIDDEN_ACTIONS = (
    "arbitrary_command",
    "benchmark",
    "cache_construction_or_mutation",
    "cloud_or_spend",
    "generation",
    "inference",
    "model_discovery_or_download",
    "model_load",
    "package_installation_or_retrieval",
    "prompt_or_token_processing",
    "tensor_allocation_or_operation",
    "tokenizer_discovery_or_load",
)
_ZERO_ACTION_COUNTERS: dict[str, int] = {
    "authorization_creations": 0,
    "authorization_consumptions": 0,
    "backend_queries": 0,
    "benchmark_actions": 0,
    "cache_actions": 0,
    "cloud_actions": 0,
    "device_queries": 0,
    "distribution_queries": 0,
    "generation_requests": 0,
    "inference_requests": 0,
    "metal_queries": 0,
    "model_discoveries": 0,
    "model_loads": 0,
    "package_installations": 0,
    "package_network_requests": 0,
    "output_root_bindings": 0,
    "process_starts": 0,
    "prompt_actions": 0,
    "runtime_imports": 0,
    "runtime_closure_verifications": 0,
    "socket_creations": 0,
    "spend_actions": 0,
    "stream_queries": 0,
    "synchronizations": 0,
    "tensor_actions": 0,
    "tokenizer_discoveries": 0,
    "tokenizer_loads": 0,
    "worker_launches": 0,
}


@dataclass(frozen=True, slots=True)
class Schema11ReplayResult:
    """Verified summary of the deterministic schema-1.1 refusal fixture."""

    bundle_root: str
    protocol_id: str
    spec_id: str
    fixture_id: str
    synthetic_record_id: str
    historical_record_id: str
    synthetic_prerequisites_satisfied: bool
    historical_prerequisites_satisfied: bool
    authoritative_authorization_custody_supported: bool
    independent_output_root_binding_supported: bool
    independent_nonce_binding_supported: bool
    package_installations: int
    process_starts: int
    runtime_imports: int
    authorization_creations: int
    worker_launches: int
    physical_actions: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "protocol_id": self.protocol_id,
            "spec_id": self.spec_id,
            "fixture_id": self.fixture_id,
            "synthetic_record_id": self.synthetic_record_id,
            "historical_record_id": self.historical_record_id,
            "synthetic_prerequisites_satisfied": self.synthetic_prerequisites_satisfied,
            "historical_prerequisites_satisfied": self.historical_prerequisites_satisfied,
            "authoritative_authorization_custody_supported": (
                self.authoritative_authorization_custody_supported
            ),
            "independent_output_root_binding_supported": (
                self.independent_output_root_binding_supported
            ),
            "independent_nonce_binding_supported": self.independent_nonce_binding_supported,
            "package_installations": self.package_installations,
            "process_starts": self.process_starts,
            "runtime_imports": self.runtime_imports,
            "authorization_creations": self.authorization_creations,
            "worker_launches": self.worker_launches,
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


def _sha256(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _verify_zero_actions(value: JsonValue, label: str) -> None:
    counters = _mapping(value, label)
    _keys(counters, set(_ZERO_ACTION_COUNTERS), label)
    for name in sorted(_ZERO_ACTION_COUNTERS):
        if _integer(counters[name], f"{label}.{name}") != 0:
            raise ContractError(f"{label}.{name} must remain zero")


def runtime_preflight_protocol_1_1() -> dict[str, JsonValue]:
    """Return the prospective, unimplemented schema-1.1 protocol."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_protocol",
        "schema_version": SCHEMA_VERSION,
        "action": ACTION,
        "implementation_state": "prospective_unimplemented_unreachable",
        "transport": "future_parent_created_inherited_private_af_unix_socketpair",
        "framing": "uint32_be_length_then_canonical_json",
        "sequence": [
            "validate_committed_real_candidate_qualification",
            "require_authoritative_authorization_acquisition_expiry_and_consumption_custody",
            "require_independent_output_root_and_nonce_bindings",
            "verify_exact_isolated_runtime_closure",
            "future_parent_launch_and_identity",
            "future_authorization_consumption",
            "model_free_preflight_once",
            "strict_parent_result_validation",
            "shutdown_and_parent_wait",
        ],
        "attempts": 1,
        "retries": 0,
        "warmups": 0,
        "concurrency": 1,
        "runtime_selection": (
            "exact_target_anchor_pins_and_bytes_from_committed_qualification_anchor"
        ),
        "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        "base_allowed_physical_actions": list(_ATTEMPTED_ACTIONS),
        "conditional_physical_action": {
            "action": _CONDITIONAL_SYNCHRONIZATION_ACTION,
            "maximum": 1,
            "requires_distinct_explicit_one_shot_authorization": True,
        },
        "imports": {
            "allowed": ["mlx.core", "mlx_lm"],
            "pinned_to_isolated_runtime_closure": True,
            "import_before_authorization": False,
            "other_runtime_imports": "forbidden_except_transitive_bound_closure",
        },
        "bounded_metadata": [
            "distribution_versions",
            "default_device_representation",
            "default_stream_representation",
            "metal_is_available",
        ],
        "metadata_bounds": {
            "distribution_records": 2,
            "imported_module_records": 4096,
            "representation_utf8_bytes_each": 256,
            "values": "canonical_json_only",
        },
        "forbidden_actions": list(_FORBIDDEN_ACTIONS),
        "result_ledgers": {
            "attempted_actions": (
                "all attempted allowed_or_forbidden_actions_before_outcome_interpretation"
            ),
            "completed_actions": "only actions proven completed",
            "accepted_evidence": "only strict_parent_validated_completed_action_evidence",
            "ledgers_are_disjoint_claim_scopes": True,
        },
        "audit_hooks": {
            "role": "defense_in_depth_attempt_telemetry",
            "os_sandbox": False,
            "proof_of_non_occurrence": False,
        },
        "parent_owned_custody": {
            "authorization_consumption": True,
            "child_lifecycle_and_wait": True,
            "output_publication": "receipt_last_closed_bundle",
            "supplied_root": "retained_descriptor_no_follow_exact_byte_closure",
        },
        "worker_implementation_present": False,
        "execution_command_present": False,
    }
    content["protocol_id"] = canonical_identity(content)
    return content


def runtime_preflight_spec_1_1() -> dict[str, JsonValue]:
    """Return the canonical schema-1.1 model-free preflight contract."""
    protocol = runtime_preflight_protocol_1_1()
    qualification = qualification_spec()
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_spec",
        "schema_version": SCHEMA_VERSION,
        "action": ACTION,
        "protocol_id": protocol["protocol_id"],
        "qualification_spec_id": qualification["spec_id"],
        "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        "prerequisites": {
            "qualification": {
                "record_type": "mlx_runtime_qualification_record",
                "schema_version": "1.0",
                "candidate_kind": "reviewed_candidate",
                "decision": ELIGIBLE,
                "review_anchor_must_be_committed_in_qualification_spec": True,
                "separate_reviewed_anchor_required": True,
                "synthetic_fixture_accepted": False,
                "historical_schema_1_0_record_accepted": False,
                "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
                "exact_runtime_target_identity_required": True,
            },
            "runtime_target_observation": {
                "development_host_observation_accepted": False,
                "future_independent_observation_required": True,
                "self_attested_observation_accepted": False,
                "target_drift_accepted": False,
            },
            "authorization": {
                "authoritative_custody_state": "unimplemented_unavailable",
                "required_future_properties": [
                    "authoritative_acquisition",
                    "current_expiry_observation",
                    "exclusive_consumption",
                    "independent_nonce_binding",
                    "independent_output_root_binding",
                    "nonreuse_proof",
                    "one_shot",
                ],
                "maximum_future_lifetime_ns": AUTHORIZATION_LIFETIME_NS,
                "caller_supplied_claim": {
                    "record_type": "mlx_runtime_preflight_authorization_claim",
                    "schema_version": SCHEMA_VERSION,
                    "evidence_kind": "caller_supplied_structure_only",
                    "can_satisfy_authoritative_prerequisite": False,
                    "can_prove_current_freshness": False,
                    "can_prove_independent_bindings": False,
                    "can_prove_nonreuse_or_consumption": False,
                },
                "unresolved_blockers": list(_UNRESOLVED_AUTHORIZATION_BLOCKERS),
            },
        },
        "execution": {
            "reachable": False,
            "implementation_present": False,
            "worker_present": False,
            "authorization_creator_present": False,
            "authorization_consumer_present": False,
            "authoritative_authorization_prerequisite_satisfiable": False,
            "package_retrieval_or_installation_present": False,
            "public_or_internal_execute_entrypoint_present": False,
            "becomes_reachable_when_prerequisites_satisfied": False,
        },
        "future_physical_action_contract": {
            "base_allowed_actions": list(_ATTEMPTED_ACTIONS),
            "conditional_synchronization_action": _CONDITIONAL_SYNCHRONIZATION_ACTION,
            "forbidden_actions": list(_FORBIDDEN_ACTIONS),
            "model_activity": False,
        },
        "historical_schema_1_0": {
            "state": "permanently_disabled",
            "records_rewritten": False,
            "retry_authorized": False,
        },
        "claim_scope": (
            "prospective_contract_validation_and_refusal_only_no_physical_runtime_evidence"
        ),
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def verify_authorization_claim_1_1(value: JsonValue) -> dict[str, JsonValue]:
    """Validate a caller-supplied structure that is not authoritative authorization evidence."""
    claim = _mapping(value, "schema_1_1_authorization_claim")
    fields = {
        "action",
        "claim_id",
        "claimed_consumption_state",
        "claimed_decision",
        "claimed_expires_at_unix_ns",
        "claimed_issued_at_unix_ns",
        "claimed_nonce_sha256",
        "claimed_one_shot",
        "claimed_output_root_id",
        "claimed_validation_time_unix_ns",
        "evidence_kind",
        "protocol_id",
        "qualification_record_id",
        "qualification_review_anchor_id",
        "record_type",
        "schema_version",
        "spec_id",
        "synchronization_canary_claimed_authorized",
    }
    _keys(claim, fields, "schema_1_1_authorization_claim")
    spec = runtime_preflight_spec_1_1()
    if (
        claim["record_type"] != "mlx_runtime_preflight_authorization_claim"
        or claim["schema_version"] != SCHEMA_VERSION
        or claim["evidence_kind"] != "caller_supplied_structure_only"
        or claim["action"] != ACTION
        or claim["claimed_decision"] != "authorize_once"
        or claim["claimed_one_shot"] is not True
        or claim["claimed_consumption_state"] != "unconsumed"
        or claim["synchronization_canary_claimed_authorized"] is not False
        or claim["spec_id"] != spec["spec_id"]
        or claim["protocol_id"] != spec["protocol_id"]
    ):
        raise ContractError("unsupported schema-1.1 authorization claim")
    _sha256(
        claim["qualification_record_id"],
        "schema_1_1_authorization_claim.qualification_record_id",
    )
    _sha256(
        claim["qualification_review_anchor_id"],
        "schema_1_1_authorization_claim.qualification_review_anchor_id",
    )
    _sha256(
        claim["claimed_nonce_sha256"],
        "schema_1_1_authorization_claim.claimed_nonce_sha256",
    )
    _sha256(
        claim["claimed_output_root_id"],
        "schema_1_1_authorization_claim.claimed_output_root_id",
    )
    issued = _integer(
        claim["claimed_issued_at_unix_ns"],
        "schema_1_1_authorization_claim.claimed_issued_at_unix_ns",
        minimum=1,
    )
    validation_time = _integer(
        claim["claimed_validation_time_unix_ns"],
        "schema_1_1_authorization_claim.claimed_validation_time_unix_ns",
        minimum=issued,
    )
    expires = _integer(
        claim["claimed_expires_at_unix_ns"],
        "schema_1_1_authorization_claim.claimed_expires_at_unix_ns",
        minimum=validation_time + 1,
    )
    if expires - issued > AUTHORIZATION_LIFETIME_NS:
        raise ContractError("schema-1.1 authorization claim exceeds its structural lifetime bound")
    identity = _sha256(
        claim["claim_id"],
        "schema_1_1_authorization_claim.claim_id",
    )
    content = dict(claim)
    del content["claim_id"]
    if identity != canonical_identity(content):
        raise ContractError("schema-1.1 authorization claim identity mismatch")
    return dict(claim)


def load_authorization_claim_1_1(path: Path) -> dict[str, JsonValue]:
    """Load a canonical caller-supplied authorization claim."""
    return verify_authorization_claim_1_1(
        load_canonical_json_file(path, "schema-1.1 authorization claim")
    )


def _qualification_prerequisite_assessment(
    qualification_record: dict[str, JsonValue],
) -> tuple[list[JsonValue], list[str], str]:
    package = _mapping(
        qualification_record["qualification_package"],
        "schema-1.1 qualification package",
    )
    assessment = _mapping(
        qualification_record["assessment"],
        "schema-1.1 qualification assessment",
    )
    target = _mapping(
        package["target_environment"],
        "schema-1.1 qualification target environment",
    )
    review_anchor_id = _sha256(
        assessment["review_anchor_id"],
        "schema-1.1 qualification review anchor",
    )
    reviewed_anchors = cast(
        "list[JsonValue]",
        qualification_spec()["reviewed_candidate_anchors"],
    )
    checks: list[JsonValue] = []
    blockers: list[str] = []
    predicates = [
        (
            "qualification_candidate_is_reviewed_real_candidate",
            package["candidate_kind"] == "reviewed_candidate",
            "qualification_candidate_is_not_reviewed_real_candidate",
        ),
        (
            "qualification_decision_is_eligible",
            qualification_record["decision"] == ELIGIBLE,
            "qualification_decision_is_not_eligible",
        ),
        (
            "qualification_review_anchor_is_committed",
            review_anchor_id in reviewed_anchors,
            f"qualification_review_anchor_not_committed:{review_anchor_id}",
        ),
        (
            "qualification_runtime_target_anchor_is_exact",
            target.get("runtime_target_anchor_id") == EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
            "qualification_runtime_target_anchor_is_not_exact",
        ),
        (
            "qualification_schema_1_0_remains_disabled",
            qualification_record["schema_1_0_remains_permanently_disabled"] is True,
            "qualification_does_not_preserve_schema_1_0_disablement",
        ),
    ]
    for name, satisfied, blocker in predicates:
        checks.append({"name": name, "satisfied": satisfied})
        if not satisfied:
            blockers.append(blocker)
    return checks, blockers, review_anchor_id


def build_runtime_preflight_record_1_1(
    qualification_value: JsonValue,
    authorization_claim_value: JsonValue | None = None,
) -> dict[str, JsonValue]:
    """Build a deterministic contract/refusal record without physical runtime action."""
    qualification_record = verify_qualification_record(qualification_value)
    qualification_checks, blockers, review_anchor_id = _qualification_prerequisite_assessment(
        qualification_record
    )
    authorization_claim: dict[str, JsonValue] | None
    authorization_claim_checks: list[JsonValue]
    if authorization_claim_value is None:
        authorization_claim = None
        authorization_claim_checks = [
            {
                "name": "caller_supplied_authorization_claim_structure_present",
                "satisfied": False,
            }
        ]
        blockers.append("authorization_claim_structure_missing")
    else:
        authorization_claim = verify_authorization_claim_1_1(authorization_claim_value)
        bindings = [
            (
                "authorization_claim_names_qualification_record",
                authorization_claim["qualification_record_id"] == qualification_record["record_id"],
                "authorization_claim_qualification_record_mismatch",
            ),
            (
                "authorization_claim_names_review_anchor",
                authorization_claim["qualification_review_anchor_id"] == review_anchor_id,
                "authorization_claim_review_anchor_mismatch",
            ),
        ]
        authorization_claim_checks = [
            {
                "name": "caller_supplied_authorization_claim_structure_present",
                "satisfied": True,
            }
        ]
        for name, satisfied, blocker in bindings:
            authorization_claim_checks.append({"name": name, "satisfied": satisfied})
            if not satisfied:
                blockers.append(blocker)
    blockers.extend(_UNRESOLVED_AUTHORIZATION_BLOCKERS)
    sorted_blockers = sorted(set(blockers))
    spec = runtime_preflight_spec_1_1()
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_contract_record",
        "schema_version": SCHEMA_VERSION,
        "spec_id": spec["spec_id"],
        "protocol_id": spec["protocol_id"],
        "qualification_record": qualification_record,
        "qualification_record_id": qualification_record["record_id"],
        "qualification_review_anchor_id": review_anchor_id,
        "authorization_claim": authorization_claim,
        "authorization_claim_id": (
            None if authorization_claim is None else authorization_claim["claim_id"]
        ),
        "prerequisite_assessment": {
            "qualification_checks": qualification_checks,
            "authorization_claim_checks": authorization_claim_checks,
            "authoritative_authorization_custody_supported": False,
            "independent_output_root_binding_supported": False,
            "independent_nonce_binding_supported": False,
            "blockers": cast("list[JsonValue]", sorted_blockers),
            "prerequisites_satisfied": False,
        },
        "execution_disposition": {
            "state": "disabled_unreachable_contract_only",
            "execution_reachable": False,
            "worker_implementation_present": False,
            "execute_entrypoint_present": False,
            "prerequisites_do_not_unlock_execution": True,
            "authoritative_authorization_prerequisite_satisfiable": False,
        },
        "evidence_ledgers": {
            "attempted_actions": [],
            "completed_actions": [],
            "accepted_evidence": [],
        },
        "schema_1_0_state": "permanently_disabled",
        "historical_records_rewritten": False,
        "private_raw_evidence_published": False,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    record["record_id"] = canonical_identity(record)
    return record


def verify_runtime_preflight_record_1_1(value: JsonValue) -> dict[str, JsonValue]:
    """Reconstruct a schema-1.1 contract record and reject forged readiness claims."""
    record = _mapping(value, "schema_1_1_runtime_preflight_record")
    fields = {
        "authorization_claim",
        "authorization_claim_id",
        "evidence_ledgers",
        "execution_disposition",
        "historical_records_rewritten",
        "prerequisite_assessment",
        "private_raw_evidence_published",
        "protocol_id",
        "qualification_record",
        "qualification_record_id",
        "qualification_review_anchor_id",
        "record_id",
        "record_type",
        "schema_1_0_state",
        "schema_version",
        "spec_id",
        "static_action_counters",
    }
    _keys(record, fields, "schema_1_1_runtime_preflight_record")
    spec = runtime_preflight_spec_1_1()
    if (
        record["record_type"] != "mlx_runtime_preflight_contract_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["spec_id"] != spec["spec_id"]
        or record["protocol_id"] != spec["protocol_id"]
        or record["schema_1_0_state"] != "permanently_disabled"
        or record["historical_records_rewritten"] is not False
        or record["private_raw_evidence_published"] is not False
    ):
        raise ContractError("unsupported schema-1.1 runtime preflight contract record")
    _verify_zero_actions(
        record["static_action_counters"],
        "schema_1_1_runtime_preflight_record.static_action_counters",
    )
    ledgers = _mapping(record["evidence_ledgers"], "schema-1.1 evidence ledgers")
    _keys(
        ledgers,
        {"accepted_evidence", "attempted_actions", "completed_actions"},
        "schema-1.1 evidence ledgers",
    )
    for name in ("attempted_actions", "completed_actions", "accepted_evidence"):
        if _array(ledgers[name], f"schema-1.1 evidence ledgers.{name}") != []:
            raise ContractError(f"schema-1.1 evidence ledgers.{name} must remain empty")
    assessment = _mapping(record["prerequisite_assessment"], "schema-1.1 assessment")
    blockers = {
        _text(item, f"schema-1.1 assessment.blockers[{index}]")
        for index, item in enumerate(_array(assessment["blockers"], "schema-1.1 blockers"))
    }
    if (
        assessment["prerequisites_satisfied"] is not False
        or assessment["authoritative_authorization_custody_supported"] is not False
        or assessment["independent_output_root_binding_supported"] is not False
        or assessment["independent_nonce_binding_supported"] is not False
        or not set(_UNRESOLVED_AUTHORIZATION_BLOCKERS).issubset(blockers)
    ):
        raise ContractError(
            "schema-1.1 authoritative authorization prerequisites remain unresolved"
        )
    identity = _sha256(record["record_id"], "schema_1_1_runtime_preflight_record.record_id")
    content = dict(record)
    del content["record_id"]
    if identity != canonical_identity(content):
        raise ContractError("schema-1.1 runtime preflight record identity mismatch")
    authorization_claim = record["authorization_claim"]
    rebuilt = build_runtime_preflight_record_1_1(
        record["qualification_record"],
        authorization_claim,
    )
    if canonical_json(rebuilt) != canonical_json(record):
        raise ContractError("schema-1.1 runtime preflight record reconstruction mismatch")
    return dict(record)


def write_runtime_preflight_record_1_1(path: Path, value: JsonValue) -> None:
    """Write one verified record with exclusive no-follow creation."""
    record = verify_runtime_preflight_record_1_1(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        data = canonical_json(record)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_runtime_preflight_record_1_1(path: Path) -> dict[str, JsonValue]:
    """Load one canonical schema-1.1 contract record."""
    return verify_runtime_preflight_record_1_1(
        load_canonical_json_file(path, "schema-1.1 runtime preflight contract record")
    )


def inspect_runtime_preflight_record_1_1(value: JsonValue) -> dict[str, JsonValue]:
    """Return a bounded process-free readiness/refusal projection."""
    record = verify_runtime_preflight_record_1_1(value)
    assessment = _mapping(record["prerequisite_assessment"], "schema-1.1 assessment")
    return {
        "record_id": record["record_id"],
        "spec_id": record["spec_id"],
        "protocol_id": record["protocol_id"],
        "qualification_record_id": record["qualification_record_id"],
        "qualification_review_anchor_id": record["qualification_review_anchor_id"],
        "authorization_claim_id": record["authorization_claim_id"],
        "prerequisites_satisfied": assessment["prerequisites_satisfied"],
        "blockers": assessment["blockers"],
        "authoritative_authorization_custody_supported": False,
        "independent_output_root_binding_supported": False,
        "independent_nonce_binding_supported": False,
        "execution_state": "disabled_unreachable_contract_only",
        "schema_1_0_state": "permanently_disabled",
        "private_raw_evidence_published": False,
        "attempted_actions": [],
        "completed_actions": [],
        "accepted_evidence": [],
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }


def runtime_preflight_capability_report_1_1() -> dict[str, JsonValue]:
    """Report the pure schema-1.1 contract surface."""
    spec = runtime_preflight_spec_1_1()
    return {
        "record_type": "mlx_runtime_preflight_capability_report",
        "schema_version": SCHEMA_VERSION,
        "action": ACTION,
        "spec_id": spec["spec_id"],
        "protocol_id": spec["protocol_id"],
        "execution_reachable": False,
        "execute_command_present": False,
        "worker_implementation_present": False,
        "authorization_creator_present": False,
        "authorization_consumer_present": False,
        "authoritative_authorization_custody_present": False,
        "prerequisites_satisfiable": False,
        "unresolved_authorization_blockers": list(_UNRESOLVED_AUTHORIZATION_BLOCKERS),
        "pure_commands": [
            "mlx runtime-preflight-1-1-capability-report",
            "mlx runtime-preflight-1-1-fixture-compile",
            "mlx runtime-preflight-1-1-fixture-replay",
            "mlx runtime-preflight-1-1-protocol",
            "mlx runtime-preflight-1-1-record-create",
            "mlx runtime-preflight-1-1-record-inspect",
            "mlx runtime-preflight-1-1-record-verify",
            "mlx runtime-preflight-1-1-spec",
        ],
        "physical_actions": 0,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }


def _fixture_source() -> dict[str, JsonValue]:
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_preflight_contract_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_and_historical_refusal_contract_evidence",
        "real_candidate_evidence_present": False,
        "authoritative_authorization_custody_present": False,
        "authorization_claim_present": False,
        "independent_output_root_binding_present": False,
        "independent_nonce_binding_present": False,
        "private_raw_evidence_committed": False,
        "private_raw_evidence_path_disclosed": False,
        "historical_records_rewritten": False,
        "schema_1_0_state": "permanently_disabled",
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    content["fixture_id"] = canonical_identity(content)
    return content


def compile_runtime_preflight_fixture_1_1(
    output_root: Path,
) -> tuple[Path, Schema11ReplayResult]:
    """Publish deterministic schema-1.1 refusal records and replay them."""
    synthetic_qualification = build_qualification_record(synthetic_eligible_qualification_package())
    historical_qualification = build_qualification_record(
        historical_incompatible_qualification_package()
    )
    synthetic_record = build_runtime_preflight_record_1_1(synthetic_qualification)
    historical_record = build_runtime_preflight_record_1_1(historical_qualification)
    destination = publish_bundle(
        {
            "source/fixture.json": canonical_json(_fixture_source()),
            "source/protocol.json": canonical_json(runtime_preflight_protocol_1_1()),
            "source/spec.json": canonical_json(runtime_preflight_spec_1_1()),
            "qualification/synthetic-eligible-record.json": canonical_json(synthetic_qualification),
            "qualification/historical-incompatible-record.json": canonical_json(
                historical_qualification
            ),
            "records/synthetic-refusal-record.json": canonical_json(synthetic_record),
            "records/historical-refusal-record.json": canonical_json(historical_record),
        },
        output_root,
        name_prefix="localinferencelab-mlx-runtime-preflight-contract-synthetic-v1-1",
    )
    return destination, replay_runtime_preflight_fixture_1_1(destination)


def _canonical_value(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def replay_runtime_preflight_fixture_1_1(bundle: Path) -> Schema11ReplayResult:
    """Reconstruct the fixture process-free and require both inputs to refuse."""
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/fixture.json",
        "source/protocol.json",
        "source/spec.json",
        "qualification/synthetic-eligible-record.json",
        "qualification/historical-incompatible-record.json",
        "records/synthetic-refusal-record.json",
        "records/historical-refusal-record.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("schema-1.1 runtime preflight fixture has an invalid content set")
    source = _canonical_value(files["source/fixture.json"], "schema-1.1 fixture source")
    if canonical_json(source) != canonical_json(_fixture_source()):
        raise ContractError("schema-1.1 fixture source or zero-action claims drift")
    protocol = _mapping(
        _canonical_value(files["source/protocol.json"], "schema-1.1 protocol"),
        "schema-1.1 protocol",
    )
    spec = _mapping(
        _canonical_value(files["source/spec.json"], "schema-1.1 spec"),
        "schema-1.1 spec",
    )
    if canonical_json(protocol) != canonical_json(
        runtime_preflight_protocol_1_1()
    ) or canonical_json(spec) != canonical_json(runtime_preflight_spec_1_1()):
        raise ContractError("schema-1.1 fixture protocol or specification drift")
    synthetic_qualification = verify_qualification_record(
        _canonical_value(
            files["qualification/synthetic-eligible-record.json"],
            "synthetic qualification record",
        )
    )
    historical_qualification = verify_qualification_record(
        _canonical_value(
            files["qualification/historical-incompatible-record.json"],
            "historical qualification record",
        )
    )
    synthetic_record = verify_runtime_preflight_record_1_1(
        _canonical_value(
            files["records/synthetic-refusal-record.json"],
            "synthetic schema-1.1 refusal record",
        )
    )
    historical_record = verify_runtime_preflight_record_1_1(
        _canonical_value(
            files["records/historical-refusal-record.json"],
            "historical schema-1.1 refusal record",
        )
    )
    expected_synthetic = build_runtime_preflight_record_1_1(synthetic_qualification)
    expected_historical = build_runtime_preflight_record_1_1(historical_qualification)
    if canonical_json(synthetic_record) != canonical_json(expected_synthetic) or canonical_json(
        historical_record
    ) != canonical_json(expected_historical):
        raise ContractError("schema-1.1 fixture record reconstruction mismatch")
    synthetic_assessment = _mapping(
        synthetic_record["prerequisite_assessment"],
        "synthetic prerequisite assessment",
    )
    historical_assessment = _mapping(
        historical_record["prerequisite_assessment"],
        "historical prerequisite assessment",
    )
    if (
        synthetic_assessment["prerequisites_satisfied"] is not False
        or historical_assessment["prerequisites_satisfied"] is not False
    ):
        raise ContractError("schema-1.1 fixture must not satisfy physical prerequisites")
    return Schema11ReplayResult(
        bundle_root=content_root,
        protocol_id=cast("str", protocol["protocol_id"]),
        spec_id=cast("str", spec["spec_id"]),
        fixture_id=cast("str", _mapping(source, "schema-1.1 fixture source")["fixture_id"]),
        synthetic_record_id=cast("str", synthetic_record["record_id"]),
        historical_record_id=cast("str", historical_record["record_id"]),
        synthetic_prerequisites_satisfied=False,
        historical_prerequisites_satisfied=False,
        authoritative_authorization_custody_supported=False,
        independent_output_root_binding_supported=False,
        independent_nonce_binding_supported=False,
        package_installations=0,
        process_starts=0,
        runtime_imports=0,
        authorization_creations=0,
        worker_launches=0,
        physical_actions=0,
    )
