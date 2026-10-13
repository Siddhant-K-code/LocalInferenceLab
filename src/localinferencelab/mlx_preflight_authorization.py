"""Offline prospective requests; no production authority or acquisition capability."""

from __future__ import annotations

from typing import NoReturn, cast

from localinferencelab.canonical import (
    SHA256_ID_LENGTH,
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_json_bytes,
)
from localinferencelab.mlx_preflight_custody import ACTION, custody_bridge_spec_1_1
from localinferencelab.mlx_preflight_protocol import expected_frame
from localinferencelab.mlx_preflight_worker import (
    ACTIONS,
    ENVIRONMENT,
    MAX_LIFETIME_NS,
    PROTOCOL_ID,
    WorkerError,
    validate_hello,
)
from localinferencelab.mlx_preflight_worker import (
    SCHEMA_VERSION as WORKER_SCHEMA_VERSION,
)
from localinferencelab.mlx_qualification_publication import (
    COMMITTED_MANIFEST_PATH,
    EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID,
)
from localinferencelab.mlx_wheel_custody import load_wheel_evidence_manifest

SCHEMA_VERSION = "1.0"
MAX_REQUEST_BYTES = 32_768
_MAX_OBJECT_ID = (1 << 64) - 1
_MAX_PID = 2_147_483_647
_TOKEN_LENGTH = 64
_ROOT_ROLES = ("custody", "output", "runtime_container")
_REFERENCE_FIELDS = (
    "fresh_wheel_verification_id",
    "installation_custody_id",
    "stdlib_closure_id",
    "native_loader_closure_id",
    "framework_closure_id",
)
_SOURCE_IDS = {
    "contract": "sha256:aa9920736f4ad6f380e6bf21832daba837c1c5a8debe1e6562fd7d105c972bd6",
    "custody": "sha256:fa22a202b4468231296e01a610a7b4d6a1bc3a409497ccf3e1151ec9a47f7b13",
    "ledger": "sha256:af58dd042d0c64047bb1318c035511a9cf24c50765db95bba95836e8e7a1c46a",
    "attempt": "sha256:e4072e4127c5f3b8dbf8392795da30fc1419009c8fb24e30bd0eb0e25c33962e",
    "execution": "sha256:723b4d37e371a4c2be0ebf2bcc25f597cf703a1630731bd4b9d19adb27d48248",
    "protocol": "sha256:29b1802415f685827c9acb59c4a21def315841a0137f221fd91936b8d1aa0b69",
    "report": "sha256:c462d1826c7866a5f9282e22963012de5c3428522183ba3178f7d6a91ad08b14",
    "worker": "sha256:063f357df20b2b58be6b1b8b68c6321a33fdd15ba169e3c6173838524fee694a",
}
_PREREQUISITES = (
    "independently_reviewed_production_authority_and_approval_policy",
    "independently_retained_trust_root",
    "reviewed_authority_material_custody",
    "independent_trusted_time_and_freshness_custody",
    "separate_explicit_user_provisioning_approval",
    "fresh_actual_wheel_bytes_and_installation_custody",
    "exact_environment_native_loader_and_framework_custody",
    "independent_host_process_and_root_observation_custody",
    "independent_schema_1_2_source_and_protocol_runtime_review",
    "reviewed_exact_environment_os_enforcement_and_child_identity",
    "fresh_explicit_user_one_attempt_runtime_approval",
    "reviewed_schema_1_2_production_ledger_binding_and_dispatch_adapter",
    "independent_physical_evidence_acceptance_verifier",
)
_CONTEXT_FIELDS = {
    "record_type",
    "schema_version",
    "evidence_scope",
    "candidate_bindings",
    "source_bindings",
    "policy_id",
    "parent_process",
    "host_provenance_claim_id",
    "roots",
    "execution_root",
    "environment",
    "session",
}
_REQUEST_FIELDS = {
    "record_type",
    "schema_version",
    "action",
    "decision",
    "spec_id",
    "context",
    "requested_validity",
    "unapproved_prerequisites",
    "attempt_id",
    "hello",
    "request_id",
}


def _object(value: JsonValue, fields: set[str], label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict) or value.keys() != fields:
        raise ContractError(f"{label}: exact object fields required")
    return value


def _integer(value: JsonValue, label: str, *, minimum: int = 0, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ContractError(f"{label}: bounded exact integer required")
    return value


def _digest(value: JsonValue, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != SHA256_ID_LENGTH
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ContractError(f"{label}: lowercase prefixed SHA-256 required")
    return value


def _exact(value: JsonValue, expected: JsonValue, label: str) -> None:
    if canonical_json(value) != canonical_json(expected):
        raise ContractError(f"{label}: pinned contract mismatch")


def _root(value: JsonValue, mode: int) -> tuple[int, int, int]:
    root = _object(value, {"device", "inode", "owner", "mode"}, "root")
    device = _integer(root["device"], "root.device", maximum=_MAX_OBJECT_ID)
    inode = _integer(root["inode"], "root.inode", minimum=1, maximum=_MAX_OBJECT_ID)
    owner = _integer(root["owner"], "root.owner", maximum=_MAX_OBJECT_ID)
    _integer(root["mode"], "root.mode", maximum=0o777)
    _exact(root["mode"], mode, "root.mode")
    return device, inode, owner


def authorization_request_spec() -> dict[str, JsonValue]:
    """Bind static candidates and unmet requirements, never an approval or host observation."""
    bridge = custody_bridge_spec_1_1()
    manifest = load_wheel_evidence_manifest(
        COMMITTED_MANIFEST_PATH, EXPECTED_WHEEL_EVIDENCE_MANIFEST_ID
    )
    distributions = manifest["distributions"]
    if not isinstance(distributions, list):
        raise ContractError("committed distribution list unavailable")
    expected_distributions: list[JsonValue] = []
    for distribution in distributions:
        if not isinstance(distribution, dict) or not isinstance(distribution["metadata"], dict):
            raise ContractError("committed distribution metadata unavailable")
        expected_distributions.append(
            {
                "name": distribution["name"],
                "version": distribution["version"],
                "metadata_sha256": distribution["metadata"]["sha256"],
            }
        )
    policy: dict[str, JsonValue] = {
        "action": ACTION,
        "actions": list(ACTIONS),
        "action_limits": dict.fromkeys(ACTIONS, 1),
        "forbidden_actions": bridge["forbidden_actions"],
        "attempts": 1,
        "retries": 0,
        "warmups": 0,
        "concurrency": 1,
        "maximum_lifetime_ns": MAX_LIFETIME_NS,
        "environment": dict(ENVIRONMENT),
        "inherited_environment_allowed": False,
        "provisioning_authorized_by_runtime_request": False,
        "durable_consumption": {
            "production_adapter_state": "unavailable",
            "merged_api_scope": "synthetic_only_consume_once_and_dispatch_synthetic_once",
            "intent_fsynced_before_dispatch": True,
            "object_issuer_process_store_inode_and_attempt_binding_required": True,
            "claim_terminal_before_validation": True,
            "no_refund_remint_or_automatic_retry": True,
            "parent_retirement_is_raw_ledger_revocation": False,
            "serialized_journal_or_receipt_is_permission": False,
        },
        "root_policy": {
            "private_root_roles": list(_ROOT_ROLES),
            "private_mode": 0o700,
            "execution_parent_role": "runtime_container",
            "execution_relative_name": "preflight-runtime",
            "execution_mode": 0o555,
            "independent_descriptor_and_nesting_observation_required": True,
        },
        "native_enforcement": {
            "reviewed_contract_id": None,
            "metal_compatibility": "untested",
            "native_network_process_and_filesystem_enforcement_required": True,
            "native_model_cache_and_tensor_nonaction_evidence_required": True,
            "audit_hooks_or_offline_environment_is_enforcement": False,
            "benign_probe_receipt_is_production_enforcement": False,
        },
    }
    policy["policy_id"] = canonical_identity(policy)
    spec: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_authorization_request_spec",
        "schema_version": SCHEMA_VERSION,
        "request_fields": cast("list[JsonValue]", sorted(_REQUEST_FIELDS)),
        "context_fields": cast("list[JsonValue]", sorted(_CONTEXT_FIELDS)),
        "environment_reference_fields": list(_REFERENCE_FIELDS),
        "evidence_scopes": ["caller_supplied_unverified", "synthetic_non_promotable"],
        "bounds": {
            "maximum_request_bytes": MAX_REQUEST_BYTES,
            "maximum_object_and_time_integer": _MAX_OBJECT_ID,
            "maximum_pid": _MAX_PID,
            "exact_integer_types_required": True,
        },
        "identity_rules": {
            "request": "canonical_request_without_request_id",
            "attempt": "canonical_spec_id_context_and_requested_validity",
            "challenge": "unprefixed_attempt_digest",
            "session": "canonical_challenge_and_nonce",
            "identity_proves_authenticity": False,
        },
        "worker_schema_version": WORKER_SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "source_bindings": dict(_SOURCE_IDS),
        "candidate_bindings": bridge["identity_bindings"],
        "runtime_target": bridge["runtime_target"],
        "expected_distributions": expected_distributions,
        "wheel_artifact_count": 34,
        "wheel_total_size_bytes": 70_700_189,
        "policy": policy,
        "unapproved_prerequisites": dict.fromkeys(_PREREQUISITES, "unavailable"),
        "trust_policy": {
            "production_authority_id": None,
            "retained_trust_root_id": None,
            "trusted_time_policy_id": None,
            "approval_material_custody_policy_id": None,
            "positive_authority_verification_implemented": False,
            "static_review_grants_runtime_authority": False,
            "request_self_hash_grants_runtime_authority": False,
        },
        "claim_scope": "offline_request_structure_only_no_authenticity_or_permission",
    }
    spec["spec_id"] = canonical_identity(spec)
    return spec


def _validate_context(
    value: JsonValue, spec: dict[str, JsonValue], *, schema_version: str = SCHEMA_VERSION
) -> dict[str, JsonValue]:
    context = _object(value, _CONTEXT_FIELDS, "context")
    _exact(context["record_type"], "mlx_preflight_prospective_attempt_context", "context.type")
    _exact(context["schema_version"], schema_version, "context.version")
    scope = context["evidence_scope"]
    if type(scope) is not str or scope not in {
        "caller_supplied_unverified",
        "synthetic_non_promotable",
    }:
        raise ContractError("context.scope: no authentic or approved scope is supported")
    _exact(context["candidate_bindings"], spec["candidate_bindings"], "candidate bindings")
    _exact(context["source_bindings"], spec["source_bindings"], "source bindings")
    policy = spec["policy"]
    if not isinstance(policy, dict):
        raise ContractError("request policy unavailable")
    _exact(context["policy_id"], policy["policy_id"], "policy identity")
    process = _object(context["parent_process"], {"pid", "process_instance_id"}, "parent process")
    _integer(process["pid"], "parent pid", minimum=1, maximum=_MAX_PID)
    _digest(process["process_instance_id"], "parent process instance")
    if context["host_provenance_claim_id"] is not None:
        _digest(context["host_provenance_claim_id"], "host provenance claim")

    roots = _object(context["roots"], set(_ROOT_ROLES), "roots")
    identities = [_root(roots[role], 0o700) for role in _ROOT_ROLES]
    execution = _object(
        context["execution_root"],
        {"parent_role", "relative_name", "object", "tree_id"},
        "execution root",
    )
    _exact(execution["parent_role"], "runtime_container", "execution parent role")
    _exact(execution["relative_name"], "preflight-runtime", "execution relative name")
    execution_identity = _root(execution["object"], 0o555)
    if len({item[:2] for item in (*identities, execution_identity)}) != len(_ROOT_ROLES) + 1:
        raise ContractError("root objects must be distinct by device and inode")
    if execution_identity[0] != identities[-1][0]:
        raise ContractError("fixed nested execution root must share container device")
    if len({item[2] for item in (*identities, execution_identity)}) != 1:
        raise ContractError("all proposed roots must share parent ownership")
    _digest(execution["tree_id"], "execution tree")

    environment = _object(
        context["environment"],
        {
            "interpreter_sha256",
            "runtime_manifest_id",
            "distributions",
            "import_files",
            *_REFERENCE_FIELDS,
        },
        "environment",
    )
    target = spec["runtime_target"]
    if not isinstance(target, dict) or not isinstance(target["interpreter"], dict):
        raise ContractError("runtime target unavailable")
    _exact(
        environment["interpreter_sha256"],
        target["interpreter"]["executable_sha256"],
        "exact target interpreter",
    )
    _digest(environment["runtime_manifest_id"], "runtime manifest")
    _exact(environment["distributions"], spec["expected_distributions"], "distribution closure")
    for field in _REFERENCE_FIELDS:
        if environment[field] is not None:
            _digest(environment[field], field)
    imports = _object(environment["import_files"], {"mlx.core", "mlx_lm"}, "import files")
    for module, relative in (
        ("mlx.core", "mlx/core.cpython-313-darwin.so"),
        ("mlx_lm", "mlx_lm/__init__.py"),
    ):
        item = _object(imports[module], {"relative_file", "sha256"}, "import file")
        _exact(item["relative_file"], relative, "exact import path")
        _digest(item["sha256"], "import file identity")
    session = _object(
        context["session"],
        {"started_monotonic_ns", "deadline_monotonic_ns", "nonce"},
        "session",
    )
    started = _integer(
        session["started_monotonic_ns"], "session start", minimum=1, maximum=_MAX_OBJECT_ID
    )
    deadline = _integer(
        session["deadline_monotonic_ns"], "session deadline", minimum=1, maximum=_MAX_OBJECT_ID
    )
    if not 0 < deadline - started <= MAX_LIFETIME_NS:
        raise ContractError("session lifetime exceeds one bounded attempt")
    nonce = session["nonce"]
    if (
        type(nonce) is not str
        or len(nonce) != _TOKEN_LENGTH
        or any(character not in "0123456789abcdef" for character in nonce)
    ):
        raise ContractError("session nonce: exact lowercase 32-byte token required")
    return context


def _validity(value: JsonValue, context: dict[str, JsonValue]) -> dict[str, JsonValue]:
    validity = _object(
        value, {"requested_at_unix_ns", "not_before_unix_ns", "expires_at_unix_ns"}, "validity"
    )
    values = {
        name: _integer(item, name, minimum=1, maximum=_MAX_OBJECT_ID)
        for name, item in validity.items()
    }
    requested, not_before, expires = (
        values[name]
        for name in ("requested_at_unix_ns", "not_before_unix_ns", "expires_at_unix_ns")
    )
    if not requested <= not_before < expires or expires - requested > MAX_LIFETIME_NS:
        raise ContractError("requested validity must be ordered and at most 30 seconds")
    session = context["session"]
    if not isinstance(session, dict):
        raise ContractError("session unavailable")
    started = _integer(session["started_monotonic_ns"], "session start", maximum=_MAX_OBJECT_ID)
    deadline = _integer(session["deadline_monotonic_ns"], "deadline", maximum=_MAX_OBJECT_ID)
    if expires - not_before != deadline - started:
        raise ContractError("proposed wall and monotonic lifetimes must agree")
    return validity


def _hello(
    context: dict[str, JsonValue], validity: dict[str, JsonValue], spec_id: JsonValue
) -> tuple[str, dict[str, JsonValue]]:
    attempt_id = canonical_identity(
        {"spec_id": spec_id, "context": context, "requested_validity": validity}
    )
    session, environment, execution, sources = (
        context[name] for name in ("session", "environment", "execution_root", "source_bindings")
    )
    session = _object(
        session, {"started_monotonic_ns", "deadline_monotonic_ns", "nonce"}, "session"
    )
    if not isinstance(environment, dict) or not isinstance(execution, dict):
        raise ContractError("attempt environment unavailable")
    if not isinstance(sources, dict) or not isinstance(execution["object"], dict):
        raise ContractError("attempt sources or root unavailable")
    hello = expected_frame(
        "hello",
        0,
        canonical_identity({"challenge": attempt_id[7:], "nonce": session["nonce"]}),
        challenge=attempt_id[7:],
        nonce=session["nonce"],
        deadline_ns=session["deadline_monotonic_ns"],
        interpreter_sha256=environment["interpreter_sha256"],
        runtime_root={field: execution["object"][field] for field in ("device", "inode", "mode")},
        distributions=environment["distributions"],
        worker_program_id=sources["worker"],
        import_files=environment["import_files"],
    )
    try:
        validate_hello(hello)
    except WorkerError as error:
        raise ContractError("prospective hello violates schema-1.2 worker contract") from error
    return attempt_id, hello


def _verify(
    value: JsonValue, spec: dict[str, JsonValue], *, schema_version: str = SCHEMA_VERSION
) -> dict[str, JsonValue]:
    request = _object(value, _REQUEST_FIELDS, "authorization request")
    for field, expected in (
        ("record_type", "mlx_preflight_authorization_request"),
        ("schema_version", schema_version),
        ("action", ACTION),
        ("decision", "request_independent_review_only"),
        ("spec_id", spec["spec_id"]),
        ("unapproved_prerequisites", spec["unapproved_prerequisites"]),
    ):
        _exact(request[field], expected, field)
    context = _validate_context(request["context"], spec, schema_version=schema_version)
    validity = _validity(request["requested_validity"], context)
    attempt_id, hello = _hello(context, validity, spec["spec_id"])
    _exact(request["attempt_id"], attempt_id, "attempt identity")
    _exact(request["hello"], hello, "prospective hello")
    content = {name: item for name, item in request.items() if name != "request_id"}
    _exact(
        _digest(request["request_id"], "request identity"), canonical_identity(content), "request"
    )
    return request


def _verify_bytes(
    data: bytes, spec: dict[str, JsonValue], *, schema_version: str = SCHEMA_VERSION
) -> dict[str, JsonValue]:
    if type(data) is not bytes or not 0 < len(data) <= MAX_REQUEST_BYTES:
        raise ContractError("authorization request exceeds canonical byte bound")
    try:
        value = load_json_bytes(data)
    except RecursionError as error:
        raise ContractError("authorization request nesting exceeds parser bound") from error
    if canonical_json(value) != data:
        raise ContractError("authorization request must use canonical JSON bytes")
    return _verify(value, spec, schema_version=schema_version)


def verify_authorization_request_bytes(data: bytes) -> dict[str, JsonValue]:
    """Validate bounded canonical bytes and content bindings, not authenticity or authority."""
    return _verify_bytes(data, authorization_request_spec())


def verify_authorization_request_structure(value: JsonValue) -> dict[str, JsonValue]:
    """Return a detached structure-only copy; a matching self-hash never grants permission."""
    return verify_authorization_request_bytes(canonical_json(value))


def build_authorization_request(
    context: JsonValue, requested_validity: JsonValue
) -> dict[str, JsonValue]:
    """Build a proposal from supplied claims without observing roots, time or runtime bytes."""
    return _build_request(context, requested_validity, authorization_request_spec())


def _build_request(
    context: JsonValue,
    requested_validity: JsonValue,
    spec: dict[str, JsonValue],
    *,
    schema_version: str = SCHEMA_VERSION,
) -> dict[str, JsonValue]:
    context = _validate_context(context, spec, schema_version=schema_version)
    validity = _validity(requested_validity, context)
    attempt_id, hello = _hello(context, validity, spec["spec_id"])
    request: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_authorization_request",
        "schema_version": schema_version,
        "action": ACTION,
        "decision": "request_independent_review_only",
        "spec_id": spec["spec_id"],
        "context": context,
        "requested_validity": validity,
        "unapproved_prerequisites": spec["unapproved_prerequisites"],
        "attempt_id": attempt_id,
        "hello": hello,
    }
    request["request_id"] = canonical_identity(request)
    return _verify_bytes(canonical_json(request), spec, schema_version=schema_version)


def _claimed_window(request: dict[str, JsonValue], clock: JsonValue) -> str:
    if clock is None:
        return "unavailable_no_current_time_observation"
    sample = _object(clock, {"unix_ns", "monotonic_ns"}, "claimed clock")
    unix = _integer(sample["unix_ns"], "claimed unix time", minimum=1, maximum=_MAX_OBJECT_ID)
    monotonic = _integer(
        sample["monotonic_ns"], "claimed monotonic time", minimum=1, maximum=_MAX_OBJECT_ID
    )
    context, validity = request["context"], request["requested_validity"]
    if not isinstance(context, dict) or not isinstance(validity, dict):
        raise ContractError("requested temporal bindings unavailable")
    session = context["session"]
    if not isinstance(session, dict):
        raise ContractError("requested session unavailable")
    not_before = _integer(validity["not_before_unix_ns"], "not before", maximum=_MAX_OBJECT_ID)
    expires = _integer(validity["expires_at_unix_ns"], "expires", maximum=_MAX_OBJECT_ID)
    started = _integer(session["started_monotonic_ns"], "start", maximum=_MAX_OBJECT_ID)
    if unix - not_before != monotonic - started:
        raise ContractError("claimed clock rollback or wall/monotonic inconsistency")
    if unix < not_before:
        return "not_yet_within_caller_claimed_window"
    if unix >= expires:
        return "expired_caller_claimed_window"
    return "within_caller_claimed_window_not_trusted_freshness"


def assess_authorization_request(
    value: JsonValue, *, claimed_clock: JsonValue = None
) -> dict[str, JsonValue]:
    """Produce an explicit blocked refusal even for coherently rehashed matching claims."""
    request = verify_authorization_request_structure(value)
    context = request["context"]
    if not isinstance(context, dict) or not isinstance(context["environment"], dict):
        raise ContractError("request context unavailable")
    environment = context["environment"]
    references: dict[str, JsonValue] = {
        name: "unavailable" if environment[name] is None else "supplied_reference_not_authenticated"
        for name in _REFERENCE_FIELDS
    }
    references["host_provenance_claim_id"] = (
        "unavailable"
        if context["host_provenance_claim_id"] is None
        else "supplied_reference_not_authenticated"
    )
    refusal: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_authorization_acquisition_refusal",
        "schema_version": SCHEMA_VERSION,
        "request_id": request["request_id"],
        "attempt_id": request["attempt_id"],
        "evidence_scope": context["evidence_scope"],
        "disposition": "blocked_before_authority_roots_ledger_socket_process_or_import",
        "structure_validation": "content_bindings_only",
        "authority_verification": "unavailable_not_performed",
        "trusted_freshness_verification": "unavailable_not_performed",
        "claimed_clock_window": _claimed_window(request, claimed_clock),
        "evidence_reference_status": references,
        "unapproved_prerequisites": request["unapproved_prerequisites"],
        "runtime_authorized": False,
        "consumable": False,
        "physical_launch_enabled": False,
        "accepted_physical_evidence": False,
        "wheel_bytes_verification": "not_performed",
        "source_and_environment_bytes_verification": "not_performed",
        "root_and_process_authentication": "unavailable_not_performed",
        "native_enforcement_verification": "unavailable_not_performed",
        "live_ledger_verification": "not_opened_or_consumed",
        "requested_action_outcomes": "unknown_not_executed_or_observed",
        "preparation_actions": {
            "authority_acquisitions": 0,
            "root_observations": 0,
            "ledger_opens": 0,
            "authorization_consumptions": 0,
            "socket_creations": 0,
            "process_starts": 0,
            "runtime_imports": 0,
        },
    }
    refusal["refusal_id"] = canonical_identity(refusal)
    return refusal


class AuthorizationAcquisitionError(ContractError):
    """Explicit preparation failure retaining only immutable, privacy-safe refusal bytes."""

    def __init__(self, refusal: dict[str, JsonValue]) -> None:
        """Retain a diagnostic, never a permit or an acquired authorization."""
        super().__init__("production authorization acquisition blocked: prerequisites unavailable")
        self.refusal_bytes = canonical_json(refusal)


def prepare_authorization_acquisition(
    value: JsonValue, *, claimed_clock: JsonValue = None
) -> NoReturn:
    """Refuse without a callback, grant, issuer, flag or production ledger opener."""
    raise AuthorizationAcquisitionError(
        assess_authorization_request(value, claimed_clock=claimed_clock)
    )
