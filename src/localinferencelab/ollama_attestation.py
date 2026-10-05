"""Offline feasibility contract for Ollama listener and runner attestation."""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
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

SCHEMA_VERSION = "1.0"
FOUNDATION_COMMIT = "7f89682bdc50a944cf74e4729f5acffa48dc6f1a"
DECLARATION_COMMIT = "8f97e3de113bc334ce6928c3d135edea6fbe3b8c"
OLLAMA_REVISION = "42e911bc3d05798cad729cb474bf62f378cb2e26"
XNU_REVISION = "f6217f891ac0bb64f3d375211650a4c1ff8ca1ea"
SECURITY_REVISION = "db15acbe6a7f257a859ad9a3bb86097bfe0679d9"
GENERATION_REQUEST_SHA256 = (
    "sha256:bb3ec4c6433cd55c6a4690808b6f2116effae0a689bf2477b8c3198da5c211d9"
)

_DIGEST_LENGTH = 71
_MAX_TEXT = 1_024
_MAX_ITEMS = 32
_MAX_PORT = 65_535
_CONTROL_CHARACTER_LIMIT = 32
_SUBJECTS = {"listener", "runner", "chain"}
_CONTINUITIES = {
    "point_in_time",
    "atomic_through_external_request",
    "atomic_through_generation_response",
}
_EVIDENCE_CLASSES = {
    "kernel_content_bound",
    "process_content_bound",
    "in_process_content_bound",
    "cryptographic_chain",
}
_CANDIDATE_CATEGORIES = {
    "darwin_libproc",
    "darwin_tcp_pcb",
    "darwin_code_signing",
    "ollama_public_api",
    "ollama_internal_source",
    "future_privileged_kernel",
    "future_in_process_cooperation",
}
_CANDIDATE_STATUSES = {
    "insufficient_snapshot",
    "insufficient_semantics",
    "unsupported_public_api",
    "required_future_primitive",
}
_STRENGTHS = {
    "authoritative_for_listed_fields_only",
    "candidate_observation_only",
    "source_behavior_not_runtime_evidence",
    "not_implemented",
}
_THREAT_OUTCOME = "not_attested"
_VERDICT_REASON = (
    "No reviewed nonprivileged public mechanism content-binds the retained external TCP "
    "connection and exact request to one stable Ollama process instance, then to the exact "
    "scheduler runner/model instance and Metal backend through the generation response."
)


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = _MAX_ITEMS) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum count {maximum}")
    return value


def _keys(data: Mapping[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - data.keys()
    extra = data.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(
    value: JsonValue,
    label: str,
    *,
    maximum: int = _MAX_TEXT,
    empty: bool = False,
) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ContractError(f"{label} must be a{' non-empty' if not empty else ''} string")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in value):
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


def _literal(value: JsonValue, allowed: set[str], label: str) -> str:
    text = _text(value, label)
    if text not in allowed:
        raise ContractError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return text


def _sha256(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _identifier(value: JsonValue, label: str) -> str:
    text = _text(value, label, maximum=96)
    allowed = "abcdefghijklmnopqrstuvwxyz0123456789_"
    if any(character not in allowed for character in text):
        raise ContractError(f"{label} must use lowercase snake_case")
    return text


def _identifier_array(
    value: JsonValue,
    label: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    values = tuple(
        _identifier(item, f"{label}[{index}]") for index, item in enumerate(_array(value, label))
    )
    if not allow_empty and not values:
        raise ContractError(f"{label} must not be empty")
    if len(set(values)) != len(values):
        raise ContractError(f"{label} contains duplicate IDs")
    if tuple(sorted(values)) != values:
        raise ContractError(f"{label} must be sorted")
    return values


def _reference(
    candidate_id: str,
    category: str,
    title: str,
    revision: str,
    url: str,
    lines: str,
) -> dict[str, JsonValue]:
    return {
        "candidate_id": candidate_id,
        "category": category,
        "title": title,
        "source_revision": revision,
        "source_url": url,
        "source_lines": lines,
    }


def _requirement(
    requirement_id: str,
    subject: str,
    statement: str,
    continuity: str,
    evidence_class: str,
) -> dict[str, JsonValue]:
    return {
        "requirement_id": requirement_id,
        "subject": subject,
        "statement": statement,
        "continuity": continuity,
        "required_evidence_class": evidence_class,
        "mandatory": True,
    }


def _candidate(
    reference: Mapping[str, JsonValue],
    *,
    status: str,
    strength: str,
    requirement_ids: Sequence[str],
    reason: str,
) -> dict[str, JsonValue]:
    addressed: list[JsonValue] = []
    addressed.extend(sorted(requirement_ids))
    return {
        **reference,
        "status": status,
        "evidentiary_strength": strength,
        "addresses_requirement_ids": addressed,
        "reason": reason,
    }


def _threat(
    scenario_id: str,
    mutation: str,
    blocked_by: Sequence[str],
) -> dict[str, JsonValue]:
    requirement_ids: list[JsonValue] = []
    requirement_ids.extend(sorted(blocked_by))
    return {
        "scenario_id": scenario_id,
        "mutation": mutation,
        "blocked_by_requirement_ids": requirement_ids,
        "required_outcome": _THREAT_OUTCOME,
    }


def attestation_feasibility_spec() -> dict[str, JsonValue]:
    """Return the immutable pinned source-analysis input for the offline assessment."""
    requirements: list[dict[str, JsonValue]] = [
        _requirement(
            "accepted_connection_owner",
            "listener",
            (
                "Bind the exact retained external TCP connection accepted for the declared "
                "numeric-loopback request and stable kernel socket identity to its owning "
                "process, not merely the listening port."
            ),
            "atomic_through_external_request",
            "kernel_content_bound",
        ),
        _requirement(
            "exact_generation_request_binding",
            "chain",
            (
                "Bind the canonical generation request digest to the retained external "
                "connection and the internal scheduler dispatch that services it."
            ),
            "atomic_through_generation_response",
            "cryptographic_chain",
        ),
        _requirement(
            "listener_executable_identity",
            "listener",
            (
                "Bind a no-follow regular-file byte digest and validated signing identity, when "
                "present, including authoritative designated/team identity, to the same listener "
                "process instance."
            ),
            "atomic_through_external_request",
            "process_content_bound",
        ),
        _requirement(
            "listener_process_instance",
            "listener",
            (
                "Bind owner UID, PID, and anti-reuse process birth or kernel unique identity for "
                "the process that owns the accepted connection."
            ),
            "atomic_through_external_request",
            "kernel_content_bound",
        ),
        _requirement(
            "listener_socket_continuity",
            "listener",
            (
                "Prevent listener close, rebind, accepted-socket replacement, proxying, or "
                "forwarding from breaking the owner binding before request completion."
            ),
            "atomic_through_generation_response",
            "kernel_content_bound",
        ),
        _requirement(
            "metal_execution_state",
            "runner",
            (
                "Prove the backend and active Metal execution state that actually evaluates the "
                "exact generation request; configuration, VRAM ratios, and load state are weak."
            ),
            "atomic_through_generation_response",
            "in_process_content_bound",
        ),
        _requirement(
            "model_closure_and_load_instance",
            "runner",
            (
                "Bind the exact manifest/config/layer closure and one model load lifecycle "
                "instance to the internal runner that services the request."
            ),
            "atomic_through_generation_response",
            "in_process_content_bound",
        ),
        _requirement(
            "runner_executable_identity",
            "runner",
            (
                "Bind the internal runner process instance, parent relation, and executable or "
                "loaded artifact byte closure without trusting mutable argv, environment, or logs."
            ),
            "atomic_through_generation_response",
            "process_content_bound",
        ),
        _requirement(
            "runner_instance_dispatch",
            "runner",
            (
                "Bind the exact Ollama scheduler runnerRef and internal completion transport to "
                "the exact external generation request and response."
            ),
            "atomic_through_generation_response",
            "in_process_content_bound",
        ),
    ]
    requirement_ids = [cast("str", item["requirement_id"]) for item in requirements]
    ollama_base = f"https://github.com/ollama/ollama/blob/{OLLAMA_REVISION}"
    xnu_base = f"https://github.com/apple-oss-distributions/xnu/blob/{XNU_REVISION}"
    security_base = f"https://github.com/apple-oss-distributions/Security/blob/{SECURITY_REVISION}"
    candidates: list[dict[str, JsonValue]] = [
        _candidate(
            _reference(
                "darwin_process_birth_owner",
                "darwin_libproc",
                "proc_bsdinfo process owner and start time",
                XNU_REVISION,
                f"{xnu_base}/bsd/sys/proc_info.h#L55-L82",
                "55-82",
            ),
            status="insufficient_snapshot",
            strength="authoritative_for_listed_fields_only",
            requirement_ids=["listener_process_instance"],
            reason=(
                "Owner and birth time can reduce PID-reuse ambiguity, but a separate snapshot "
                "does not bind that process instance to the retained accepted connection."
            ),
        ),
        _candidate(
            _reference(
                "darwin_process_fd_socket_snapshot",
                "darwin_libproc",
                "proc_pidinfo and proc_pidfdinfo socket records",
                XNU_REVISION,
                f"{xnu_base}/bsd/sys/proc_info.h#L377-L430",
                "377-430,541-575,722-730,781-788",
            ),
            status="insufficient_snapshot",
            strength="authoritative_for_listed_fields_only",
            requirement_ids=[
                "accepted_connection_owner",
                "listener_process_instance",
                "listener_socket_continuity",
            ],
            reason=(
                "The API can enumerate same-user process file descriptors and return endpoint, "
                "state, generation, and opaque socket fields, but enumeration and lookup are "
                "separate point-in-time calls with no request-scoped retained kernel assertion."
            ),
        ),
        _candidate(
            _reference(
                "darwin_tcp_pcb_snapshot",
                "darwin_tcp_pcb",
                "Darwin TCP PCB endpoint and generation records",
                XNU_REVISION,
                f"{xnu_base}/bsd/netinet/in_pcb.h#L537-L577",
                "537-577",
            ),
            status="insufficient_snapshot",
            strength="candidate_observation_only",
            requirement_ids=[
                "accepted_connection_owner",
                "listener_socket_continuity",
            ],
            reason=(
                "Endpoint and generation fields support correlation heuristics, not an atomic "
                "content-bound assertion of which process accepted and retained this request."
            ),
        ),
        _candidate(
            _reference(
                "darwin_dynamic_code_identity",
                "darwin_code_signing",
                "SecCode dynamic guest and validity interfaces",
                SECURITY_REVISION,
                f"{security_base}/OSX/libsecurity_codesigning/lib/SecCode.h#L123-L190",
                "123-190,217-227,307-347",
            ),
            status="insufficient_semantics",
            strength="authoritative_for_listed_fields_only",
            requirement_ids=[
                "listener_executable_identity",
                "runner_executable_identity",
            ],
            reason=(
                "Dynamic code identity and validity can authenticate code selected by process "
                "attributes, but do not prove listener or internal request ownership and do not "
                "replace a no-follow executable byte closure for unsigned or mutable artifacts."
            ),
        ),
        _candidate(
            _reference(
                "ollama_public_ps",
                "ollama_public_api",
                "Ollama process-model response",
                OLLAMA_REVISION,
                f"{ollama_base}/server/routes.go#L2440-L2462",
                "routes.go:2440-2462; api/types.go:856-865",
            ),
            status="unsupported_public_api",
            strength="authoritative_for_listed_fields_only",
            requirement_ids=[
                "metal_execution_state",
                "model_closure_and_load_instance",
                "runner_instance_dispatch",
            ],
            reason=(
                "/api/ps exposes a scheduler load snapshot with model digest, sizes, expiry, and "
                "context length; it exposes no runner PID, process birth, backend, Metal state, "
                "load-instance identity, external connection, or request-to-runner correlation."
            ),
        ),
        _candidate(
            _reference(
                "ollama_internal_scheduler",
                "ollama_internal_source",
                "Ollama scheduler runnerRef lifecycle",
                OLLAMA_REVISION,
                f"{ollama_base}/server/sched.go#L174-L215",
                "174-215,477-496,701-756,1347-1373,1758-1786",
            ),
            status="insufficient_semantics",
            strength="source_behavior_not_runtime_evidence",
            requirement_ids=[
                "model_closure_and_load_instance",
                "runner_instance_dispatch",
            ],
            reason=(
                "Pinned source retains a runnerRef and reference count while a request is active, "
                "but this identity and dispatch relation are not emitted as a public, signed, "
                "request-bound attestation."
            ),
        ),
        _candidate(
            _reference(
                "ollama_internal_completion_transport",
                "ollama_internal_source",
                "Ollama external handler to internal completion request",
                OLLAMA_REVISION,
                f"{ollama_base}/server/routes.go#L693-L729",
                "routes.go:693-729; llm/llama_server.go:194-208,1623-1742",
            ),
            status="insufficient_semantics",
            strength="source_behavior_not_runtime_evidence",
            requirement_ids=[
                "exact_generation_request_binding",
                "runner_instance_dispatch",
            ],
            reason=(
                "Pinned source maps the external request into a runner completion and a separate "
                "non-pooled loopback HTTP call, but exposes no unforgeable correlation token "
                "spanning the external accepted socket, scheduler runnerRef, and newly connected "
                "internal completion socket."
            ),
        ),
        _candidate(
            _reference(
                "ollama_internal_runner_process",
                "ollama_internal_source",
                "Ollama llama-server subprocess launch and PID",
                OLLAMA_REVISION,
                f"{ollama_base}/llm/llama_server.go#L203-L228",
                "203-228,426-442",
            ),
            status="insufficient_semantics",
            strength="source_behavior_not_runtime_evidence",
            requirement_ids=[
                "metal_execution_state",
                "runner_executable_identity",
            ],
            reason=(
                "Pinned source starts a child and retains its PID, but argv, environment, names, "
                "and logs are not content-bound proof that this process and Metal backend served "
                "the exact internal request."
            ),
        ),
        _candidate(
            _reference(
                "future_listener_kernel_assertion",
                "future_privileged_kernel",
                "Future retained accepted-socket ownership assertion",
                "not_implemented",
                "urn:localinferencelab:future:listener-kernel-assertion",
                "not_applicable",
            ),
            status="required_future_primitive",
            strength="not_implemented",
            requirement_ids=[
                "accepted_connection_owner",
                "listener_process_instance",
                "listener_socket_continuity",
            ],
            reason=(
                "A future privileged primitive must retain a stable kernel socket identity and "
                "bind accept/ownership to an audit-token-like process identity through response."
            ),
        ),
        _candidate(
            _reference(
                "future_ollama_cooperative_attestation",
                "future_in_process_cooperation",
                "Future Ollama request-to-runner cooperative assertion",
                "not_implemented",
                "urn:localinferencelab:future:ollama-cooperative-attestation",
                "not_applicable",
            ),
            status="required_future_primitive",
            strength="not_implemented",
            requirement_ids=[
                "exact_generation_request_binding",
                "metal_execution_state",
                "model_closure_and_load_instance",
                "runner_executable_identity",
                "runner_instance_dispatch",
            ],
            reason=(
                "Ollama or an in-process reviewed shim must attest the external request digest, "
                "runnerRef/load instance, internal transport, exact model closure, and backend "
                "Metal execution, then chain that evidence to the kernel socket assertion."
            ),
        ),
    ]
    threats: list[dict[str, JsonValue]] = [
        _threat(
            "coordinated_record_receipt_tampering",
            "assessment_or_bundle_rewritten",
            requirement_ids,
        ),
        _threat(
            "executable_socket_mismatch",
            "socket_owner_executable_differs",
            ["accepted_connection_owner", "listener_executable_identity"],
        ),
        _threat(
            "listener_owner_uid_mismatch",
            "listener_owner_uid_differs",
            ["accepted_connection_owner", "listener_process_instance"],
        ),
        _threat(
            "listener_rebind_race",
            "listener_or_accepted_socket_replaced",
            ["accepted_connection_owner", "listener_socket_continuity"],
        ),
        _threat(
            "metal_claim_from_weak_evidence",
            "metal_claim_uses_ps_logs_or_env",
            ["metal_execution_state"],
        ),
        _threat(
            "model_closure_drift",
            "manifest_config_or_layer_closure_changes",
            ["model_closure_and_load_instance"],
        ),
        _threat("pid_reuse", "pid_reused_after_snapshot", ["listener_process_instance"]),
        _threat(
            "privilege_mismatch",
            "observer_lacks_required_privilege_or_entitlement",
            requirement_ids,
        ),
        _threat(
            "process_birth_drift",
            "process_birth_identity_changes",
            ["listener_process_instance", "runner_executable_identity"],
        ),
        _threat(
            "runner_replacement",
            "scheduler_runner_or_child_changes",
            ["runner_executable_identity", "runner_instance_dispatch"],
        ),
        _threat(
            "socket_endpoint_mismatch",
            "family_host_port_or_peer_differs",
            ["accepted_connection_owner", "listener_socket_continuity"],
        ),
    ]
    ordered_requirements: list[dict[str, JsonValue]] = sorted(
        requirements,
        key=lambda item: cast("str", item["requirement_id"]),
    )
    sorted_requirements: list[JsonValue] = []
    sorted_requirements.extend(ordered_requirements)
    ordered_candidates: list[dict[str, JsonValue]] = sorted(
        candidates,
        key=lambda item: cast("str", item["candidate_id"]),
    )
    sorted_candidates: list[JsonValue] = []
    sorted_candidates.extend(ordered_candidates)
    ordered_threats: list[dict[str, JsonValue]] = sorted(
        threats,
        key=lambda item: cast("str", item["scenario_id"]),
    )
    sorted_threats: list[JsonValue] = []
    sorted_threats.extend(ordered_threats)
    return {
        "record_type": "ollama_attestation_feasibility_spec",
        "schema_version": SCHEMA_VERSION,
        "contract_binding": {
            "repository": "Siddhant-K-code/LocalInferenceLab",
            "foundation_commit": FOUNDATION_COMMIT,
            "declaration_contract_commit": DECLARATION_COMMIT,
            "declaration_record_type": "ollama_repeatability_study_declaration",
            "declaration_schema_version": "1.0",
            "runner_contract_schema_version": "1.0",
            "ollama_revision": OLLAMA_REVISION,
            "generation_request_sha256": GENERATION_REQUEST_SHA256,
        },
        "platform_scope": {
            "operating_system": "macOS",
            "os_version": "27.0.1",
            "os_build": "26A434",
            "architecture": "arm64",
            "privilege_scope": "non_root_no_special_entitlements",
            "process_scope": "same_effective_uid_where_libproc_permits",
            "public_source_parity": "not_claimed_for_exact_os_build",
            "endpoint": {
                "scheme": "http",
                "address_family": "AF_INET",
                "host": "127.0.0.1",
                "port": 11_434,
                "dns": "forbidden",
                "proxy": "forbidden",
                "redirect": "forbidden",
                "unix_forwarding": "forbidden",
            },
        },
        "normative_requirements": sorted_requirements,
        "candidate_mechanisms": sorted_candidates,
        "threat_scenarios": sorted_threats,
    }


def _parse_contract_binding(value: JsonValue) -> None:
    binding = _mapping(value, "attestation_spec.contract_binding")
    fields = {
        "repository",
        "foundation_commit",
        "declaration_contract_commit",
        "declaration_record_type",
        "declaration_schema_version",
        "runner_contract_schema_version",
        "ollama_revision",
        "generation_request_sha256",
    }
    _keys(binding, fields, "attestation_spec.contract_binding")
    for field in fields - {"generation_request_sha256"}:
        _text(binding[field], f"attestation_spec.contract_binding.{field}")
    _sha256(
        binding["generation_request_sha256"],
        "attestation_spec.contract_binding.generation_request_sha256",
    )


def _parse_platform_scope(value: JsonValue) -> None:
    scope = _mapping(value, "attestation_spec.platform_scope")
    fields = {
        "operating_system",
        "os_version",
        "os_build",
        "architecture",
        "privilege_scope",
        "process_scope",
        "public_source_parity",
        "endpoint",
    }
    _keys(scope, fields, "attestation_spec.platform_scope")
    for field in fields - {"endpoint"}:
        _text(scope[field], f"attestation_spec.platform_scope.{field}")
    endpoint = _mapping(scope["endpoint"], "attestation_spec.platform_scope.endpoint")
    endpoint_fields = {
        "scheme",
        "address_family",
        "host",
        "port",
        "dns",
        "proxy",
        "redirect",
        "unix_forwarding",
    }
    _keys(endpoint, endpoint_fields, "attestation_spec.platform_scope.endpoint")
    for field in endpoint_fields - {"port"}:
        _text(endpoint[field], f"attestation_spec.platform_scope.endpoint.{field}")
    _integer(
        endpoint["port"],
        "attestation_spec.platform_scope.endpoint.port",
        minimum=1,
        maximum=_MAX_PORT,
    )


def _parse_requirements(value: JsonValue) -> tuple[str, ...]:
    fields = {
        "requirement_id",
        "subject",
        "statement",
        "continuity",
        "required_evidence_class",
        "mandatory",
    }
    identifiers: list[str] = []
    for index, item in enumerate(_array(value, "attestation_spec.normative_requirements")):
        label = f"attestation_spec.normative_requirements[{index}]"
        requirement = _mapping(item, label)
        _keys(requirement, fields, label)
        identifiers.append(_identifier(requirement["requirement_id"], f"{label}.requirement_id"))
        _literal(requirement["subject"], _SUBJECTS, f"{label}.subject")
        _text(requirement["statement"], f"{label}.statement")
        _literal(requirement["continuity"], _CONTINUITIES, f"{label}.continuity")
        _literal(
            requirement["required_evidence_class"],
            _EVIDENCE_CLASSES,
            f"{label}.required_evidence_class",
        )
        if not _boolean(requirement["mandatory"], f"{label}.mandatory"):
            raise ContractError(f"{label}.mandatory must be true")
    if not identifiers:
        raise ContractError("attestation_spec.normative_requirements must not be empty")
    if len(set(identifiers)) != len(identifiers):
        raise ContractError("attestation_spec.normative_requirements contains duplicate IDs")
    if identifiers != sorted(identifiers):
        raise ContractError("attestation_spec.normative_requirements must be sorted by ID")
    return tuple(identifiers)


def _parse_candidates(value: JsonValue, requirement_ids: set[str]) -> tuple[str, ...]:
    fields = {
        "candidate_id",
        "category",
        "title",
        "source_revision",
        "source_url",
        "source_lines",
        "status",
        "evidentiary_strength",
        "addresses_requirement_ids",
        "reason",
    }
    identifiers: list[str] = []
    covered: set[str] = set()
    for index, item in enumerate(_array(value, "attestation_spec.candidate_mechanisms")):
        label = f"attestation_spec.candidate_mechanisms[{index}]"
        candidate = _mapping(item, label)
        _keys(candidate, fields, label)
        identifiers.append(_identifier(candidate["candidate_id"], f"{label}.candidate_id"))
        _literal(candidate["category"], _CANDIDATE_CATEGORIES, f"{label}.category")
        for field in ("title", "source_revision", "source_url", "source_lines", "reason"):
            _text(candidate[field], f"{label}.{field}")
        _literal(candidate["status"], _CANDIDATE_STATUSES, f"{label}.status")
        _literal(
            candidate["evidentiary_strength"],
            _STRENGTHS,
            f"{label}.evidentiary_strength",
        )
        addressed = set(
            _identifier_array(
                candidate["addresses_requirement_ids"],
                f"{label}.addresses_requirement_ids",
            )
        )
        unknown = addressed - requirement_ids
        if unknown:
            raise ContractError(f"{label} refers to unknown requirement IDs")
        covered.update(addressed)
    if not identifiers:
        raise ContractError("attestation_spec.candidate_mechanisms must not be empty")
    if len(set(identifiers)) != len(identifiers):
        raise ContractError("attestation_spec.candidate_mechanisms contains duplicate IDs")
    if identifiers != sorted(identifiers):
        raise ContractError("attestation_spec.candidate_mechanisms must be sorted by ID")
    if covered != requirement_ids:
        raise ContractError("attestation_spec.candidate_mechanisms do not cover every requirement")
    return tuple(identifiers)


def _parse_threats(value: JsonValue, requirement_ids: set[str]) -> tuple[str, ...]:
    fields = {
        "scenario_id",
        "mutation",
        "blocked_by_requirement_ids",
        "required_outcome",
    }
    identifiers: list[str] = []
    for index, item in enumerate(_array(value, "attestation_spec.threat_scenarios")):
        label = f"attestation_spec.threat_scenarios[{index}]"
        scenario = _mapping(item, label)
        _keys(scenario, fields, label)
        identifiers.append(_identifier(scenario["scenario_id"], f"{label}.scenario_id"))
        _text(scenario["mutation"], f"{label}.mutation")
        blocked_by = set(
            _identifier_array(
                scenario["blocked_by_requirement_ids"],
                f"{label}.blocked_by_requirement_ids",
            )
        )
        if blocked_by - requirement_ids:
            raise ContractError(f"{label} refers to unknown requirement IDs")
        if scenario["required_outcome"] != _THREAT_OUTCOME:
            raise ContractError(f"{label}.required_outcome must be {_THREAT_OUTCOME}")
    if not identifiers:
        raise ContractError("attestation_spec.threat_scenarios must not be empty")
    if len(set(identifiers)) != len(identifiers):
        raise ContractError("attestation_spec.threat_scenarios contains duplicate IDs")
    if identifiers != sorted(identifiers):
        raise ContractError("attestation_spec.threat_scenarios must be sorted by ID")
    return tuple(identifiers)


def _parse_spec(value: JsonValue) -> dict[str, JsonValue]:
    spec = _mapping(value, "ollama_attestation_feasibility_spec")
    fields = {
        "record_type",
        "schema_version",
        "contract_binding",
        "platform_scope",
        "normative_requirements",
        "candidate_mechanisms",
        "threat_scenarios",
    }
    _keys(spec, fields, "ollama_attestation_feasibility_spec")
    if (
        spec["record_type"] != "ollama_attestation_feasibility_spec"
        or spec["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported Ollama attestation feasibility specification")
    _parse_contract_binding(spec["contract_binding"])
    _parse_platform_scope(spec["platform_scope"])
    requirements = set(_parse_requirements(spec["normative_requirements"]))
    _parse_candidates(spec["candidate_mechanisms"], requirements)
    _parse_threats(spec["threat_scenarios"], requirements)
    return dict(spec)


def verify_attestation_spec(value: JsonValue) -> dict[str, JsonValue]:
    """Verify the strict input and require the repository-pinned source analysis."""
    spec = _parse_spec(value)
    if canonical_json(spec) != canonical_json(attestation_feasibility_spec()):
        raise ContractError(
            "attestation feasibility specification differs from the pinned analysis"
        )
    return spec


def build_attestation_assessment(
    spec_value: JsonValue | None = None,
) -> dict[str, JsonValue]:
    """Build the derived negative assessment without any live acquisition."""
    spec = verify_attestation_spec(
        attestation_feasibility_spec() if spec_value is None else spec_value
    )
    requirements = _array(spec["normative_requirements"], "normative_requirements")
    requirement_id_values = sorted(
        cast("str", _mapping(item, "requirement")["requirement_id"]) for item in requirements
    )
    requirement_ids: list[JsonValue] = list(requirement_id_values)
    source_spec_id = canonical_identity(spec)
    feasibility: dict[str, JsonValue] = {
        "record_type": "ollama_attestation_feasibility",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "pinned_source_analysis_not_live_attestation",
        "source_spec_id": source_spec_id,
        "contract_binding": spec["contract_binding"],
        "platform_scope": spec["platform_scope"],
        "normative_requirements": spec["normative_requirements"],
        "candidate_mechanisms": spec["candidate_mechanisms"],
        "threat_scenarios": spec["threat_scenarios"],
        "missing_primitive_ids": [
            "accepted_socket_process_assertion",
            "ollama_request_runner_metal_assertion",
            "request_scoped_attestation_chain",
        ],
        "conclusion": "insufficient",
    }
    feasibility_id = canonical_identity(feasibility)
    verdict: dict[str, JsonValue] = {
        "record_type": "ollama_attestation_verdict",
        "schema_version": SCHEMA_VERSION,
        "feasibility_id": feasibility_id,
        "decision": "insufficient",
        "required_requirement_ids": requirement_ids,
        "satisfied_requirement_ids": [],
        "missing_requirement_ids": requirement_ids,
        "listener_owner_attestation_id": None,
        "active_internal_runner_metal_attestation_id": None,
        "observed_generation_eligible": False,
        "observed_generation_replay_eligible": False,
        "metadata_preflight": "separately_authorized_generation_free",
        "reason": _VERDICT_REASON,
    }
    verdict_id = canonical_identity(verdict)
    assessment: dict[str, JsonValue] = {
        "record_type": "ollama_attestation_assessment",
        "schema_version": SCHEMA_VERSION,
        "source_spec_id": source_spec_id,
        "feasibility": feasibility,
        "feasibility_id": feasibility_id,
        "verdict": verdict,
        "verdict_id": verdict_id,
        "non_actions": {
            "live_process_probes": 0,
            "live_socket_inspections": 0,
            "socket_calls": 0,
            "subprocess_calls": 0,
            "physical_network_requests": 0,
            "ollama_requests": 0,
            "model_process_starts": 0,
            "model_loads": 0,
            "model_inferences": 0,
            "model_mutations": 0,
            "authorization_nonce_consumptions": 0,
            "output_root_consumptions": 0,
            "external_network_actions": 0,
            "cloud_actions": 0,
            "spend_actions": 0,
        },
    }
    assessment["assessment_id"] = canonical_identity(assessment)
    return assessment


def _parse_non_actions(value: JsonValue) -> None:
    non_actions = _mapping(value, "attestation_assessment.non_actions")
    fields = {
        "live_process_probes",
        "live_socket_inspections",
        "socket_calls",
        "subprocess_calls",
        "physical_network_requests",
        "ollama_requests",
        "model_process_starts",
        "model_loads",
        "model_inferences",
        "model_mutations",
        "authorization_nonce_consumptions",
        "output_root_consumptions",
        "external_network_actions",
        "cloud_actions",
        "spend_actions",
    }
    _keys(non_actions, fields, "attestation_assessment.non_actions")
    for field in fields:
        if _integer(non_actions[field], f"attestation_assessment.non_actions.{field}") != 0:
            raise ContractError("attestation assessment non-actions must remain zero")


def _parse_feasibility(value: JsonValue) -> None:
    feasibility = _mapping(value, "attestation_assessment.feasibility")
    fields = {
        "record_type",
        "schema_version",
        "evidence_status",
        "source_spec_id",
        "contract_binding",
        "platform_scope",
        "normative_requirements",
        "candidate_mechanisms",
        "threat_scenarios",
        "missing_primitive_ids",
        "conclusion",
    }
    _keys(feasibility, fields, "attestation_assessment.feasibility")
    if (
        feasibility["record_type"] != "ollama_attestation_feasibility"
        or feasibility["schema_version"] != SCHEMA_VERSION
        or feasibility["evidence_status"] != "pinned_source_analysis_not_live_attestation"
        or feasibility["conclusion"] != "insufficient"
    ):
        raise ContractError("unsupported Ollama attestation feasibility record")
    _sha256(feasibility["source_spec_id"], "attestation_assessment.feasibility.source_spec_id")
    _parse_contract_binding(feasibility["contract_binding"])
    _parse_platform_scope(feasibility["platform_scope"])
    requirements = set(_parse_requirements(feasibility["normative_requirements"]))
    _parse_candidates(feasibility["candidate_mechanisms"], requirements)
    _parse_threats(feasibility["threat_scenarios"], requirements)
    _identifier_array(
        feasibility["missing_primitive_ids"],
        "attestation_assessment.feasibility.missing_primitive_ids",
    )


def _parse_verdict(value: JsonValue) -> None:
    verdict = _mapping(value, "attestation_assessment.verdict")
    fields = {
        "record_type",
        "schema_version",
        "feasibility_id",
        "decision",
        "required_requirement_ids",
        "satisfied_requirement_ids",
        "missing_requirement_ids",
        "listener_owner_attestation_id",
        "active_internal_runner_metal_attestation_id",
        "observed_generation_eligible",
        "observed_generation_replay_eligible",
        "metadata_preflight",
        "reason",
    }
    _keys(verdict, fields, "attestation_assessment.verdict")
    if (
        verdict["record_type"] != "ollama_attestation_verdict"
        or verdict["schema_version"] != SCHEMA_VERSION
        or verdict["decision"] != "insufficient"
    ):
        raise ContractError("unsupported Ollama attestation verdict")
    _sha256(verdict["feasibility_id"], "attestation_assessment.verdict.feasibility_id")
    required = _identifier_array(
        verdict["required_requirement_ids"],
        "attestation_assessment.verdict.required_requirement_ids",
    )
    satisfied = _identifier_array(
        verdict["satisfied_requirement_ids"],
        "attestation_assessment.verdict.satisfied_requirement_ids",
        allow_empty=True,
    )
    missing = _identifier_array(
        verdict["missing_requirement_ids"],
        "attestation_assessment.verdict.missing_requirement_ids",
    )
    if satisfied or missing != required:
        raise ContractError("insufficient verdict must leave every requirement unsatisfied")
    if (
        verdict["listener_owner_attestation_id"] is not None
        or verdict["active_internal_runner_metal_attestation_id"] is not None
    ):
        raise ContractError("insufficient verdict cannot contain positive attestation IDs")
    if _boolean(
        verdict["observed_generation_eligible"],
        "attestation_assessment.verdict.observed_generation_eligible",
    ) or _boolean(
        verdict["observed_generation_replay_eligible"],
        "attestation_assessment.verdict.observed_generation_replay_eligible",
    ):
        raise ContractError("insufficient verdict cannot grant generation eligibility")
    _text(verdict["metadata_preflight"], "attestation_assessment.verdict.metadata_preflight")
    _text(verdict["reason"], "attestation_assessment.verdict.reason")


def verify_attestation_assessment(value: JsonValue) -> dict[str, JsonValue]:
    """Reject unknown fields, caller-forged eligibility, and any semantic drift."""
    assessment = _mapping(value, "ollama_attestation_assessment")
    fields = {
        "record_type",
        "schema_version",
        "source_spec_id",
        "feasibility",
        "feasibility_id",
        "verdict",
        "verdict_id",
        "non_actions",
        "assessment_id",
    }
    _keys(assessment, fields, "ollama_attestation_assessment")
    if (
        assessment["record_type"] != "ollama_attestation_assessment"
        or assessment["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported Ollama attestation assessment")
    for field in ("source_spec_id", "feasibility_id", "verdict_id", "assessment_id"):
        _sha256(assessment[field], f"attestation_assessment.{field}")
    _parse_feasibility(assessment["feasibility"])
    _parse_verdict(assessment["verdict"])
    _parse_non_actions(assessment["non_actions"])
    feasibility = _mapping(assessment["feasibility"], "attestation_assessment.feasibility")
    verdict = _mapping(assessment["verdict"], "attestation_assessment.verdict")
    source_spec_id = canonical_identity(attestation_feasibility_spec())
    if (
        assessment["source_spec_id"] != source_spec_id
        or feasibility["source_spec_id"] != source_spec_id
    ):
        raise ContractError("attestation assessment source specification identity mismatch")
    if (
        assessment["feasibility_id"] != canonical_identity(feasibility)
        or verdict["feasibility_id"] != assessment["feasibility_id"]
    ):
        raise ContractError("attestation feasibility identity mismatch")
    if assessment["verdict_id"] != canonical_identity(verdict):
        raise ContractError("attestation verdict identity mismatch")
    assessment_content = dict(assessment)
    del assessment_content["assessment_id"]
    if assessment["assessment_id"] != canonical_identity(assessment_content):
        raise ContractError("attestation assessment identity mismatch")
    rebuilt = build_attestation_assessment()
    if canonical_json(assessment) != canonical_json(rebuilt):
        raise ContractError("Ollama attestation assessment semantic or identity drift")
    return dict(assessment)


def write_attestation_assessment(path: Path, value: JsonValue) -> None:
    """Write one verified assessment without replacing an existing file."""
    assessment = verify_attestation_assessment(value)
    with path.open("xb") as output:
        output.write(canonical_json(assessment))
        output.flush()
        os.fsync(output.fileno())


def load_attestation_spec(path: Path) -> dict[str, JsonValue]:
    """Load one canonical pinned feasibility specification."""
    return verify_attestation_spec(load_canonical_json_file(path, "attestation specification"))


def load_attestation_assessment(path: Path) -> dict[str, JsonValue]:
    """Load one canonical assessment without following a final symlink."""
    return verify_attestation_assessment(load_canonical_json_file(path, "attestation assessment"))


def attestation_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Return the bounded fail-closed inspection projection."""
    assessment = verify_attestation_assessment(value)
    feasibility = _mapping(assessment["feasibility"], "feasibility")
    verdict = _mapping(assessment["verdict"], "verdict")
    return {
        "assessment_id": assessment["assessment_id"],
        "feasibility_id": assessment["feasibility_id"],
        "verdict_id": assessment["verdict_id"],
        "decision": verdict["decision"],
        "observed_generation_eligible": verdict["observed_generation_eligible"],
        "observed_generation_replay_eligible": verdict["observed_generation_replay_eligible"],
        "metadata_preflight": verdict["metadata_preflight"],
        "missing_requirement_ids": verdict["missing_requirement_ids"],
        "missing_primitive_ids": feasibility["missing_primitive_ids"],
        "physical_network_requests": 0,
        "model_actions": 0,
    }


@dataclass(frozen=True, slots=True)
class AttestationReplayResult:
    """Offline replay summary for the deterministic attestation fixture."""

    bundle_root: str
    assessment_id: str
    feasibility_id: str
    verdict_id: str
    decision: str
    missing_requirements: int
    physical_network_requests: int
    model_actions: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "assessment_id": self.assessment_id,
            "feasibility_id": self.feasibility_id,
            "verdict_id": self.verdict_id,
            "decision": self.decision,
            "missing_requirements": self.missing_requirements,
            "physical_network_requests": self.physical_network_requests,
            "model_actions": self.model_actions,
        }


def compile_attestation_fixture(output_root: Path) -> tuple[Path, AttestationReplayResult]:
    """Publish deterministic synthetic feasibility evidence with zero physical actions."""
    spec = attestation_feasibility_spec()
    assessment = build_attestation_assessment(spec)
    source: dict[str, JsonValue] = {
        "record_type": "ollama_attestation_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_offline_feasibility_contract_evidence",
        "live_attestation": False,
        "physical_network_requests": 0,
        "live_process_probes": 0,
        "live_socket_inspections": 0,
        "socket_calls": 0,
        "subprocess_calls": 0,
        "model_actions": 0,
        "authorization_nonce_consumptions": 0,
        "output_root_consumptions": 0,
        "external_network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }
    destination = publish_bundle(
        {
            "source/fixture.json": canonical_json(source),
            "source/attestation-spec.json": canonical_json(spec),
            "attestation-assessment.json": canonical_json(assessment),
        },
        output_root,
        name_prefix="localinferencelab-ollama-attestation-synthetic-v1",
    )
    return destination, replay_attestation_fixture(destination)


def _canonical_bytes(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def replay_attestation_fixture(bundle: Path) -> AttestationReplayResult:
    """Replay the closed feasibility bundle without network or process inspection."""
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/fixture.json",
        "source/attestation-spec.json",
        "attestation-assessment.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("attestation fixture bundle has an invalid content set")
    source = _mapping(
        _canonical_bytes(files["source/fixture.json"], "attestation fixture source"),
        "ollama_attestation_fixture_source",
    )
    source_fields = {
        "record_type",
        "schema_version",
        "evidence_status",
        "live_attestation",
        "physical_network_requests",
        "live_process_probes",
        "live_socket_inspections",
        "socket_calls",
        "subprocess_calls",
        "model_actions",
        "authorization_nonce_consumptions",
        "output_root_consumptions",
        "external_network_actions",
        "cloud_actions",
        "spend_actions",
    }
    _keys(source, source_fields, "ollama_attestation_fixture_source")
    expected_source: dict[str, JsonValue] = {
        "record_type": "ollama_attestation_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_offline_feasibility_contract_evidence",
        "live_attestation": False,
        "physical_network_requests": 0,
        "live_process_probes": 0,
        "live_socket_inspections": 0,
        "socket_calls": 0,
        "subprocess_calls": 0,
        "model_actions": 0,
        "authorization_nonce_consumptions": 0,
        "output_root_consumptions": 0,
        "external_network_actions": 0,
        "cloud_actions": 0,
        "spend_actions": 0,
    }
    if files["source/fixture.json"] != canonical_json(expected_source):
        raise ContractError("attestation fixture source non-actions drift")
    spec = verify_attestation_spec(
        _canonical_bytes(
            files["source/attestation-spec.json"],
            "attestation fixture specification",
        )
    )
    assessment = verify_attestation_assessment(
        _canonical_bytes(
            files["attestation-assessment.json"],
            "attestation fixture assessment",
        )
    )
    if assessment != build_attestation_assessment(spec):
        raise ContractError("attestation fixture does not replay from its source spec")
    verdict = _mapping(assessment["verdict"], "attestation verdict")
    return AttestationReplayResult(
        content_root,
        cast("str", assessment["assessment_id"]),
        cast("str", assessment["feasibility_id"]),
        cast("str", assessment["verdict_id"]),
        cast("str", verdict["decision"]),
        len(_array(verdict["missing_requirement_ids"], "missing_requirement_ids")),
        0,
        0,
    )
