"""Synthetic-only ledger/parent bindings; never physical authority or dispatch permission."""

from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.mlx_custody import _revalidate_output_root_path
from localinferencelab.mlx_manifest import _scan_open_tree
from localinferencelab.mlx_preflight_custody import (
    _verify_authorization,
    _verify_authorization_at,
    verify_consumption_1_1,
)
from localinferencelab.mlx_preflight_ledger import (
    ParentBindings,
    synthetic_parent_bindings,
    synthetic_root_ids,
)
from localinferencelab.mlx_preflight_protocol import AcquisitionError, expected_frame
from localinferencelab.mlx_preflight_worker import (
    ACTIONS,
    MAX_LIFETIME_NS,
    PROTOCOL_ID,
    WorkerError,
    validate_hello,
    validate_root,
)

if TYPE_CHECKING:
    from localinferencelab.mlx_preflight_execution import _PreparedLaunch

_RUNTIME_NAME = "preflight-runtime"
_ROLES = ("custody_root_id", "output_root_id", "runtime_root_id")
_PRIVATE_MODE = 0o700
_CONTEXT_FIELDS = {
    "record_type",
    "schema_version",
    "evidence_scope",
    "worker_program_id",
    "protocol_id",
    "interpreter_sha256",
    "execution_root",
    "execution_tree_id",
    "root_objects",
    "distributions",
    "import_files",
    "actions",
    "started_ns",
    "deadline_ns",
    "nonce",
}


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise AcquisitionError("synthetic_attempt_object")
    return value


def _integer(value: JsonValue) -> int:
    if type(value) is not int or value < 0:
        raise AcquisitionError("synthetic_attempt_integer")
    return value


def _digest(value: JsonValue) -> str:
    if (
        not isinstance(value, str)
        or len(value) != len("sha256:") + 64
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise AcquisitionError("synthetic_attempt_digest")
    return value


def _same(left: JsonValue, right: JsonValue) -> bool:
    return canonical_json(left) == canonical_json(right)


def _authorization(value: JsonValue) -> dict[str, JsonValue]:
    item = _object(value)
    if item.get("evidence_kind") != "synthetic_fixture_only":
        raise AcquisitionError("synthetic_attempt_authorization")
    try:
        return _verify_authorization(item, allow_synthetic=True)
    except ContractError as error:
        raise AcquisitionError("synthetic_attempt_authorization") from error


@dataclass(frozen=True, slots=True)
class SyntheticParentAttempt:
    """Immutable observed input bytes; not an issuer, permit or production capability."""

    context_bytes: bytes
    hello_bytes: bytes
    roots: tuple[int, int, int]

    def context(self) -> dict[str, JsonValue]:
        return _object(load_json_bytes(self.context_bytes))

    def hello(self) -> dict[str, JsonValue]:
        return _object(load_json_bytes(self.hello_bytes))


def _context(
    launch: _PreparedLaunch,
    roots: tuple[int, int, int],
    *,
    started_ns: int,
    deadline_ns: int,
    nonce: str,
) -> dict[str, JsonValue]:
    synthetic_root_ids(roots)
    if roots[:2] != (launch.custody_descriptor, launch.output_descriptor):
        raise AcquisitionError("synthetic_attempt_roots")
    nested = os.stat(_RUNTIME_NAME, dir_fd=roots[2], follow_symlinks=False)
    runtime = os.fstat(launch.runtime_descriptor)
    if not stat.S_ISDIR(nested.st_mode) or (nested.st_dev, nested.st_ino, nested.st_mode) != (
        runtime.st_dev,
        runtime.st_ino,
        runtime.st_mode,
    ):
        raise AcquisitionError("synthetic_attempt_execution_root")
    root, files = _scan_open_tree(launch.runtime_descriptor)
    if not _same(root, launch.runtime_manifest["package_root"]) or not _same(
        files, launch.runtime_manifest["files"]
    ):
        raise AcquisitionError("synthetic_attempt_runtime_changed")
    _revalidate_output_root_path(launch.output_path, launch.output_descriptor)
    worker_bytes = Path(__file__).with_name("mlx_preflight_worker.py").read_bytes()
    interpreter_id = digest_bytes(launch.interpreter_bytes)
    if (
        launch.worker_bytes != worker_bytes
        or interpreter_id != launch.interpreter_identity["sha256"]
    ):
        raise AcquisitionError("synthetic_attempt_source_or_interpreter")
    pins: list[JsonValue] = []
    for descriptor in roots:
        metadata = os.fstat(descriptor)
        pins.append(
            {
                "device": metadata.st_dev,
                "inode": metadata.st_ino,
                "owner": metadata.st_uid,
                "mode": stat.S_IMODE(metadata.st_mode),
            }
        )
    return {
        "record_type": "mlx_preflight_synthetic_parent_context",
        "schema_version": "1.0",
        "evidence_scope": "synthetic_non_promotable",
        "worker_program_id": digest_bytes(worker_bytes),
        "protocol_id": PROTOCOL_ID,
        "interpreter_sha256": interpreter_id,
        "execution_root": {
            "device": runtime.st_dev,
            "inode": runtime.st_ino,
            "mode": stat.S_IMODE(runtime.st_mode),
        },
        "execution_tree_id": canonical_identity({"root": root, "files": files}),
        "root_objects": pins,
        "distributions": launch.distributions,
        "import_files": launch.import_files,
        "actions": list(ACTIONS),
        "started_ns": started_ns,
        "deadline_ns": deadline_ns,
        "nonce": nonce,
    }


def prepare_synthetic_attempt(
    launch: _PreparedLaunch, *, runtime_container_descriptor: int
) -> SyntheticParentAttempt:
    """Pin inert inputs before fixture enrollment; native spawn remains independently closed."""
    started = time.monotonic_ns()
    roots = (launch.custody_descriptor, launch.output_descriptor, runtime_container_descriptor)
    context = _context(
        launch,
        roots,
        started_ns=started,
        deadline_ns=started + MAX_LIFETIME_NS,
        nonce=os.urandom(32).hex(),
    )
    challenge = digest_bytes(canonical_json(context))[7:]
    hello = expected_frame(
        "hello",
        0,
        canonical_identity({"challenge": challenge, "nonce": context["nonce"]}),
        challenge=challenge,
        nonce=context["nonce"],
        deadline_ns=context["deadline_ns"],
        interpreter_sha256=context["interpreter_sha256"],
        runtime_root=context["execution_root"],
        distributions=context["distributions"],
        import_files=context["import_files"],
        worker_program_id=context["worker_program_id"],
    )
    try:
        validate_hello(hello)
    except WorkerError as error:
        raise AcquisitionError("synthetic_attempt_hello") from error
    return SyntheticParentAttempt(canonical_json(context), canonical_json(hello), roots)


def parent_bindings_for_attempt(
    authorization: JsonValue, attempt: SyntheticParentAttempt
) -> ParentBindings:
    """Observe merged ledger pins and check token hashes; never enroll an authorization."""
    hello = attempt.hello()
    try:
        validate_hello(hello)
    except WorkerError as error:
        raise AcquisitionError("synthetic_attempt_hello") from error
    authorization = _authorization(authorization)
    session = _object(authorization["session_bindings"])
    if session != {
        "challenge_sha256": digest_bytes(cast("str", hello["challenge"]).encode("ascii")),
        "nonce_sha256": digest_bytes(cast("str", hello["nonce"]).encode("ascii")),
    }:
        raise AcquisitionError("synthetic_attempt_authorization_tokens")
    return synthetic_parent_bindings(
        authorization,
        session_id=cast("str", hello["session_id"]),
        interpreter_sha256=cast("str", hello["interpreter_sha256"]),
        root_descriptors=attempt.roots,
    )


def revalidate_synthetic_attempt(attempt: SyntheticParentAttempt, launch: _PreparedLaunch) -> None:
    """Reobserve all inputs inside the retired-permit callback before parent acquisition."""
    context = attempt.context()
    observed = _context(
        launch,
        attempt.roots,
        started_ns=_integer(context["started_ns"]),
        deadline_ns=_integer(context["deadline_ns"]),
        nonce=cast("str", context["nonce"]),
    )
    if canonical_json(observed) != attempt.context_bytes:
        raise AcquisitionError("synthetic_attempt_live_input_drift")


def synthetic_attempt_record(
    attempt: SyntheticParentAttempt,
    bindings: ParentBindings,
    consumption: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    """Project callback audit data only after merged-ledger single-dispatch validation."""
    record: dict[str, JsonValue] = {
        "record_type": "mlx_preflight_synthetic_consumed_attempt",
        "schema_version": "1.0",
        "evidence_scope": "synthetic_non_promotable",
        "context": attempt.context(),
        "parent_bindings": bindings.to_dict(),
        "durable_consumption": consumption,
    }
    record["attempt_id"] = canonical_identity(record)
    verify_synthetic_attempt_record(record, attempt.hello())
    return record


def verify_synthetic_attempt_record(
    value: JsonValue, hello: dict[str, JsonValue]
) -> dict[str, JsonValue]:
    """Offline binding verification only; JSON can never recover a live dispatch permit."""
    record = _object(value)
    if (
        record.keys()
        != {
            "record_type",
            "schema_version",
            "evidence_scope",
            "context",
            "parent_bindings",
            "durable_consumption",
            "attempt_id",
        }
        or record["record_type"] != "mlx_preflight_synthetic_consumed_attempt"
        or record["schema_version"] != "1.0"
        or record["evidence_scope"] != "synthetic_non_promotable"
    ):
        raise AcquisitionError("synthetic_attempt_fields")
    content = {key: item for key, item in record.items() if key != "attempt_id"}
    if _digest(record["attempt_id"]) != canonical_identity(content):
        raise AcquisitionError("synthetic_attempt_identity")
    context = _object(record["context"])
    bindings = _object(record["parent_bindings"])
    if (
        context.keys() != _CONTEXT_FIELDS
        or context["record_type"] != "mlx_preflight_synthetic_parent_context"
        or context["schema_version"] != "1.0"
        or context["evidence_scope"] != "synthetic_non_promotable"
        or context["protocol_id"] != PROTOCOL_ID
        or context["actions"] != list(ACTIONS)
        or bindings.keys() != {"authorization", "session_id", "interpreter_sha256", "root_objects"}
    ):
        raise AcquisitionError("synthetic_attempt_context")
    try:
        validate_hello(hello)
        validate_root(context["execution_root"])
    except WorkerError as error:
        raise AcquisitionError("synthetic_attempt_hello") from error
    _digest(context["execution_tree_id"])
    if (
        hello["challenge"] != digest_bytes(canonical_json(context))[7:]
        or hello["nonce"] != context["nonce"]
        or not 0
        < _integer(context["deadline_ns"]) - _integer(context["started_ns"])
        <= MAX_LIFETIME_NS
        or any(
            not _same(hello[hello_key], context[context_key])
            for hello_key, context_key in (
                ("worker_program_id", "worker_program_id"),
                ("interpreter_sha256", "interpreter_sha256"),
                ("runtime_root", "execution_root"),
                ("distributions", "distributions"),
                ("import_files", "import_files"),
                ("deadline_ns", "deadline_ns"),
            )
        )
        or bindings["session_id"] != hello["session_id"]
        or bindings["interpreter_sha256"] != hello["interpreter_sha256"]
        or not _same(bindings["root_objects"], context["root_objects"])
    ):
        raise AcquisitionError("synthetic_attempt_context_binding")
    pins = context["root_objects"]
    if not isinstance(pins, list) or len(pins) != len(_ROLES):
        raise AcquisitionError("synthetic_attempt_root_pins")
    root_ids: list[str] = []
    for role, pin in zip(("custody", "output", "runtime"), pins, strict=True):
        item = _object(pin)
        if item.keys() != {"device", "inode", "owner", "mode"}:
            raise AcquisitionError("synthetic_attempt_root_pins")
        for scalar in item.values():
            _integer(scalar)
        if item["mode"] != _PRIVATE_MODE or item["inode"] == 0:
            raise AcquisitionError("synthetic_attempt_root_pins")
        root_ids.append(
            canonical_identity({"scope": "synthetic_non_promotable", "role": role, "object": item})
        )
    if len({(_object(pin)["device"], _object(pin)["inode"]) for pin in pins}) != len(_ROLES):
        raise AcquisitionError("synthetic_attempt_root_pins")
    authorization = _authorization(bindings["authorization"])
    roots = _object(authorization["root_bindings"])
    if [roots[role] for role in _ROLES] != root_ids or len(set(root_ids)) != len(_ROLES):
        raise AcquisitionError("synthetic_attempt_root_binding")
    if _object(authorization["session_bindings"]) != {
        "challenge_sha256": digest_bytes(cast("str", hello["challenge"]).encode("ascii")),
        "nonce_sha256": digest_bytes(cast("str", hello["nonce"]).encode("ascii")),
    }:
        raise AcquisitionError("synthetic_attempt_authorization_tokens")
    durable = _object(record["durable_consumption"])
    if (
        durable.keys()
        != {
            "record_type",
            "schema_version",
            "evidence_scope",
            "header_id",
            "parent_bindings_id",
            "clock",
            "consumption",
        }
        or durable["record_type"] != "mlx_preflight_durable_consumption"
        or durable["schema_version"] != "1.0"
        or durable["evidence_scope"] != "synthetic_non_promotable"
        or durable["parent_bindings_id"] != canonical_identity(bindings)
    ):
        raise AcquisitionError("synthetic_attempt_consumption")
    _digest(durable["header_id"])
    clock = _object(durable["clock"])
    if clock.keys() != {"unix_ns", "monotonic_ns"} or any(
        _integer(item) == 0 for item in clock.values()
    ):
        raise AcquisitionError("synthetic_attempt_clock")
    try:
        _verify_authorization_at(
            authorization, observed_at_unix_ns=_integer(clock["unix_ns"]), allow_synthetic=True
        )
        consumption = verify_consumption_1_1(durable["consumption"], authorization)
    except ContractError as error:
        raise AcquisitionError("synthetic_attempt_consumption") from error
    if (
        consumption["session_id"] != hello["session_id"]
        or not _same(consumption["consumed_at_unix_ns"], clock["unix_ns"])
        or authorization["evidence_kind"] != "synthetic_fixture_only"
    ):
        raise AcquisitionError("synthetic_attempt_consumption_binding")
    return record


def consumed_attempt_id(record: dict[str, JsonValue] | None) -> JsonValue:
    if record is None:
        return None
    return _object(_object(record["durable_consumption"])["consumption"])["consumption_id"]
