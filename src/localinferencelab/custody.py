"""Closed-bundle verification, offline replay, and atomic publication."""

from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from localinferencelab.analysis import analyze_runs
from localinferencelab.canonical import (
    SHA256_ID_LENGTH,
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_json_bytes,
)
from localinferencelab.contracts import (
    Eligibility,
    ExecutionDeclaration,
    FixtureSource,
    HostIdentity,
    ModelIdentity,
    Protocol,
    RunRecord,
    RuntimeIdentity,
    parse_record,
    record_id,
)

AT_FDCWD = -100
RENAME_NOREPLACE = 1
RENAME_EXCL = 4


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Verified summary of a closed bundle replay."""

    bundle_root: str
    protocol_id: str
    run_count: int
    group_count: int
    exactly_repeatable_groups: int
    divergent_groups: int
    representation_equivalence: tuple[str, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "protocol_id": self.protocol_id,
            "run_count": self.run_count,
            "group_count": self.group_count,
            "exactly_repeatable_groups": self.exactly_repeatable_groups,
            "divergent_groups": self.divergent_groups,
            "representation_equivalence": list(self.representation_equivalence),
        }


def _strict_keys(data: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - data.keys()
    extra = data.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _object(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _text(value: JsonValue, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _count(value: JsonValue, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


def _safe_relative(value: str) -> PurePosixPath:
    if "\\" in value:
        raise ContractError("bundle paths must use POSIX separators")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise ContractError(f"unsafe bundle path: {value}")
    if path.as_posix() != value:
        raise ContractError(f"non-canonical bundle path: {value}")
    return path


def _safe_existing_directory(path: Path) -> Path:
    if ".." in path.parts:
        raise ContractError("path traversal is forbidden")
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise ContractError(f"symlink path component is forbidden: {current}")
    if not absolute.is_dir():
        raise ContractError(f"directory does not exist: {absolute}")
    if os.lstat(absolute).st_mode & 0o022:
        raise ContractError(f"output or bundle directory is group/world writable: {absolute}")
    return absolute


def _write_fsynced(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(data)
        written = 0
        while written < len(data):
            written += os.write(descriptor, view[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_tree_directories(root: Path) -> None:
    directories = [path for path in root.rglob("*") if path.is_dir()]
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        _fsync_directory(directory)
    _fsync_directory(root)


def _rename_no_replace(source: Path, destination: Path) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    source_bytes = os.fsencode(source)
    destination_bytes = os.fsencode(destination)
    if hasattr(libc, "renameat2"):
        function = libc.renameat2
        function.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        function.restype = ctypes.c_int
        result = function(
            AT_FDCWD,
            source_bytes,
            AT_FDCWD,
            destination_bytes,
            RENAME_NOREPLACE,
        )
    elif hasattr(libc, "renamex_np"):
        function = libc.renamex_np
        function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        result = function(source_bytes, destination_bytes, RENAME_EXCL)
    else:
        raise ContractError("atomic no-replace rename is unavailable on this platform")
    if result != 0:
        error_number = ctypes.get_errno()
        if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error_number, os.strerror(error_number), destination)
        raise OSError(error_number, os.strerror(error_number), destination)


def make_index(
    content_files: dict[str, bytes],
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    """Create an index and receipt for content files."""
    entries: list[JsonValue] = []
    for name in sorted(content_files):
        _safe_relative(name)
        if name in {"index.json", "receipt.json"}:
            raise ContractError(f"reserved bundle path: {name}")
        entries.append(
            {
                "path": name,
                "sha256": digest_bytes(content_files[name]),
                "size_bytes": len(content_files[name]),
            },
        )
    content_root = canonical_identity(entries)
    index: dict[str, JsonValue] = {
        "record_type": "bundle_index",
        "schema_version": "1.0",
        "bundle_format": "closed_bundle_v1",
        "content_root": content_root,
        "entries": entries,
    }
    receipt: dict[str, JsonValue] = {
        "record_type": "publication_receipt",
        "schema_version": "1.0",
        "content_root": content_root,
        "index_sha256": digest_bytes(canonical_json(index)),
        "entry_count": len(entries),
        "publication_method": "atomic_no_replace_receipt_last_v1",
    }
    return index, receipt


def publish_bundle(
    content_files: dict[str, bytes],
    output_root: Path,
    *,
    name_prefix: str,
) -> Path:
    """Publish a bundle with durable files, no-clobber rename, and receipt-last closure."""
    root = _safe_existing_directory(output_root)
    prefix = _safe_relative(name_prefix)
    if len(prefix.parts) != 1:
        raise ContractError("bundle name prefix must be one canonical basename")
    index, receipt = make_index(content_files)
    content_root = cast("str", index["content_root"])
    destination = root / f"{name_prefix}-{content_root[7:]}"
    if destination.parent != root:
        raise ContractError("bundle destination must be an immediate child of the output root")
    stage = Path(tempfile.mkdtemp(prefix=".localinferencelab-stage-", dir=root))
    renamed = False
    complete = False
    try:
        staged_files = dict(content_files)
        staged_files["index.json"] = canonical_json(index)
        for relative_name, data in sorted(staged_files.items()):
            relative = _safe_relative(relative_name)
            target = stage.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            _write_fsynced(target, data)
        _fsync_tree_directories(stage)
        _rename_no_replace(stage, destination)
        renamed = True
        _fsync_directory(root)
        _write_fsynced(destination / "receipt.json", canonical_json(receipt))
        _fsync_directory(destination)
        _fsync_directory(root)
        complete = True
        return destination
    finally:
        if not renamed and stage.exists():
            shutil.rmtree(stage)
        if renamed and not complete and destination.exists():
            shutil.rmtree(destination)
            _fsync_directory(root)


def _read_no_follow(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ContractError(f"non-regular bundle file: {path.name}")
        blocks: list[bytes] = []
        while block := os.read(descriptor, 1024 * 1024):
            blocks.append(block)
        return b"".join(blocks)
    finally:
        os.close(descriptor)


def _read_canonical_json(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} is not canonical JSON")
    return value


def _parse_index(
    index_bytes: bytes,
    receipt_bytes: bytes,
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    index = _object(_read_canonical_json(index_bytes, "index.json"), "index")
    _strict_keys(
        index,
        {"record_type", "schema_version", "bundle_format", "content_root", "entries"},
        "index",
    )
    if (
        index["record_type"] != "bundle_index"
        or index["schema_version"] != "1.0"
        or index["bundle_format"] != "closed_bundle_v1"
    ):
        raise ContractError("unsupported bundle index")
    entries_value = index["entries"]
    if not isinstance(entries_value, list):
        raise ContractError("index.entries must be an array")
    seen: set[str] = set()
    entries: list[JsonValue] = []
    for item in entries_value:
        entry = _object(item, "index.entries[]")
        _strict_keys(entry, {"path", "sha256", "size_bytes"}, "index.entries[]")
        name = _text(entry["path"], "index.entries[].path")
        _safe_relative(name)
        if name in {"index.json", "receipt.json"} or name in seen:
            raise ContractError(f"duplicate or reserved indexed path: {name}")
        seen.add(name)
        digest = _text(entry["sha256"], "index.entries[].sha256")
        if (
            not digest.startswith("sha256:")
            or len(digest) != SHA256_ID_LENGTH
            or digest != digest.lower()
        ):
            raise ContractError("index entry has invalid SHA-256")
        try:
            int(digest[7:], 16)
        except ValueError as error:
            raise ContractError("index entry has invalid SHA-256") from error
        entries.append(
            {
                "path": name,
                "sha256": digest,
                "size_bytes": _count(entry["size_bytes"], "index.entries[].size_bytes"),
            },
        )
    if entries != sorted(
        entries, key=lambda item: cast("str", cast("dict[str, JsonValue]", item)["path"])
    ):
        raise ContractError("index entries are not sorted")
    if index["content_root"] != canonical_identity(entries):
        raise ContractError("bundle content root mismatch")

    receipt = _object(_read_canonical_json(receipt_bytes, "receipt.json"), "receipt")
    _strict_keys(
        receipt,
        {
            "record_type",
            "schema_version",
            "content_root",
            "index_sha256",
            "entry_count",
            "publication_method",
        },
        "receipt",
    )
    if (
        receipt["record_type"] != "publication_receipt"
        or receipt["schema_version"] != "1.0"
        or receipt["publication_method"] != "atomic_no_replace_receipt_last_v1"
    ):
        raise ContractError("unsupported publication receipt")
    if receipt["content_root"] != index["content_root"]:
        raise ContractError("receipt content root mismatch")
    if receipt["index_sha256"] != digest_bytes(index_bytes):
        raise ContractError("receipt index digest mismatch")
    if receipt["entry_count"] != len(entries):
        raise ContractError("receipt entry count mismatch")
    return index, receipt


def _verify_closed_set(
    path: Path,
    index: dict[str, JsonValue],
    index_bytes: bytes,
    receipt_bytes: bytes,
) -> dict[str, bytes]:
    entries = cast("list[JsonValue]", index["entries"])
    expected_files = {
        cast("str", cast("dict[str, JsonValue]", item)["path"]): cast(
            "dict[str, JsonValue]",
            item,
        )
        for item in entries
    }
    expected_files.update({"index.json": {}, "receipt.json": {}})
    expected_directories = {
        PurePosixPath(name).parent.as_posix()
        for name in expected_files
        if PurePosixPath(name).parent != PurePosixPath(".")
    }
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for root, directories, files in os.walk(path, followlinks=False):
        root_path = Path(root)
        for directory in directories:
            directory_path = root_path / directory
            if stat.S_ISLNK(os.lstat(directory_path).st_mode):
                raise ContractError(f"symlink in bundle: {directory_path}")
            actual_directories.add(directory_path.relative_to(path).as_posix())
        for filename in files:
            actual_files.add((root_path / filename).relative_to(path).as_posix())
    if actual_files != set(expected_files):
        missing = sorted(set(expected_files) - actual_files)
        extra = sorted(actual_files - set(expected_files))
        raise ContractError(f"bundle closure mismatch; missing={missing}, extra={extra}")
    if actual_directories != expected_directories:
        raise ContractError("bundle contains missing or extra directories")
    file_bytes = {"index.json": index_bytes, "receipt.json": receipt_bytes}
    for name, entry in expected_files.items():
        if not entry:
            continue
        data = _read_no_follow(path / name)
        if len(data) != entry["size_bytes"] or digest_bytes(data) != entry["sha256"]:
            raise ContractError(f"indexed file digest mismatch: {name}")
        file_bytes[name] = data
    return file_bytes


def replay_bundle(bundle: Path) -> ReplayResult:
    """Strictly verify and recompute a closed bundle without network or model access."""
    path = _safe_existing_directory(bundle)
    try:
        index_bytes = _read_no_follow(path / "index.json")
        receipt_bytes = _read_no_follow(path / "receipt.json")
    except FileNotFoundError as error:
        raise ContractError("bundle has no publication receipt") from error
    index, _receipt = _parse_index(index_bytes, receipt_bytes)
    file_bytes = _verify_closed_set(path, index, index_bytes, receipt_bytes)

    protocol: Protocol | None = None
    source: FixtureSource | None = None
    hosts: dict[str, HostIdentity] = {}
    runtimes: dict[str, RuntimeIdentity] = {}
    models: dict[str, ModelIdentity] = {}
    declarations: dict[str, ExecutionDeclaration] = {}
    eligibility: list[Eligibility] = []
    runs: list[RunRecord] = []

    entries = cast("list[JsonValue]", index["entries"])
    for item in entries:
        name = cast("str", cast("dict[str, JsonValue]", item)["path"])
        if name == "analysis.json":
            continue
        value = _read_canonical_json(file_bytes[name], name)
        record = parse_record(value)
        identity = record_id(record)
        if isinstance(record, Protocol):
            if name != "protocol.json":
                raise ContractError("protocol record is in the wrong bundle path")
            if protocol is not None:
                raise ContractError("bundle must contain exactly one protocol")
            protocol = record
        elif isinstance(record, HostIdentity):
            if name != "identities/host.json":
                raise ContractError("host identity is in the wrong bundle path")
            hosts[identity] = record
        elif isinstance(record, RuntimeIdentity):
            expected = f"identities/runtime-{record.backend.replace('.', '-')}.json"
            if name != expected:
                raise ContractError("runtime identity is in the wrong bundle path")
            runtimes[identity] = record
        elif isinstance(record, ModelIdentity):
            expected = f"identities/model-{record.backend.replace('.', '-')}.json"
            if name != expected:
                raise ContractError("model identity is in the wrong bundle path")
            models[identity] = record
        elif isinstance(record, ExecutionDeclaration):
            expected = f"authorizations/{record.backend.replace('.', '-')}.json"
            if name != expected:
                raise ContractError("execution declaration is in the wrong bundle path")
            declarations[identity] = record
        elif isinstance(record, Eligibility):
            eligibility.append(record)
        elif isinstance(record, FixtureSource):
            if name != "source/fixture.json" or source is not None:
                raise ContractError("fixture source is missing or in the wrong bundle path")
            source = record
        elif isinstance(record, RunRecord):
            expected = f"runs/{record.run_order:04d}-{record.run_id}.json"
            if name != expected:
                raise ContractError("run record is in the wrong bundle path")
            runs.append(record)

    if protocol is None:
        raise ContractError("bundle has no protocol")
    if source is None:
        raise ContractError("bundle has no strict fixture source")
    protocol_id = record_id(protocol)
    if set(protocol.allowed_runtime_ids) != set(runtimes):
        raise ContractError("protocol runtime allowlist does not match bundle identities")
    if set(protocol.allowed_model_ids) != set(models):
        raise ContractError("protocol model allowlist does not match bundle identities")
    if set(protocol.allowed_host_ids) != set(hosts):
        raise ContractError("protocol host allowlist does not match bundle identities")
    if not runs:
        raise ContractError("bundle has no run records")
    if sorted(run.run_order for run in runs) != list(range(1, len(runs) + 1)):
        raise ContractError("run order must be unique and contiguous")
    observed_backends = {run.backend for run in runs}
    if observed_backends != set(protocol.backend_order):
        raise ContractError("run backends do not match the protocol backend order")
    observed_cohorts = {run.cache_cohort for run in runs}
    if observed_cohorts != set(protocol.cache_cohorts):
        raise ContractError("run cache cohorts do not match the protocol")
    backend_sequence = [run.backend for run in sorted(runs, key=lambda item: item.run_order)]
    expected_positions = {backend: index for index, backend in enumerate(protocol.backend_order)}
    if protocol.ordering == "backend_blocked" and backend_sequence != sorted(
        backend_sequence,
        key=expected_positions.__getitem__,
    ):
        raise ContractError("run order violates backend_blocked ordering")

    for declaration_id, declaration in declarations.items():
        if declaration.protocol_id != protocol_id:
            raise ContractError("declaration protocol identity drift")
        if declaration.runtime_id not in runtimes or declaration.model_id not in models:
            raise ContractError("declaration references an unknown identity")
        if (
            runtimes[declaration.runtime_id].backend != declaration.backend
            or models[declaration.model_id].backend != declaration.backend
        ):
            raise ContractError("declaration backend does not match runtime and model identities")
        if declaration.host_id is not None and declaration.host_id not in hosts:
            raise ContractError("declaration references an unknown host")
        if (
            declaration.host_id is not None
            and hosts[declaration.host_id].host_class != declaration.host_class
        ):
            raise ContractError("declaration host class does not match the exact host")
        matches = [item for item in eligibility if item.declaration_id == declaration_id]
        if len(matches) != 1:
            raise ContractError("each declaration requires exactly one eligibility record")
        eligibility_path = f"eligibility/{declaration.backend.replace('.', '-')}.json"
        eligibility_record = matches[0]
        eligibility_identity = record_id(eligibility_record)
        indexed_record = parse_record(
            _read_canonical_json(file_bytes[eligibility_path], eligibility_path),
        )
        if record_id(indexed_record) != eligibility_identity:
            raise ContractError("eligibility record is in the wrong bundle path")
        expected_decision = (
            "model_execution_forbidden"
            if declaration.disposition == "model_execution_forbidden"
            else "eligible"
        )
        expected_actions: tuple[str, ...] = tuple(
            sorted(
                action
                for action, budget in (
                    ("model_process_start", declaration.action_budget.model_process_starts),
                    ("inference_request", declaration.action_budget.inference_requests),
                )
                if budget > 0
            ),
        )
        host_matches = (
            eligibility_record.host_id == declaration.host_id
            if declaration.host_policy == "exact_identity"
            else (
                eligibility_record.host_id in hosts
                and hosts[eligibility_record.host_id].host_class == declaration.host_class
            )
        )
        if (
            eligibility_record.decision != expected_decision
            or eligibility_record.protocol_id != declaration.protocol_id
            or eligibility_record.runtime_id != declaration.runtime_id
            or eligibility_record.model_id != declaration.model_id
            or not host_matches
            or eligibility_record.allowed_actions != expected_actions
        ):
            raise ContractError("eligibility identity set does not match its declaration")
    if len(eligibility) != len(declarations) or any(
        item.declaration_id not in declarations for item in eligibility
    ):
        raise ContractError("bundle contains orphan or duplicate eligibility records")

    eligibility_by_declaration = {item.declaration_id: item for item in eligibility}
    action_counts: dict[str, tuple[int, int]] = {}
    for run in runs:
        if run.protocol_id != protocol_id:
            raise ContractError("run protocol identity drift")
        if run.runtime_id not in runtimes or run.model_id not in models or run.host_id not in hosts:
            raise ContractError("run references an unknown identity")
        run_declaration = declarations.get(run.declaration_id)
        if run_declaration is None:
            raise ContractError("run references an unknown declaration")
        if (
            run.backend != run_declaration.backend
            or run.runtime_id != run_declaration.runtime_id
            or run.model_id != run_declaration.model_id
        ):
            raise ContractError("run identity does not match its declaration")
        if (
            run_declaration.host_policy == "exact_identity"
            and run.host_id != run_declaration.host_id
        ) or (
            run_declaration.host_policy == "host_class"
            and hosts[run.host_id].host_class != run_declaration.host_class
        ):
            raise ContractError("run host does not satisfy its declaration")
        run_eligibility = eligibility_by_declaration[run.declaration_id]
        if run.host_id != run_eligibility.host_id:
            raise ContractError("run host does not match its eligibility decision")
        if run.cache_cohort not in protocol.cache_cohorts:
            raise ContractError("run uses a cache cohort outside the protocol")
        if (
            run_declaration.disposition == "model_execution_forbidden"
            and run.evidence_kind != "synthetic_fixture"
        ):
            raise ContractError("forbidden declaration cannot custody observed execution")
        if run.evidence_kind == "observed_execution" and (
            run_eligibility.decision != "eligible"
            or "inference_request" not in run_eligibility.allowed_actions
            or not runtimes[run.runtime_id].identity_complete
            or runtimes[run.runtime_id].evidence_kind != "observed_execution"
            or models[run.model_id].evidence_kind != "observed_execution"
            or hosts[run.host_id].evidence_kind != "safe_host_probe"
        ):
            raise ContractError("observed run lacks complete eligible observed identities")
        process_starts, inference_requests = action_counts.get(run.declaration_id, (0, 0))
        action_counts[run.declaration_id] = (
            process_starts + run.model_process_start_count,
            inference_requests + run.inference_request_count,
        )

    for declaration_id, declaration in declarations.items():
        process_starts, inference_requests = action_counts.get(declaration_id, (0, 0))
        if (
            process_starts > declaration.action_budget.model_process_starts
            or inference_requests > declaration.action_budget.inference_requests
        ):
            raise ContractError("run action accounting exceeds the declaration budget")

    repeat_groups: dict[tuple[str, str, str, str, str, str, str], int] = {}
    for run in runs:
        repeat_key = (
            run.backend,
            run.runtime_id,
            run.model_id,
            run.host_id,
            run.protocol_id,
            run.cache_cohort,
            run.request_sha256,
        )
        repeat_groups[repeat_key] = repeat_groups.get(repeat_key, 0) + 1
    if any(count != protocol.repeats_per_cohort for count in repeat_groups.values()):
        raise ContractError("run repeat count does not match the protocol")

    analysis = analyze_runs(runs, models)
    stored_analysis = _read_canonical_json(file_bytes["analysis.json"], "analysis.json")
    if stored_analysis != analysis:
        raise ContractError("analysis replay mismatch")
    groups = cast("list[JsonValue]", analysis["groups"])
    exact = 0
    divergent = 0
    for item in groups:
        group = cast("dict[str, JsonValue]", item)
        equality = cast("dict[str, JsonValue]", group["exact_repeatability"])
        if all(value == "equal" for value in equality.values()):
            exact += 1
        else:
            divergent += 1
    pairs = cast("list[JsonValue]", analysis["representation_pairs"])
    equivalence = tuple(
        sorted(
            {cast("str", cast("dict[str, JsonValue]", pair)["equivalence"]) for pair in pairs},
        ),
    )
    if (
        any(
            declaration.disposition != "model_execution_forbidden"
            for declaration in declarations.values()
        )
        or source.model_process_starts != sum(run.model_process_start_count for run in runs)
        or source.inference_requests != sum(run.inference_request_count for run in runs)
        or source.network_requests != 0
        or source.downloads != 0
        or source.expected_run_count != len(runs)
        or source.expected_exact_groups != exact
        or source.expected_divergent_groups != divergent
        or source.expected_representation_equivalence != equivalence
        or any(run.evidence_kind != "synthetic_fixture" for run in runs)
    ):
        raise ContractError("fixture source intent does not match replayed evidence")
    return ReplayResult(
        cast("str", index["content_root"]),
        protocol_id,
        len(runs),
        len(groups),
        exact,
        divergent,
        equivalence,
    )
