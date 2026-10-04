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
    CachePreparation,
    ConcurrencyIdentity,
    Eligibility,
    ExecutionDeclaration,
    FixtureSource,
    HostIdentity,
    ModelIdentity,
    ModelInstance,
    ProcessInstance,
    Protocol,
    RunRecord,
    RunScheduleEntry,
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
    incomplete_groups: int
    not_comparable_groups: int
    representation_equivalence: tuple[str, ...]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "protocol_id": self.protocol_id,
            "run_count": self.run_count,
            "group_count": self.group_count,
            "exactly_repeatable_groups": self.exactly_repeatable_groups,
            "divergent_groups": self.divergent_groups,
            "incomplete_groups": self.incomplete_groups,
            "not_comparable_groups": self.not_comparable_groups,
            "representation_equivalence": list(self.representation_equivalence),
        }


def _fixture_evidence_is_synthetic(
    hosts: dict[str, HostIdentity],
    runtimes: dict[str, RuntimeIdentity],
    models: dict[str, ModelIdentity],
    processes: dict[str, ProcessInstance],
    model_instances: dict[str, ModelInstance],
    cache_preparations: dict[str, CachePreparation],
    runs: list[RunRecord],
) -> bool:
    collections = (
        hosts.values(),
        runtimes.values(),
        models.values(),
        processes.values(),
        model_instances.values(),
        cache_preparations.values(),
        runs,
    )
    return all(
        record.evidence_kind == "synthetic_fixture" for records in collections for record in records
    )


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


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def _require_directory(descriptor: int, label: str) -> None:
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        raise ContractError(f"non-directory bundle path component: {label}")


def _require_trusted_directory(
    descriptor: int,
    label: str,
    *,
    expected_owner: int,
) -> None:
    metadata = os.fstat(descriptor)
    if metadata.st_uid != expected_owner:
        raise ContractError(f"bundle directory has untrusted ownership: {label}")
    if metadata.st_mode & 0o022:
        raise ContractError(f"bundle directory is group/world writable: {label}")


def _open_child_directory(
    parent_descriptor: int,
    name: str,
    *,
    expected_owner: int | None = None,
) -> int:
    descriptor = os.open(name, _directory_flags(), dir_fd=parent_descriptor)
    try:
        _require_directory(descriptor, name)
        if expected_owner is not None:
            _require_trusted_directory(
                descriptor,
                name,
                expected_owner=expected_owner,
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_bundle_root(path: Path) -> int:
    if ".." in path.parts:
        raise ContractError("path traversal is forbidden")
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor, _directory_flags())
    try:
        for part in absolute.parts[1:]:
            child = _open_child_directory(descriptor, part)
            os.close(descriptor)
            descriptor = child
        _require_trusted_directory(
            descriptor,
            str(absolute),
            expected_owner=os.geteuid(),
        )
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ContractError("symlink or non-directory bundle path component") from error
        raise
    except Exception:
        os.close(descriptor)
        raise
    else:
        return descriptor


def _read_relative_file(root_descriptor: int, relative_name: str) -> bytes:
    relative = _safe_relative(relative_name)
    root_owner = os.fstat(root_descriptor).st_uid
    directory = os.dup(root_descriptor)
    try:
        for part in relative.parts[:-1]:
            child = _open_child_directory(
                directory,
                part,
                expected_owner=root_owner,
            )
            os.close(directory)
            directory = child
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_NONBLOCK"):
            flags |= os.O_NONBLOCK
        descriptor = os.open(relative.parts[-1], flags, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ContractError(f"non-regular bundle file: {relative_name}")
            blocks: list[bytes] = []
            while block := os.read(descriptor, 1024 * 1024):
                blocks.append(block)
            return b"".join(blocks)
        finally:
            os.close(descriptor)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENOTDIR, errno.ENXIO}:
            raise ContractError(f"unsafe bundle path: {relative_name}") from error
        raise
    finally:
        os.close(directory)


def _snapshot_tree(root_descriptor: int) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    root_owner = os.fstat(root_descriptor).st_uid

    def visit(descriptor: int, prefix: PurePosixPath) -> None:
        for name in sorted(os.listdir(descriptor)):
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            relative = prefix / name
            if stat.S_ISLNK(metadata.st_mode):
                raise ContractError(f"symlink in bundle: {relative.as_posix()}")
            if stat.S_ISDIR(metadata.st_mode):
                directories.add(relative.as_posix())
                child = _open_child_directory(
                    descriptor,
                    name,
                    expected_owner=root_owner,
                )
                try:
                    visit(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative.as_posix())
            else:
                raise ContractError(f"non-regular bundle entry: {relative.as_posix()}")

    visit(root_descriptor, PurePosixPath())
    return files, directories


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
    root_descriptor: int,
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
    expected_directories: set[str] = set()
    for name in expected_files:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent
    actual_files, actual_directories = _snapshot_tree(root_descriptor)
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
        data = _read_relative_file(root_descriptor, name)
        if len(data) != entry["size_bytes"] or digest_bytes(data) != entry["sha256"]:
            raise ContractError(f"indexed file digest mismatch: {name}")
        file_bytes[name] = data
    return file_bytes


def replay_bundle(bundle: Path) -> ReplayResult:
    """Strictly verify and recompute a closed bundle without network or model access."""
    root_descriptor = _open_bundle_root(bundle)
    try:
        try:
            index_bytes = _read_relative_file(root_descriptor, "index.json")
            receipt_bytes = _read_relative_file(root_descriptor, "receipt.json")
        except FileNotFoundError as error:
            raise ContractError("bundle has no publication receipt") from error
        index, _receipt = _parse_index(index_bytes, receipt_bytes)
        file_bytes = _verify_closed_set(
            root_descriptor,
            index,
            index_bytes,
            receipt_bytes,
        )
    finally:
        os.close(root_descriptor)

    protocol: Protocol | None = None
    source: FixtureSource | None = None
    hosts: dict[str, HostIdentity] = {}
    runtimes: dict[str, RuntimeIdentity] = {}
    models: dict[str, ModelIdentity] = {}
    processes: dict[str, ProcessInstance] = {}
    model_instances: dict[str, ModelInstance] = {}
    cache_preparations: dict[str, CachePreparation] = {}
    concurrency_identities: dict[str, ConcurrencyIdentity] = {}
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
        elif isinstance(record, ProcessInstance):
            if name != f"state/process/{identity}.json":
                raise ContractError("process instance is in the wrong bundle path")
            processes[identity] = record
        elif isinstance(record, ModelInstance):
            if name != f"state/model/{identity}.json":
                raise ContractError("model instance is in the wrong bundle path")
            model_instances[identity] = record
        elif isinstance(record, CachePreparation):
            if name != f"state/cache/{identity}.json":
                raise ContractError("cache preparation is in the wrong bundle path")
            cache_preparations[identity] = record
        elif isinstance(record, ConcurrencyIdentity):
            if name != f"state/concurrency/{identity}.json":
                raise ContractError("concurrency identity is in the wrong bundle path")
            concurrency_identities[identity] = record
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
    schedule_processes = {entry.process_instance_id for entry in protocol.run_schedule}
    schedule_models = {entry.model_instance_id for entry in protocol.run_schedule}
    schedule_concurrency = {entry.concurrency_id for entry in protocol.run_schedule}
    if schedule_processes != set(processes):
        raise ContractError("protocol schedule process instances do not match the bundle")
    if schedule_models != set(model_instances):
        raise ContractError("protocol schedule model instances do not match the bundle")
    if schedule_concurrency != set(concurrency_identities):
        raise ContractError("protocol schedule concurrency identities do not match the bundle")
    scheduled_cache = {entry.cache_preparation_id for entry in protocol.run_schedule}
    required_cache: set[str] = set()
    remaining = list(scheduled_cache)
    while remaining:
        cache_id = remaining.pop()
        if cache_id in required_cache:
            continue
        preparation = cache_preparations.get(cache_id)
        if preparation is None:
            raise ContractError("protocol schedule references an unknown cache preparation")
        required_cache.add(cache_id)
        if preparation.parent_preparation_id is not None:
            remaining.append(preparation.parent_preparation_id)
    if required_cache != set(cache_preparations):
        raise ContractError("bundle contains orphan cache preparation state")
    for process_id, process in processes.items():
        runtime = runtimes.get(process.runtime_id)
        if (
            runtime is None
            or process.host_id not in hosts
            or runtime.backend != process.backend
            or process.max_concurrency > protocol.concurrency
        ):
            raise ContractError(f"process instance identity drift: {process_id}")
    for instance_id, instance in model_instances.items():
        process_record = processes.get(instance.process_instance_id)
        model = models.get(instance.model_id)
        if (
            process_record is None
            or model is None
            or process_record.backend != instance.backend
            or model.backend != instance.backend
            or instance.context_tokens != protocol.context_tokens
        ):
            raise ContractError(f"model instance identity drift: {instance_id}")
    for cache_id, preparation in cache_preparations.items():
        model_instance_record = model_instances.get(preparation.model_instance_id)
        parent = (
            None
            if preparation.parent_preparation_id is None
            else cache_preparations.get(preparation.parent_preparation_id)
        )
        if model_instance_record is None or model_instance_record.backend != preparation.backend:
            raise ContractError(f"cache preparation identity drift: {cache_id}")
        if preparation.parent_preparation_id is not None and (
            parent is None or parent.model_instance_id != preparation.model_instance_id
        ):
            raise ContractError("cache preparation lineage crosses model instances")
        seen_lineage = {cache_id}
        ancestor_id = preparation.parent_preparation_id
        while ancestor_id is not None:
            if ancestor_id in seen_lineage:
                raise ContractError("cache preparation lineage contains a cycle")
            seen_lineage.add(ancestor_id)
            ancestor = cache_preparations.get(ancestor_id)
            if ancestor is None:
                raise ContractError("cache preparation lineage references an unknown parent")
            ancestor_id = ancestor.parent_preparation_id
    if any(
        identity.max_concurrency != protocol.concurrency
        for identity in concurrency_identities.values()
    ):
        raise ContractError("concurrency identity does not match protocol concurrency")
    schedule_waves: dict[int, list[RunScheduleEntry]] = {}
    for entry in protocol.run_schedule:
        schedule_waves.setdefault(entry.concurrency_wave, []).append(entry)
    for wave_entries in schedule_waves.values():
        if len(wave_entries) > protocol.concurrency:
            raise ContractError("scheduled concurrency wave exceeds protocol concurrency")
        slots: set[int] = set()
        process_counts: dict[str, int] = {}
        for schedule_entry in wave_entries:
            concurrency_record = concurrency_identities[schedule_entry.concurrency_id]
            peers = tuple(
                sorted(
                    other.request_sha256
                    for other in wave_entries
                    if other.sequence != schedule_entry.sequence
                ),
            )
            if (
                concurrency_record.worker_slot in slots
                or concurrency_record.active_peers != len(wave_entries) - 1
                or concurrency_record.peer_request_sha256 != peers
            ):
                raise ContractError("concurrency identity does not match its scheduled wave")
            slots.add(concurrency_record.worker_slot)
            process_counts[schedule_entry.process_instance_id] = (
                process_counts.get(schedule_entry.process_instance_id, 0) + 1
            )
        if any(
            count > processes[process_id].max_concurrency
            for process_id, count in process_counts.items()
        ):
            raise ContractError("scheduled wave exceeds process-instance concurrency")
    if not runs:
        raise ContractError("bundle has no run records")
    if len(runs) != len(protocol.run_schedule):
        raise ContractError("run count does not match the exact protocol schedule")
    if sorted(run.run_order for run in runs) != list(range(1, len(runs) + 1)):
        raise ContractError("run order must be unique and contiguous")
    for run, entry in zip(
        sorted(runs, key=lambda item: item.run_order),
        protocol.run_schedule,
        strict=True,
    ):
        actual_slot = (
            run.run_order,
            run.run_id,
            run.backend,
            run.runtime_id,
            run.model_id,
            run.host_id,
            run.process_instance_id,
            run.model_instance_id,
            run.cache_preparation_id,
            run.concurrency_id,
            run.concurrency_wave,
            run.cache_cohort,
            run.request_sha256,
        )
        expected_slot = (
            entry.sequence,
            entry.run_id,
            entry.backend,
            entry.runtime_id,
            entry.model_id,
            entry.host_id,
            entry.process_instance_id,
            entry.model_instance_id,
            entry.cache_preparation_id,
            entry.concurrency_id,
            entry.concurrency_wave,
            entry.cache_cohort,
            entry.request_sha256,
        )
        if actual_slot != expected_slot:
            raise ContractError("run does not match its exact protocol schedule slot")
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
        run_process = processes.get(run.process_instance_id)
        model_instance = model_instances.get(run.model_instance_id)
        preparation = cache_preparations.get(run.cache_preparation_id)
        concurrency = concurrency_identities.get(run.concurrency_id)
        if (
            run_process is None
            or model_instance is None
            or preparation is None
            or concurrency is None
            or run_process.backend != run.backend
            or run_process.runtime_id != run.runtime_id
            or run_process.host_id != run.host_id
            or model_instance.backend != run.backend
            or model_instance.process_instance_id != run.process_instance_id
            or model_instance.model_id != run.model_id
            or preparation.backend != run.backend
            or preparation.model_instance_id != run.model_instance_id
            or preparation.cache_cohort != run.cache_cohort
            or run_process.evidence_kind != run.evidence_kind
            or model_instance.evidence_kind != run.evidence_kind
            or preparation.evidence_kind != run.evidence_kind
        ):
            raise ContractError("run state identity does not match its scheduled execution state")
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

    repeat_groups: dict[
        tuple[str, str, str, str, str, str, str, str, str, str, str],
        int,
    ] = {}
    for run in runs:
        repeat_key = (
            run.backend,
            run.runtime_id,
            run.model_id,
            run.host_id,
            run.protocol_id,
            run.process_instance_id,
            run.model_instance_id,
            run.cache_preparation_id,
            run.concurrency_id,
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
    classifications = [
        cast("str", cast("dict[str, JsonValue]", item)["group_classification"]) for item in groups
    ]
    exact = classifications.count("exact")
    divergent = classifications.count("divergent")
    incomplete = classifications.count("incomplete")
    not_comparable = classifications.count("not_comparable")
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
        or source.expected_incomplete_groups != incomplete
        or source.expected_not_comparable_groups != not_comparable
        or source.expected_representation_equivalence != equivalence
        or not _fixture_evidence_is_synthetic(
            hosts,
            runtimes,
            models,
            processes,
            model_instances,
            cache_preparations,
            runs,
        )
    ):
        raise ContractError("fixture source intent does not match replayed evidence")
    return ReplayResult(
        cast("str", index["content_root"]),
        protocol_id,
        len(runs),
        len(groups),
        exact,
        divergent,
        incomplete,
        not_comparable,
        equivalence,
    )
