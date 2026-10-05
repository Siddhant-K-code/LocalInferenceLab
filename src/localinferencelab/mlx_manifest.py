"""Descriptor-relative offline manifests for prospective MLX execution."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    load_canonical_json_file,
)

SCHEMA_VERSION = "1.0"
MAX_FILES = 16_384
MAX_ENTRIES = 24_576
MAX_DEPTH = 32
MAX_PATH_BYTES = 1_024
MAX_FILE_BYTES = 256 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024 * 1024
MAX_EXTERNAL_JSON_BYTES = 16 * 1024 * 1024
MIN_REQUIRED_DISTRIBUTIONS = 2
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_CHUNK_SIZE = 1024 * 1024
_RUNTIME_ENVIRONMENT: tuple[tuple[str, str], ...] = (
    ("HF_HUB_OFFLINE", "1"),
    ("MLXLM_USE_MODELSCOPE", "False"),
    ("PYTHONHASHSEED", "0"),
    ("PYTHONDONTWRITEBYTECODE", "1"),
    ("PYTHONNOUSERSITE", "1"),
    ("TOKENIZERS_PARALLELISM", "false"),
    ("TRANSFORMERS_OFFLINE", "1"),
)
_FORBIDDEN_RUNTIME_STEMS = {"sitecustomize", "usercustomize"}
_MODEL_SUFFIXES = {
    ".json",
    ".jsonl",
    ".jinja",
    ".model",
    ".safetensors",
    ".tiktoken",
    ".txt",
}


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = MAX_FILES) -> list[JsonValue]:
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


def _text(value: JsonValue, label: str, *, maximum: int = MAX_PATH_BYTES) -> str:
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


def _relative(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if "\\" in text:
        raise ContractError(f"{label} must use POSIX separators")
    path = PurePosixPath(text)
    if (
        path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != text
    ):
        raise ContractError(f"{label} must be a canonical relative path")
    return text


def _directory_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _open_directory(path: Path) -> int:
    if ".." in path.parts:
        raise ContractError("path traversal is forbidden")
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor, _directory_flags())
    try:
        for part in absolute.parts[1:]:
            child = _open_path_component(descriptor, part)
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ContractError("symlink or non-directory path component") from error
        raise
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _open_path_component(parent_descriptor: int, part: str) -> int:
    metadata = os.stat(part, dir_fd=parent_descriptor, follow_symlinks=False)
    if stat.S_ISLNK(metadata.st_mode):
        raise ContractError("symlink path components are forbidden")
    child = os.open(part, _directory_flags(), dir_fd=parent_descriptor)
    if not stat.S_ISDIR(os.fstat(child).st_mode):
        os.close(child)
        raise ContractError("explicit scan root must be a directory")
    return child


def _open_file(path: Path) -> int:
    absolute = path.absolute()
    parent = _open_directory(absolute.parent)
    try:
        descriptor = os.open(absolute.name, _file_flags(), dir_fd=parent)
    except OSError as error:
        if error.errno in {errno.ELOOP, errno.ENXIO}:
            raise ContractError("explicit file must be a no-follow regular file") from error
        raise
    finally:
        os.close(parent)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ContractError("explicit file must be a regular file")
    return descriptor


def _stable_tuple(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _physical_identity(metadata: os.stat_result) -> dict[str, JsonValue]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "link_count": metadata.st_nlink,
        "owner_scope": (
            "current_effective_user"
            if metadata.st_uid == os.geteuid()
            else "different_effective_user"
        ),
    }


def _require_owned_immutable(metadata: os.stat_result, label: str) -> None:
    if metadata.st_uid != os.geteuid():
        raise ContractError(f"{label} must be owned by the current effective user")
    if metadata.st_mode & 0o022:
        raise ContractError(f"{label} must not be group/world writable")


def _hash_open_file(
    descriptor: int,
    label: str,
    *,
    executable: bool | None = None,
) -> tuple[dict[str, JsonValue], bytes | None]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise ContractError(f"{label} must be a regular file")
    _require_owned_immutable(before, label)
    if before.st_nlink != 1:
        raise ContractError(f"{label} must not have mutable hard-link aliases")
    if executable is True and before.st_mode & 0o111 == 0:
        raise ContractError(f"{label} must be executable")
    if executable is False and before.st_mode & 0o111:
        raise ContractError(f"{label} must not be executable")
    if before.st_size > MAX_FILE_BYTES:
        raise ContractError(f"{label} exceeds the fixed file-size bound")
    digest = hashlib.sha256()
    captured = bytearray() if before.st_size <= MAX_EXTERNAL_JSON_BYTES else None
    total = 0
    while block := os.read(descriptor, _CHUNK_SIZE):
        total += len(block)
        if total > before.st_size or total > MAX_FILE_BYTES:
            raise ContractError(f"{label} changed or exceeded bounds while read")
        digest.update(block)
        if captured is not None:
            captured.extend(block)
    after = os.fstat(descriptor)
    if total != before.st_size or _stable_tuple(before) != _stable_tuple(after):
        raise ContractError(f"{label} changed while it was read")
    record = {
        **_physical_identity(before),
        "size_bytes": before.st_size,
        "sha256": f"sha256:{digest.hexdigest()}",
    }
    return record, None if captured is None else bytes(captured)


@dataclass(slots=True)
class _ScanState:
    files: list[dict[str, JsonValue]] = field(default_factory=list)
    total_size: int = 0
    entry_count: int = 0


def _scan_open_tree(root_descriptor: int) -> tuple[dict[str, JsonValue], list[JsonValue]]:
    root_before = os.fstat(root_descriptor)
    if not stat.S_ISDIR(root_before.st_mode):
        raise ContractError("scan root must be a directory")
    _require_owned_immutable(root_before, "scan root")
    state = _ScanState()

    def visit(descriptor: int, prefix: PurePosixPath, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise ContractError("scan tree exceeds the fixed depth bound")
        directory_before = os.fstat(descriptor)
        names: list[str] = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                state.entry_count += 1
                if state.entry_count > MAX_ENTRIES:
                    raise ContractError("scan tree exceeds the fixed entry-count bound")
                names.append(entry.name)
        for name in sorted(names):
            if (
                not name
                or name in {".", ".."}
                or name.startswith(".")
                or any(ord(character) < _CONTROL_LIMIT for character in name)
            ):
                raise ContractError("scan tree contains a forbidden entry name")
            relative = prefix / name
            relative_text = relative.as_posix()
            if len(relative_text.encode("utf-8")) > MAX_PATH_BYTES:
                raise ContractError("scan tree contains an overlong relative path")
            metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise ContractError(f"symlink is forbidden in scan tree: {relative_text}")
            if stat.S_ISDIR(metadata.st_mode):
                _require_owned_immutable(metadata, f"directory {relative_text}")
                child = os.open(name, _directory_flags(), dir_fd=descriptor)
                try:
                    if _stable_tuple(os.fstat(child)) != _stable_tuple(metadata):
                        raise ContractError(f"directory replaced during scan: {relative_text}")
                    visit(child, relative, depth + 1)
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise ContractError(f"special file is forbidden in scan tree: {relative_text}")
            if len(state.files) >= MAX_FILES:
                raise ContractError("scan tree exceeds the fixed file-count bound")
            file_descriptor = os.open(name, _file_flags(), dir_fd=descriptor)
            try:
                observed, _captured = _hash_open_file(
                    file_descriptor,
                    f"file {relative_text}",
                    executable=None,
                )
            finally:
                os.close(file_descriptor)
            if (
                cast("int", observed["device"]) != metadata.st_dev
                or cast("int", observed["inode"]) != metadata.st_ino
            ):
                raise ContractError(f"file replaced during scan: {relative_text}")
            size = cast("int", observed["size_bytes"])
            state.total_size += size
            if state.total_size > MAX_TOTAL_BYTES:
                raise ContractError("scan tree exceeds the fixed total-size bound")
            state.files.append({"path": relative_text, **observed})
        if _stable_tuple(directory_before) != _stable_tuple(os.fstat(descriptor)):
            raise ContractError(f"directory changed during scan: {prefix.as_posix() or '.'}")

    visit(root_descriptor, PurePosixPath(), 0)
    root_after = os.fstat(root_descriptor)
    if _stable_tuple(root_before) != _stable_tuple(root_after):
        raise ContractError("scan root changed while it was read")
    state.files.sort(key=lambda item: cast("str", item["path"]))
    files: list[JsonValue] = list(state.files)
    root: dict[str, JsonValue] = {
        **_physical_identity(root_before),
        "file_count": len(files),
        "total_size_bytes": state.total_size,
        "closure_sha256": canonical_identity(files),
    }
    return root, files


def _reject_runtime_injection(path: str) -> None:
    pure_path = PurePosixPath(path)
    basename = pure_path.name.casefold()
    top_level_stem = pure_path.parts[0].split(".", 1)[0].casefold()
    if basename.endswith((".pth", ".egg-link")) or top_level_stem in _FORBIDDEN_RUNTIME_STEMS:
        raise ContractError(
            f"supplied package-root byte closure contains import-path injection: {path}"
        )


def _read_relative_file(
    root_descriptor: int,
    relative_name: str,
    expected_files: dict[str, dict[str, JsonValue]],
) -> bytes:
    relative = PurePosixPath(_relative(relative_name, "relative file"))
    directory = os.dup(root_descriptor)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, _directory_flags(), dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(relative.parts[-1], _file_flags(), dir_fd=directory)
        try:
            observed, captured = _hash_open_file(
                descriptor,
                f"file {relative_name}",
                executable=None,
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
    expected = expected_files.get(relative_name)
    if expected is None or any(
        observed[field] != expected[field] for field in ("device", "inode", "size_bytes", "sha256")
    ):
        raise ContractError(f"file changed after tree scan: {relative_name}")
    if captured is None:
        raise ContractError(f"file exceeds the bounded metadata-read size: {relative_name}")
    return captured


def _file_map(files: list[JsonValue]) -> dict[str, dict[str, JsonValue]]:
    return {
        cast("str", _mapping(item, "files[]")["path"]): _mapping(item, "files[]") for item in files
    }


def _normalize_distribution_name(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", value).lower()
    if not normalized or any(
        character not in "abcdefghijklmnopqrstuvwxyz0123456789-" for character in normalized
    ):
        raise ContractError("distribution name is not canonical")
    return normalized


def closed_runtime_environment() -> list[JsonValue]:
    """Return the exact future worker environment allowlist."""
    return [{"name": name, "value": value} for name, value in _RUNTIME_ENVIRONMENT]


def verify_runtime_scan_spec(value: JsonValue) -> dict[str, JsonValue]:
    """Verify a canonical, execution-free runtime scan declaration."""
    spec = _mapping(value, "mlx_runtime_scan_spec")
    fields = {
        "record_type",
        "schema_version",
        "python",
        "expected_distributions",
        "selected_module_files",
        "environment",
    }
    _keys(spec, fields, "mlx_runtime_scan_spec")
    if spec["record_type"] != "mlx_runtime_scan_spec" or spec["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported MLX runtime scan specification")
    python = _mapping(spec["python"], "runtime_scan_spec.python")
    _keys(
        python,
        {"implementation", "version", "abi", "platform"},
        "runtime_scan_spec.python",
    )
    for field_name in ("implementation", "version", "abi", "platform"):
        _text(python[field_name], f"runtime_scan_spec.python.{field_name}", maximum=256)
    distributions: list[dict[str, JsonValue]] = []
    for index, item in enumerate(
        _array(
            spec["expected_distributions"], "runtime_scan_spec.expected_distributions", maximum=256
        )
    ):
        distribution = _mapping(item, f"expected_distributions[{index}]")
        _keys(distribution, {"name", "version"}, f"expected_distributions[{index}]")
        name = _normalize_distribution_name(
            _text(distribution["name"], f"expected_distributions[{index}].name", maximum=128)
        )
        version = _text(
            distribution["version"],
            f"expected_distributions[{index}].version",
            maximum=256,
        )
        distributions.append({"name": name, "version": version})
    if len(distributions) < MIN_REQUIRED_DISTRIBUTIONS:
        raise ContractError("runtime scan must bind at least MLX and MLX-LM")
    names = [cast("str", item["name"]) for item in distributions]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ContractError("expected distributions must be unique and sorted")
    if not {"mlx", "mlx-lm"}.issubset(names):
        raise ContractError("runtime scan must include exact mlx and mlx-lm distributions")
    modules = [
        _relative(item, f"selected_module_files[{index}]")
        for index, item in enumerate(
            _array(
                spec["selected_module_files"],
                "runtime_scan_spec.selected_module_files",
                maximum=256,
            )
        )
    ]
    if not modules or modules != sorted(modules) or len(modules) != len(set(modules)):
        raise ContractError("selected module files must be non-empty, unique, and sorted")
    required_modules = {
        "mlx/__init__.py",
        "mlx_lm/__init__.py",
        "mlx_lm/generate.py",
        "mlx_lm/models/cache.py",
        "mlx_lm/sample_utils.py",
        "mlx_lm/utils.py",
    }
    if not required_modules.issubset(modules):
        raise ContractError("selected module closure omits required direct-runner modules")
    environment = _array(spec["environment"], "runtime_scan_spec.environment", maximum=32)
    expected_environment = closed_runtime_environment()
    if canonical_json(environment) != canonical_json(expected_environment):
        raise ContractError("runtime environment must equal the closed allowlist")
    return dict(spec)


def load_runtime_scan_spec(path: Path) -> dict[str, JsonValue]:
    """Load one canonical runtime scan specification without following its final symlink."""
    return verify_runtime_scan_spec(
        load_canonical_json_file(path, "MLX runtime scan specification")
    )


def _metadata_headers(data: bytes, label: str) -> dict[str, list[str]]:
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} must use UTF-8 metadata headers") from error
    unfolded: list[str] = []
    for line in text.splitlines():
        if not line:
            break
        if line[:1].isspace():
            if not unfolded:
                raise ContractError(f"{label} has an invalid folded header")
            unfolded[-1] += line.strip()
        else:
            unfolded.append(line)
    headers: dict[str, list[str]] = {}
    for line in unfolded:
        name, separator, value = line.partition(":")
        if not separator:
            raise ContractError(f"{label} has a malformed metadata header")
        headers.setdefault(name.lower(), []).append(value.strip())
    return headers


def _runtime_distributions(
    root_descriptor: int,
    files: list[JsonValue],
) -> list[JsonValue]:
    file_records = _file_map(files)
    metadata_paths = sorted(
        path
        for path in file_records
        if path.count("/") == 1 and path.endswith(".dist-info/METADATA")
    )
    distributions: list[JsonValue] = []
    for path in metadata_paths:
        headers = _metadata_headers(
            _read_relative_file(root_descriptor, path, file_records),
            path,
        )
        names = headers.get("name", [])
        versions = headers.get("version", [])
        if len(names) != 1 or len(versions) != 1:
            raise ContractError(f"{path} must contain one Name and one Version")
        requirements = sorted(headers.get("requires-dist", []))
        distribution_directory = PurePosixPath(path).parent
        direct_url_path = (distribution_directory / "direct_url.json").as_posix()
        direct_url_sha256: JsonValue = None
        if direct_url_path in file_records:
            direct_url = _external_object(
                _read_relative_file(root_descriptor, direct_url_path, file_records),
                direct_url_path,
            )
            directory_info = direct_url.get("dir_info")
            if isinstance(directory_info, dict) and directory_info.get("editable") is True:
                raise ContractError(f"editable install is forbidden: {direct_url_path}")
            direct_url_sha256 = file_records[direct_url_path]["sha256"]
        distributions.append(
            {
                "name": _normalize_distribution_name(names[0]),
                "version": _text(versions[0], f"{path} Version", maximum=256),
                "metadata_path": path,
                "metadata_sha256": file_records[path]["sha256"],
                "requires_dist": cast("list[JsonValue]", requirements),
                "editable": False,
                "direct_url_sha256": direct_url_sha256,
            }
        )
    names = [cast("str", _mapping(item, "distribution")["name"]) for item in distributions]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ContractError("installed distribution metadata is duplicate or not canonical")
    return distributions


def _verify_file_records(
    value: JsonValue,
    label: str,
) -> tuple[list[JsonValue], int]:
    files = _array(value, label)
    normalized: list[JsonValue] = []
    total = 0
    for index, item in enumerate(files):
        record = _mapping(item, f"{label}[{index}]")
        _keys(
            record,
            {
                "path",
                "device",
                "inode",
                "mode",
                "link_count",
                "owner_scope",
                "size_bytes",
                "sha256",
            },
            f"{label}[{index}]",
        )
        normalized_record: dict[str, JsonValue] = {
            "path": _relative(record["path"], f"{label}[{index}].path"),
            "device": _integer(record["device"], f"{label}[{index}].device"),
            "inode": _integer(record["inode"], f"{label}[{index}].inode", minimum=1),
            "mode": _integer(record["mode"], f"{label}[{index}].mode", maximum=0o7777),
            "link_count": _integer(
                record["link_count"],
                f"{label}[{index}].link_count",
                minimum=1,
            ),
            "owner_scope": _text(
                record["owner_scope"],
                f"{label}[{index}].owner_scope",
                maximum=64,
            ),
            "size_bytes": _integer(
                record["size_bytes"],
                f"{label}[{index}].size_bytes",
                maximum=MAX_FILE_BYTES,
            ),
            "sha256": _sha256(record["sha256"], f"{label}[{index}].sha256"),
        }
        if normalized_record["link_count"] != 1:
            raise ContractError(f"{label}[{index}] must have exactly one hard link")
        if normalized_record["owner_scope"] not in {
            "current_effective_user",
            "synthetic_fixture",
        }:
            raise ContractError(f"{label}[{index}] has an unsupported owner scope")
        if cast("int", normalized_record["mode"]) & 0o022:
            raise ContractError(f"{label}[{index}] must not be group/world writable")
        normalized.append(normalized_record)
        total += cast("int", normalized_record["size_bytes"])
        if total > MAX_TOTAL_BYTES:
            raise ContractError(f"{label} exceeds the fixed total-size bound")
    paths = [cast("str", _mapping(item, "file")["path"]) for item in normalized]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise ContractError(f"{label} paths must be unique and sorted")
    return normalized, total


def _verify_physical_file(
    value: JsonValue,
    label: str,
    *,
    require_executable: bool | None,
) -> dict[str, JsonValue]:
    record = _mapping(value, label)
    _keys(
        record,
        {
            "device",
            "inode",
            "mode",
            "link_count",
            "owner_scope",
            "size_bytes",
            "sha256",
        },
        label,
    )
    parsed: dict[str, JsonValue] = {
        "device": _integer(record["device"], f"{label}.device"),
        "inode": _integer(record["inode"], f"{label}.inode", minimum=1),
        "mode": _integer(record["mode"], f"{label}.mode", maximum=0o7777),
        "link_count": _integer(record["link_count"], f"{label}.link_count", minimum=1),
        "owner_scope": _text(record["owner_scope"], f"{label}.owner_scope", maximum=64),
        "size_bytes": _integer(
            record["size_bytes"],
            f"{label}.size_bytes",
            maximum=MAX_FILE_BYTES,
        ),
        "sha256": _sha256(record["sha256"], f"{label}.sha256"),
    }
    if parsed["link_count"] != 1:
        raise ContractError(f"{label} must have exactly one hard link")
    if parsed["owner_scope"] not in {"current_effective_user", "synthetic_fixture"}:
        raise ContractError(f"{label} has an unsupported owner scope")
    mode = cast("int", parsed["mode"])
    if mode & 0o022:
        raise ContractError(f"{label} must not be group/world writable")
    if require_executable is True and mode & 0o111 == 0:
        raise ContractError(f"{label} must be executable")
    if require_executable is False and mode & 0o111:
        raise ContractError(f"{label} must not be executable")
    return parsed


def _verify_root(
    value: JsonValue,
    files: list[JsonValue],
    total: int,
    label: str,
) -> dict[str, JsonValue]:
    root = _mapping(value, label)
    _keys(
        root,
        {
            "device",
            "inode",
            "mode",
            "link_count",
            "owner_scope",
            "file_count",
            "total_size_bytes",
            "closure_sha256",
        },
        label,
    )
    _integer(root["device"], f"{label}.device")
    _integer(root["inode"], f"{label}.inode", minimum=1)
    mode = _integer(root["mode"], f"{label}.mode", maximum=0o7777)
    _integer(root["link_count"], f"{label}.link_count", minimum=1)
    owner = _text(root["owner_scope"], f"{label}.owner_scope", maximum=64)
    if owner not in {"current_effective_user", "synthetic_fixture"}:
        raise ContractError(f"{label} has an unsupported owner scope")
    if mode & 0o022:
        raise ContractError(f"{label} must not be group/world writable")
    if root["file_count"] != len(files) or root["total_size_bytes"] != total:
        raise ContractError(f"{label} file totals drift")
    if _sha256(root["closure_sha256"], f"{label}.closure_sha256") != canonical_identity(files):
        raise ContractError(f"{label} closure digest mismatch")
    return dict(root)


def _verify_distributions(value: JsonValue) -> list[JsonValue]:
    distributions = _array(value, "mlx_runtime_manifest.distributions", maximum=256)
    parsed: list[JsonValue] = []
    for index, item in enumerate(distributions):
        distribution = _mapping(item, f"distributions[{index}]")
        _keys(
            distribution,
            {
                "name",
                "version",
                "metadata_path",
                "metadata_sha256",
                "requires_dist",
                "editable",
                "direct_url_sha256",
            },
            f"distributions[{index}]",
        )
        requirements = [
            _text(requirement, f"distributions[{index}].requires_dist[]", maximum=1_024)
            for requirement in _array(
                distribution["requires_dist"],
                f"distributions[{index}].requires_dist",
                maximum=256,
            )
        ]
        if requirements != sorted(requirements):
            raise ContractError("distribution requirements must be sorted")
        if _boolean(distribution["editable"], f"distributions[{index}].editable"):
            raise ContractError("editable runtime distributions are forbidden")
        direct_url_value = distribution["direct_url_sha256"]
        direct_url_sha256 = (
            None
            if direct_url_value is None
            else _sha256(direct_url_value, f"distributions[{index}].direct_url_sha256")
        )
        parsed.append(
            {
                "name": _normalize_distribution_name(
                    _text(distribution["name"], f"distributions[{index}].name", maximum=128)
                ),
                "version": _text(
                    distribution["version"],
                    f"distributions[{index}].version",
                    maximum=256,
                ),
                "metadata_path": _relative(
                    distribution["metadata_path"],
                    f"distributions[{index}].metadata_path",
                ),
                "metadata_sha256": _sha256(
                    distribution["metadata_sha256"],
                    f"distributions[{index}].metadata_sha256",
                ),
                "requires_dist": cast("list[JsonValue]", requirements),
                "editable": False,
                "direct_url_sha256": direct_url_sha256,
            }
        )
    names = [cast("str", _mapping(item, "distribution")["name"]) for item in parsed]
    if names != sorted(names) or len(names) != len(set(names)):
        raise ContractError("runtime distributions must be unique and sorted")
    if not {"mlx", "mlx-lm"}.issubset(names):
        raise ContractError("runtime manifest omits mlx or mlx-lm")
    return parsed


def compile_runtime_manifest(
    scan_spec: JsonValue,
    runtime_root: Path,
    interpreter: Path,
    worker_program: Path,
) -> dict[str, JsonValue]:
    """Compile a no-import supplied package-root byte closure."""
    spec = verify_runtime_scan_spec(scan_spec)
    root_descriptor = _open_directory(runtime_root)
    try:
        root, files = _scan_open_tree(root_descriptor)
        file_records = _file_map(files)
        for path in file_records:
            _reject_runtime_injection(path)
        modules = cast("list[JsonValue]", spec["selected_module_files"])
        for module in modules:
            module_path = cast("str", module)
            if module_path not in file_records:
                raise ContractError(
                    "selected module is absent from supplied package-root byte closure: "
                    f"{module_path}"
                )
        distributions = _runtime_distributions(root_descriptor, files)
    finally:
        os.close(root_descriptor)
    expected = cast("list[JsonValue]", spec["expected_distributions"])
    observed_projection = [
        {
            "name": _mapping(item, "distribution")["name"],
            "version": _mapping(item, "distribution")["version"],
        }
        for item in distributions
    ]
    if canonical_json(observed_projection) != canonical_json(expected):
        raise ContractError("installed distribution set/version differs from scan specification")
    interpreter_descriptor = _open_file(interpreter)
    try:
        interpreter_record, _interpreter_bytes = _hash_open_file(
            interpreter_descriptor,
            "Python interpreter",
            executable=True,
        )
    finally:
        os.close(interpreter_descriptor)
    worker_descriptor = _open_file(worker_program)
    try:
        worker_record, _worker_bytes = _hash_open_file(
            worker_descriptor,
            "worker program",
            executable=False,
        )
    finally:
        os.close(worker_descriptor)
    manifest: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_manifest",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "offline_filesystem_manifest",
        "scan_spec_id": canonical_identity(spec),
        "python": spec["python"],
        "interpreter": interpreter_record,
        "worker_program": worker_record,
        "environment": spec["environment"],
        "distributions": distributions,
        "selected_module_files": modules,
        "package_root": root,
        "files": files,
        "imports_performed": 0,
        "process_actions": 0,
        "network_actions": 0,
    }
    manifest["manifest_id"] = canonical_identity(manifest)
    return verify_runtime_manifest(manifest)


def verify_runtime_manifest(value: JsonValue) -> dict[str, JsonValue]:
    """Verify one supplied package-root byte closure without importing it."""
    manifest = _mapping(value, "mlx_runtime_manifest")
    fields = {
        "record_type",
        "schema_version",
        "evidence_kind",
        "scan_spec_id",
        "python",
        "interpreter",
        "worker_program",
        "environment",
        "distributions",
        "selected_module_files",
        "package_root",
        "files",
        "imports_performed",
        "process_actions",
        "network_actions",
        "manifest_id",
    }
    _keys(manifest, fields, "mlx_runtime_manifest")
    if (
        manifest["record_type"] != "mlx_runtime_manifest"
        or manifest["schema_version"] != SCHEMA_VERSION
        or manifest["evidence_kind"] not in {"offline_filesystem_manifest", "synthetic_fixture"}
    ):
        raise ContractError("unsupported MLX runtime manifest")
    evidence_kind = cast("str", manifest["evidence_kind"])
    expected_owner_scope = (
        "synthetic_fixture" if evidence_kind == "synthetic_fixture" else "current_effective_user"
    )
    scan_spec_id = _sha256(manifest["scan_spec_id"], "mlx_runtime_manifest.scan_spec_id")
    python = _mapping(manifest["python"], "mlx_runtime_manifest.python")
    _keys(python, {"implementation", "version", "abi", "platform"}, "mlx_runtime_manifest.python")
    for field_name in ("implementation", "version", "abi", "platform"):
        _text(python[field_name], f"mlx_runtime_manifest.python.{field_name}", maximum=256)
    interpreter = _verify_physical_file(
        manifest["interpreter"],
        "mlx_runtime_manifest.interpreter",
        require_executable=True,
    )
    worker_program = _verify_physical_file(
        manifest["worker_program"],
        "mlx_runtime_manifest.worker_program",
        require_executable=False,
    )
    if canonical_json(manifest["environment"]) != canonical_json(closed_runtime_environment()):
        raise ContractError("runtime manifest environment differs from the closed allowlist")
    distributions = _verify_distributions(manifest["distributions"])
    files, total = _verify_file_records(manifest["files"], "mlx_runtime_manifest.files")
    package_root = _verify_root(
        manifest["package_root"],
        files,
        total,
        "mlx_runtime_manifest.package_root",
    )
    physical_scopes = {
        cast("str", interpreter["owner_scope"]),
        cast("str", worker_program["owner_scope"]),
        cast("str", package_root["owner_scope"]),
        *(cast("str", _mapping(item, "runtime file")["owner_scope"]) for item in files),
    }
    if physical_scopes != {expected_owner_scope}:
        raise ContractError("runtime evidence kind differs from its physical owner scopes")
    file_records = _file_map(files)
    for path in file_records:
        _reject_runtime_injection(path)
    for distribution_value in distributions:
        distribution = _mapping(distribution_value, "distribution")
        path = cast("str", distribution["metadata_path"])
        file_record = file_records.get(path)
        if file_record is None or file_record["sha256"] != distribution["metadata_sha256"]:
            raise ContractError("distribution metadata is outside or mismatched with the closure")
        direct_url_digest = distribution["direct_url_sha256"]
        direct_url_path = (PurePosixPath(path).parent / "direct_url.json").as_posix()
        direct_url_record = file_records.get(direct_url_path)
        if (direct_url_digest is None) != (direct_url_record is None):
            raise ContractError("distribution direct URL projection differs from closure")
        if direct_url_record is not None and direct_url_record["sha256"] != direct_url_digest:
            raise ContractError("distribution direct URL is mismatched with closure")
    modules = [
        _relative(item, "mlx_runtime_manifest.selected_module_files[]")
        for item in _array(
            manifest["selected_module_files"],
            "mlx_runtime_manifest.selected_module_files",
            maximum=256,
        )
    ]
    if modules != sorted(modules) or len(modules) != len(set(modules)):
        raise ContractError("selected module files must be unique and sorted")
    if any(module not in file_records for module in modules):
        raise ContractError("selected module file is outside the package closure")
    reconstructed_spec = verify_runtime_scan_spec(
        {
            "record_type": "mlx_runtime_scan_spec",
            "schema_version": SCHEMA_VERSION,
            "python": dict(python),
            "expected_distributions": [
                {
                    "name": _mapping(item, "distribution")["name"],
                    "version": _mapping(item, "distribution")["version"],
                }
                for item in distributions
            ],
            "selected_module_files": list(cast("list[JsonValue]", modules)),
            "environment": manifest["environment"],
        }
    )
    if canonical_identity(reconstructed_spec) != scan_spec_id:
        raise ContractError("runtime manifest scan specification identity mismatch")
    for field_name in ("imports_performed", "process_actions", "network_actions"):
        if _integer(manifest[field_name], f"mlx_runtime_manifest.{field_name}") != 0:
            raise ContractError("runtime manifest compilation must perform zero physical actions")
    identity = _sha256(manifest["manifest_id"], "mlx_runtime_manifest.manifest_id")
    content = dict(manifest)
    del content["manifest_id"]
    if identity != canonical_identity(content):
        raise ContractError("MLX runtime manifest identity mismatch")
    return dict(manifest)


def load_runtime_manifest(path: Path) -> dict[str, JsonValue]:
    """Load one canonical runtime manifest."""
    return verify_runtime_manifest(load_canonical_json_file(path, "MLX runtime manifest"))


def _external_object(data: bytes, label: str) -> dict[str, object]:
    if len(data) > MAX_EXTERNAL_JSON_BYTES:
        raise ContractError(f"{label} exceeds the fixed metadata-read bound")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        output: dict[str, object] = {}
        for key, item in pairs:
            if key in output:
                raise ContractError(f"{label} contains duplicate JSON key: {key}")
            output[key] = item
        return output

    def reject_constant(value: str) -> None:
        raise ContractError(f"{label} contains non-finite JSON constant: {value}")

    try:
        value = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} must contain valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ContractError(f"{label} must contain a JSON object")
    return value


def _contains_remote_code_marker(value: object) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"auto_map", "model_file", "trust_remote_code"} and item not in (
                None,
                False,
                "",
                {},
                [],
            ):
                return True
            if _contains_remote_code_marker(item):
                return True
    elif isinstance(value, list):
        return any(_contains_remote_code_marker(item) for item in value)
    return False


def compile_model_manifest(model_root: Path) -> dict[str, JsonValue]:
    """Compile one complete local MLX snapshot without loading or resolving it."""
    root_descriptor = _open_directory(model_root)
    try:
        root, files = _scan_open_tree(root_descriptor)
        file_records = _file_map(files)
        paths = sorted(file_records)
        for path in paths:
            pure = PurePosixPath(path)
            if len(pure.parts) != 1:
                raise ContractError("MLX model snapshot must be a flat materialized directory")
            if pure.suffix not in _MODEL_SUFFIXES:
                raise ContractError(f"unsupported file in MLX model snapshot: {path}")
            if pure.suffix in {".py", ".so", ".dylib", ".pyd"}:
                raise ContractError(
                    f"executable/custom code is forbidden in model snapshot: {path}"
                )
            if cast("int", file_records[path]["mode"]) & 0o111:
                raise ContractError(f"executable files are forbidden in model snapshot: {path}")
        required = {"config.json", "tokenizer_config.json"}
        if not required.issubset(paths):
            raise ContractError("model snapshot lacks config.json or tokenizer_config.json")
        config = _external_object(
            _read_relative_file(root_descriptor, "config.json", file_records),
            "config.json",
        )
        tokenizer_config = _external_object(
            _read_relative_file(root_descriptor, "tokenizer_config.json", file_records),
            "tokenizer_config.json",
        )
        if _contains_remote_code_marker(config) or _contains_remote_code_marker(tokenizer_config):
            raise ContractError("model snapshot requests remote or custom code")
        weights = sorted(
            path for path in paths if path.startswith("model") and path.endswith(".safetensors")
        )
        if not weights:
            raise ContractError("model snapshot has no model*.safetensors weights")
        index_path = "model.safetensors.index.json"
        referenced: list[str] = []
        if len(weights) > 1 and index_path not in paths:
            raise ContractError("sharded model snapshot lacks model.safetensors.index.json")
        if index_path in paths:
            index = _external_object(
                _read_relative_file(root_descriptor, index_path, file_records),
                index_path,
            )
            weight_map = index.get("weight_map")
            if not isinstance(weight_map, dict) or not weight_map:
                raise ContractError("model weight index has no non-empty weight_map")
            referenced_values = list(weight_map.values())
            if any(not isinstance(item, str) for item in referenced_values):
                raise ContractError("model weight index contains a non-string shard path")
            referenced = sorted(set(cast("list[str]", referenced_values)))
            if referenced != weights:
                raise ContractError("model weight index has missing or extra shards")
        tokenizer_files = sorted(
            path
            for path in paths
            if path in {"tokenizer.json", "tokenizer.model", "tiktoken.model"}
            or path.endswith(".tiktoken")
        )
        if not tokenizer_files:
            raise ContractError("model snapshot has no tokenizer vocabulary artifact")
        if "chat_template.jinja" in paths:
            template_bytes = _read_relative_file(
                root_descriptor,
                "chat_template.jinja",
                file_records,
            )
            chat_template: dict[str, JsonValue] = {
                "source": "chat_template.jinja",
                "sha256": digest_bytes(template_bytes),
            }
        else:
            template = tokenizer_config.get("chat_template")
            if isinstance(template, str) and template:
                chat_template = {
                    "source": "tokenizer_config.json:chat_template",
                    "sha256": digest_bytes(template.encode("utf-8")),
                }
            else:
                chat_template = {"source": "absent", "sha256": None}
    finally:
        os.close(root_descriptor)
    manifest: dict[str, JsonValue] = {
        "record_type": "mlx_model_manifest",
        "schema_version": SCHEMA_VERSION,
        "evidence_kind": "offline_filesystem_manifest",
        "representation": "mlx_snapshot",
        "resolved_directory": root,
        "files": files,
        "config_sha256": file_records["config.json"]["sha256"],
        "tokenizer_config_sha256": file_records["tokenizer_config.json"]["sha256"],
        "tokenizer_files": list(cast("list[JsonValue]", tokenizer_files)),
        "weight_files": list(cast("list[JsonValue]", weights)),
        "weight_index_path": index_path if index_path in paths else None,
        "weight_index_sha256": (
            file_records[index_path]["sha256"] if index_path in paths else None
        ),
        "weight_index_referenced_shards": cast("list[JsonValue]", referenced),
        "chat_template": chat_template,
        "custom_code": "forbidden_absent",
        "network_resolution": "forbidden_not_performed",
        "model_loads": 0,
        "tokenizer_loads": 0,
        "network_actions": 0,
    }
    manifest["manifest_id"] = canonical_identity(manifest)
    return verify_model_manifest(manifest)


def verify_model_manifest(value: JsonValue) -> dict[str, JsonValue]:
    """Verify one complete no-follow MLX snapshot manifest."""
    manifest = _mapping(value, "mlx_model_manifest")
    fields = {
        "record_type",
        "schema_version",
        "evidence_kind",
        "representation",
        "resolved_directory",
        "files",
        "config_sha256",
        "tokenizer_config_sha256",
        "tokenizer_files",
        "weight_files",
        "weight_index_path",
        "weight_index_sha256",
        "weight_index_referenced_shards",
        "chat_template",
        "custom_code",
        "network_resolution",
        "model_loads",
        "tokenizer_loads",
        "network_actions",
        "manifest_id",
    }
    _keys(manifest, fields, "mlx_model_manifest")
    if (
        manifest["record_type"] != "mlx_model_manifest"
        or manifest["schema_version"] != SCHEMA_VERSION
        or manifest["evidence_kind"] not in {"offline_filesystem_manifest", "synthetic_fixture"}
        or manifest["representation"] != "mlx_snapshot"
        or manifest["custom_code"] != "forbidden_absent"
        or manifest["network_resolution"] != "forbidden_not_performed"
    ):
        raise ContractError("unsupported MLX model manifest")
    evidence_kind = cast("str", manifest["evidence_kind"])
    expected_owner_scope = (
        "synthetic_fixture" if evidence_kind == "synthetic_fixture" else "current_effective_user"
    )
    files, total = _verify_file_records(manifest["files"], "mlx_model_manifest.files")
    file_records = _file_map(files)
    for path, record in file_records.items():
        pure = PurePosixPath(path)
        if len(pure.parts) != 1 or pure.suffix not in _MODEL_SUFFIXES:
            raise ContractError(f"unsupported path in MLX model manifest: {path}")
        if cast("int", record["mode"]) & 0o111:
            raise ContractError(f"executable file is forbidden in MLX model manifest: {path}")
    if not {"config.json", "tokenizer_config.json"}.issubset(file_records):
        raise ContractError("MLX model manifest lacks required configuration files")
    resolved_directory = _verify_root(
        manifest["resolved_directory"],
        files,
        total,
        "mlx_model_manifest.resolved_directory",
    )
    physical_scopes = {
        cast("str", resolved_directory["owner_scope"]),
        *(cast("str", _mapping(item, "model file")["owner_scope"]) for item in files),
    }
    if physical_scopes != {expected_owner_scope}:
        raise ContractError("model evidence kind differs from its physical owner scopes")
    for field_name, path in (
        ("config_sha256", "config.json"),
        ("tokenizer_config_sha256", "tokenizer_config.json"),
    ):
        digest = _sha256(manifest[field_name], f"mlx_model_manifest.{field_name}")
        if path not in file_records or file_records[path]["sha256"] != digest:
            raise ContractError(f"model manifest {field_name} is outside the file closure")
    tokenizer_files = [
        _relative(item, "mlx_model_manifest.tokenizer_files[]")
        for item in _array(
            manifest["tokenizer_files"],
            "mlx_model_manifest.tokenizer_files",
            maximum=256,
        )
    ]
    weight_files = [
        _relative(item, "mlx_model_manifest.weight_files[]")
        for item in _array(
            manifest["weight_files"],
            "mlx_model_manifest.weight_files",
            maximum=MAX_FILES,
        )
    ]
    for paths, label in (
        (tokenizer_files, "tokenizer files"),
        (weight_files, "weight files"),
    ):
        if not paths or paths != sorted(paths) or len(paths) != len(set(paths)):
            raise ContractError(f"MLX model {label} must be non-empty, unique, and sorted")
        if any(path not in file_records for path in paths):
            raise ContractError(f"MLX model {label} escape the file closure")
    actual_weights = sorted(
        path for path in file_records if path.startswith("model") and path.endswith(".safetensors")
    )
    if actual_weights != weight_files:
        raise ContractError("MLX model weight-file projection differs from the closure")
    actual_tokenizers = sorted(
        path
        for path in file_records
        if path in {"tokenizer.json", "tokenizer.model", "tiktoken.model"}
        or path.endswith(".tiktoken")
    )
    if actual_tokenizers != tokenizer_files:
        raise ContractError("MLX model tokenizer-file projection differs from the closure")
    expected_index_path = (
        "model.safetensors.index.json" if "model.safetensors.index.json" in file_records else None
    )
    index_value = manifest["weight_index_path"]
    index_path = (
        None
        if index_value is None
        else _relative(index_value, "mlx_model_manifest.weight_index_path")
    )
    if index_path != expected_index_path:
        raise ContractError("MLX model weight-index path projection differs from the closure")
    index_digest_value = manifest["weight_index_sha256"]
    referenced_shards = [
        _relative(item, "mlx_model_manifest.weight_index_referenced_shards[]")
        for item in _array(
            manifest["weight_index_referenced_shards"],
            "mlx_model_manifest.weight_index_referenced_shards",
            maximum=MAX_FILES,
        )
    ]
    if index_path is None:
        if index_digest_value is not None or referenced_shards:
            raise ContractError("absent MLX model weight index cannot have projected evidence")
    else:
        index_digest = _sha256(
            index_digest_value,
            "mlx_model_manifest.weight_index_sha256",
        )
        if file_records[index_path]["sha256"] != index_digest:
            raise ContractError("MLX model weight-index digest differs from the closure")
        if referenced_shards != weight_files:
            raise ContractError("MLX model weight-index shard projection differs from weights")
    if len(weight_files) > 1 and index_path is None:
        raise ContractError("sharded MLX model manifest requires a weight index")
    chat_template = _mapping(manifest["chat_template"], "mlx_model_manifest.chat_template")
    _keys(chat_template, {"source", "sha256"}, "mlx_model_manifest.chat_template")
    source = _text(chat_template["source"], "mlx_model_manifest.chat_template.source")
    if source == "absent":
        if chat_template["sha256"] is not None:
            raise ContractError("absent chat template cannot have a digest")
    else:
        template_digest = _sha256(
            chat_template["sha256"],
            "mlx_model_manifest.chat_template.sha256",
        )
        if source == "chat_template.jinja":
            if source not in file_records:
                raise ContractError("chat-template file is outside the model closure")
            if file_records[source]["sha256"] != template_digest:
                raise ContractError("chat-template digest differs from the file closure")
        if source not in {
            "chat_template.jinja",
            "tokenizer_config.json:chat_template",
        }:
            raise ContractError("unsupported chat-template source")
    for field_name in ("model_loads", "tokenizer_loads", "network_actions"):
        if _integer(manifest[field_name], f"mlx_model_manifest.{field_name}") != 0:
            raise ContractError("model manifest compilation must perform zero physical actions")
    identity = _sha256(manifest["manifest_id"], "mlx_model_manifest.manifest_id")
    content = dict(manifest)
    del content["manifest_id"]
    if identity != canonical_identity(content):
        raise ContractError("MLX model manifest identity mismatch")
    return dict(manifest)


def load_model_manifest(path: Path) -> dict[str, JsonValue]:
    """Load one canonical MLX model manifest."""
    return verify_model_manifest(load_canonical_json_file(path, "MLX model manifest"))


def write_manifest(path: Path, value: JsonValue) -> None:
    """Write one already-verified manifest without replacing a path."""
    if isinstance(value, dict) and value.get("record_type") == "mlx_runtime_manifest":
        verified = verify_runtime_manifest(value)
    else:
        verified = verify_model_manifest(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        data = canonical_json(verified)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
