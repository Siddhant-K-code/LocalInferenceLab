"""Parent-owned process, IPC, authorization, and replay custody for inert MLX refusal."""

from __future__ import annotations

import contextlib
import errno
import fcntl
import os
import signal
import socket
import stat
import struct
import sys
import time
from dataclasses import dataclass
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
from localinferencelab.custody import publish_bundle_at, read_closed_bundle
from localinferencelab.mlx_inert_worker import (
    AUTHORIZATION_LIFETIME_NS,
    ENVIRONMENT_ID,
    MAX_FRAME_BYTES,
    PROTOCOL_DESCRIPTOR,
    PROTOCOL_ID,
    REFUSAL_REASON,
    WORKER_CODE_ID,
    WORKER_DESCRIPTOR,
    WORKER_FD,
)
from localinferencelab.mlx_runner import (
    build_mlx_prospective_package,
    mlx_study_spec,
    verify_mlx_prospective_package,
)

SCHEMA_VERSION = "1.0"
DEFAULT_DEADLINE_NS = AUTHORIZATION_LIFETIME_NS
MAX_BUNDLE_FILE_BYTES = 1024 * 1024
EXPECTED_WORKER_PROGRAM_SHA256 = (
    "sha256:4b91716305c4d7acddfc911d9ff882c29dfc933b505503d7dff12cce0c042748"
)
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_NONCE_BYTES = 32
_PRIVATE_DIRECTORY_MODE = 0o700
_WORKER_ENVIRONMENT = {
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
    "TZ": "UTC",
}
_MESSAGE_SEQUENCE = cast("list[str]", PROTOCOL_DESCRIPTOR["sequence"])
_PARENT_MESSAGES = {"parent_hello", "authorize_once", "generate_once", "shutdown"}
_WORKER_MESSAGES = {
    "worker_identity",
    "authorization_ack",
    "result_or_terminal_error",
    "shutdown_ack",
}
_NON_ACTIONS = {
    "mlx_imports": 0,
    "mlx_lm_imports": 0,
    "metal_initializations": 0,
    "device_queries": 0,
    "model_loads": 0,
    "tokenizer_loads": 0,
    "inference_requests": 0,
    "physical_network_requests": 0,
    "listener_creations": 0,
    "dns_queries": 0,
    "proxy_actions": 0,
    "redirect_actions": 0,
    "shell_actions": 0,
    "arbitrary_command_actions": 0,
    "model_downloads": 0,
    "model_cache_mutations": 0,
    "cloud_actions": 0,
    "spend_actions": 0,
}
_ACTION_LEDGER = {
    "attempts": 1,
    "retries": 0,
    "warmups": 0,
    "worker_process_starts": 1,
    "socketpair_creations": 1,
    "authorizations_consumed": 1,
    "parent_frames": 4,
    "worker_frames": 4,
    "generate_once_commands": 1,
    "terminal_refusals": 1,
    "shutdowns": 1,
}


@dataclass(frozen=True, slots=True)
class InertCustodyReplayResult:
    """Verified summary of one physical inert-custody run."""

    bundle_root: str
    custody_record_id: str
    package_id: str
    protocol_id: str
    terminal_state: str
    refusal_reason: str
    child_exit_code: int
    authorization_consumptions: int
    process_actions: int
    socket_actions: int
    model_actions: int
    network_actions: int
    missing_requirements: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "custody_record_id": self.custody_record_id,
            "package_id": self.package_id,
            "protocol_id": self.protocol_id,
            "terminal_state": self.terminal_state,
            "refusal_reason": self.refusal_reason,
            "child_exit_code": self.child_exit_code,
            "authorization_consumptions": self.authorization_consumptions,
            "process_actions": self.process_actions,
            "socket_actions": self.socket_actions,
            "model_actions": self.model_actions,
            "network_actions": self.network_actions,
            "missing_requirements": self.missing_requirements,
        }


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = 64) -> list[JsonValue]:
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


def _nonce(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    try:
        decoded = decode_bytes(text)
    except ContractError as error:
        raise ContractError(f"{label} must be canonical URL-safe base64") from error
    if len(decoded) != _NONCE_BYTES:
        raise ContractError(f"{label} must encode exactly 32 bytes")
    return text


def _canonical_value(data: bytes, label: str) -> JsonValue:
    if len(data) > MAX_BUNDLE_FILE_BYTES:
        raise ContractError(f"{label} exceeds the custody artifact bound")
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def inert_custody_spec() -> dict[str, JsonValue]:
    """Return the exact refusal-only physical custody specification."""
    return {
        "record_type": "mlx_inert_custody_spec",
        "schema_version": SCHEMA_VERSION,
        "protocol": cast("dict[str, JsonValue]", PROTOCOL_DESCRIPTOR),
        "protocol_id": PROTOCOL_ID,
        "worker": cast("dict[str, JsonValue]", WORKER_DESCRIPTOR),
        "worker_code_id": WORKER_CODE_ID,
        "worker_program_sha256": EXPECTED_WORKER_PROGRAM_SHA256,
        "launch": {
            "mechanism": "os_posix_spawn_trusted_interpreter_with_sealed_anonymous_stdin",
            "interpreter_flags": ["-I", "-S", "-E", "-s", "-"],
            "worker_arguments": [],
            "worker_source": "parent_sealed_unlinked_output_root_snapshot_on_stdin",
            "child_ipc_fd": WORKER_FD,
            "stdio": "sealed_worker_source_then_devnull_stdin_and_devnull_stdout_stderr",
            "unrelated_file_descriptors": "enumerated_parent_descriptors_closed_by_spawn_actions",
            "environment": [
                {"name": name, "value": value}
                for name, value in sorted(_WORKER_ENVIRONMENT.items())
            ],
            "platform_injected_environment": (
                "__CF_USER_TEXT_ENCODING=current_effective_uid_encoding_on_darwin_only"
            ),
            "environment_id": ENVIRONMENT_ID,
            "shell": False,
            "arbitrary_command": False,
        },
        "authorization": {
            "action": "inert_refusal_only",
            "one_shot": True,
            "atomic_consumption": "exclusive_no_follow_output_root_marker",
            "binds_absolute_wall_expiry": True,
            "binds_absolute_monotonic_deadline": True,
            "authorizes_mlx_import": False,
            "authorizes_model_load": False,
            "authorizes_generation": False,
        },
        "output_custody": {
            "root": "explicit_preexisting_current_owner_mode_0700_directory",
            "physical_binding": "device_inode_mode_owner_scope_and_nonce_digest",
            "publication": "descriptor_relative_atomic_no_replace_receipt_last",
            "absolute_paths_published": False,
        },
        "result": {
            "only_status": "refused",
            "reason": REFUSAL_REASON,
            "generated_result_producer": False,
        },
        "deadline_ns": DEFAULT_DEADLINE_NS,
    }


def inert_custody_capability_report() -> dict[str, JsonValue]:
    """Report the additive refusal-only custody surface without taking physical actions."""
    return {
        "record_type": "mlx_inert_custody_capability_report",
        "schema_version": SCHEMA_VERSION,
        "action": "inert_refusal_only",
        "explicit_processful_command": "mlx custody-self-test",
        "worker_launch": True,
        "private_inherited_af_unix_socketpair": True,
        "canonical_bounded_protocol": True,
        "one_shot_authorization": True,
        "output_root_physical_binding": True,
        "closed_bundle_replay": True,
        "worker_program_sha256": EXPECTED_WORKER_PROGRAM_SHA256,
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "generated_result_producer": False,
        "production_worker_launch": False,
        "model_actions": 0,
        "network_actions": 0,
        "cache_mutations": 0,
        "process_socket_actions": "explicit_command_only",
    }


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


def _require_trusted_launch_metadata(metadata: os.stat_result, label: str) -> None:
    if metadata.st_uid not in {0, os.geteuid()} or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise ContractError(f"{label} must be root/current-owner and not group/world writable")


def _open_directory_no_follow(
    path: Path,
    label: str,
    *,
    trusted_launch_path: bool = False,
) -> int:
    if ".." in path.parts:
        raise ContractError(f"{label} path traversal is forbidden")
    absolute = path.absolute()
    descriptor = os.open(absolute.anchor, _directory_flags())
    try:
        if trusted_launch_path:
            _require_trusted_launch_metadata(os.fstat(descriptor), label)
        for part in absolute.parts[1:]:
            metadata = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            _reject_symlink(metadata, label)
            if trusted_launch_path:
                _require_trusted_launch_metadata(metadata, label)
            child = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
    except OSError as error:
        os.close(descriptor)
        if error.errno in {errno.ELOOP, errno.ENOTDIR}:
            raise ContractError(f"{label} has an unsafe path component") from error
        raise
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def _reject_symlink(metadata: os.stat_result, label: str) -> None:
    if stat.S_ISLNK(metadata.st_mode):
        raise ContractError(f"{label} path components must not be symlinks")


def _open_private_output_root(path: Path) -> int:
    descriptor = _open_directory_no_follow(path, "output root")
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        os.close(descriptor)
        raise ContractError("output root must be a current-owner mode-0700 directory")
    return descriptor


def _output_root_binding(descriptor: int, nonce: bytes) -> dict[str, JsonValue]:
    metadata = os.fstat(descriptor)
    binding: dict[str, JsonValue] = {
        "record_type": "mlx_inert_output_root_binding",
        "schema_version": SCHEMA_VERSION,
        "binding_mode": "physical_instance",
        "owner_scope": "current_effective_user",
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "nonce_sha256": digest_bytes(nonce),
    }
    binding["output_root_id"] = canonical_identity(binding)
    return binding


def _verify_output_root_binding(value: JsonValue) -> dict[str, JsonValue]:
    binding = _mapping(value, "mlx_inert_output_root_binding")
    fields = {
        "record_type",
        "schema_version",
        "binding_mode",
        "owner_scope",
        "device",
        "inode",
        "mode",
        "nonce_sha256",
        "output_root_id",
    }
    _keys(binding, fields, "mlx_inert_output_root_binding")
    if (
        binding["record_type"] != "mlx_inert_output_root_binding"
        or binding["schema_version"] != SCHEMA_VERSION
        or binding["binding_mode"] != "physical_instance"
        or binding["owner_scope"] != "current_effective_user"
    ):
        raise ContractError("unsupported inert output-root binding")
    _integer(binding["device"], "output_root.device")
    _integer(binding["inode"], "output_root.inode")
    if _integer(binding["mode"], "output_root.mode") != _PRIVATE_DIRECTORY_MODE:
        raise ContractError("inert output-root binding must record mode 0700")
    _sha256(binding["nonce_sha256"], "output_root.nonce_sha256")
    identity = _sha256(binding["output_root_id"], "output_root.output_root_id")
    content = dict(binding)
    del content["output_root_id"]
    if identity != canonical_identity(content):
        raise ContractError("inert output-root identity mismatch")
    return dict(binding)


def _revalidate_output_root_path(path: Path, retained_descriptor: int) -> None:
    current = _open_private_output_root(path)
    try:
        retained = os.fstat(retained_descriptor)
        observed = os.fstat(current)
        if (retained.st_dev, retained.st_ino) != (observed.st_dev, observed.st_ino):
            raise ContractError("output-root path was replaced after physical binding")
    finally:
        os.close(current)


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    return flags


def _read_launch_target(
    path: Path,
    label: str,
    *,
    executable: bool,
) -> tuple[dict[str, JsonValue], bytes]:
    resolved = path.resolve(strict=True)
    parent = _open_directory_no_follow(
        resolved.parent,
        label,
        trusted_launch_path=True,
    )
    try:
        descriptor = os.open(resolved.name, _file_flags(), dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{label} must be a regular file")
        _require_trusted_launch_metadata(before, label)
        if executable and before.st_mode & 0o111 == 0:
            raise ContractError(f"{label} must be executable")
        blocks: list[bytes] = []
        total = 0
        while block := os.read(descriptor, 1024 * 1024):
            total += len(block)
            if total > MAX_BUNDLE_FILE_BYTES and not executable:
                raise ContractError(f"{label} exceeds the custody artifact bound")
            blocks.append(block)
        after = os.fstat(descriptor)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        data = b"".join(blocks)
        if len(data) != before.st_size or stable_before != stable_after:
            raise ContractError(f"{label} changed while it was read")
        identity: dict[str, JsonValue] = {
            "basename": resolved.name,
            "device": before.st_dev,
            "inode": before.st_ino,
            "mode": stat.S_IMODE(before.st_mode),
            "size_bytes": before.st_size,
            "sha256": digest_bytes(data),
        }
        return identity, data
    finally:
        os.close(descriptor)


def _create_worker_snapshot_at(
    output_root_descriptor: int,
    worker_bytes: bytes,
    basename: str,
) -> tuple[int, dict[str, JsonValue]]:
    name = f".localinferencelab-mlx-worker-{os.urandom(32).hex()}"
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=output_root_descriptor)
    unlinked = False
    complete = False
    try:
        os.unlink(name, dir_fd=output_root_descriptor)
        unlinked = True
        os.fsync(output_root_descriptor)
        view = memoryview(worker_bytes)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise ContractError("worker snapshot write made no progress")
            written += count
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(worker_bytes):
            raise ContractError("worker snapshot identity mismatch")
        identity: dict[str, JsonValue] = {
            "basename": basename,
            "device": metadata.st_dev,
            "inode": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
            "size_bytes": metadata.st_size,
            "sha256": digest_bytes(worker_bytes),
        }
        os.lseek(descriptor, 0, os.SEEK_SET)
        complete = True
        return descriptor, identity
    finally:
        if not complete:
            os.close(descriptor)
            if not unlinked:
                os.unlink(name, dir_fd=output_root_descriptor)


def _verify_file_identity(value: JsonValue, label: str) -> dict[str, JsonValue]:
    identity = _mapping(value, label)
    fields = {"basename", "device", "inode", "mode", "size_bytes", "sha256"}
    _keys(identity, fields, label)
    basename = _text(identity["basename"], f"{label}.basename", maximum=255)
    if "/" in basename or "\\" in basename or basename in {".", ".."}:
        raise ContractError(f"{label}.basename must not contain a path")
    for field in ("device", "inode", "mode", "size_bytes"):
        _integer(identity[field], f"{label}.{field}")
    _sha256(identity["sha256"], f"{label}.sha256")
    return dict(identity)


def _open_descriptors() -> set[int]:
    directory = Path("/proc/self/fd") if Path("/proc/self/fd").is_dir() else Path("/dev/fd")
    try:
        candidates = {int(item.name) for item in directory.iterdir() if item.name.isdigit()}
    except OSError as error:
        raise ContractError("parent cannot enumerate open file descriptors") from error
    result: set[int] = set()
    for descriptor in candidates:
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        result.add(descriptor)
    return result


def _spawn_worker(
    interpreter: Path,
    worker_source_descriptor: int,
    child_endpoint: socket.socket,
) -> int:
    descriptors = _open_descriptors()
    minimum = max(descriptors | {WORKER_FD}) + 1
    duplicate_command = getattr(fcntl, "F_DUPFD_CLOEXEC", fcntl.F_DUPFD)
    sealed_source = fcntl.fcntl(worker_source_descriptor, duplicate_command, minimum)
    sealed_socket: int | None = None
    try:
        sealed_socket = fcntl.fcntl(
            child_endpoint.fileno(),
            duplicate_command,
            sealed_source + 1,
        )
        if duplicate_command == fcntl.F_DUPFD:
            os.set_inheritable(sealed_source, False)
            os.set_inheritable(sealed_socket, False)
        descriptors = _open_descriptors()
        file_actions: list[tuple[int, ...] | tuple[int, int, str, int, int]] = [
            (os.POSIX_SPAWN_DUP2, sealed_source, 0),
            (os.POSIX_SPAWN_OPEN, 1, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_OPEN, 2, os.devnull, os.O_WRONLY, 0),
            (os.POSIX_SPAWN_DUP2, sealed_socket, WORKER_FD),
        ]
        file_actions.extend(
            (os.POSIX_SPAWN_CLOSE, descriptor)
            for descriptor in sorted(descriptors)
            if descriptor >= WORKER_FD and descriptor != WORKER_FD
        )
        argv = (str(interpreter), "-I", "-S", "-E", "-s", "-")
        try:
            return os.posix_spawn(
                str(interpreter),
                argv,
                _WORKER_ENVIRONMENT,
                file_actions=file_actions,
            )
        except OSError as error:
            raise ContractError("sealed inert worker launch failed") from error
    finally:
        if sealed_socket is not None:
            os.close(sealed_socket)
        os.close(sealed_source)


def _parse_frame_payload(data: bytes) -> dict[str, JsonValue]:
    value = _mapping(load_json_bytes(data), "frame")
    if canonical_json(value) != data:
        raise ContractError("frame payload must use canonical JSON bytes")
    return value


def _frame_entry(
    direction: str,
    value: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    payload = canonical_json(value)
    framed = struct.pack(">I", len(payload)) + payload
    return {
        "direction": direction,
        "message_type": value["message_type"],
        "sequence": value["sequence"],
        "size_bytes": len(payload),
        "payload_base64": encode_bytes(payload),
        "payload_sha256": digest_bytes(payload),
        "frame_sha256": digest_bytes(framed),
    }


class _FrameChannel:
    def __init__(
        self,
        endpoint: socket.socket,
        deadline_ns: int,
        entries: list[JsonValue],
    ) -> None:
        self.endpoint = endpoint
        self.deadline_ns = deadline_ns
        self.entries = entries

    def _remaining_seconds(self) -> float:
        remaining = self.deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            raise ContractError("absolute custody deadline expired")
        return remaining / 1_000_000_000

    def _read_exact(self, size: int, label: str) -> bytes:
        blocks = bytearray()
        while len(blocks) < size:
            self.endpoint.settimeout(self._remaining_seconds())
            try:
                block = self.endpoint.recv(size - len(blocks))
            except TimeoutError as error:
                raise ContractError("absolute custody deadline expired") from error
            if not block:
                if not blocks:
                    raise ContractError(f"peer EOF before {label}")
                raise ContractError(f"truncated {label}")
            blocks.extend(block)
        return bytes(blocks)

    def send(self, value: dict[str, JsonValue]) -> None:
        payload = canonical_json(value)
        if not payload or len(payload) > MAX_FRAME_BYTES:
            raise ContractError("outbound frame length is outside 1..1048576 bytes")
        framed = struct.pack(">I", len(payload)) + payload
        self.endpoint.settimeout(self._remaining_seconds())
        try:
            self.endpoint.sendall(framed)
        except TimeoutError as error:
            raise ContractError("absolute custody deadline expired") from error
        self.entries.append(_frame_entry("parent_to_worker", value))

    def receive(self) -> dict[str, JsonValue]:
        header = self._read_exact(4, "frame header")
        length = struct.unpack(">I", header)[0]
        if length == 0 or length > MAX_FRAME_BYTES:
            raise ContractError("frame length is outside 1..1048576 bytes")
        value = _parse_frame_payload(self._read_exact(length, "frame payload"))
        self.entries.append(_frame_entry("worker_to_parent", value))
        return value

    def expect_eof(self) -> None:
        self.endpoint.settimeout(self._remaining_seconds())
        try:
            extra = self.endpoint.recv(1)
        except TimeoutError as error:
            raise ContractError("worker did not close output before the deadline") from error
        if extra:
            raise ContractError("worker emitted extra output after shutdown_ack")


def _expect_message(
    value: dict[str, JsonValue],
    message_type: str,
    sequence: int,
    fields: set[str],
) -> None:
    _keys(value, fields | {"message_type", "sequence"}, message_type)
    if value["message_type"] != message_type:
        raise ContractError(f"expected {message_type}")
    if _integer(value["sequence"], f"{message_type}.sequence", minimum=1) != sequence:
        raise ContractError(f"{message_type} has wrong sequence")


def _verify_worker_identity(
    value: dict[str, JsonValue],
    *,
    hello: dict[str, JsonValue],
    child_pid: int,
    parent_pid: int,
    interpreter: dict[str, JsonValue],
    worker_program: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    fields = {
        "protocol_id",
        "worker_code_id",
        "study_spec_id",
        "package_id",
        "package_sha256",
        "parent_nonce",
        "worker_nonce",
        "pid",
        "ppid",
        "worker_fd",
        "open_file_descriptors",
        "environment_id",
        "interpreter",
        "worker_program",
    }
    _expect_message(value, "worker_identity", 2, fields)
    expected = {
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "study_spec_id": hello["study_spec_id"],
        "package_id": hello["package_id"],
        "package_sha256": hello["package_sha256"],
        "parent_nonce": hello["parent_nonce"],
        "pid": child_pid,
        "ppid": parent_pid,
        "worker_fd": WORKER_FD,
        "environment_id": ENVIRONMENT_ID,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise ContractError(f"worker identity {field} mismatch")
    _nonce(value["worker_nonce"], "worker_identity.worker_nonce")
    descriptors = _array(
        value["open_file_descriptors"],
        "worker_identity.open_file_descriptors",
        maximum=8,
    )
    if descriptors != [0, 1, 2, WORKER_FD]:
        raise ContractError("worker inherited unrelated file descriptors")
    observed_interpreter = _verify_file_identity(
        value["interpreter"],
        "worker_identity.interpreter",
    )
    observed_program = _verify_file_identity(
        value["worker_program"],
        "worker_identity.worker_program",
    )
    if observed_interpreter != interpreter or observed_program != worker_program:
        raise ContractError("worker launch-target identity mismatch")
    return dict(value)


def _build_authorization(
    hello: dict[str, JsonValue],
    worker_nonce: str,
    created_at_unix_ns: int,
) -> dict[str, JsonValue]:
    authorization: dict[str, JsonValue] = {
        "record_type": "mlx_inert_one_shot_authorization",
        "schema_version": SCHEMA_VERSION,
        "action": "inert_refusal_only",
        "package_id": hello["package_id"],
        "package_sha256": hello["package_sha256"],
        "interpreter_sha256": hello["interpreter_sha256"],
        "worker_program_sha256": hello["worker_program_sha256"],
        "study_spec_id": hello["study_spec_id"],
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": worker_nonce,
        "output_root_id": hello["output_root_id"],
        "created_at_unix_ns": created_at_unix_ns,
        "expires_at_unix_ns": created_at_unix_ns + DEFAULT_DEADLINE_NS,
        "deadline_monotonic_ns": hello["deadline_monotonic_ns"],
    }
    authorization["authorization_id"] = canonical_identity(authorization)
    return authorization


def _verify_authorization(
    value: JsonValue,
    *,
    check_current_expiry: bool,
) -> dict[str, JsonValue]:
    authorization = _mapping(value, "mlx_inert_one_shot_authorization")
    fields = {
        "record_type",
        "schema_version",
        "action",
        "package_id",
        "package_sha256",
        "interpreter_sha256",
        "worker_program_sha256",
        "study_spec_id",
        "protocol_id",
        "worker_code_id",
        "parent_nonce",
        "worker_nonce",
        "output_root_id",
        "created_at_unix_ns",
        "expires_at_unix_ns",
        "deadline_monotonic_ns",
        "authorization_id",
    }
    _keys(authorization, fields, "mlx_inert_one_shot_authorization")
    if (
        authorization["record_type"] != "mlx_inert_one_shot_authorization"
        or authorization["schema_version"] != SCHEMA_VERSION
        or authorization["action"] != "inert_refusal_only"
    ):
        raise ContractError("unsupported inert one-shot authorization")
    for field in (
        "package_id",
        "package_sha256",
        "interpreter_sha256",
        "worker_program_sha256",
        "study_spec_id",
        "protocol_id",
        "worker_code_id",
        "output_root_id",
    ):
        _sha256(authorization[field], f"authorization.{field}")
    _nonce(authorization["parent_nonce"], "authorization.parent_nonce")
    _nonce(authorization["worker_nonce"], "authorization.worker_nonce")
    created = _integer(
        authorization["created_at_unix_ns"],
        "authorization.created_at_unix_ns",
        minimum=1,
    )
    expires = _integer(
        authorization["expires_at_unix_ns"],
        "authorization.expires_at_unix_ns",
        minimum=1,
    )
    deadline = _integer(
        authorization["deadline_monotonic_ns"],
        "authorization.deadline_monotonic_ns",
        minimum=1,
    )
    if expires != created + AUTHORIZATION_LIFETIME_NS:
        raise ContractError("authorization has an unexpected wall-clock lifetime")
    if check_current_expiry and (time.time_ns() >= expires or time.monotonic_ns() >= deadline):
        raise ContractError("authorization has expired")
    identity = _sha256(
        authorization["authorization_id"],
        "authorization.authorization_id",
    )
    content = dict(authorization)
    del content["authorization_id"]
    if identity != canonical_identity(content):
        raise ContractError("inert authorization identity mismatch")
    return dict(authorization)


def _write_exclusive_at(directory_descriptor: int, name: str, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_descriptor)
    try:
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory_descriptor)


def _consume_authorization_at(
    output_root_descriptor: int,
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    verified_root = _verify_output_root_binding(output_root)
    verified = _verify_authorization(authorization, check_current_expiry=True)
    if verified["output_root_id"] != verified_root["output_root_id"]:
        raise ContractError("authorization output-root identity mismatch")
    consumed_at_unix_ns = time.time_ns()
    consumed_at_monotonic_ns = time.monotonic_ns()
    if consumed_at_unix_ns >= cast(
        "int", verified["expires_at_unix_ns"]
    ) or consumed_at_monotonic_ns >= cast("int", verified["deadline_monotonic_ns"]):
        raise ContractError("authorization expired before atomic consumption")
    consumption: dict[str, JsonValue] = {
        "record_type": "mlx_inert_authorization_consumption",
        "schema_version": SCHEMA_VERSION,
        "authorization_id": verified["authorization_id"],
        "action": "inert_refusal_only",
        "package_id": verified["package_id"],
        "output_root_id": verified["output_root_id"],
        "consumed_at_unix_ns": consumed_at_unix_ns,
        "consumed_at_monotonic_ns": consumed_at_monotonic_ns,
        "atomic_method": "exclusive_no_follow_output_root_marker",
    }
    consumption["consumption_id"] = canonical_identity(consumption)
    name = f".localinferencelab-mlx-consumed-{str(verified['authorization_id'])[7:]}.json"
    try:
        _write_exclusive_at(output_root_descriptor, name, canonical_json(consumption))
    except FileExistsError as error:
        raise ContractError("inert authorization was already consumed") from error
    return consumption


def _verify_consumption(
    value: JsonValue,
    authorization: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    consumption = _mapping(value, "mlx_inert_authorization_consumption")
    fields = {
        "record_type",
        "schema_version",
        "authorization_id",
        "action",
        "package_id",
        "output_root_id",
        "consumed_at_unix_ns",
        "consumed_at_monotonic_ns",
        "atomic_method",
        "consumption_id",
    }
    _keys(consumption, fields, "mlx_inert_authorization_consumption")
    if (
        consumption["record_type"] != "mlx_inert_authorization_consumption"
        or consumption["schema_version"] != SCHEMA_VERSION
        or consumption["action"] != "inert_refusal_only"
        or consumption["atomic_method"] != "exclusive_no_follow_output_root_marker"
    ):
        raise ContractError("unsupported inert authorization consumption")
    expected = {
        "authorization_id": authorization["authorization_id"],
        "package_id": authorization["package_id"],
        "output_root_id": output_root["output_root_id"],
    }
    for field, expected_value in expected.items():
        if consumption[field] != expected_value:
            raise ContractError(f"authorization consumption {field} mismatch")
    consumed_wall = _integer(
        consumption["consumed_at_unix_ns"],
        "consumption.consumed_at_unix_ns",
        minimum=1,
    )
    consumed_monotonic = _integer(
        consumption["consumed_at_monotonic_ns"],
        "consumption.consumed_at_monotonic_ns",
        minimum=1,
    )
    if not (
        cast("int", authorization["created_at_unix_ns"])
        <= consumed_wall
        < cast("int", authorization["expires_at_unix_ns"])
    ):
        raise ContractError("authorization consumption is outside its wall-clock validity")
    if consumed_monotonic >= cast("int", authorization["deadline_monotonic_ns"]):
        raise ContractError("authorization consumption is outside its monotonic deadline")
    identity = _sha256(consumption["consumption_id"], "consumption.consumption_id")
    content = dict(consumption)
    del content["consumption_id"]
    if identity != canonical_identity(content):
        raise ContractError("authorization consumption identity mismatch")
    return dict(consumption)


def _verify_authorization_ack(
    value: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
) -> None:
    fields = {"authorization_id", "parent_nonce", "worker_nonce", "consumed"}
    _expect_message(value, "authorization_ack", 4, fields)
    expected = {
        "authorization_id": authorization["authorization_id"],
        "parent_nonce": authorization["parent_nonce"],
        "worker_nonce": authorization["worker_nonce"],
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise ContractError(f"authorization_ack {field} mismatch")
    if not _boolean(value["consumed"], "authorization_ack.consumed"):
        raise ContractError("authorization_ack must confirm consumption")


def _verify_authorization_session_bindings(
    authorization: dict[str, JsonValue],
    *,
    hello: dict[str, JsonValue],
    identity: dict[str, JsonValue],
) -> None:
    expected = {
        "package_id": hello["package_id"],
        "package_sha256": hello["package_sha256"],
        "interpreter_sha256": hello["interpreter_sha256"],
        "worker_program_sha256": hello["worker_program_sha256"],
        "study_spec_id": hello["study_spec_id"],
        "protocol_id": hello["protocol_id"],
        "worker_code_id": hello["worker_code_id"],
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": identity["worker_nonce"],
        "output_root_id": hello["output_root_id"],
        "deadline_monotonic_ns": hello["deadline_monotonic_ns"],
    }
    for field, expected_value in expected.items():
        if authorization[field] != expected_value:
            raise ContractError(f"authorization {field} session binding mismatch")


def _verify_refusal(
    value: dict[str, JsonValue],
    *,
    authorization: dict[str, JsonValue],
    request_nonce: str,
) -> None:
    fields = {
        "status",
        "reason",
        "generated_result_present",
        "authorization_id",
        "package_id",
        "output_root_id",
        "parent_nonce",
        "worker_nonce",
        "request_nonce",
        "mlx_imports",
        "mlx_lm_imports",
        "model_loads",
        "tokenizer_loads",
        "device_queries",
        "metal_initializations",
        "inference_requests",
        "network_actions",
        "cache_mutations",
    }
    _expect_message(value, "result_or_terminal_error", 6, fields)
    expected = {
        "status": "refused",
        "reason": REFUSAL_REASON,
        "generated_result_present": False,
        "authorization_id": authorization["authorization_id"],
        "package_id": authorization["package_id"],
        "output_root_id": authorization["output_root_id"],
        "parent_nonce": authorization["parent_nonce"],
        "worker_nonce": authorization["worker_nonce"],
        "request_nonce": request_nonce,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise ContractError(f"refusal result {field} mismatch")
    for field in (
        "mlx_imports",
        "mlx_lm_imports",
        "model_loads",
        "tokenizer_loads",
        "device_queries",
        "metal_initializations",
        "inference_requests",
        "network_actions",
        "cache_mutations",
    ):
        if _integer(value[field], f"refusal.{field}") != 0:
            raise ContractError("inert refusal cannot report model, backend, or network actions")


def _verify_shutdown_ack(
    value: dict[str, JsonValue],
    *,
    parent_nonce: str,
    worker_nonce: str,
    request_nonce: str,
) -> None:
    fields = {"parent_nonce", "worker_nonce", "request_nonce", "terminal_state"}
    _expect_message(value, "shutdown_ack", 8, fields)
    if (
        value["parent_nonce"] != parent_nonce
        or value["worker_nonce"] != worker_nonce
        or value["request_nonce"] != request_nonce
        or value["terminal_state"] != "refused_and_closed"
    ):
        raise ContractError("shutdown_ack binding mismatch")


def _parent_process_evidence(
    child_pid: int,
    parent_pid: int,
    interpreter: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    if sys.platform.startswith("linux"):
        try:
            metadata = Path(f"/proc/{child_pid}/exe").stat()
        except OSError as error:
            raise ContractError("could not inspect Linux child executable identity") from error
        matched = (
            metadata.st_dev == interpreter["device"] and metadata.st_ino == interpreter["inode"]
        )
        if not matched:
            raise ContractError("Linux child executable differs from the launch target")
        return {
            "method": "linux_proc_exe_device_inode",
            "available": True,
            "matched": True,
            "parent_pid": parent_pid,
            "child_pid": child_pid,
        }
    return {
        "method": "unavailable_on_platform",
        "available": False,
        "matched": None,
        "parent_pid": parent_pid,
        "child_pid": child_pid,
    }


def _wait_child(child_pid: int, deadline_ns: int) -> dict[str, JsonValue]:
    while True:
        waited_pid, status = os.waitpid(child_pid, os.WNOHANG)
        if waited_pid == child_pid:
            if os.WIFEXITED(status):
                return {
                    "pid": child_pid,
                    "wait_owned": True,
                    "exited": True,
                    "exit_code": os.WEXITSTATUS(status),
                    "signal": None,
                }
            if os.WIFSIGNALED(status):
                return {
                    "pid": child_pid,
                    "wait_owned": True,
                    "exited": False,
                    "exit_code": None,
                    "signal": os.WTERMSIG(status),
                }
            raise ContractError("child wait returned an unsupported status")
        if time.monotonic_ns() >= deadline_ns:
            raise ContractError("child did not exit before the absolute custody deadline")
        time.sleep(0.005)


def _terminate_and_wait(child_pid: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.kill(child_pid, signal.SIGTERM)
    deadline = time.monotonic_ns() + 500_000_000
    while True:
        try:
            waited_pid, _status = os.waitpid(child_pid, os.WNOHANG)
        except ChildProcessError:
            return
        if waited_pid == child_pid:
            return
        if time.monotonic_ns() >= deadline:
            break
        time.sleep(0.005)
    with contextlib.suppress(ProcessLookupError):
        os.kill(child_pid, signal.SIGKILL)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(child_pid, 0)


def _transcript(entries: list[JsonValue]) -> dict[str, JsonValue]:
    transcript: dict[str, JsonValue] = {
        "record_type": "mlx_inert_custody_transcript",
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "frames": entries,
    }
    transcript["transcript_id"] = canonical_identity(transcript)
    return transcript


def _reconstruct_eligibility(package: dict[str, JsonValue]) -> dict[str, JsonValue]:
    legacy_eligibility = _mapping(package["eligibility"], "legacy eligibility")
    legacy_missing = cast("list[JsonValue]", legacy_eligibility["missing_requirements"])
    remaining = {cast("str", item) for item in legacy_missing}
    for blocker in (
        "one_shot_authorization",
        "output_root_physical_binding",
        "production_worker_private_ipc_protocol_and_result_validation_implementation",
        "worker_process_birth_and_executable_binding",
    ):
        remaining.remove(blocker)
    remaining.update(
        {
            "generated_result_producer_and_validation_implementation",
            "mlx_model_action_one_shot_authorization",
            "parent_observed_running_executable_identity_on_all_supported_platforms",
        }
    )
    return {
        "record_type": "mlx_inert_custody_eligibility",
        "schema_version": SCHEMA_VERSION,
        "decision": "ineligible",
        "observed_generation_reachable": False,
        "inert_refusal_observed": True,
        "legacy_missing_requirements": legacy_missing,
        "closed_or_split_requirements": [
            {
                "legacy": "one_shot_authorization",
                "closed": "inert_refusal_one_shot_authorization",
                "remaining": "mlx_model_action_one_shot_authorization",
            },
            {
                "legacy": "output_root_physical_binding",
                "closed": "descriptor_retained_output_root_physical_binding",
                "remaining": None,
            },
            {
                "legacy": (
                    "production_worker_private_ipc_protocol_and_result_validation_implementation"
                ),
                "closed": "inert_private_ipc_protocol_and_refusal_validation_implementation",
                "remaining": "generated_result_producer_and_validation_implementation",
            },
            {
                "legacy": "worker_process_birth_and_executable_binding",
                "closed": "parent_owned_birth_wait_and_exact_launch_target_binding",
                "remaining": (
                    "parent_observed_running_executable_identity_on_all_supported_platforms"
                ),
            },
        ],
        "remaining_requirements": cast("list[JsonValue]", sorted(remaining)),
        "reason": (
            "the observed run proves only the inert process, private IPC, one-shot refusal "
            "authorization, physical output-root, terminal wait, and refusal replay machinery; "
            "it never authorizes or performs MLX, model, device, or generation actions"
        ),
    }


def _custody_record(
    *,
    package: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
    consumption: dict[str, JsonValue],
    transcript: dict[str, JsonValue],
    interpreter: dict[str, JsonValue],
    worker_program: dict[str, JsonValue],
    process_evidence: dict[str, JsonValue],
    child_wait: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    eligibility = _reconstruct_eligibility(package)
    record: dict[str, JsonValue] = {
        "record_type": "mlx_inert_custody_record",
        "schema_version": SCHEMA_VERSION,
        "custody_spec_id": canonical_identity(inert_custody_spec()),
        "study_spec_id": package["study_spec_id"],
        "package_id": package["package_id"],
        "package_sha256": digest_bytes(canonical_json(package)),
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "interpreter": interpreter,
        "worker_program": worker_program,
        "output_root_id": output_root["output_root_id"],
        "authorization_id": authorization["authorization_id"],
        "consumption_id": consumption["consumption_id"],
        "transcript_id": transcript["transcript_id"],
        "terminal_state": "refused_and_closed",
        "refusal_reason": REFUSAL_REASON,
        "generated_result_present": False,
        "parent_process_evidence": process_evidence,
        "child_wait": child_wait,
        "action_ledger": dict(_ACTION_LEDGER),
        "non_actions": dict(_NON_ACTIONS),
        "eligibility": eligibility,
    }
    record["custody_record_id"] = canonical_identity(record)
    return record


def _write_terminal_failure_at(
    output_root_descriptor: int,
    *,
    phase: str,
    output_root_id: JsonValue,
    package_id: JsonValue,
    actions: dict[str, JsonValue],
    authorization_id: JsonValue,
) -> dict[str, JsonValue]:
    failure: dict[str, JsonValue] = {
        "record_type": "mlx_inert_terminal_failure",
        "schema_version": SCHEMA_VERSION,
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "phase": phase,
        "terminal_state": "failed_closed",
        "reason": "custody_protocol_or_process_failure",
        "output_root_id": output_root_id,
        "package_id": package_id,
        "authorization_id": authorization_id,
        "child_reaped": True,
        "action_ledger": actions,
        "non_actions": dict(_NON_ACTIONS),
        "failure_nonce_sha256": digest_bytes(os.urandom(32)),
    }
    failure["failure_id"] = canonical_identity(failure)
    name = f".localinferencelab-mlx-terminal-{str(failure['failure_id'])[7:]}.json"
    _write_exclusive_at(output_root_descriptor, name, canonical_json(failure))
    return failure


def _require_sealed_worker_program(worker_program: dict[str, JsonValue]) -> None:
    if worker_program["sha256"] != EXPECTED_WORKER_PROGRAM_SHA256:
        raise ContractError("inert worker program differs from its sealed digest")


def _require_unchanged_launch_target(
    before: dict[str, JsonValue],
    after: dict[str, JsonValue],
) -> None:
    if after != before:
        raise ContractError("Python interpreter changed before worker launch")


def _require_successful_terminal_state(
    child_wait: dict[str, JsonValue],
    actions: dict[str, JsonValue],
) -> None:
    if child_wait["exit_code"] != 0:
        raise ContractError("sealed inert worker did not exit successfully")
    if actions != _ACTION_LEDGER:
        raise ContractError("inert custody action reservation ledger drift")


def _require_bounded_content(content_files: dict[str, bytes]) -> None:
    if any(len(data) > MAX_BUNDLE_FILE_BYTES for data in content_files.values()):
        raise ContractError("inert custody artifact exceeds its byte bound")


def run_inert_custody_self_test(
    output_root: Path,
) -> tuple[Path, InertCustodyReplayResult]:
    """Run one exact sealed child/socket exchange and publish its refusal bundle."""
    root_descriptor = _open_private_output_root(output_root)
    parent_endpoint: socket.socket | None = None
    child_endpoint: socket.socket | None = None
    child_pid: int | None = None
    worker_source_descriptor: int | None = None
    root_binding: dict[str, JsonValue] | None = None
    package: dict[str, JsonValue] | None = None
    authorization: dict[str, JsonValue] | None = None
    phase = "initialization"
    actions: dict[str, JsonValue] = {
        "attempts": 1,
        "retries": 0,
        "warmups": 0,
        "worker_process_starts": 0,
        "socketpair_creations": 0,
        "authorizations_consumed": 0,
        "parent_frames": 0,
        "worker_frames": 0,
        "generate_once_commands": 0,
        "terminal_refusals": 0,
        "shutdowns": 0,
    }
    try:
        root_nonce = os.urandom(32)
        root_binding = _output_root_binding(root_descriptor, root_nonce)
        package = build_mlx_prospective_package(mlx_study_spec())
        package_digest = digest_bytes(canonical_json(package))
        interpreter_path = Path(sys.executable).resolve(strict=True)
        worker_program_path = Path(__file__).with_name("mlx_inert_worker.py").resolve(strict=True)
        interpreter, _interpreter_bytes = _read_launch_target(
            interpreter_path,
            "Python interpreter",
            executable=True,
        )
        source_worker_program, worker_bytes = _read_launch_target(
            worker_program_path,
            "inert worker program",
            executable=False,
        )
        _require_sealed_worker_program(source_worker_program)
        worker_source_descriptor, worker_program = _create_worker_snapshot_at(
            root_descriptor,
            worker_bytes,
            worker_program_path.name,
        )
        _require_sealed_worker_program(worker_program)
        parent_pid = os.getpid()
        parent_nonce = encode_bytes(os.urandom(32))
        deadline_ns = time.monotonic_ns() + DEFAULT_DEADLINE_NS
        hello: dict[str, JsonValue] = {
            "message_type": "parent_hello",
            "sequence": 1,
            "protocol_id": PROTOCOL_ID,
            "worker_code_id": WORKER_CODE_ID,
            "study_spec_id": package["study_spec_id"],
            "package_id": package["package_id"],
            "package_sha256": package_digest,
            "interpreter_sha256": interpreter["sha256"],
            "worker_program_sha256": worker_program["sha256"],
            "parent_nonce": parent_nonce,
            "output_root_id": root_binding["output_root_id"],
            "deadline_monotonic_ns": deadline_ns,
        }
        phase = "socketpair_creation"
        actions["socketpair_creations"] = 1
        parent_endpoint, child_endpoint = socket.socketpair(
            socket.AF_UNIX,
            socket.SOCK_STREAM,
        )
        phase = "worker_process_start"
        actions["worker_process_starts"] = 1
        current_interpreter, _current_interpreter_bytes = _read_launch_target(
            interpreter_path,
            "Python interpreter",
            executable=True,
        )
        _require_unchanged_launch_target(interpreter, current_interpreter)
        child_pid = _spawn_worker(
            interpreter_path,
            worker_source_descriptor,
            child_endpoint,
        )
        os.close(worker_source_descriptor)
        worker_source_descriptor = None
        child_endpoint.close()
        child_endpoint = None
        entries: list[JsonValue] = []
        channel = _FrameChannel(parent_endpoint, deadline_ns, entries)
        phase = "parent_hello"
        channel.send(hello)
        actions["parent_frames"] = 1
        phase = "worker_identity"
        identity = _verify_worker_identity(
            channel.receive(),
            hello=hello,
            child_pid=child_pid,
            parent_pid=parent_pid,
            interpreter=interpreter,
            worker_program=worker_program,
        )
        actions["worker_frames"] = 1
        process_evidence = _parent_process_evidence(child_pid, parent_pid, interpreter)
        worker_nonce = cast("str", identity["worker_nonce"])
        authorization = _build_authorization(hello, worker_nonce, time.time_ns())
        _verify_authorization(authorization, check_current_expiry=True)
        phase = "authorization_consumption"
        actions["authorizations_consumed"] = 1
        consumption = _consume_authorization_at(
            root_descriptor,
            root_binding,
            authorization,
        )
        phase = "authorize_once"
        channel.send(
            {
                "message_type": "authorize_once",
                "sequence": 3,
                "authorization": authorization,
            }
        )
        actions["parent_frames"] = 2
        phase = "authorization_ack"
        _verify_authorization_ack(channel.receive(), authorization)
        actions["worker_frames"] = 2
        request_nonce = encode_bytes(os.urandom(32))
        phase = "generate_once"
        actions["generate_once_commands"] = 1
        channel.send(
            {
                "message_type": "generate_once",
                "sequence": 5,
                "action": "inert_refusal_only",
                "authorization_id": authorization["authorization_id"],
                "package_id": package["package_id"],
                "output_root_id": root_binding["output_root_id"],
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
            }
        )
        actions["parent_frames"] = 3
        phase = "terminal_refusal"
        _verify_refusal(
            channel.receive(),
            authorization=authorization,
            request_nonce=request_nonce,
        )
        actions["worker_frames"] = 3
        actions["terminal_refusals"] = 1
        phase = "shutdown"
        actions["shutdowns"] = 1
        channel.send(
            {
                "message_type": "shutdown",
                "sequence": 7,
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
            }
        )
        actions["parent_frames"] = 4
        parent_endpoint.shutdown(socket.SHUT_WR)
        phase = "shutdown_ack"
        _verify_shutdown_ack(
            channel.receive(),
            parent_nonce=parent_nonce,
            worker_nonce=worker_nonce,
            request_nonce=request_nonce,
        )
        actions["worker_frames"] = 4
        channel.expect_eof()
        phase = "child_wait"
        child_wait = _wait_child(child_pid, deadline_ns)
        child_pid = None
        _require_successful_terminal_state(child_wait, actions)
        transcript = _transcript(entries)
        record = _custody_record(
            package=package,
            output_root=root_binding,
            authorization=authorization,
            consumption=consumption,
            transcript=transcript,
            interpreter=interpreter,
            worker_program=worker_program,
            process_evidence=process_evidence,
            child_wait=child_wait,
        )
        phase = "publication"
        _revalidate_output_root_path(output_root, root_descriptor)
        content_files = {
            "source/custody-spec.json": canonical_json(inert_custody_spec()),
            "source/worker-program.py": worker_bytes,
            "prospective-package.json": canonical_json(package),
            "output-root-binding.json": canonical_json(root_binding),
            "authorization.json": canonical_json(authorization),
            "authorization-consumption.json": canonical_json(consumption),
            "transcript.json": canonical_json(transcript),
            "custody-record.json": canonical_json(record),
        }
        _require_bounded_content(content_files)
        destination = publish_bundle_at(
            content_files,
            output_root,
            root_descriptor,
            name_prefix="localinferencelab-mlx-inert-custody-v1",
        )
        _revalidate_output_root_path(output_root, root_descriptor)
        return destination, replay_inert_custody_bundle(destination)
    except (ContractError, OSError):
        if child_pid is not None:
            _terminate_and_wait(child_pid)
            child_pid = None
        _write_terminal_failure_at(
            root_descriptor,
            phase=phase,
            output_root_id=None if root_binding is None else root_binding["output_root_id"],
            package_id=None if package is None else package["package_id"],
            authorization_id=(None if authorization is None else authorization["authorization_id"]),
            actions=actions,
        )
        raise
    finally:
        if child_endpoint is not None:
            child_endpoint.close()
        if parent_endpoint is not None:
            parent_endpoint.close()
        if child_pid is not None:
            _terminate_and_wait(child_pid)
        if worker_source_descriptor is not None:
            os.close(worker_source_descriptor)
        os.close(root_descriptor)


def _decode_transcript_entry(
    value: JsonValue,
    expected_direction: str,
    expected_message_type: str,
    expected_sequence: int,
) -> dict[str, JsonValue]:
    entry = _mapping(value, "transcript.frames[]")
    fields = {
        "direction",
        "message_type",
        "sequence",
        "size_bytes",
        "payload_base64",
        "payload_sha256",
        "frame_sha256",
    }
    _keys(entry, fields, "transcript.frames[]")
    if (
        entry["direction"] != expected_direction
        or entry["message_type"] != expected_message_type
        or entry["sequence"] != expected_sequence
    ):
        raise ContractError("transcript frame order or direction mismatch")
    payload = decode_bytes(_text(entry["payload_base64"], "frame.payload_base64"))
    size = _integer(
        entry["size_bytes"],
        "frame.size_bytes",
        minimum=1,
        maximum=MAX_FRAME_BYTES,
    )
    if len(payload) != size or digest_bytes(payload) != _sha256(
        entry["payload_sha256"],
        "frame.payload_sha256",
    ):
        raise ContractError("transcript payload size or digest mismatch")
    framed = struct.pack(">I", size) + payload
    if digest_bytes(framed) != _sha256(entry["frame_sha256"], "frame.frame_sha256"):
        raise ContractError("transcript framed-byte digest mismatch")
    message = _parse_frame_payload(payload)
    if (
        message.get("message_type") != expected_message_type
        or message.get("sequence") != expected_sequence
    ):
        raise ContractError("transcript payload label mismatch")
    return message


def _verify_transcript(
    value: JsonValue,
    package: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
    interpreter: dict[str, JsonValue],
    worker_program: dict[str, JsonValue],
    *,
    child_pid: int,
    parent_pid: int,
) -> dict[str, JsonValue]:
    transcript = _mapping(value, "mlx_inert_custody_transcript")
    fields = {"record_type", "schema_version", "protocol_id", "frames", "transcript_id"}
    _keys(transcript, fields, "mlx_inert_custody_transcript")
    if (
        transcript["record_type"] != "mlx_inert_custody_transcript"
        or transcript["schema_version"] != SCHEMA_VERSION
        or transcript["protocol_id"] != PROTOCOL_ID
    ):
        raise ContractError("unsupported inert custody transcript")
    frames = _array(transcript["frames"], "transcript.frames", maximum=8)
    if len(frames) != len(_MESSAGE_SEQUENCE):
        raise ContractError("inert transcript must contain exactly eight frames")
    messages: list[dict[str, JsonValue]] = []
    for index, message_type in enumerate(_MESSAGE_SEQUENCE):
        direction = "parent_to_worker" if message_type in _PARENT_MESSAGES else "worker_to_parent"
        messages.append(
            _decode_transcript_entry(
                frames[index],
                direction,
                message_type,
                index + 1,
            )
        )
    hello, identity, authorize, ack, generate, refusal, shutdown, shutdown_ack = messages
    hello_fields = {
        "protocol_id",
        "worker_code_id",
        "study_spec_id",
        "package_id",
        "package_sha256",
        "interpreter_sha256",
        "worker_program_sha256",
        "parent_nonce",
        "output_root_id",
        "deadline_monotonic_ns",
    }
    _expect_message(hello, "parent_hello", 1, hello_fields)
    expected_hello = {
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "study_spec_id": package["study_spec_id"],
        "package_id": package["package_id"],
        "package_sha256": digest_bytes(canonical_json(package)),
        "interpreter_sha256": interpreter["sha256"],
        "worker_program_sha256": worker_program["sha256"],
        "output_root_id": output_root["output_root_id"],
    }
    for field, expected_value in expected_hello.items():
        if hello[field] != expected_value:
            raise ContractError(f"transcript parent_hello {field} mismatch")
    _nonce(hello["parent_nonce"], "parent_hello.parent_nonce")
    _integer(hello["deadline_monotonic_ns"], "parent_hello.deadline", minimum=1)
    verified_identity = _verify_worker_identity(
        identity,
        hello=hello,
        child_pid=child_pid,
        parent_pid=parent_pid,
        interpreter=interpreter,
        worker_program=worker_program,
    )
    _expect_message(authorize, "authorize_once", 3, {"authorization"})
    if authorize["authorization"] != authorization:
        raise ContractError("transcript authorization differs from the custody artifact")
    _verify_authorization_session_bindings(
        authorization,
        hello=hello,
        identity=verified_identity,
    )
    _verify_authorization_ack(ack, authorization)
    generate_fields = {
        "action",
        "authorization_id",
        "package_id",
        "output_root_id",
        "parent_nonce",
        "worker_nonce",
        "request_nonce",
    }
    _expect_message(generate, "generate_once", 5, generate_fields)
    expected_generate = {
        "action": "inert_refusal_only",
        "authorization_id": authorization["authorization_id"],
        "package_id": package["package_id"],
        "output_root_id": output_root["output_root_id"],
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": verified_identity["worker_nonce"],
    }
    for field, expected_value in expected_generate.items():
        if generate[field] != expected_value:
            raise ContractError(f"transcript generate_once {field} mismatch")
    request_nonce = _nonce(generate["request_nonce"], "generate_once.request_nonce")
    _verify_refusal(
        refusal,
        authorization=authorization,
        request_nonce=request_nonce,
    )
    shutdown_fields = {"parent_nonce", "worker_nonce", "request_nonce"}
    _expect_message(shutdown, "shutdown", 7, shutdown_fields)
    if (
        shutdown["parent_nonce"] != hello["parent_nonce"]
        or shutdown["worker_nonce"] != verified_identity["worker_nonce"]
        or shutdown["request_nonce"] != request_nonce
    ):
        raise ContractError("transcript shutdown binding mismatch")
    _verify_shutdown_ack(
        shutdown_ack,
        parent_nonce=cast("str", hello["parent_nonce"]),
        worker_nonce=cast("str", verified_identity["worker_nonce"]),
        request_nonce=request_nonce,
    )
    identity_value = _sha256(transcript["transcript_id"], "transcript.transcript_id")
    content = dict(transcript)
    del content["transcript_id"]
    if identity_value != canonical_identity(content):
        raise ContractError("inert transcript identity mismatch")
    return dict(transcript)


def _verify_custody_record(
    value: JsonValue,
    *,
    package: dict[str, JsonValue],
    output_root: dict[str, JsonValue],
    authorization: dict[str, JsonValue],
    consumption: dict[str, JsonValue],
    transcript: dict[str, JsonValue],
    worker_bytes: bytes,
) -> dict[str, JsonValue]:
    record = _mapping(value, "mlx_inert_custody_record")
    fields = {
        "record_type",
        "schema_version",
        "custody_spec_id",
        "study_spec_id",
        "package_id",
        "package_sha256",
        "protocol_id",
        "worker_code_id",
        "interpreter",
        "worker_program",
        "output_root_id",
        "authorization_id",
        "consumption_id",
        "transcript_id",
        "terminal_state",
        "refusal_reason",
        "generated_result_present",
        "parent_process_evidence",
        "child_wait",
        "action_ledger",
        "non_actions",
        "eligibility",
        "custody_record_id",
    }
    _keys(record, fields, "mlx_inert_custody_record")
    if (
        record["record_type"] != "mlx_inert_custody_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["terminal_state"] != "refused_and_closed"
        or record["refusal_reason"] != REFUSAL_REASON
        or record["generated_result_present"] is not False
    ):
        raise ContractError("unsupported inert custody terminal record")
    interpreter = _verify_file_identity(record["interpreter"], "custody.interpreter")
    worker_program = _verify_file_identity(record["worker_program"], "custody.worker_program")
    if worker_program["sha256"] != digest_bytes(worker_bytes):
        raise ContractError("published worker bytes differ from the launched worker identity")
    if worker_program["sha256"] != EXPECTED_WORKER_PROGRAM_SHA256:
        raise ContractError("published worker bytes differ from the sealed worker digest")
    if (
        authorization["interpreter_sha256"] != interpreter["sha256"]
        or authorization["worker_program_sha256"] != worker_program["sha256"]
    ):
        raise ContractError("authorization launch-target digest binding mismatch")
    expected = {
        "custody_spec_id": canonical_identity(inert_custody_spec()),
        "study_spec_id": package["study_spec_id"],
        "package_id": package["package_id"],
        "package_sha256": digest_bytes(canonical_json(package)),
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "output_root_id": output_root["output_root_id"],
        "authorization_id": authorization["authorization_id"],
        "consumption_id": consumption["consumption_id"],
        "transcript_id": transcript["transcript_id"],
    }
    for field, expected_value in expected.items():
        if record[field] != expected_value:
            raise ContractError(f"inert custody record {field} mismatch")
    process_evidence = _mapping(record["parent_process_evidence"], "parent_process_evidence")
    _keys(
        process_evidence,
        {"method", "available", "matched", "parent_pid", "child_pid"},
        "parent_process_evidence",
    )
    method = _text(process_evidence["method"], "parent_process_evidence.method")
    available = _boolean(process_evidence["available"], "parent_process_evidence.available")
    process_parent_pid = _integer(
        process_evidence["parent_pid"],
        "parent_process_evidence.parent_pid",
        minimum=1,
    )
    process_child_pid = _integer(
        process_evidence["child_pid"],
        "parent_process_evidence.child_pid",
        minimum=1,
    )
    if method == "linux_proc_exe_device_inode":
        if not available or process_evidence["matched"] is not True:
            raise ContractError("Linux process evidence must report an exact match")
    elif method == "unavailable_on_platform":
        if available or process_evidence["matched"] is not None:
            raise ContractError("unavailable process evidence cannot report a match")
    else:
        raise ContractError("unsupported parent process-evidence method")
    child_wait = _mapping(record["child_wait"], "child_wait")
    _keys(child_wait, {"pid", "wait_owned", "exited", "exit_code", "signal"}, "child_wait")
    child_wait_pid = _integer(child_wait["pid"], "child_wait.pid", minimum=1)
    if (
        child_wait["wait_owned"] is not True
        or child_wait["exited"] is not True
        or child_wait["exit_code"] != 0
        or child_wait["signal"] is not None
    ):
        raise ContractError("child wait evidence is not one clean parent-owned exit")
    if process_child_pid != child_wait_pid:
        raise ContractError("parent process evidence and child wait PID mismatch")
    action_ledger = _mapping(record["action_ledger"], "action_ledger")
    if action_ledger != _ACTION_LEDGER:
        raise ContractError("inert custody action ledger drift")
    non_actions = _mapping(record["non_actions"], "non_actions")
    if non_actions != _NON_ACTIONS:
        raise ContractError("inert custody non-action ledger drift")
    if record["eligibility"] != _reconstruct_eligibility(package):
        raise ContractError("inert custody eligibility reconstruction mismatch")
    verified_transcript = _verify_transcript(
        transcript,
        package,
        output_root,
        authorization,
        interpreter,
        worker_program,
        child_pid=process_child_pid,
        parent_pid=process_parent_pid,
    )
    if verified_transcript["transcript_id"] != record["transcript_id"]:
        raise ContractError("custody transcript binding mismatch")
    identity = _sha256(record["custody_record_id"], "custody.custody_record_id")
    content = dict(record)
    del content["custody_record_id"]
    if identity != canonical_identity(content):
        raise ContractError("inert custody record identity mismatch")
    return dict(record)


def _replay_inert_custody_snapshot(
    bundle: Path,
) -> tuple[InertCustodyReplayResult, dict[str, JsonValue]]:
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/custody-spec.json",
        "source/worker-program.py",
        "prospective-package.json",
        "output-root-binding.json",
        "authorization.json",
        "authorization-consumption.json",
        "transcript.json",
        "custody-record.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("inert custody bundle has an invalid content set")
    for name, data in files.items():
        if len(data) > MAX_BUNDLE_FILE_BYTES:
            raise ContractError(f"inert custody artifact exceeds its bound: {name}")
    spec = _canonical_value(files["source/custody-spec.json"], "inert custody spec")
    if canonical_json(spec) != canonical_json(inert_custody_spec()):
        raise ContractError("inert custody specification drift")
    package = verify_mlx_prospective_package(
        _canonical_value(files["prospective-package.json"], "prospective package")
    )
    if canonical_json(package) != canonical_json(build_mlx_prospective_package(mlx_study_spec())):
        raise ContractError("inert custody must bind the built-in legacy prospective package")
    output_root = _verify_output_root_binding(
        _canonical_value(files["output-root-binding.json"], "output-root binding")
    )
    authorization = _verify_authorization(
        _canonical_value(files["authorization.json"], "authorization"),
        check_current_expiry=False,
    )
    if (
        authorization["package_id"] != package["package_id"]
        or authorization["package_sha256"] != digest_bytes(canonical_json(package))
        or authorization["study_spec_id"] != package["study_spec_id"]
        or authorization["protocol_id"] != PROTOCOL_ID
        or authorization["worker_code_id"] != WORKER_CODE_ID
        or authorization["output_root_id"] != output_root["output_root_id"]
    ):
        raise ContractError("inert authorization package, protocol, worker, or root substitution")
    consumption = _verify_consumption(
        _canonical_value(
            files["authorization-consumption.json"],
            "authorization consumption",
        ),
        authorization,
        output_root,
    )
    transcript = _canonical_value(files["transcript.json"], "custody transcript")
    record = _verify_custody_record(
        _canonical_value(files["custody-record.json"], "custody record"),
        package=package,
        output_root=output_root,
        authorization=authorization,
        consumption=consumption,
        transcript=_mapping(transcript, "custody transcript"),
        worker_bytes=files["source/worker-program.py"],
    )
    eligibility = _mapping(record["eligibility"], "custody eligibility")
    remaining = _array(
        eligibility["remaining_requirements"],
        "eligibility.remaining_requirements",
    )
    result = InertCustodyReplayResult(
        bundle_root=content_root,
        custody_record_id=cast("str", record["custody_record_id"]),
        package_id=cast("str", package["package_id"]),
        protocol_id=PROTOCOL_ID,
        terminal_state=cast("str", record["terminal_state"]),
        refusal_reason=cast("str", record["refusal_reason"]),
        child_exit_code=0,
        authorization_consumptions=1,
        process_actions=1,
        socket_actions=1,
        model_actions=0,
        network_actions=0,
        missing_requirements=len(remaining),
    )
    return result, dict(eligibility)


def replay_inert_custody_bundle(bundle: Path) -> InertCustodyReplayResult:
    """Replay one refusal bundle without starting a process or opening a socket."""
    result, _eligibility = _replay_inert_custody_snapshot(bundle)
    return result


def inspect_inert_custody_bundle(bundle: Path) -> dict[str, JsonValue]:
    """Return the mechanically reconstructed eligibility projection after replay."""
    replay, eligibility = _replay_inert_custody_snapshot(bundle)
    return {
        **replay.to_dict(),
        "decision": eligibility["decision"],
        "observed_generation_reachable": eligibility["observed_generation_reachable"],
        "inert_refusal_observed": eligibility["inert_refusal_observed"],
        "closed_or_split_requirements": eligibility["closed_or_split_requirements"],
        "remaining_requirements": eligibility["remaining_requirements"],
    }
