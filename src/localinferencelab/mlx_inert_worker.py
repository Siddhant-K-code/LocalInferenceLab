"""Standalone refusal-only worker for the direct MLX custody protocol."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import stat
import struct
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn

SCHEMA_VERSION = "1.0"
WORKER_FD = 3
INTERPRETER_IDENTITY_FD = 4
MAX_FRAME_BYTES = 1024 * 1024
AUTHORIZATION_LIFETIME_NS = 5_000_000_000
REFUSAL_REASON = "mlx_execution_unimplemented_and_unauthorized"
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_SURROGATE_START = 0xD800
_SURROGATE_END = 0xDFFF
_MAX_TEXT_BYTES = 4096
_NONCE_BYTES = 32
_EXPECTED_ENVIRONMENT = {
    "LC_ALL": "C",
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONUTF8": "1",
    "TZ": "UTC",
}
_ENVIRONMENT_DESCRIPTOR = {
    "explicit": [
        {"name": name, "value": value} for name, value in sorted(_EXPECTED_ENVIRONMENT.items())
    ],
    "platform_injected": ("__CF_USER_TEXT_ENCODING=current_effective_uid_encoding_on_darwin_only"),
}
PROTOCOL_DESCRIPTOR = {
    "record_type": "mlx_inert_custody_protocol",
    "schema_version": SCHEMA_VERSION,
    "transport": "parent_created_inherited_af_unix_socketpair",
    "worker_fd": WORKER_FD,
    "transient_interpreter_identity_fd": INTERPRETER_IDENTITY_FD,
    "framing": "uint32_be_length_then_canonical_json",
    "max_frame_bytes": MAX_FRAME_BYTES,
    "sequence": [
        "parent_hello",
        "worker_identity",
        "authorize_once",
        "authorization_ack",
        "generate_once",
        "result_or_terminal_error",
        "shutdown",
        "shutdown_ack",
    ],
    "action": "inert_refusal_only",
    "terminal_result": "refused",
    "attempts": 1,
    "retries": 0,
    "warmups": 0,
    "concurrency": 1,
}
WORKER_DESCRIPTOR = {
    "record_type": "mlx_inert_worker_code",
    "schema_version": SCHEMA_VERSION,
    "protocol_id": "",
    "action": "inert_refusal_only",
    "result_producer": "canonical_refusal_only",
    "reason": REFUSAL_REASON,
    "mlx_imports": 0,
    "mlx_lm_imports": 0,
    "model_actions": 0,
    "device_actions": 0,
    "network_actions": 0,
    "subprocess_actions": 0,
}


class WorkerProtocolError(ValueError):
    """Raised when the parent violates the sealed worker protocol."""


def _reject_float(_value: str) -> NoReturn:
    raise WorkerProtocolError("floating-point JSON numbers are forbidden")


def _reject_constant(value: str) -> NoReturn:
    raise WorkerProtocolError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerProtocolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _validate_json(value: object, path: str = "$") -> object:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if any(_SURROGATE_START <= ord(character) <= _SURROGATE_END for character in value):
            raise WorkerProtocolError(f"{path}: Unicode surrogate code points are forbidden")
        return value
    if isinstance(value, float):
        raise WorkerProtocolError(f"{path}: floating-point values are forbidden")
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise WorkerProtocolError(f"{path}: object keys must be strings")
            output[key] = _validate_json(item, f"{path}.{key}")
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_validate_json(item, f"{path}[{index}]") for index, item in enumerate(value)]
    raise WorkerProtocolError(f"{path}: unsupported JSON type {type(value).__name__}")


def _canonical_json(value: object) -> bytes:
    checked = _validate_json(value)
    return json.dumps(
        checked,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest_bytes(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _canonical_identity(value: object) -> str:
    return _digest_bytes(_canonical_json(value))


PROTOCOL_ID = _canonical_identity(PROTOCOL_DESCRIPTOR)
WORKER_DESCRIPTOR["protocol_id"] = PROTOCOL_ID
WORKER_CODE_ID = _canonical_identity(WORKER_DESCRIPTOR)
ENVIRONMENT_ID = _canonical_identity(_ENVIRONMENT_DESCRIPTOR)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise WorkerProtocolError(f"{label} must be an object")
    return value


def _keys(value: dict[str, object], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise WorkerProtocolError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise WorkerProtocolError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise WorkerProtocolError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > _MAX_TEXT_BYTES:
        raise WorkerProtocolError(f"{label} exceeds its byte bound")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise WorkerProtocolError(f"{label} contains control characters")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise WorkerProtocolError(f"{label} must be an integer >= {minimum}")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise WorkerProtocolError(f"{label} must be a boolean")
    return value


def _sha256(value: object, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise WorkerProtocolError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _nonce(value: object, label: str) -> str:
    text = _text(value, label)
    padding = "=" * (-len(text) % 4)
    try:
        decoded = base64.b64decode(text + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as error:
        raise WorkerProtocolError(f"{label} must be canonical URL-safe base64") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != text or len(decoded) != _NONCE_BYTES:
        raise WorkerProtocolError(f"{label} must encode exactly 32 bytes")
    return text


def _parse_canonical(data: bytes) -> dict[str, object]:
    try:
        text = data.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkerProtocolError("frame payload must be strict UTF-8 JSON") from error
    value = _mapping(_validate_json(parsed), "frame")
    if _canonical_json(value) != data:
        raise WorkerProtocolError("frame payload must use canonical JSON bytes")
    return value


class _Channel:
    def __init__(self, endpoint: socket.socket, deadline_ns: int) -> None:
        self.endpoint = endpoint
        self.deadline_ns = deadline_ns

    def remaining_seconds(self) -> float:
        remaining = self.deadline_ns - time.monotonic_ns()
        if remaining <= 0:
            raise WorkerProtocolError("absolute protocol deadline expired")
        return remaining / 1_000_000_000

    def _read_exact(self, size: int, label: str) -> bytes:
        blocks = bytearray()
        while len(blocks) < size:
            self.endpoint.settimeout(self.remaining_seconds())
            try:
                block = self.endpoint.recv(size - len(blocks))
            except TimeoutError as error:
                raise WorkerProtocolError("absolute protocol deadline expired") from error
            if not block:
                if not blocks:
                    raise WorkerProtocolError(f"peer EOF before {label}")
                raise WorkerProtocolError(f"truncated {label}")
            blocks.extend(block)
        return bytes(blocks)

    def receive(self) -> dict[str, object]:
        header = self._read_exact(4, "frame header")
        length = struct.unpack(">I", header)[0]
        if length == 0 or length > MAX_FRAME_BYTES:
            raise WorkerProtocolError("frame length is outside 1..1048576 bytes")
        return _parse_canonical(self._read_exact(length, "frame payload"))

    def send(self, value: dict[str, object]) -> None:
        payload = _canonical_json(value)
        if not payload or len(payload) > MAX_FRAME_BYTES:
            raise WorkerProtocolError("outbound frame length is outside bounds")
        self.endpoint.settimeout(self.remaining_seconds())
        try:
            self.endpoint.sendall(struct.pack(">I", len(payload)) + payload)
        except TimeoutError as error:
            raise WorkerProtocolError("absolute protocol deadline expired") from error


def _expect_message(
    value: dict[str, object],
    message_type: str,
    sequence: int,
    fields: set[str],
) -> None:
    _keys(value, fields | {"message_type", "sequence"}, message_type)
    if value["message_type"] != message_type:
        raise WorkerProtocolError(f"expected {message_type}")
    if _integer(value["sequence"], f"{message_type}.sequence", minimum=1) != sequence:
        raise WorkerProtocolError(f"{message_type} has wrong sequence")


def _file_identity_from_descriptor(
    descriptor: int,
    basename: str,
    *,
    executable: bool,
) -> dict[str, object]:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode):
        raise WorkerProtocolError("launch target must be a regular file")
    if executable and before.st_mode & 0o111 == 0:
        raise WorkerProtocolError("interpreter launch target must be executable")
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while block := os.read(descriptor, 1024 * 1024):
        digest.update(block)
        total += len(block)
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
    if total != before.st_size or stable_before != stable_after:
        raise WorkerProtocolError("launch target changed while it was hashed")
    return {
        "basename": basename,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "size_bytes": before.st_size,
        "sha256": f"sha256:{digest.hexdigest()}",
    }


def _file_identity(path: str, *, executable: bool) -> dict[str, object]:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        return _file_identity_from_descriptor(
            descriptor,
            Path(path).name,
            executable=executable,
        )
    finally:
        os.close(descriptor)


def _open_file_descriptors() -> list[int]:
    proc_fds = Path("/proc/self/fd")
    directory = proc_fds if proc_fds.is_dir() else Path("/dev/fd")
    try:
        candidates = [int(item.name) for item in directory.iterdir() if item.name.isdigit()]
    except OSError as error:
        raise WorkerProtocolError("worker cannot enumerate its descriptor table") from error
    result: list[int] = []
    for descriptor in sorted(set(candidates)):
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        result.append(descriptor)
    return result


def _verify_hello(value: dict[str, object]) -> dict[str, object]:
    fields = {
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
    _expect_message(value, "parent_hello", 1, fields)
    if _sha256(value["protocol_id"], "parent_hello.protocol_id") != PROTOCOL_ID:
        raise WorkerProtocolError("parent protocol identity mismatch")
    if _sha256(value["worker_code_id"], "parent_hello.worker_code_id") != WORKER_CODE_ID:
        raise WorkerProtocolError("parent worker-code identity mismatch")
    for field in (
        "study_spec_id",
        "package_id",
        "package_sha256",
        "interpreter_sha256",
        "worker_program_sha256",
        "output_root_id",
    ):
        _sha256(value[field], f"parent_hello.{field}")
    _nonce(value["parent_nonce"], "parent_hello.parent_nonce")
    deadline = _integer(
        value["deadline_monotonic_ns"],
        "parent_hello.deadline_monotonic_ns",
        minimum=1,
    )
    if deadline <= time.monotonic_ns():
        raise WorkerProtocolError("parent hello deadline has expired")
    return value


def _verify_authorization(
    value: dict[str, object],
    hello: dict[str, object],
    worker_nonce: str,
) -> tuple[dict[str, object], str]:
    _expect_message(value, "authorize_once", 3, {"authorization"})
    authorization = _mapping(value["authorization"], "authorization")
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
    _keys(authorization, fields, "authorization")
    if (
        authorization["record_type"] != "mlx_inert_one_shot_authorization"
        or authorization["schema_version"] != SCHEMA_VERSION
        or authorization["action"] != "inert_refusal_only"
    ):
        raise WorkerProtocolError("unsupported inert authorization")
    bindings = {
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
        "deadline_monotonic_ns": hello["deadline_monotonic_ns"],
    }
    for field, expected in bindings.items():
        if authorization[field] != expected:
            raise WorkerProtocolError(f"authorization {field} mismatch")
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
        raise WorkerProtocolError("authorization has an unexpected wall-clock lifetime")
    if time.time_ns() >= expires or time.monotonic_ns() >= deadline:
        raise WorkerProtocolError("authorization has expired")
    authorization_id = _sha256(
        authorization["authorization_id"],
        "authorization.authorization_id",
    )
    content = dict(authorization)
    del content["authorization_id"]
    if authorization_id != _canonical_identity(content):
        raise WorkerProtocolError("authorization identity mismatch")
    return authorization, authorization_id


def _verify_generate(
    value: dict[str, object],
    hello: dict[str, object],
    worker_nonce: str,
    authorization_id: str,
) -> str:
    fields = {
        "action",
        "authorization_id",
        "package_id",
        "output_root_id",
        "parent_nonce",
        "worker_nonce",
        "request_nonce",
    }
    _expect_message(value, "generate_once", 5, fields)
    expected = {
        "action": "inert_refusal_only",
        "authorization_id": authorization_id,
        "package_id": hello["package_id"],
        "output_root_id": hello["output_root_id"],
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": worker_nonce,
    }
    for field, expected_value in expected.items():
        if value[field] != expected_value:
            raise WorkerProtocolError(f"generate_once {field} mismatch")
    _sha256(value["authorization_id"], "generate_once.authorization_id")
    _nonce(value["request_nonce"], "generate_once.request_nonce")
    return str(value["request_nonce"])


def _verify_shutdown(
    value: dict[str, object],
    parent_nonce: object,
    worker_nonce: str,
    request_nonce: str,
) -> None:
    fields = {"parent_nonce", "worker_nonce", "request_nonce"}
    _expect_message(value, "shutdown", 7, fields)
    if (
        value["parent_nonce"] != parent_nonce
        or value["worker_nonce"] != worker_nonce
        or value["request_nonce"] != request_nonce
    ):
        raise WorkerProtocolError("shutdown nonce mismatch")


def _worker_main() -> None:
    environment = dict(os.environ)
    if sys.platform == "darwin":
        expected = f"0x{os.geteuid():X}:0x0:0x0"
        if environment.pop("__CF_USER_TEXT_ENCODING", None) != expected:
            raise WorkerProtocolError("worker has invalid macOS system-injected environment")
    if environment != _EXPECTED_ENVIRONMENT:
        raise WorkerProtocolError("worker environment is not the exact closed allowlist")
    worker_program = _file_identity_from_descriptor(
        0,
        "mlx_inert_worker.py",
        executable=False,
    )
    interpreter = _file_identity_from_descriptor(
        INTERPRETER_IDENTITY_FD,
        "python-interpreter",
        executable=True,
    )
    os.close(INTERPRETER_IDENTITY_FD)
    devnull = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(devnull, 0)
    finally:
        if devnull != 0:
            os.close(devnull)
    endpoint = socket.socket(fileno=WORKER_FD)
    try:
        initial_deadline = time.monotonic_ns() + 10_000_000_000
        channel = _Channel(endpoint, initial_deadline)
        hello = _verify_hello(channel.receive())
        channel.deadline_ns = _integer(
            hello["deadline_monotonic_ns"],
            "parent_hello.deadline_monotonic_ns",
            minimum=1,
        )
        parent_nonce = str(hello["parent_nonce"])
        worker_nonce = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
        open_descriptors = _open_file_descriptors()
        if open_descriptors != [0, 1, 2, WORKER_FD]:
            raise WorkerProtocolError("worker inherited unrelated file descriptors")
        identity = {
            "message_type": "worker_identity",
            "sequence": 2,
            "protocol_id": PROTOCOL_ID,
            "worker_code_id": WORKER_CODE_ID,
            "study_spec_id": hello["study_spec_id"],
            "package_id": hello["package_id"],
            "package_sha256": hello["package_sha256"],
            "parent_nonce": parent_nonce,
            "worker_nonce": worker_nonce,
            "pid": os.getpid(),
            "ppid": os.getppid(),
            "worker_fd": WORKER_FD,
            "open_file_descriptors": open_descriptors,
            "environment_id": ENVIRONMENT_ID,
            "interpreter": interpreter,
            "worker_program": worker_program,
        }
        channel.send(identity)
        _authorization, authorization_id = _verify_authorization(
            channel.receive(),
            hello,
            worker_nonce,
        )
        channel.send(
            {
                "message_type": "authorization_ack",
                "sequence": 4,
                "authorization_id": authorization_id,
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "consumed": True,
            }
        )
        request_nonce = _verify_generate(
            channel.receive(),
            hello,
            worker_nonce,
            authorization_id,
        )
        channel.send(
            {
                "message_type": "result_or_terminal_error",
                "sequence": 6,
                "status": "refused",
                "reason": REFUSAL_REASON,
                "generated_result_present": False,
                "authorization_id": authorization_id,
                "package_id": hello["package_id"],
                "output_root_id": hello["output_root_id"],
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
                "mlx_imports": 0,
                "mlx_lm_imports": 0,
                "model_loads": 0,
                "tokenizer_loads": 0,
                "device_queries": 0,
                "metal_initializations": 0,
                "inference_requests": 0,
                "network_actions": 0,
                "cache_mutations": 0,
            }
        )
        _verify_shutdown(
            channel.receive(),
            parent_nonce,
            worker_nonce,
            request_nonce,
        )
        channel.send(
            {
                "message_type": "shutdown_ack",
                "sequence": 8,
                "parent_nonce": parent_nonce,
                "worker_nonce": worker_nonce,
                "request_nonce": request_nonce,
                "terminal_state": "refused_and_closed",
            }
        )
        endpoint.shutdown(socket.SHUT_WR)
        endpoint.settimeout(channel.remaining_seconds())
        if endpoint.recv(1) != b"":
            raise WorkerProtocolError("extra parent frame bytes after shutdown")
    finally:
        endpoint.close()


def main() -> int:
    """Run the sealed worker and expose no command or argument surface."""
    if len(sys.argv) != 1:
        return 2
    try:
        _worker_main()
    except (OSError, WorkerProtocolError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
