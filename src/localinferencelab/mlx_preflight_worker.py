"""Isolated schema-1.2 model-free worker source; native dispatch remains closed."""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import json
import os
import re
import resource
import socket
import stat
import struct
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import NoReturn, Protocol, cast

SCHEMA_VERSION = "1.2"
MAX_FRAME_BYTES = 16_384
MAX_METADATA_BYTES = 1_048_576
MAX_LIFETIME_NS = 30_000_000_000
WORKER_FD = 3
INTERPRETER_FD = 4
RUNTIME_FD = 5
ACTIONS = (
    "candidate_distribution_identity_checks",
    "import_mlx",
    "import_mlx_lm",
    "default_device",
    "default_stream",
    "metal_is_available",
    "synchronize",
)
ENVIRONMENT = {
    "HF_HUB_OFFLINE": "1",
    "LC_ALL": "C",
    "MLXLM_USE_MODELSCOPE": "False",
    "PYTHONDONTWRITEBYTECODE": "1",
    "TOKENIZERS_PARALLELISM": "false",
    "TRANSFORMERS_OFFLINE": "1",
    "TZ": "UTC",
}
PROTOCOL: dict[str, object] = {
    "schema_version": SCHEMA_VERSION,
    "transport": "inherited_parent_af_unix_socketpair",
    "framing": "uint32_be_length_canonical_json",
    "max_frame_bytes": MAX_FRAME_BYTES,
    "actions": list(ACTIONS),
    "sequence": "hello_identity_then_command_started_terminal_per_action_then_shutdown_eof",
    "attempts": 1,
    "retries": 0,
    "model_free": True,
}
_SAFE_REPR = re.compile(r"[A-Za-z0-9_(), .=:-]{1,256}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TOKEN = re.compile(r"[0-9a-f]{64}\Z")


class WorkerError(ValueError):
    """A bounded worker protocol or observation failed."""


def _no_number(_value: str) -> NoReturn:
    raise WorkerError("non_integer_json")


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise WorkerError("duplicate_json_key")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("ascii")


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


PROTOCOL_ID = _digest(_canonical(PROTOCOL))


def _parse(data: bytes) -> dict[str, object]:
    try:
        value: object = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique,
            parse_float=_no_number,
            parse_constant=_no_number,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise WorkerError("invalid_json") from error
    if not isinstance(value, dict) or _canonical(value) != data:
        raise WorkerError("noncanonical_json_object")
    return value


def _keys(value: dict[str, object], expected: set[str]) -> None:
    if value.keys() != expected:
        raise WorkerError("frame_fields_mismatch")


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise WorkerError("invalid_integer")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise WorkerError("invalid_digest")
    return value


def _token(value: object) -> str:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise WorkerError("invalid_token")
    return value


def _send(endpoint: socket.socket, value: dict[str, object], deadline: int) -> None:
    payload = _canonical(value)
    if not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise WorkerError("outbound_size")
    remaining = deadline - time.monotonic_ns()
    if remaining <= 0:
        raise WorkerError("deadline")
    endpoint.settimeout(remaining / 1_000_000_000)
    endpoint.sendall(struct.pack(">I", len(payload)) + payload)


def _receive(endpoint: socket.socket, deadline: int) -> dict[str, object]:
    def read(size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                raise WorkerError("deadline")
            endpoint.settimeout(remaining / 1_000_000_000)
            block = endpoint.recv(size - len(data))
            if not block:
                raise WorkerError("eof")
            data.extend(block)
        return bytes(data)

    length = struct.unpack(">I", read(4))[0]
    if not 0 < length <= MAX_FRAME_BYTES:
        raise WorkerError("inbound_size")
    return _parse(read(length))


def _file_digest(descriptor: int, maximum: int) -> str:
    before = os.fstat(descriptor)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise WorkerError("file_identity")
    digest = hashlib.sha256()
    offset = 0
    while block := os.pread(descriptor, min(65_536, maximum + 1 - offset), offset):
        offset += len(block)
        if offset > maximum:
            raise WorkerError("file_bound")
        digest.update(block)
    after = os.fstat(descriptor)
    stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
    if (
        tuple(getattr(before, name) for name in stable_fields)
        != tuple(getattr(after, name) for name in stable_fields)
        or offset != before.st_size
    ):
        raise WorkerError("file_changed")
    return "sha256:" + digest.hexdigest()


def _root_identity(descriptor: int) -> dict[str, object]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise WorkerError("root_identity")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
    }


class RuntimeOperations(Protocol):
    """Only fixed observations are callable through the worker's action loop."""

    def distributions(self) -> object: ...

    def import_mlx(self) -> object: ...

    def import_mlx_lm(self) -> object: ...

    def default_device(self) -> object: ...

    def default_stream(self) -> object: ...

    def metal_is_available(self) -> object: ...

    def synchronize(self) -> object: ...


class _MetalAPI(Protocol):
    def is_available(self) -> bool: ...


class _MLXAPI(Protocol):
    metal: _MetalAPI

    def default_device(self) -> object: ...

    def default_stream(self, device: object) -> object: ...

    def synchronize(self) -> object: ...


class _InstalledRuntime:
    def __init__(
        self,
        root: Path,
        expected: dict[str, tuple[str, str]],
        imports: dict[str, tuple[str, str]],
    ) -> None:
        self.root = root
        self.expected = expected
        self.imports = imports
        self.mlx: _MLXAPI | None = None
        self.device: object = None

    def distributions(self) -> object:
        observed: dict[str, tuple[str, str]] = {}
        for distribution in importlib.metadata.distributions(path=[str(self.root)]):
            name = re.sub(r"[-_.]+", "-", distribution.metadata["Name"].lower())
            if name in observed or name not in self.expected:
                raise WorkerError("distribution_set_mismatch")
            metadata_files = [
                item
                for item in distribution.files or ()
                if str(item).endswith(".dist-info/METADATA")
            ]
            if len(metadata_files) != 1:
                raise WorkerError("metadata_identity_missing")
            path = Path(str(distribution.locate_file(metadata_files[0])))
            if path.parent.parent != self.root or path.is_symlink() or path.parent.is_symlink():
                raise WorkerError("metadata_root_mismatch")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                identity = _file_digest(descriptor, MAX_METADATA_BYTES)
            finally:
                os.close(descriptor)
            observed[name] = (distribution.version, identity)
        if observed != self.expected:
            raise WorkerError("distribution_identity_mismatch")
        return [
            {"name": name, "version": version, "metadata_sha256": identity}
            for name, (version, identity) in sorted(observed.items())
        ]

    def _import(self, module: str) -> object:
        if str(self.root) not in sys.path:
            sys.path.insert(0, str(self.root))
        imported = importlib.import_module(module)
        filename = getattr(imported, "__file__", None)
        if not isinstance(filename, str):
            raise WorkerError("import_origin_missing")
        path = Path(filename)
        if not path.is_relative_to(self.root) or path.is_symlink():
            raise WorkerError("import_origin_mismatch")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            identity = _file_digest(descriptor, 64 * MAX_METADATA_BYTES)
        finally:
            os.close(descriptor)
        relative = path.relative_to(self.root).as_posix()
        if self.imports[module] != (relative, identity):
            raise WorkerError("import_file_identity_mismatch")
        if module == "mlx.core":
            self.mlx = cast("_MLXAPI", imported)
        return {
            "module": module,
            "relative_file": path.relative_to(self.root).as_posix(),
            "sha256": identity,
        }

    def import_mlx(self) -> object:
        return self._import("mlx.core")

    def import_mlx_lm(self) -> object:
        return self._import("mlx_lm")

    def _module(self) -> _MLXAPI:
        if self.mlx is None:
            raise WorkerError("mlx_not_imported")
        return self.mlx

    @staticmethod
    def _representation(value: object) -> str:
        text = repr(value)
        if _SAFE_REPR.fullmatch(text) is None:
            raise WorkerError("unsafe_representation")
        return text

    def default_device(self) -> object:
        self.device = self._module().default_device()
        return self._representation(self.device)

    def default_stream(self) -> object:
        return self._representation(self._module().default_stream(self.device))

    def metal_is_available(self) -> object:
        value: object = self._module().metal.is_available()
        if not isinstance(value, bool):
            raise WorkerError("nonboolean_metal")
        return value

    def synchronize(self) -> object:
        value: object = self._module().synchronize()
        if value is not None:
            raise WorkerError("synchronization_return")
        return {"completed": True, "scope": "mlx_default_streams", "kernel_execution_proven": False}


def _serve(
    endpoint: socket.socket,
    hello: dict[str, object],
    runtime: RuntimeOperations,
    identity: dict[str, object],
) -> None:
    """Execute the fixed loop; tests supply inert operations, never a native adapter."""
    deadline = _integer(hello["deadline_ns"])
    session = _sha(hello["session_id"])
    challenge = _token(hello["challenge"])
    nonce = _token(hello["nonce"])
    if challenge == nonce or not 0 < deadline - time.monotonic_ns() <= MAX_LIFETIME_NS:
        raise WorkerError("session_deadline_or_nonce")
    sequence = 1

    def frame(kind: str, **content: object) -> dict[str, object]:
        return {
            "kind": kind,
            "sequence": sequence,
            "protocol_id": PROTOCOL_ID,
            "session_id": session,
            **content,
        }

    _send(endpoint, frame("identity", challenge=challenge, nonce=nonce, **identity), deadline)
    operations: tuple[Callable[[], object], ...] = (
        runtime.distributions,
        runtime.import_mlx,
        runtime.import_mlx_lm,
        runtime.default_device,
        runtime.default_stream,
        runtime.metal_is_available,
        runtime.synchronize,
    )
    for action, operation in zip(ACTIONS, operations, strict=True):
        sequence += 1
        command = _receive(endpoint, deadline)
        _keys(command, {"kind", "sequence", "protocol_id", "session_id", "action"})
        if command != frame("run_action", action=action):
            raise WorkerError("action_order_or_binding")
        sequence += 1
        _send(endpoint, frame("action_started", action=action), deadline)
        sequence += 1
        try:
            observation = operation()
        except (ImportError, AttributeError, OSError, RuntimeError, TypeError, ValueError) as error:
            # The error text may contain a private pathname or credential: never transmit it.
            _send(
                endpoint,
                frame("action_failed", action=action, error_category=type(error).__name__),
                deadline,
            )
            return
        _send(endpoint, frame("action_completed", action=action, observation=observation), deadline)
    sequence += 1
    if _receive(endpoint, deadline) != frame("shutdown"):
        raise WorkerError("shutdown_mismatch")
    sequence += 1
    _send(endpoint, frame("shutdown_ack"), deadline)


def _native_enforcement_gate() -> None:
    raise WorkerError("reviewed_os_native_network_and_forbidden_action_enforcement_unavailable")


def _verify_target_platform() -> None:
    if sys.platform != "darwin" or os.uname().machine != "arm64":
        raise WorkerError("target_platform_mismatch")


def _worker_main() -> None:
    _native_enforcement_gate()
    if dict(os.environ) != ENVIRONMENT:
        raise WorkerError("environment_mismatch")
    if not all(
        (
            sys.flags.isolated,
            sys.flags.no_site,
            sys.flags.ignore_environment,
            sys.dont_write_bytecode,
        )
    ):
        raise WorkerError("interpreter_flags")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    endpoint = socket.socket(fileno=WORKER_FD)
    with endpoint:
        if endpoint.family != socket.AF_UNIX or endpoint.type != socket.SOCK_STREAM:
            raise WorkerError("socket_identity")
        deadline = time.monotonic_ns() + MAX_LIFETIME_NS
        hello = _receive(endpoint, deadline)
        _keys(
            hello,
            {
                "kind",
                "sequence",
                "protocol_id",
                "session_id",
                "challenge",
                "nonce",
                "deadline_ns",
                "interpreter_sha256",
                "runtime_root",
                "distributions",
                "worker_program_id",
                "import_files",
            },
        )
        if (hello["kind"], _integer(hello["sequence"]), hello["protocol_id"]) != (
            "hello",
            0,
            PROTOCOL_ID,
        ):
            raise WorkerError("hello_mismatch")
        interpreter = _file_digest(INTERPRETER_FD, 128 * MAX_METADATA_BYTES)
        root_identity = _root_identity(RUNTIME_FD)
        if hello["interpreter_sha256"] != interpreter or hello["runtime_root"] != root_identity:
            raise WorkerError("launch_identity_mismatch")
        worker_identity = _file_digest(0, MAX_METADATA_BYTES)
        if _sha(hello["worker_program_id"]) != worker_identity:
            raise WorkerError("worker_source_identity_mismatch")
        if sys.implementation.name != "cpython" or sys.version_info[:3] != (3, 13, 15):
            raise WorkerError("interpreter_version_mismatch")
        _verify_target_platform()
        import fcntl  # noqa: PLC0415

        path_command: object = getattr(fcntl, "F_GETPATH", None)
        if not isinstance(path_command, int):
            raise WorkerError("runtime_descriptor_path_unavailable")
        raw: object = fcntl.fcntl(RUNTIME_FD, path_command, b"\0" * 1024)
        if not isinstance(raw, bytes):
            raise WorkerError("runtime_descriptor_path")
        root = Path(raw.split(b"\0", 1)[0].decode("utf-8"))
        current_root = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            if _root_identity(current_root) != root_identity:
                raise WorkerError("runtime_root_replaced")
        finally:
            os.close(current_root)
        distributions = hello["distributions"]
        if not isinstance(distributions, list):
            raise WorkerError("distribution_schema")
        expected: dict[str, tuple[str, str]] = {}
        for item in distributions:
            if not isinstance(item, dict):
                raise WorkerError("distribution_schema")
            _keys(item, {"name", "version", "metadata_sha256"})
            name, version = item["name"], item["version"]
            if not isinstance(name, str) or not isinstance(version, str) or name in expected:
                raise WorkerError("distribution_schema")
            expected[name] = version, _sha(item["metadata_sha256"])
        if expected.get("mlx", ("", ""))[0] != "0.30.4" or (
            expected.get("mlx-lm", ("", ""))[0] != "0.30.6"
        ):
            raise WorkerError("candidate_version_mismatch")
        import_files = hello["import_files"]
        if not isinstance(import_files, dict) or import_files.keys() != {"mlx.core", "mlx_lm"}:
            raise WorkerError("import_identity_schema")
        imports: dict[str, tuple[str, str]] = {}
        for module, item in import_files.items():
            if not isinstance(item, dict):
                raise WorkerError("import_identity_schema")
            _keys(item, {"relative_file", "sha256"})
            relative = item["relative_file"]
            if not isinstance(relative, str):
                raise WorkerError("import_identity_schema")
            imports[module] = relative, _sha(item["sha256"])
        _serve(
            endpoint,
            hello,
            _InstalledRuntime(root, expected, imports),
            {
                "pid": os.getpid(),
                "parent_pid": os.getppid(),
                "interpreter_sha256": interpreter,
                "runtime_root": root_identity,
                "worker_program_id": worker_identity,
            },
        )


def main() -> int:
    """Refuse native dispatch independently of the parent's closed gate."""
    try:
        _worker_main()
    except (WorkerError, OSError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
