"""Explicit, bounded macOS feasibility experiment; never a production MLX launcher."""

from __future__ import annotations

import argparse
import os
import selectors
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Literal

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
)
from localinferencelab.native_confinement_contract import (
    CLEANUP_TIMEOUT_NS,
    COMMAND_TIMEOUT_NS,
    COMPILE_TIMEOUT_NS,
    MAX_CAPTURE_BYTES,
    MAX_REPORT_BYTES,
    PROBES,
    PROFILE_TEMPLATE,
    RUN_TIMEOUT_NS,
    Capture,
    build_report,
    replay_bytes,
    specification,
)

_SOURCE_BOUND = 1_048_576
_TOOL_BOUND = 64 * 1024 * 1024
_PRINTABLE_ASCII_MIN = 32
_PRINTABLE_ASCII_MAX = 126
_TOOLS = {"sandbox_exec_id": Path("/usr/bin/sandbox-exec"), "compiler_id": Path("/usr/bin/clang")}


def _read_regular(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ContractError("native input size or type")
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(data) != info.st_size or any(
            getattr(after, field) != getattr(info, field) for field in stable_fields
        ):
            raise ContractError("native input changed")
        return bytes(data)
    finally:
        os.close(descriptor)


def source_identities() -> dict[str, JsonValue]:
    """Hash only this packaged candidate, never a supplied production environment."""
    return _variant_identities("pre_exec")


def _variant_identities(candidate: Literal["pre_exec", "after_startup"]) -> dict[str, JsonValue]:
    sources = {}
    names: tuple[str, ...] = (
        "native_confinement.py",
        "native_confinement_contract.py",
        "native_confinement_probe.c",
    )
    if candidate == "after_startup":
        names += (
            "native_confinement_after_startup.py",
            "native_confinement_after_startup_probe.c",
        )
    for name in names:
        sources[name] = digest_bytes(_read_regular(Path(__file__).with_name(name), _SOURCE_BOUND))
    probe_source_id = sources["native_confinement_probe.c"]
    if candidate == "after_startup":
        probe_source_id = canonical_identity(
            {name: identity for name, identity in sources.items() if name.endswith(".c")}
        )
    return {
        "implementation_id": canonical_identity(sources),
        "probe_source_id": probe_source_id,
        "profile_template_id": canonical_identity(PROFILE_TEMPLATE),
        "profile_id": None,
        "helper_id": None,
        "sandbox_exec_id": None,
        "compiler_id": None,
    }


def _literal(path: Path) -> str:
    text = str(path)
    if not path.is_absolute() or any(
        not _PRINTABLE_ASCII_MIN <= ord(c) <= _PRINTABLE_ASCII_MAX for c in text
    ):
        raise ContractError("native profile path refused")
    return canonical_json(text).decode("ascii")


def _profile(helper: Path, read: Path, write: Path, read_link: Path, write_link: Path) -> str:
    return PROFILE_TEMPLATE.format(
        helper=_literal(helper),
        read=_literal(read),
        write=_literal(write),
        read_link=_literal(read_link),
        write_link=_literal(write_link),
    )


def _run_command(
    argv: list[str],
    *,
    cwd: Path,
    deadline_ns: int,
    timeout_ns: int,
    environment: dict[str, str] | None = None,
) -> Capture:
    started = time.monotonic_ns()
    if started >= deadline_ns:
        return Capture()
    deadline = min(deadline_ns, started + timeout_ns)
    try:
        process = subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env={} if environment is None else environment,
            close_fds=True,
        )
    except OSError:
        return Capture("may_have_run", "spawn_failed", time.monotonic_ns() - started)
    if process.stdout is None or process.stderr is None:
        raise ContractError("native collection pipes unavailable")
    output = [bytearray(), bytearray()]
    terminal = "complete"
    try:
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic_ns()
                if remaining <= 0:
                    terminal = "deadline"
                    break
                events = selector.select(remaining / 1_000_000_000)
                for key, _mask in events:
                    index = key.data
                    block = os.read(key.fd, MAX_CAPTURE_BYTES + 1)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        room = MAX_CAPTURE_BYTES - len(output[index])
                        output[index].extend(block[:room])
                        if len(block) > room:
                            terminal = "output_limit"
                            break
                if terminal != "complete":
                    break
            if terminal == "complete":
                remaining = deadline - time.monotonic_ns()
                if remaining <= 0:
                    terminal = "deadline"
                else:
                    try:
                        process.wait(timeout=remaining / 1_000_000_000)
                    except subprocess.TimeoutExpired:
                        terminal = "deadline"
            if time.monotonic_ns() > deadline and terminal == "complete":
                terminal = "deadline"
    finally:
        if process.poll() is None:
            process.kill()
        try:
            process.wait(timeout=CLEANUP_TIMEOUT_NS / 1_000_000_000)
        except subprocess.TimeoutExpired as error:
            raise ContractError("native owned child could not be reaped") from error
        process.stdout.close()
        process.stderr.close()
    elapsed = time.monotonic_ns() - started
    if terminal == "complete" and elapsed > min(timeout_ns, deadline_ns - started):
        terminal = "deadline"
    if terminal == "complete" and process.returncode != 0:
        terminal = "exit_error"
    return Capture(
        "may_have_run",
        terminal,
        elapsed,
        process.returncode,
        bytes(output[0]),
        bytes(output[1]),
        pid=process.pid,
    )


def _pin(path: Path) -> dict[str, JsonValue]:
    info = path.lstat()
    return {"device": info.st_dev, "inode": info.st_ino, "mode": stat.S_IMODE(info.st_mode)}


def _experiment(
    root: Path,
    identities: dict[str, JsonValue],
    host: dict[str, JsonValue],
    deadline: int,
    candidate: Literal["pre_exec", "after_startup"] = "pre_exec",
) -> dict[str, JsonValue]:
    if candidate not in {"pre_exec", "after_startup"}:
        raise ContractError("native candidate refused")
    helper, other, source = root / "helper", root / "other", root / "probe.c"
    read, write = root / 'allow-"read\\(deny default)', root / "allow-write"
    denied_read, denied_write = root / "deny-read", root / "deny-write"
    sibling, read_link, write_link = (
        Path(str(read) + "-sibling"),
        root / "read-link",
        root / "write-link",
    )
    for path in (read, write, denied_read, denied_write, sibling):
        path.write_bytes(b"A")
    read_link.symlink_to(denied_read)
    write_link.symlink_to(denied_write)
    profile = _profile(helper, read, write, read_link, write_link)
    identities["profile_id"] = digest_bytes(profile.encode("ascii"))
    source.write_bytes(
        _read_regular(Path(__file__).with_name("native_confinement_probe.c"), _SOURCE_BOUND)
    )
    compilation_source = source
    if candidate == "after_startup":
        compilation_source = root / "after_startup.c"
        compilation_source.write_bytes(
            _read_regular(
                Path(__file__).with_name("native_confinement_after_startup_probe.c"), _SOURCE_BOUND
            )
        )
    compilation = _run_command(
        [
            str(_TOOLS["compiler_id"]),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O0",
            str(compilation_source),
            "-o",
            str(helper),
        ],
        cwd=root,
        deadline_ns=deadline,
        timeout_ns=COMPILE_TIMEOUT_NS,
        environment={"PATH": "/usr/bin:/bin"},
    )
    if compilation.terminal != "complete":
        host["finished_ns"] = time.monotonic_ns()
        return build_report(
            identities=identities, host=host, compilation=compilation, reason="compilation_failed"
        )
    identities["helper_id"] = digest_bytes(_read_regular(helper, _TOOL_BOUND))
    other.write_bytes(_read_regular(helper, _TOOL_BOUND))
    other.chmod(0o700)
    fixture: dict[str, JsonValue] = {"root": _pin(root), "read_initial": _pin(read)}
    replacement = root / "replacement"
    replacement.write_bytes(b"B")
    observations = [(Capture(), Capture()) for _ in PROBES]
    reason = "none"
    fixture["read_replacement"] = None
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener,
        (root / "fd-canary").open("wb") as canary,
    ):
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        os.set_inheritable(canary.fileno(), True)
        for index, (operation, _expectation) in enumerate(PROBES):
            if operation == "read_replacement":
                replacement.replace(read)
                fixture["read_replacement"] = _pin(read)
            target = {
                "read_allowed": read,
                "write_allowed": write,
                "read_denied": denied_read,
                "write_denied": denied_write,
                "read_prefix_sibling": sibling,
                "read_symlink": read_link,
                "write_symlink": write_link,
                "read_replacement": read,
                "exec_self": helper,
                "exec_other": other,
                "connect_loopback": str(listener.getsockname()[1]),
            }.get(operation, "unused")
            args = [str(helper), operation, str(target)]
            baseline = _run_command(
                args, cwd=root, deadline_ns=deadline, timeout_ns=COMMAND_TIMEOUT_NS
            )
            if operation in {"write_allowed", "write_denied", "write_symlink"}:
                write.write_bytes(b"A")
                denied_write.write_bytes(b"A")
            command = (
                [str(_TOOLS["sandbox_exec_id"]), "-p", profile, *args]
                if candidate == "pre_exec"
                else [str(helper), "--apply-profile-after-startup", profile, operation, str(target)]
            )
            measured = _run_command(
                command,
                cwd=root,
                deadline_ns=deadline,
                timeout_ns=COMMAND_TIMEOUT_NS,
            )
            observations[index] = baseline, measured
            if index == 0 and measured.terminal != "complete":
                reason = "candidate_startup_unavailable"
                break
    host["finished_ns"] = time.monotonic_ns()
    return build_report(
        identities=identities,
        host=host,
        fixture=fixture,
        compilation=compilation,
        observations=tuple(observations),
        reason=reason,
    )


def _is_darwin() -> bool:
    return sys.platform == "darwin"


def run_probes() -> dict[str, JsonValue]:
    """Invoke this harmless experiment only; unsupported tools never trigger fallback."""
    return _run_variant("pre_exec")


def _run_variant(candidate: Literal["pre_exec", "after_startup"]) -> dict[str, JsonValue]:
    if candidate not in {"pre_exec", "after_startup"}:
        raise ContractError("native candidate refused")
    identities = _variant_identities(candidate)
    if not _is_darwin():
        return build_report(identities=identities, reason="unsupported_host")
    for field, path in _TOOLS.items():
        if not path.is_file() or not os.access(path, os.X_OK):
            return build_report(
                identities=identities,
                reason="sandbox_exec_missing" if field == "sandbox_exec_id" else "compiler_missing",
            )
        try:
            identities[field] = digest_bytes(_read_regular(path, _TOOL_BOUND))
        except (OSError, ContractError):
            return build_report(identities=identities, reason="tool_identity_unavailable")
    started = time.monotonic_ns()
    uname = os.uname()
    host: dict[str, JsonValue] = {
        "system": uname.sysname,
        "release": uname.release,
        "machine": uname.machine,
        "parent_pid": os.getpid(),
        "started_ns": started,
        "finished_ns": started,
    }
    with tempfile.TemporaryDirectory(prefix="localinferencelab-native-") as directory:
        root = Path(directory).resolve(strict=True)
        try:
            _literal(root)
        except ContractError:
            return build_report(identities=identities, host=host, reason="path_refused")
        return _experiment(root, identities, host, started + RUN_TIMEOUT_NS, candidate)


def main(argv: list[str] | None = None) -> int:
    """Dedicated module CLI; import, help, specification and replay never probe."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("spec")
    commands.add_parser("run", help="Explicitly compile/run benign native probes, never MLX")
    replay = commands.add_parser("replay", help="Offline structural replay, never authority")
    replay.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result = run_probes()
        elif args.command == "replay":
            result = replay_bytes(_read_regular(args.report, MAX_REPORT_BYTES))
        else:
            result = specification()
    except (ContractError, OSError) as error:
        print(f"native confinement error: {type(error).__name__}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json(result))
    return 2 if args.command == "run" and result["disposition"] != "enforced" else 0


if __name__ == "__main__":
    raise SystemExit(main())
