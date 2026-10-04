"""Command-line interface for contract, fixture, custody, and probe operations."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import NoReturn

from localinferencelab.backends import backend_plan, probe_runtime_artifact, validate_backend
from localinferencelab.canonical import ContractError, canonical_json, load_json_bytes
from localinferencelab.contracts import parse_record, record_id
from localinferencelab.custody import replay_bundle
from localinferencelab.fixture import compile_fixture
from localinferencelab.host import probe_host


def _emit(value: object) -> None:
    sys.stdout.buffer.write(canonical_json(value) + b"\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="localinferencelab",
        description="Offline-first local inference determinism contracts and custody",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    contract = commands.add_parser("contract", help="strict canonical record operations")
    contract_commands = contract.add_subparsers(dest="contract_command", required=True)
    verify_contract = contract_commands.add_parser("verify", help="verify one record")
    verify_contract.add_argument("path", type=Path)

    fixture = commands.add_parser("fixture", help="deterministic synthetic fixture operations")
    fixture_commands = fixture.add_subparsers(dest="fixture_command", required=True)
    compile_command = fixture_commands.add_parser("compile", help="compile and publish fixture")
    compile_command.add_argument("output_root", type=Path)

    bundle = commands.add_parser("bundle", help="closed bundle operations")
    bundle_commands = bundle.add_subparsers(dest="bundle_command", required=True)
    for name in ("verify", "replay"):
        command = bundle_commands.add_parser(name, help=f"{name} a closed bundle offline")
        command.add_argument("path", type=Path)

    host = commands.add_parser("host", help="privacy-preserving host operations")
    host_commands = host.add_subparsers(dest="host_command", required=True)
    host_commands.add_parser("probe", help="collect safe read-only host facts")

    backend = commands.add_parser("backend", help="fail-closed backend planning and identity")
    backend_commands = backend.add_subparsers(dest="backend_command", required=True)
    plan = backend_commands.add_parser("plan", help="show a non-executable backend plan")
    plan.add_argument("backend")
    probe = backend_commands.add_parser("probe", help="hash a local artifact without execution")
    probe.add_argument("backend")
    probe.add_argument("artifact", type=Path)
    probe.add_argument("--version", required=True)
    probe.add_argument("--commit")
    return parser


def _error(message: str) -> NoReturn:
    raise ContractError(message)


def run(arguments: list[str] | None = None) -> int:
    """Run the CLI and return a process status."""
    args = _parser().parse_args(arguments)
    if args.command == "contract":
        data = args.path.read_bytes()
        value = load_json_bytes(data)
        if canonical_json(value) != data:
            _error("record is valid JSON but not canonical JSON")
        record = parse_record(value)
        _emit({"status": "valid", "record_type": record.record_type, "identity": record_id(record)})
        return 0
    if args.command == "fixture":
        _path, summary = compile_fixture(args.output_root)
        _emit(summary)
        return 0
    if args.command == "bundle":
        result = replay_bundle(args.path)
        output = result.to_dict()
        output["status"] = "verified" if args.bundle_command == "verify" else "replayed"
        output["network_actions"] = 0
        output["model_actions"] = 0
        _emit(output)
        return 0
    if args.command == "host":
        record = probe_host()
        output = record.to_dict()
        output["identity"] = record_id(record)
        _emit(output)
        return 0
    if args.command == "backend":
        backend = validate_backend(args.backend)
        if args.backend_command == "plan":
            _emit(backend_plan(backend))
        else:
            record = probe_runtime_artifact(
                backend,
                args.artifact,
                version=args.version,
                commit=args.commit,
            )
            output = record.to_dict()
            output["identity"] = record_id(record)
            _emit(output)
        return 0
    return _error("unreachable command")


def main() -> int:
    """CLI entry point with concise fail-closed errors."""
    try:
        return run()
    except (ContractError, FileExistsError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
