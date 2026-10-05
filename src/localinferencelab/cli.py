"""Command-line interface for contract, fixture, custody, and probe operations."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal, NoReturn, cast

from localinferencelab.backends import backend_plan, probe_runtime_artifact, validate_backend
from localinferencelab.canonical import ContractError, canonical_json, digest_bytes, load_json_bytes
from localinferencelab.contracts import parse_record, record_id
from localinferencelab.custody import replay_bundle
from localinferencelab.fixture import compile_fixture
from localinferencelab.host import probe_host
from localinferencelab.ollama import (
    build_prospective_package,
    create_authorization_nonce,
    execute_observed,
    initialize_output_root,
    load_authorization,
    load_prospective_package,
    make_authorization,
    preflight_observed,
    read_authorization_nonce,
    replay_ollama_bundle,
    write_authorization,
    write_prospective_package,
)
from localinferencelab.ollama_declaration import (
    build_study_declaration,
    compile_declaration_fixture,
    load_study_declaration,
    qwen3_repeatability_study_spec,
    replay_declaration_fixture,
    write_study_declaration,
)
from localinferencelab.ollama_fixture import compile_ollama_contract_fixtures


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

    ollama = commands.add_parser(
        "ollama",
        help="fail-closed prospective Ollama package and explicit execution gate",
    )
    ollama_commands = ollama.add_subparsers(dest="ollama_command", required=True)
    output_root = ollama_commands.add_parser(
        "output-root-init",
        help="bind one existing output root before declaration",
    )
    output_root.add_argument("output_root", type=Path)
    output_root.add_argument("--nonce", required=True)
    authorization_nonce = ollama_commands.add_parser(
        "authorization-nonce-init",
        help="create one owner-only nonce and print its prospective digest commitment",
    )
    authorization_nonce.add_argument("output", type=Path)
    prospective = ollama_commands.add_parser(
        "prospective-create",
        help="construct an exact package without runtime or network action",
    )
    prospective.add_argument("spec", type=Path)
    prospective.add_argument("output", type=Path)
    prospective.add_argument("--runtime-artifact", type=Path, required=True)
    prospective.add_argument("--model-manifest", type=Path, required=True)
    prospective.add_argument("--blob-root", type=Path, required=True)
    verify_prospective = ollama_commands.add_parser(
        "prospective-verify",
        help="verify an exact prospective package offline",
    )
    verify_prospective.add_argument("package", type=Path)
    ollama_commands.add_parser(
        "declaration-spec",
        help="emit the pinned Qwen3 repeatability study specification",
    )
    declaration_create = ollama_commands.add_parser(
        "declaration-create",
        help="construct a replayable preflight-only repeatability declaration",
    )
    declaration_create.add_argument("spec", type=Path)
    declaration_create.add_argument("output", type=Path)
    declaration_create.add_argument(
        "--prospective-package",
        type=Path,
        action="append",
        default=[],
        help="exact verified per-run package; provide all declared runs or none",
    )
    declaration_verify = ollama_commands.add_parser(
        "declaration-verify",
        help="strictly verify a canonical repeatability declaration offline",
    )
    declaration_verify.add_argument("declaration", type=Path)
    declaration_inspect = ollama_commands.add_parser(
        "declaration-inspect",
        help="inspect declaration completeness and fail-closed eligibility",
    )
    declaration_inspect.add_argument("declaration", type=Path)
    declaration_fixture = ollama_commands.add_parser(
        "declaration-fixture-compile",
        help="publish deterministic non-observed declaration contract evidence",
    )
    declaration_fixture.add_argument("output_root", type=Path)
    declaration_replay = ollama_commands.add_parser(
        "declaration-replay",
        help="replay a closed declaration fixture bundle offline",
    )
    declaration_replay.add_argument("bundle", type=Path)
    authorize = ollama_commands.add_parser(
        "authorize",
        help="create a separate phase-scoped one-shot authorization",
    )
    authorize.add_argument("package", type=Path)
    authorize.add_argument(
        "phase",
        choices=("preflight_only", "identity_guard", "generation"),
    )
    authorize.add_argument("output", type=Path)
    authorize.add_argument("--nonce-file", type=Path, required=True)
    preflight = ollama_commands.add_parser(
        "preflight",
        help="perform separately authorized read-only loopback identity calls",
    )
    preflight.add_argument("package", type=Path)
    preflight.add_argument("authorization", type=Path)
    preflight.add_argument("output_root", type=Path)
    preflight.add_argument("--runtime-artifact", type=Path, required=True)
    preflight.add_argument("--model-manifest", type=Path, required=True)
    preflight.add_argument("--blob-root", type=Path, required=True)
    execute = ollama_commands.add_parser(
        "execute",
        help="execute one exact study with two separately supplied authorizations",
    )
    execute.add_argument("package", type=Path)
    execute.add_argument("identity_authorization", type=Path)
    execute.add_argument("generation_authorization", type=Path)
    execute.add_argument("output_root", type=Path)
    execute.add_argument("--runtime-artifact", type=Path, required=True)
    execute.add_argument("--model-manifest", type=Path, required=True)
    execute.add_argument("--blob-root", type=Path, required=True)
    evidence = ollama_commands.add_parser(
        "evidence-replay",
        help="strictly replay Ollama evidence without model or network access",
    )
    evidence.add_argument("bundle", type=Path)
    fixture_ollama = ollama_commands.add_parser(
        "fixture-compile",
        help="publish deterministic sealed-script contract evidence",
    )
    fixture_ollama.add_argument("output_root", type=Path)
    return parser


def _error(message: str) -> NoReturn:
    raise ContractError(message)


def run(arguments: list[str] | None = None) -> int:  # noqa: PLR0911
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
    if args.command == "ollama":
        if args.ollama_command == "output-root-init":
            identity = initialize_output_root(args.output_root, args.nonce)
            _emit(
                {
                    "status": "initialized",
                    "output_root_id": identity,
                    "network_actions": 0,
                    "model_actions": 0,
                },
            )
            return 0
        if args.ollama_command == "authorization-nonce-init":
            _emit(
                {
                    "status": "created",
                    "nonce_sha256": create_authorization_nonce(args.output),
                    "network_actions": 0,
                    "model_actions": 0,
                }
            )
            return 0
        if args.ollama_command == "prospective-create":
            spec_bytes = args.spec.read_bytes()
            spec = load_json_bytes(spec_bytes)
            if canonical_json(spec) != spec_bytes:
                _error("Ollama study specification must use canonical JSON")
            prospective_package_value = build_prospective_package(
                spec,
                runtime_artifact=args.runtime_artifact,
                model_manifest=args.model_manifest,
                blob_root=args.blob_root,
            )
            write_prospective_package(args.output, prospective_package_value)
            verified = load_prospective_package(args.output)
            _emit(
                {
                    "status": "created",
                    "package_id": verified.identity,
                    "request_sha256": digest_bytes(verified.request),
                    "network_actions": 0,
                    "model_actions": 0,
                },
            )
            return 0
        if args.ollama_command == "prospective-verify":
            verified_package = load_prospective_package(args.package)
            _emit(
                {
                    "status": "valid",
                    "package_id": verified_package.identity,
                    "protocol_id": verified_package.protocol_id,
                    "declaration_id": verified_package.declaration_id,
                    "request_sha256": digest_bytes(verified_package.request),
                    "network_actions": 0,
                    "model_actions": 0,
                },
            )
            return 0
        if args.ollama_command == "declaration-spec":
            _emit(qwen3_repeatability_study_spec())
            return 0
        if args.ollama_command == "declaration-create":
            spec_bytes = args.spec.read_bytes()
            spec_value = load_json_bytes(spec_bytes)
            if canonical_json(spec_value) != spec_bytes:
                _error("Ollama repeatability study specification must use canonical JSON")
            package_values = [
                load_prospective_package(path).value for path in args.prospective_package
            ]
            declaration_value = build_study_declaration(
                spec_value,
                prospective_packages=package_values,
            )
            write_study_declaration(args.output, declaration_value)
            declaration = load_study_declaration(args.output)
            completeness = cast(
                "dict[str, object]",
                cast("dict[str, object]", declaration["eligibility"])["declaration_completeness"],
            )
            _emit(
                {
                    "status": "created",
                    "declaration_id": declaration["declaration_id"],
                    "declaration_complete": completeness["status"] == "complete",
                    "physical_network_requests": 0,
                    "model_actions": 0,
                },
            )
            return 0
        if args.ollama_command in {"declaration-verify", "declaration-inspect"}:
            declaration = load_study_declaration(args.declaration)
            eligibility = cast("dict[str, object]", declaration["eligibility"])
            completeness = cast(
                "dict[str, object]",
                eligibility["declaration_completeness"],
            )
            observed = cast("dict[str, object]", eligibility["observed_generation"])
            _emit(
                {
                    "status": (
                        "valid" if args.ollama_command == "declaration-verify" else "inspected"
                    ),
                    "declaration_id": declaration["declaration_id"],
                    "declaration_complete": completeness["status"] == "complete",
                    "missing_fields": completeness["missing_fields"],
                    "metadata_preflight": eligibility["metadata_preflight"],
                    "observed_generation": observed,
                    "scheduled_runs": len(
                        cast("list[object]", declaration["run_schedule"]),
                    ),
                    "physical_network_requests": 0,
                    "model_actions": 0,
                },
            )
            return 0
        if args.ollama_command == "declaration-fixture-compile":
            fixture_path, replay = compile_declaration_fixture(args.output_root)
            output = replay.to_dict()
            output["status"] = "compiled"
            output["path"] = fixture_path.name
            output["evidence_status"] = "synthetic_declaration_contract_evidence_only"
            _emit(output)
            return 0
        if args.ollama_command == "declaration-replay":
            declaration_replay_result = replay_declaration_fixture(args.bundle)
            output = declaration_replay_result.to_dict()
            output["status"] = "replayed"
            output["external_network_actions"] = 0
            _emit(output)
            return 0
        if args.ollama_command == "authorize":
            authorization_package = load_prospective_package(args.package)
            phase = cast(
                "Literal['identity_guard', 'generation', 'preflight_only']",
                args.phase,
            )
            authorization = make_authorization(
                authorization_package,
                phase,
                read_authorization_nonce(args.nonce_file),
            )
            write_authorization(args.output, authorization)
            _emit(
                {
                    "status": "created",
                    "authorization_id": authorization.identity,
                    "phase": authorization.phase,
                    "network_actions": 0,
                    "model_actions": 0,
                },
            )
            return 0
        if args.ollama_command == "preflight":
            preflight_result = preflight_observed(
                package=load_prospective_package(args.package),
                authorization=load_authorization(args.authorization),
                output_root=args.output_root,
                runtime_artifact=args.runtime_artifact,
                model_manifest=args.model_manifest,
                blob_root=args.blob_root,
            )
            _emit(preflight_result.to_dict())
            return 0
        if args.ollama_command == "execute":
            execution_result = execute_observed(
                package=load_prospective_package(args.package),
                identity_authorization=load_authorization(args.identity_authorization),
                generation_authorization=load_authorization(args.generation_authorization),
                output_root=args.output_root,
                runtime_artifact=args.runtime_artifact,
                model_manifest=args.model_manifest,
                blob_root=args.blob_root,
            )
            _emit(execution_result.to_dict())
            return 0
        if args.ollama_command == "fixture-compile":
            _emit(compile_ollama_contract_fixtures(args.output_root))
            return 0
        evidence_result = replay_ollama_bundle(args.bundle)
        output = evidence_result.to_dict()
        output["status"] = evidence_result.status
        output["network_actions"] = 0
        output["model_actions"] = 0
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
