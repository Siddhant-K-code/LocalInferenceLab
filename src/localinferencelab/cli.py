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
from localinferencelab.mlx_custody import (
    inert_custody_capability_report,
    inspect_inert_custody_bundle,
    replay_inert_custody_bundle,
    run_inert_custody_self_test,
)
from localinferencelab.mlx_determinism_canary import (
    canary_inspection,
    compile_determinism_fixture,
    determinism_canary_spec,
    load_canary_record,
    replay_determinism_fixture,
)
from localinferencelab.mlx_fixture import compile_mlx_fixture, replay_mlx_fixture
from localinferencelab.mlx_manifest import (
    compile_model_manifest,
    compile_runtime_manifest,
    load_runtime_manifest,
    load_runtime_scan_spec,
    write_manifest,
)
from localinferencelab.mlx_preflight_contract import (
    build_runtime_preflight_record_1_1,
    compile_runtime_preflight_fixture_1_1,
    inspect_runtime_preflight_record_1_1,
    load_authorization_claim_1_1,
    load_runtime_preflight_record_1_1,
    replay_runtime_preflight_fixture_1_1,
    runtime_preflight_capability_report_1_1,
    runtime_preflight_protocol_1_1,
    runtime_preflight_spec_1_1,
    write_runtime_preflight_record_1_1,
)
from localinferencelab.mlx_qualification import (
    build_qualification_record,
    compile_qualification_fixture,
    load_qualification_package,
    load_qualification_record,
    qualification_inspection,
    qualification_spec,
    replay_qualification_fixture,
    write_qualification_record,
)
from localinferencelab.mlx_runner import (
    build_mlx_prospective_package,
    load_mlx_prospective_package,
    load_mlx_study_spec,
    load_optional_manifests,
    mlx_capability_report,
    mlx_eligibility_inspection,
    mlx_study_spec,
    write_mlx_prospective_package,
)
from localinferencelab.mlx_runtime_preflight import (
    build_runtime_preflight_package,
    inspect_runtime_preflight_bundle,
    load_install_receipt,
    load_runtime_lock,
    replay_observed_negative_projection,
    replay_runtime_preflight_bundle,
    replay_runtime_preflight_terminal_failure,
    runtime_preflight_capability_report,
    runtime_preflight_spec,
)
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
from localinferencelab.ollama_attestation import (
    attestation_feasibility_spec,
    attestation_inspection,
    build_attestation_assessment,
    compile_attestation_fixture,
    load_attestation_assessment,
    load_attestation_spec,
    replay_attestation_fixture,
    write_attestation_assessment,
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


def _emit_document(value: object) -> None:
    sys.stdout.buffer.write(canonical_json(value))


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

    mlx = commands.add_parser(
        "mlx",
        help="offline direct-worker manifests, prospective contract, and refusal fixture",
    )
    mlx_commands = mlx.add_subparsers(dest="mlx_command", required=True)
    mlx_commands.add_parser(
        "capability-report",
        help="report implemented direct-worker capabilities without probing MLX or Metal",
    )
    mlx_commands.add_parser(
        "custody-capability-report",
        help="report the additive refusal-only custody surface without starting a process",
    )
    mlx_commands.add_parser(
        "runtime-preflight-capability-report",
        help="report runtime-only preflight capabilities without imports or process actions",
    )
    mlx_commands.add_parser(
        "runtime-preflight-spec",
        help="emit the exact runtime-only preflight specification without imports",
    )
    mlx_commands.add_parser(
        "prospective-spec",
        help="emit the pinned execution-ineligible direct MLX study specification",
    )
    runtime_manifest = mlx_commands.add_parser(
        "runtime-manifest-create",
        help="compile an explicit supplied package-root byte closure without imports or execution",
    )
    runtime_manifest.add_argument("scan_spec", type=Path)
    runtime_manifest.add_argument("runtime_root", type=Path)
    runtime_manifest.add_argument("interpreter", type=Path)
    runtime_manifest.add_argument("worker_program", type=Path)
    runtime_manifest.add_argument("output", type=Path)
    model_manifest = mlx_commands.add_parser(
        "model-manifest-create",
        help=(
            "compile a supplied model-root byte closure and loader-scope projection without loading"
        ),
    )
    model_manifest.add_argument("model_root", type=Path)
    model_manifest.add_argument("output", type=Path)
    mlx_prospective = mlx_commands.add_parser(
        "prospective-create",
        help="create a fail-closed direct-worker package from optional static manifests",
    )
    mlx_prospective.add_argument("spec", type=Path)
    mlx_prospective.add_argument("output", type=Path)
    mlx_prospective.add_argument("--runtime-manifest", type=Path)
    mlx_prospective.add_argument("--model-manifest", type=Path)
    mlx_verify = mlx_commands.add_parser(
        "prospective-verify",
        help="strictly verify one direct-worker prospective package",
    )
    mlx_verify.add_argument("package", type=Path)
    mlx_inspect = mlx_commands.add_parser(
        "eligibility-inspect",
        help="inspect exact missing evidence and the closed execution gate",
    )
    mlx_inspect.add_argument("package", type=Path)
    mlx_fixture = mlx_commands.add_parser(
        "fixture-compile",
        help="publish deterministic synthetic refusal-contract evidence",
    )
    mlx_fixture.add_argument("output_root", type=Path)
    mlx_replay = mlx_commands.add_parser(
        "fixture-replay",
        help="replay one closed MLX refusal fixture offline",
    )
    mlx_replay.add_argument("bundle", type=Path)
    mlx_custody = mlx_commands.add_parser(
        "custody-self-test",
        help=(
            "start one inert local child/private socket and consume one synthetic refusal-only "
            "authorization/output root; perform zero model or backend actions"
        ),
    )
    mlx_custody.add_argument("output_root", type=Path)
    mlx_custody_replay = mlx_commands.add_parser(
        "custody-replay",
        help="replay one inert custody bundle process-free with zero model or backend actions",
    )
    mlx_custody_replay.add_argument("bundle", type=Path)
    mlx_custody_inspect = mlx_commands.add_parser(
        "custody-inspect",
        help="inspect reconstructed inert-custody blocker splits without starting a process",
    )
    mlx_custody_inspect.add_argument("bundle", type=Path)
    runtime_preflight_disclosure = (
        "Schema 1.0 execution is disabled because MLX-LM 0.30.6 declares mlx>=0.30.4 "
        "on Darwin while the reviewed runtime pins MLX 0.29.3. This command validates and "
        "rejects that receipt without an output root, child, socket, authorization, MLX "
        "import, or probe. A compatible pair requires a separately reviewed schema and "
        "authorization; only pure replay and the negative projection are currently supported."
    )
    runtime_preflight = mlx_commands.add_parser(
        "runtime-preflight",
        help="reject the schema-1.0 dependency-incompatible runtime before physical action",
        description=runtime_preflight_disclosure,
    )
    runtime_preflight.add_argument("runtime_manifest", type=Path)
    runtime_preflight.add_argument("runtime_lock", type=Path)
    runtime_preflight.add_argument("install_receipt", type=Path)
    runtime_preflight_replay = mlx_commands.add_parser(
        "runtime-preflight-replay",
        help="replay one closed runtime preflight without imports, processes, or sockets",
    )
    runtime_preflight_replay.add_argument("bundle", type=Path)
    runtime_preflight_inspect = mlx_commands.add_parser(
        "runtime-preflight-inspect",
        help="inspect runtime-preflight facts and blockers without imports or processes",
    )
    runtime_preflight_inspect.add_argument("bundle", type=Path)
    runtime_preflight_failure_replay = mlx_commands.add_parser(
        "runtime-preflight-failure-replay",
        help="replay one failed-closed runtime preflight record without imports or processes",
    )
    runtime_preflight_failure_replay.add_argument("failure_record", type=Path)
    runtime_preflight_negative_replay = mlx_commands.add_parser(
        "runtime-preflight-negative-replay",
        help="replay the pinned failed observed-attempt projection without imports or processes",
    )
    runtime_preflight_negative_replay.add_argument("projection", type=Path)
    mlx_commands.add_parser(
        "runtime-qualification-spec",
        help="emit the process-free schema-1.0 static qualification specification",
    )
    runtime_qualification_create = mlx_commands.add_parser(
        "runtime-qualification-create",
        help="derive one static decision record from explicit candidate bytes and metadata",
    )
    runtime_qualification_create.add_argument("candidate", type=Path)
    runtime_qualification_create.add_argument("output", type=Path)
    runtime_qualification_verify = mlx_commands.add_parser(
        "runtime-qualification-verify",
        help="strictly verify and reconstruct one static qualification record",
    )
    runtime_qualification_verify.add_argument("record", type=Path)
    runtime_qualification_inspect = mlx_commands.add_parser(
        "runtime-qualification-inspect",
        help="inspect static eligibility and exact blockers without runtime action",
    )
    runtime_qualification_inspect.add_argument("record", type=Path)
    runtime_qualification_fixture = mlx_commands.add_parser(
        "runtime-qualification-fixture-compile",
        help="publish deterministic historical-negative and synthetic-positive evidence",
    )
    runtime_qualification_fixture.add_argument("output_root", type=Path)
    runtime_qualification_replay = mlx_commands.add_parser(
        "runtime-qualification-replay",
        help="replay one closed qualification fixture without imports or processes",
    )
    runtime_qualification_replay.add_argument("bundle", type=Path)
    mlx_commands.add_parser(
        "runtime-preflight-1-1-capability-report",
        help="report the prospective model-free schema-1.1 contract with execution unreachable",
    )
    mlx_commands.add_parser(
        "runtime-preflight-1-1-protocol",
        help="emit the prospective unimplemented schema-1.1 protocol",
    )
    mlx_commands.add_parser(
        "runtime-preflight-1-1-spec",
        help="emit the candidate-agnostic schema-1.1 model-free preflight specification",
    )
    runtime_preflight_1_1_create = mlx_commands.add_parser(
        "runtime-preflight-1-1-record-create",
        help="construct a process-free schema-1.1 prerequisite/refusal record",
    )
    runtime_preflight_1_1_create.add_argument("qualification_record", type=Path)
    runtime_preflight_1_1_create.add_argument("output", type=Path)
    runtime_preflight_1_1_create.add_argument(
        "--authorization-claim",
        type=Path,
        help=(
            "caller-supplied structure only; cannot prove authorization, freshness, "
            "independent bindings, consumption, or non-reuse"
        ),
    )
    runtime_preflight_1_1_verify = mlx_commands.add_parser(
        "runtime-preflight-1-1-record-verify",
        help="strictly verify a schema-1.1 prerequisite/refusal record",
    )
    runtime_preflight_1_1_verify.add_argument("record", type=Path)
    runtime_preflight_1_1_inspect = mlx_commands.add_parser(
        "runtime-preflight-1-1-record-inspect",
        help="inspect schema-1.1 blockers with zero physical runtime actions",
    )
    runtime_preflight_1_1_inspect.add_argument("record", type=Path)
    runtime_preflight_1_1_fixture = mlx_commands.add_parser(
        "runtime-preflight-1-1-fixture-compile",
        help="publish deterministic synthetic/historical refusal-only contract evidence",
    )
    runtime_preflight_1_1_fixture.add_argument("output_root", type=Path)
    runtime_preflight_1_1_replay = mlx_commands.add_parser(
        "runtime-preflight-1-1-fixture-replay",
        help="replay one closed schema-1.1 refusal fixture without physical runtime action",
    )
    runtime_preflight_1_1_replay.add_argument("bundle", type=Path)
    mlx_commands.add_parser(
        "determinism-canary-spec",
        help="emit the runtime-independent prospective determinism canary specification",
    )
    determinism_verify = mlx_commands.add_parser(
        "determinism-canary-verify",
        help="strictly verify one canonical canary spec, fixture, result, comparison, or atlas",
    )
    determinism_verify.add_argument("record", type=Path)
    determinism_inspect = mlx_commands.add_parser(
        "determinism-canary-inspect",
        help="inspect one verified canary record without runtime or hardware access",
    )
    determinism_inspect.add_argument("record", type=Path)
    determinism_fixture = mlx_commands.add_parser(
        "determinism-canary-fixture-compile",
        help="publish exact embedded synthetic vectors, results, comparisons, and atlas",
    )
    determinism_fixture.add_argument("output_root", type=Path)
    determinism_replay = mlx_commands.add_parser(
        "determinism-canary-replay",
        help="replay one closed synthetic canary bundle without physical actions",
    )
    determinism_replay.add_argument("bundle", type=Path)

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
    ollama_commands.add_parser(
        "attestation-spec",
        help="emit the pinned offline listener/runner feasibility specification",
    )
    attestation_create = ollama_commands.add_parser(
        "attestation-create",
        help="derive the fail-closed attestation assessment without live acquisition",
    )
    attestation_create.add_argument("output", type=Path)
    attestation_create.add_argument(
        "--spec",
        type=Path,
        help="explicit canonical pinned feasibility specification",
    )
    attestation_verify = ollama_commands.add_parser(
        "attestation-verify",
        help="strictly verify a canonical attestation assessment offline",
    )
    attestation_verify.add_argument("assessment", type=Path)
    attestation_inspect = ollama_commands.add_parser(
        "attestation-inspect",
        help="inspect the derived verdict and exact missing primitives",
    )
    attestation_inspect.add_argument("assessment", type=Path)
    attestation_fixture = ollama_commands.add_parser(
        "attestation-fixture-compile",
        help="publish deterministic offline attestation-feasibility evidence",
    )
    attestation_fixture.add_argument("output_root", type=Path)
    attestation_replay = ollama_commands.add_parser(
        "attestation-replay",
        help="replay a closed attestation-feasibility fixture offline",
    )
    attestation_replay.add_argument("bundle", type=Path)
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
    if args.command == "mlx":
        if args.mlx_command == "capability-report":
            _emit(mlx_capability_report())
            return 0
        if args.mlx_command == "custody-capability-report":
            _emit(inert_custody_capability_report())
            return 0
        if args.mlx_command == "runtime-preflight-capability-report":
            _emit(runtime_preflight_capability_report())
            return 0
        if args.mlx_command == "runtime-preflight-spec":
            _emit_document(runtime_preflight_spec())
            return 0
        if args.mlx_command == "prospective-spec":
            _emit_document(mlx_study_spec())
            return 0
        if args.mlx_command == "runtime-manifest-create":
            manifest = compile_runtime_manifest(
                load_runtime_scan_spec(args.scan_spec),
                args.runtime_root,
                args.interpreter,
                args.worker_program,
            )
            write_manifest(args.output, manifest)
            _emit(
                {
                    "status": "created",
                    "manifest_id": manifest["manifest_id"],
                    "mlx_imports": 0,
                    "process_actions": 0,
                    "network_actions": 0,
                }
            )
            return 0
        if args.mlx_command == "model-manifest-create":
            manifest = compile_model_manifest(args.model_root)
            write_manifest(args.output, manifest)
            _emit(
                {
                    "status": "created",
                    "manifest_id": manifest["manifest_id"],
                    "model_loads": 0,
                    "tokenizer_loads": 0,
                    "network_actions": 0,
                }
            )
            return 0
        if args.mlx_command == "prospective-create":
            runtime_manifest, model_manifest = load_optional_manifests(
                args.runtime_manifest,
                args.model_manifest,
            )
            package = build_mlx_prospective_package(
                load_mlx_study_spec(args.spec),
                runtime_manifest=runtime_manifest,
                model_manifest=model_manifest,
            )
            write_mlx_prospective_package(args.output, package)
            inspection = mlx_eligibility_inspection(package)
            inspection["status"] = "created"
            _emit(inspection)
            return 0
        if args.mlx_command in {"prospective-verify", "eligibility-inspect"}:
            package = load_mlx_prospective_package(args.package)
            inspection = mlx_eligibility_inspection(package)
            inspection["status"] = (
                "valid" if args.mlx_command == "prospective-verify" else "inspected"
            )
            _emit(inspection)
            return 0
        if args.mlx_command == "fixture-compile":
            path, mlx_replay = compile_mlx_fixture(args.output_root)
            output = mlx_replay.to_dict()
            output["status"] = "compiled"
            output["path"] = path.name
            output["evidence_status"] = "synthetic_offline_refusal_contract_evidence"
            _emit(output)
            return 0
        if args.mlx_command == "custody-self-test":
            path, custody_replay = run_inert_custody_self_test(args.output_root)
            output = custody_replay.to_dict()
            output["status"] = "refused"
            output["path"] = path.name
            output["action"] = "inert_refusal_only"
            _emit(output)
            return 0
        if args.mlx_command == "custody-replay":
            custody_replay = replay_inert_custody_bundle(args.bundle)
            output = custody_replay.to_dict()
            output["status"] = "replayed"
            output["process_actions_during_replay"] = 0
            output["socket_actions_during_replay"] = 0
            _emit(output)
            return 0
        if args.mlx_command == "custody-inspect":
            output = inspect_inert_custody_bundle(args.bundle)
            output["status"] = "inspected"
            output["process_actions_during_inspection"] = 0
            output["socket_actions_during_inspection"] = 0
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight":
            runtime_manifest = load_runtime_manifest(args.runtime_manifest)
            runtime_lock = load_runtime_lock(args.runtime_lock)
            install_receipt = load_install_receipt(
                args.install_receipt,
                runtime_lock=runtime_lock,
                runtime_manifest=runtime_manifest,
            )
            build_runtime_preflight_package(
                runtime_manifest,
                runtime_lock,
                install_receipt,
            )
            raise ContractError("unreachable runtime-preflight execution gate")
        if args.mlx_command == "runtime-preflight-replay":
            preflight_replay = replay_runtime_preflight_bundle(args.bundle)
            output = preflight_replay.to_dict()
            output["status"] = "replayed"
            output["mlx_imports_during_replay"] = 0
            output["process_actions_during_replay"] = 0
            output["socket_actions_during_replay"] = 0
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight-inspect":
            output = inspect_runtime_preflight_bundle(args.bundle)
            output["status"] = "inspected"
            output["mlx_imports_during_inspection"] = 0
            output["process_actions_during_inspection"] = 0
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight-failure-replay":
            output = replay_runtime_preflight_terminal_failure(args.failure_record)
            output["status"] = "replayed_failed_closed"
            output["mlx_imports_during_replay"] = 0
            output["process_actions_during_replay"] = 0
            output["socket_actions_during_replay"] = 0
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight-negative-replay":
            output = replay_observed_negative_projection(args.projection)
            output["status"] = "replayed_failed_closed"
            output["mlx_imports_during_replay"] = 0
            output["process_actions_during_replay"] = 0
            output["socket_actions_during_replay"] = 0
            _emit(output)
            return 0
        if args.mlx_command == "runtime-qualification-spec":
            _emit_document(qualification_spec())
            return 0
        if args.mlx_command == "runtime-qualification-create":
            qualification_record = build_qualification_record(
                load_qualification_package(args.candidate)
            )
            write_qualification_record(args.output, qualification_record)
            output = qualification_inspection(qualification_record)
            output["status"] = "created"
            _emit(output)
            return 0
        if args.mlx_command in {
            "runtime-qualification-verify",
            "runtime-qualification-inspect",
        }:
            qualification_record = load_qualification_record(args.record)
            output = qualification_inspection(qualification_record)
            output["status"] = (
                "valid" if args.mlx_command == "runtime-qualification-verify" else "inspected"
            )
            _emit(output)
            return 0
        if args.mlx_command == "runtime-qualification-fixture-compile":
            fixture_path, qualification_fixture_replay = compile_qualification_fixture(
                args.output_root
            )
            output = qualification_fixture_replay.to_dict()
            output["status"] = "compiled"
            output["path"] = fixture_path.name
            output["evidence_status"] = (
                "synthetic_static_contract_evidence_and_historical_projection"
            )
            _emit(output)
            return 0
        if args.mlx_command == "runtime-qualification-replay":
            qualification_replay = replay_qualification_fixture(args.bundle)
            output = qualification_replay.to_dict()
            output["status"] = "replayed"
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight-1-1-capability-report":
            _emit(runtime_preflight_capability_report_1_1())
            return 0
        if args.mlx_command == "runtime-preflight-1-1-protocol":
            _emit_document(runtime_preflight_protocol_1_1())
            return 0
        if args.mlx_command == "runtime-preflight-1-1-spec":
            _emit_document(runtime_preflight_spec_1_1())
            return 0
        if args.mlx_command == "runtime-preflight-1-1-record-create":
            authorization_claim = (
                None
                if args.authorization_claim is None
                else load_authorization_claim_1_1(args.authorization_claim)
            )
            schema_1_1_record = build_runtime_preflight_record_1_1(
                load_qualification_record(args.qualification_record),
                authorization_claim,
            )
            write_runtime_preflight_record_1_1(args.output, schema_1_1_record)
            output = inspect_runtime_preflight_record_1_1(schema_1_1_record)
            output["status"] = "created"
            _emit(output)
            return 0
        if args.mlx_command in {
            "runtime-preflight-1-1-record-verify",
            "runtime-preflight-1-1-record-inspect",
        }:
            schema_1_1_record = load_runtime_preflight_record_1_1(args.record)
            output = inspect_runtime_preflight_record_1_1(schema_1_1_record)
            output["status"] = (
                "valid"
                if args.mlx_command == "runtime-preflight-1-1-record-verify"
                else "inspected"
            )
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight-1-1-fixture-compile":
            path, schema_1_1_replay = compile_runtime_preflight_fixture_1_1(args.output_root)
            output = schema_1_1_replay.to_dict()
            output["status"] = "compiled"
            output["path"] = path.name
            _emit(output)
            return 0
        if args.mlx_command == "runtime-preflight-1-1-fixture-replay":
            schema_1_1_replay = replay_runtime_preflight_fixture_1_1(args.bundle)
            output = schema_1_1_replay.to_dict()
            output["status"] = "replayed"
            _emit(output)
            return 0
        if args.mlx_command == "determinism-canary-spec":
            _emit_document(determinism_canary_spec())
            return 0
        if args.mlx_command in {
            "determinism-canary-verify",
            "determinism-canary-inspect",
        }:
            output = canary_inspection(load_canary_record(args.record))
            output["status"] = (
                "valid" if args.mlx_command == "determinism-canary-verify" else "inspected"
            )
            _emit(output)
            return 0
        if args.mlx_command == "determinism-canary-fixture-compile":
            fixture_path, canary_replay = compile_determinism_fixture(args.output_root)
            output = canary_replay.to_dict()
            output["status"] = "compiled"
            output["path"] = fixture_path.name
            _emit(output)
            return 0
        if args.mlx_command == "determinism-canary-replay":
            canary_replay = replay_determinism_fixture(args.bundle)
            output = canary_replay.to_dict()
            output["status"] = "replayed"
            _emit(output)
            return 0
        mlx_replay_result = replay_mlx_fixture(args.bundle)
        output = mlx_replay_result.to_dict()
        output["status"] = "replayed"
        output["external_network_actions"] = 0
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
        if args.ollama_command == "attestation-spec":
            _emit(attestation_feasibility_spec())
            return 0
        if args.ollama_command == "attestation-create":
            specification = (
                attestation_feasibility_spec()
                if args.spec is None
                else load_attestation_spec(args.spec)
            )
            assessment_value = build_attestation_assessment(specification)
            write_attestation_assessment(args.output, assessment_value)
            output = attestation_inspection(load_attestation_assessment(args.output))
            output["status"] = "created"
            _emit(output)
            return 0
        if args.ollama_command in {"attestation-verify", "attestation-inspect"}:
            assessment = load_attestation_assessment(args.assessment)
            output = attestation_inspection(assessment)
            output["status"] = (
                "valid" if args.ollama_command == "attestation-verify" else "inspected"
            )
            _emit(output)
            return 0
        if args.ollama_command == "attestation-fixture-compile":
            fixture_path, attestation_replay = compile_attestation_fixture(args.output_root)
            output = attestation_replay.to_dict()
            output["status"] = "compiled"
            output["path"] = fixture_path.name
            output["evidence_status"] = "synthetic_offline_feasibility_contract_evidence"
            _emit(output)
            return 0
        if args.ollama_command == "attestation-replay":
            attestation_replay = replay_attestation_fixture(args.bundle)
            output = attestation_replay.to_dict()
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
