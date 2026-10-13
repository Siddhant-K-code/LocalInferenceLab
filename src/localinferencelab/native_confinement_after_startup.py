"""Separate post-startup diagnostic, never proof of startup confinement or MLX permission."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_json_bytes,
)
from localinferencelab.native_confinement import _read_regular, _run_variant
from localinferencelab.native_confinement_contract import MAX_REPORT_BYTES, verify_report

_FIELDS = {
    "record_type",
    "schema_version",
    "application_stage",
    "startup_confinement_proven",
    "runtime_authority",
    "test_record",
    "record_id",
}


def verify_diagnostic(value: JsonValue) -> dict[str, JsonValue]:
    """Replay an exact non-authority envelope that cannot promote post-startup effects."""
    if type(value) is not dict or value.keys() != _FIELDS:
        raise ContractError("native post-startup envelope fields")
    for field, expected in (
        ("record_type", "native_confinement_after_startup_diagnostic"),
        ("schema_version", "1.0"),
        ("application_stage", "after_native_startup"),
    ):
        if type(value[field]) is not str or value[field] != expected:
            raise ContractError("native post-startup envelope contract")
    for field in ("startup_confinement_proven", "runtime_authority"):
        if type(value[field]) is not bool or value[field] is not False:
            raise ContractError("native post-startup is not startup confinement or authority")
    verify_report(value["test_record"])
    identity = value["record_id"]
    if type(identity) is not str or identity != canonical_identity(
        {key: item for key, item in value.items() if key != "record_id"}
    ):
        raise ContractError("native post-startup identity")
    if len(canonical_json(value)) > MAX_REPORT_BYTES:
        raise ContractError("native post-startup byte bound")
    return value


def run_diagnostic() -> dict[str, JsonValue]:
    """Run one separate fixed benign experiment, with no automatic fallback or retry."""
    result: dict[str, JsonValue] = {
        "record_type": "native_confinement_after_startup_diagnostic",
        "schema_version": "1.0",
        "application_stage": "after_native_startup",
        "startup_confinement_proven": False,
        "runtime_authority": False,
        "test_record": _run_variant("after_startup"),
    }
    result["record_id"] = canonical_identity(result)
    return verify_diagnostic(result)


def replay_bytes(data: bytes) -> dict[str, JsonValue]:
    """Validate bounded canonical diagnostic bytes offline, without invoking any probe."""
    if len(data) > MAX_REPORT_BYTES:
        raise ContractError("native post-startup byte bound")
    try:
        result = verify_diagnostic(load_json_bytes(data))
    except RecursionError as error:
        raise ContractError("native post-startup nesting") from error
    if canonical_json(result) != data:
        raise ContractError("native post-startup noncanonical")
    return result


def main(argv: list[str] | None = None) -> int:
    """Keep this separately invoked diagnostic out of the pre-exec and legacy CLIs."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run", help="Benign post-startup policy experiment; never MLX")
    replay = commands.add_parser("replay", help="Offline non-authority diagnostic replay")
    replay.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        result = (
            run_diagnostic()
            if args.command == "run"
            else replay_bytes(_read_regular(args.report, MAX_REPORT_BYTES))
        )
    except (ContractError, OSError) as error:
        print(f"native post-startup error: {type(error).__name__}", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(canonical_json(result))
    # Even matching post-startup observations do not establish the required startup boundary.
    return 2 if args.command == "run" else 0


if __name__ == "__main__":
    raise SystemExit(main())
