"""End-to-end CLI command tests."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from localinferencelab.canonical import ContractError, canonical_json, load_json_bytes
from localinferencelab.cli import main, run
from localinferencelab.contracts import parse_record
from localinferencelab.fixture import fixture_content


def _output(capfd: pytest.CaptureFixture[str]) -> dict[str, object]:
    captured = capfd.readouterr()
    assert captured.err == ""
    value = json.loads(captured.out)
    assert isinstance(value, dict)
    return value


def test_contract_and_backend_commands(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    contract = tmp_path / "protocol.json"
    contract.write_bytes(fixture_content()["protocol.json"])
    assert run(["contract", "verify", str(contract)]) == 0
    assert _output(capfd)["status"] == "valid"

    assert run(["backend", "plan", "ollama"]) == 0
    plan = _output(capfd)
    assert plan["allowed_to_execute"] is False
    assert plan["execution_implemented"] is True
    assert json.loads(canonical_json(plan)) == plan

    artifact = tmp_path / "ollama"
    artifact.write_bytes(b"fixture artifact")
    assert (
        run(
            [
                "backend",
                "probe",
                "ollama",
                str(artifact),
                "--version",
                "fixture",
                "--commit",
                "abc123",
            ],
        )
        == 0
    )
    probe = _output(capfd)
    assert probe["executable_name"] == "ollama"
    assert probe["identity_complete"] is False
    assert str(tmp_path) not in json.dumps(probe)
    probe.pop("identity")
    assert parse_record(load_json_bytes(canonical_json(probe))).record_type == "runtime_identity"


def test_fixture_verify_and_replay_commands(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert run(["fixture", "compile", str(tmp_path)]) == 0
    compiled = _output(capfd)
    bundle = tmp_path / str(compiled["path"])
    assert compiled["model_actions"] == 0

    assert run(["bundle", "verify", str(bundle)]) == 0
    verified = _output(capfd)
    assert verified["status"] == "verified"
    assert verified["network_actions"] == 0

    assert run(["bundle", "replay", str(bundle)]) == 0
    replayed = _output(capfd)
    assert replayed["status"] == "replayed"
    assert replayed["exactly_repeatable_groups"] == 1
    assert replayed["divergent_groups"] == 1


def test_host_probe_command_is_privacy_preserving(
    capfd: pytest.CaptureFixture[str],
) -> None:
    assert run(["host", "probe"]) == 0
    output = _output(capfd)
    encoded = json.dumps(output)
    assert "/Users/" not in encoded
    assert "/home/" not in encoded
    assert "identity" in output
    output.pop("identity")
    assert parse_record(load_json_bytes(canonical_json(output))).record_type == "host_identity"


@pytest.mark.parametrize(
    "version",
    [
        "/Users/person/runtime",
        "Users/person/runtime",
        "home/person/runtime",
        "~/runtime",
        "~\\runtime",
        "username=person",
        "bad\ud800",
    ],
)
def test_backend_probe_cli_rejects_private_versions(
    tmp_path: Path,
    version: str,
) -> None:
    artifact = tmp_path / "runtime"
    artifact.write_bytes(b"fixture")
    with pytest.raises(ContractError, match=r"private|surrogate"):
        run(
            [
                "backend",
                "probe",
                "ollama",
                str(artifact),
                "--version",
                version,
            ],
        )


def test_main_reports_fail_closed_errors(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    noncanonical = tmp_path / "record.json"
    noncanonical.write_text('{ "record_type": "protocol" }', encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["localinferencelab", "contract", "verify", str(noncanonical)],
    )
    assert main() == 2
    captured = capfd.readouterr()
    assert captured.out == ""
    assert "not canonical JSON" in captured.err


def test_main_rejects_unknown_backend(
    capfd: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["localinferencelab", "backend", "plan", "unknown"],
    )
    assert main() == 2
    assert "backend must be one of" in capfd.readouterr().err
