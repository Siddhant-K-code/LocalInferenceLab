"""Adversarial custody and replay tests."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_json,
    digest_bytes,
    encode_bytes,
    load_json_bytes,
)
from localinferencelab.contracts import HostIdentity, ModelIdentity, RuntimeIdentity, parse_record
from localinferencelab.custody import (
    _fixture_evidence_is_synthetic,
    publish_bundle,
    publish_bundle_at,
    replay_bundle,
)
from localinferencelab.fixture import compile_fixture, fixture_content


def _bundle_files(path: Path) -> dict[str, bytes]:
    return {
        item.relative_to(path).as_posix(): item.read_bytes()
        for item in path.rglob("*")
        if item.is_file()
    }


def _publish_mutation(tmp_path: Path, content: dict[str, bytes], name: str) -> Path:
    root = tmp_path / name
    root.mkdir()
    return publish_bundle(content, root, name_prefix="mutated")


def _mutate_json(
    content: dict[str, bytes],
    name: str,
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    value = load_json_bytes(content[name])
    assert isinstance(value, dict)
    mutate(value)
    content[name] = canonical_json(value)


def test_fixture_is_byte_deterministic_and_replays(tmp_path: Path) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first_root.mkdir()
    second_root.mkdir()
    first, first_summary = compile_fixture(first_root)
    second, second_summary = compile_fixture(second_root)
    assert first.name == second.name
    assert _bundle_files(first) == _bundle_files(second)
    assert first_summary["bundle_root"] == second_summary["bundle_root"]
    assert (
        first_summary["bundle_root"]
        == "sha256:c4401fe71dee474a610eb95cf071fea72a0c09a3b221d80bd023c603f618617e"
    )
    assert (
        first_summary["protocol_id"]
        == "sha256:a23da6973f43faa2a9ae5e3d9bb912a43434f185507760e9363689956dfa5df5"
    )
    result = replay_bundle(first)
    assert result.run_count == 4
    assert result.group_count == 2
    assert result.exactly_repeatable_groups == 1
    assert result.divergent_groups == 1
    assert result.incomplete_groups == 0
    assert result.not_comparable_groups == 0
    assert result.representation_equivalence == ("unproven",)


@pytest.mark.parametrize(
    ("operation", "message"),
    [
        ("tamper", "digest mismatch"),
        ("extra", "closure mismatch"),
        ("missing", "closure mismatch"),
        ("receipt", "no publication receipt"),
    ],
)
def test_bundle_tampering_is_rejected(
    tmp_path: Path,
    operation: str,
    message: str,
) -> None:
    root = tmp_path / operation
    root.mkdir()
    bundle, _summary = compile_fixture(root)
    if operation == "tamper":
        with (bundle / "analysis.json").open("ab") as handle:
            handle.write(b" ")
    elif operation == "extra":
        (bundle / "extra.json").write_text("{}", encoding="utf-8")
    elif operation == "missing":
        (bundle / "protocol.json").unlink()
    else:
        (bundle / "receipt.json").unlink()
    with pytest.raises(ContractError, match=message):
        replay_bundle(bundle)


def test_swapped_files_are_rejected_after_valid_republication(tmp_path: Path) -> None:
    content = fixture_content()
    left = "identities/runtime-mlx-lm.json"
    right = "identities/runtime-llama-cpp.json"
    content[left], content[right] = content[right], content[left]
    bundle = _publish_mutation(tmp_path, content, "swapped")
    with pytest.raises(ContractError, match="wrong bundle path"):
        replay_bundle(bundle)


def test_unknown_record_key_is_rejected_after_valid_republication(tmp_path: Path) -> None:
    content = fixture_content()

    def add_unknown(value: dict[str, JsonValue]) -> None:
        value["unknown"] = True

    _mutate_json(content, "protocol.json", add_unknown)
    bundle = _publish_mutation(tmp_path, content, "unknown-key")
    with pytest.raises(ContractError, match="unknown keys"):
        replay_bundle(bundle)


def test_identity_drift_is_rejected_after_valid_republication(tmp_path: Path) -> None:
    content = fixture_content()

    def drift(value: dict[str, JsonValue]) -> None:
        value["model_id"] = "sha256:" + ("0" * 64)

    _mutate_json(content, "runs/0001-mlx-warm-model-001.json", drift)
    bundle = _publish_mutation(tmp_path, content, "identity-drift")
    with pytest.raises(ContractError, match="exact protocol schedule"):
        replay_bundle(bundle)


def test_forbidden_observed_execution_is_rejected(tmp_path: Path) -> None:
    content = fixture_content()

    def claim_observed(value: dict[str, JsonValue]) -> None:
        value["evidence_kind"] = "observed_execution"
        value["inference_request_count"] = 1
        metrics = value["native_metrics"]
        assert isinstance(metrics, list)
        for metric in metrics:
            assert isinstance(metric, dict)
            if metric["availability"] == "synthetic":
                metric["availability"] = "observed"

    _mutate_json(content, "runs/0001-mlx-warm-model-001.json", claim_observed)
    bundle = _publish_mutation(tmp_path, content, "forbidden")
    with pytest.raises(ContractError, match="cannot custody observed"):
        replay_bundle(bundle)


def test_analysis_recomputation_detects_semantic_tampering(tmp_path: Path) -> None:
    content = fixture_content()
    analysis = load_json_bytes(content["analysis.json"])
    assert isinstance(analysis, dict)
    analysis["primary_scope"] = "cross_backend_leaderboard"
    content["analysis.json"] = canonical_json(analysis)
    bundle = _publish_mutation(tmp_path, content, "analysis")
    with pytest.raises(ContractError, match="analysis replay mismatch"):
        replay_bundle(bundle)


def test_fixture_source_is_required_and_semantically_checked(tmp_path: Path) -> None:
    missing = fixture_content()
    missing.pop("source/fixture.json")
    missing_bundle = _publish_mutation(tmp_path, missing, "missing-source")
    with pytest.raises(ContractError, match="strict fixture source"):
        replay_bundle(missing_bundle)

    changed = fixture_content()

    def change_expected_count(value: dict[str, JsonValue]) -> None:
        value["expected_run_count"] = 5

    _mutate_json(changed, "source/fixture.json", change_expected_count)
    changed_bundle = _publish_mutation(tmp_path, changed, "changed-source")
    with pytest.raises(ContractError, match="source intent"):
        replay_bundle(changed_bundle)


def test_request_drift_cannot_be_pooled_as_a_repeat(tmp_path: Path) -> None:
    content = fixture_content()

    def change_request(value: dict[str, JsonValue]) -> None:
        request = canonical_json({"different": "request"})
        value["request_base64"] = encode_bytes(request)
        value["request_sha256"] = digest_bytes(request)

    _mutate_json(content, "runs/0001-mlx-warm-model-001.json", change_request)
    bundle = _publish_mutation(tmp_path, content, "request-drift")
    with pytest.raises(ContractError, match="exact protocol schedule"):
        replay_bundle(bundle)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("cache_cohort", "cold_process_model"),
        ("process_instance_id", "sha256:" + ("0" * 64)),
        ("model_instance_id", "sha256:" + ("1" * 64)),
        ("cache_preparation_id", "sha256:" + ("2" * 64)),
        ("concurrency_id", "sha256:" + ("3" * 64)),
        ("concurrency_wave", 99),
    ],
)
def test_replay_rejects_relabelled_schedule_state(
    tmp_path: Path,
    field: str,
    replacement: JsonValue,
) -> None:
    content = fixture_content()

    def relabel(value: dict[str, JsonValue]) -> None:
        value[field] = replacement

    _mutate_json(content, "runs/0001-mlx-warm-model-001.json", relabel)
    bundle = _publish_mutation(tmp_path, content, f"schedule-relabel-{field}")
    with pytest.raises(ContractError, match="exact protocol schedule"):
        replay_bundle(bundle)


def test_replay_rejects_reordered_runs(tmp_path: Path) -> None:
    content = fixture_content()
    first_name = "runs/0001-mlx-warm-model-001.json"
    second_name = "runs/0002-mlx-warm-model-002.json"
    first = load_json_bytes(content.pop(first_name))
    second = load_json_bytes(content.pop(second_name))
    assert isinstance(first, dict)
    assert isinstance(second, dict)
    first["run_order"] = 2
    second["run_order"] = 1
    content["runs/0002-mlx-warm-model-001.json"] = canonical_json(first)
    content["runs/0001-mlx-warm-model-002.json"] = canonical_json(second)
    bundle = _publish_mutation(tmp_path, content, "schedule-reordered")
    with pytest.raises(ContractError, match="exact protocol schedule"):
        replay_bundle(bundle)


def test_replay_rejects_duplicate_and_missing_runs(tmp_path: Path) -> None:
    duplicate = fixture_content()
    second_name = "runs/0002-mlx-warm-model-002.json"
    second = load_json_bytes(duplicate.pop(second_name))
    assert isinstance(second, dict)
    second["run_id"] = "mlx-warm-model-001"
    duplicate["runs/0002-mlx-warm-model-001.json"] = canonical_json(second)
    duplicate_bundle = _publish_mutation(tmp_path, duplicate, "schedule-duplicate")
    with pytest.raises(ContractError, match="exact protocol schedule"):
        replay_bundle(duplicate_bundle)

    missing = fixture_content()
    missing.pop("runs/0002-mlx-warm-model-002.json")
    missing_bundle = _publish_mutation(tmp_path, missing, "schedule-missing")
    with pytest.raises(ContractError, match="run count"):
        replay_bundle(missing_bundle)


def test_path_traversal_and_symlink_roots_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(ContractError, match="unsafe bundle path"):
        publish_bundle({"../escape.json": b"{}"}, tmp_path, name_prefix="unsafe")
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    with pytest.raises(ContractError, match="symlink path component"):
        publish_bundle(fixture_content(), link, name_prefix="unsafe")
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o777)
    unsafe.chmod(0o777)
    with pytest.raises(ContractError, match="group/world writable"):
        publish_bundle(fixture_content(), unsafe, name_prefix="unsafe")
    with pytest.raises(ContractError, match="unsafe bundle path"):
        publish_bundle(fixture_content(), tmp_path, name_prefix="../escape")
    with pytest.raises(ContractError, match="reserved bundle path"):
        publish_bundle({"receipt.json": b"{}"}, tmp_path, name_prefix="reserved")


def test_descriptor_relative_publication_is_closed_and_no_replace(tmp_path: Path) -> None:
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        content = {
            "nested/first.json": b'{"value":1}',
            "nested/second.json": b'{"value":2}',
        }
        bundle = publish_bundle_at(
            content,
            tmp_path,
            descriptor,
            name_prefix="descriptor",
        )
        assert (bundle / "receipt.json").is_file()
        assert (bundle / "nested/first.json").read_bytes() == content["nested/first.json"]
        with pytest.raises(FileExistsError):
            publish_bundle_at(
                content,
                tmp_path,
                descriptor,
                name_prefix="descriptor",
            )
        assert not list(tmp_path.glob(".localinferencelab-stage-*"))
        with pytest.raises(ContractError, match="canonical basename"):
            publish_bundle_at(
                content,
                tmp_path,
                descriptor,
                name_prefix="nested/prefix",
            )
    finally:
        os.close(descriptor)


def test_replay_rejects_symlinked_bundle_ancestor(tmp_path: Path) -> None:
    bundle, _summary = compile_fixture(tmp_path)
    external = tmp_path / "external-runs"
    shutil.copytree(bundle / "runs", external)
    shutil.rmtree(bundle / "runs")
    (bundle / "runs").symlink_to(external, target_is_directory=True)
    with pytest.raises(ContractError, match="symlink"):
        replay_bundle(bundle)


def test_replay_rejects_writable_nested_directory(tmp_path: Path) -> None:
    bundle, _summary = compile_fixture(tmp_path)
    (bundle / "runs").chmod(0o777)
    with pytest.raises(ContractError, match="group/world writable"):
        replay_bundle(bundle)


def test_fixture_evidence_requires_synthetic_top_level_identities() -> None:
    content = fixture_content()
    host = parse_record(load_json_bytes(content["identities/host.json"]))
    runtime = parse_record(load_json_bytes(content["identities/runtime-mlx-lm.json"]))
    model = parse_record(load_json_bytes(content["identities/model-mlx-lm.json"]))
    assert isinstance(host, HostIdentity)
    assert isinstance(runtime, RuntimeIdentity)
    assert isinstance(model, ModelIdentity)
    assert _fixture_evidence_is_synthetic(
        {"host": host},
        {"runtime": runtime},
        {"model": model},
        {},
        {},
        {},
        [],
    )
    assert not _fixture_evidence_is_synthetic(
        {"host": replace(host, evidence_kind="safe_host_probe")},
        {"runtime": runtime},
        {"model": model},
        {},
        {},
        {},
        [],
    )
    assert not _fixture_evidence_is_synthetic(
        {"host": host},
        {"runtime": replace(runtime, evidence_kind="static_artifact_probe")},
        {"model": model},
        {},
        {},
        {},
        [],
    )
    assert not _fixture_evidence_is_synthetic(
        {"host": host},
        {"runtime": runtime},
        {"model": replace(model, evidence_kind="static_artifact_probe")},
        {},
        {},
        {},
        [],
    )


def test_replay_fifo_failure_is_bounded(tmp_path: Path) -> None:
    bundle, _summary = compile_fixture(tmp_path)
    analysis = bundle / "analysis.json"
    analysis.unlink()
    os.mkfifo(analysis)
    script = (
        "from pathlib import Path\n"
        "from localinferencelab.canonical import ContractError\n"
        "from localinferencelab.custody import replay_bundle\n"
        f"bundle = Path({str(bundle)!r})\n"
        "try:\n"
        "    replay_bundle(bundle)\n"
        "except ContractError:\n"
        "    raise SystemExit(0)\n"
        "raise SystemExit(1)\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script],
        check=False,
        capture_output=True,
        timeout=3,
    )
    assert result.returncode == 0


def test_replay_rejects_socket_bundle_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _summary = compile_fixture(tmp_path)
    analysis = bundle / "analysis.json"
    analysis.unlink()
    monkeypatch.chdir(bundle)
    server = socket.socket(socket.AF_UNIX)
    try:
        server.bind("analysis.json")
        with pytest.raises(ContractError, match="non-regular"):
            replay_bundle(bundle)
    finally:
        server.close()


def test_publication_collision_is_no_clobber(tmp_path: Path) -> None:
    compile_fixture(tmp_path)
    with pytest.raises(FileExistsError):
        compile_fixture(tmp_path)


def test_concurrent_publication_has_one_winner(tmp_path: Path) -> None:
    def attempt() -> str:
        try:
            compile_fixture(tmp_path)
        except FileExistsError:
            return "collision"
        return "published"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(lambda _value: attempt(), range(2)))
    assert outcomes == ["collision", "published"]
