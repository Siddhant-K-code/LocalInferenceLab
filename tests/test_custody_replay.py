"""Adversarial custody and replay tests."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
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
from localinferencelab.custody import publish_bundle, replay_bundle
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
        == "sha256:9eb7a18c03e89a09ae4edf2d1b206a1629f5dafa08e0f0a35cbcf42deac5988d"
    )
    assert (
        first_summary["protocol_id"]
        == "sha256:aaec03109045825b589f5a05714aa2fd19abebffe0d1dfcd4d04e2abb2108c8f"
    )
    result = replay_bundle(first)
    assert result.run_count == 4
    assert result.group_count == 2
    assert result.exactly_repeatable_groups == 1
    assert result.divergent_groups == 1
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

    _mutate_json(content, "runs/0001-mlx-cold-001.json", drift)
    bundle = _publish_mutation(tmp_path, content, "identity-drift")
    with pytest.raises(ContractError, match="unknown identity"):
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

    _mutate_json(content, "runs/0001-mlx-cold-001.json", claim_observed)
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

    _mutate_json(content, "runs/0001-mlx-cold-001.json", change_request)
    bundle = _publish_mutation(tmp_path, content, "request-drift")
    with pytest.raises(ContractError, match="repeat count"):
        replay_bundle(bundle)


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
