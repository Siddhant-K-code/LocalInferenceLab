"""Exact prospective MLX runtime target and drift-rejection tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_runtime_target as target_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    load_canonical_json_file,
)
from localinferencelab.cli import run
from localinferencelab.mlx_runtime_target import (
    EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
    load_runtime_target_anchor,
    runtime_target_anchor,
    runtime_target_replay,
    verify_runtime_target_anchor,
    verify_runtime_target_observation,
)


def _dict(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    copied = json.loads(canonical_json(value))
    assert isinstance(copied, dict)
    return cast("dict[str, JsonValue]", copied)


def _anchor_path() -> Path:
    return (
        Path(target_module.__file__).resolve(strict=True).parents[2]
        / "runtime"
        / "mlx-runtime-target-macos-arm64-cpython-3.13.15.json"
    )


def _observation(anchor: dict[str, JsonValue]) -> dict[str, JsonValue]:
    target = _dict(anchor["prospective_target"])
    value: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_target_observation",
        "schema_version": "1.0",
        "evidence_kind": "future_independent_runtime_identity_observation",
        "observer_relationship": "independent_from_candidate",
        "self_attested": False,
        "ambiguous_host_promotion": False,
        "target_anchor_id": anchor["anchor_id"],
        "interpreter": _copy(target["interpreter"]),
        "platform": _copy(target["platform"]),
        "static_action_counters": {
            "backend_queries": 0,
            "device_queries": 0,
            "metal_queries": 0,
            "model_actions": 0,
            "package_installations": 0,
            "package_network_requests": 0,
            "process_starts": 0,
            "runtime_imports": 0,
            "socket_creations": 0,
            "synchronizations": 0,
        },
    }
    value["observation_id"] = canonical_identity(value)
    return value


def _rehash_observation(observation: dict[str, JsonValue]) -> None:
    observation.pop("observation_id", None)
    observation["observation_id"] = canonical_identity(observation)


def test_committed_target_anchor_is_exact_and_process_free() -> None:
    anchor = load_runtime_target_anchor(_anchor_path())
    assert anchor == runtime_target_anchor()
    assert anchor["anchor_id"] == EXPECTED_RUNTIME_TARGET_ANCHOR_ID
    target = _dict(anchor["prospective_target"])
    interpreter = _dict(target["interpreter"])
    platform = _dict(target["platform"])
    assert interpreter == {
        "abi_flags": "",
        "cache_tag": "cpython-313",
        "executable_realpath": ("cpython-3.13.15-macos-aarch64-none/bin/python3.13"),
        "code_signature": {
            "cdhash_sha256": ("09a976c9f1b4632fdb567ef2ab14ee4eb93aba159dd99c1096ffcdd0b2ca6673"),
            "identifier": "-",
            "signature_kind": "adhoc_linker_signed",
        },
        "executable_name": "python3.13",
        "executable_sha256": (
            "sha256:4e1dfb03f82c5f7f253bbc3c04a79bb9f09a5cd0528829c32d6984ef309ebb2f"
        ),
        "implementation_name": "cpython",
        "implementation_version": "3.13.15",
        "python_abi": "cp313",
        "python_full_version": "3.13.15",
        "python_version": "3.13",
        "realpath_kind": "installation_root_relative",
        "soabi": "cpython-313-darwin",
    }
    assert platform == {
        "architecture": "arm64",
        "macos_build_version": "26A434",
        "macos_product_version": "27.0.1",
        "platform_system": "Darwin",
        "python_interpreter_deployment_target": "11.0",
        "python_platform_tag": "macosx-11.0-arm64",
        "runtime_wheel_deployment_target": "15.0",
    }
    replay = runtime_target_replay(anchor)
    assert replay["python_full_version"] == "3.13.15"
    assert replay["python_abi"] == "cp313"
    assert replay["development_observation_is_runtime_evidence"] is False
    assert replay["runtime_observation_committed"] is False
    assert replay["runtime_authorized"] is False
    assert replay["mlx_or_metal_actions"] == 0
    selection = _dict(anchor["selection"])
    assert selection["prior_candidate_python_full_version"] == "3.13.0"
    assert selection["historical_failed_receipt_python_full_version"] == "3.13.15"
    assert selection["historical_failed_receipt_accepted_as_target_evidence"] is False
    assert selection["selected_python_full_version"] == "3.13.15"
    serialized = canonical_json(anchor)
    assert b"/Users/" not in serialized
    assert b"siddhant" not in serialized.lower()


def test_future_independent_observation_must_match_every_target_field() -> None:
    anchor = runtime_target_anchor()
    observation = _observation(anchor)
    assert verify_runtime_target_observation(anchor, observation) == observation

    mutations = [
        ("interpreter", "executable_sha256", "sha256:" + ("0" * 64)),
        (
            "interpreter",
            "executable_realpath",
            "cpython-3.13.15-macos-aarch64-none/bin/python3",
        ),
        ("interpreter", "python_full_version", "3.13.0"),
        ("interpreter", "implementation_version", "3.13.0"),
        ("interpreter", "cache_tag", "cpython-312"),
        ("interpreter", "python_abi", "cp312"),
        ("interpreter", "soabi", "cpython-312-darwin"),
        ("platform", "macos_product_version", "27.0.0"),
        ("platform", "macos_build_version", "26A433"),
        ("platform", "python_interpreter_deployment_target", "12.0"),
        ("platform", "runtime_wheel_deployment_target", "14.0"),
        ("platform", "architecture", "x86_64"),
    ]
    for section, field, value in mutations:
        drifted = _copy(observation)
        _dict(drifted[section])[field] = value
        _rehash_observation(drifted)
        with pytest.raises(ContractError, match=f"{section} identity drift"):
            verify_runtime_target_observation(anchor, drifted)


def test_target_rejects_self_attestation_ambiguity_and_malformed_types() -> None:
    anchor = runtime_target_anchor()
    for field, message in (
        ("self_attested", "self-attested"),
        ("ambiguous_host_promotion", "ambiguous host promotion"),
    ):
        observation = _observation(anchor)
        observation[field] = True
        _rehash_observation(observation)
        with pytest.raises(ContractError, match=message):
            verify_runtime_target_observation(anchor, observation)

    malformed = _observation(anchor)
    malformed["self_attested"] = 0
    _rehash_observation(malformed)
    with pytest.raises(ContractError, match="must be a boolean"):
        verify_runtime_target_observation(anchor, malformed)

    boolean_counter = _observation(anchor)
    _dict(boolean_counter["static_action_counters"])["process_starts"] = False
    _rehash_observation(boolean_counter)
    with pytest.raises(ContractError, match="must be an integer"):
        verify_runtime_target_observation(anchor, boolean_counter)

    development = _dict(anchor["development_host_observation"])
    with pytest.raises(ContractError, match="missing keys"):
        verify_runtime_target_observation(anchor, development)


def test_anchor_rejects_coordinated_rehashing_and_unknown_fields() -> None:
    anchor = runtime_target_anchor()
    rehashed = _copy(anchor)
    target = _dict(rehashed["prospective_target"])
    interpreter = _dict(target["interpreter"])
    interpreter["executable_sha256"] = "sha256:" + ("0" * 64)
    rehashed.pop("anchor_id")
    rehashed["anchor_id"] = canonical_identity(rehashed)
    with pytest.raises(ContractError, match="not the committed trust root"):
        verify_runtime_target_anchor(rehashed)

    unknown = _copy(anchor)
    unknown["host_claim"] = "self-attested"
    with pytest.raises(ContractError, match="unknown keys"):
        verify_runtime_target_anchor(unknown)

    boolean_counter = _copy(anchor)
    _dict(boolean_counter["static_action_counters"])["process_starts"] = False
    with pytest.raises(ContractError, match="must be an integer"):
        verify_runtime_target_anchor(boolean_counter)


def test_target_cli_emission_and_replay_are_offline(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert run(["mlx", "runtime-target-anchor"]) == 0
    emitted = json.loads(capsys.readouterr().out)
    assert emitted["anchor_id"] == EXPECTED_RUNTIME_TARGET_ANCHOR_ID

    assert run(["mlx", "runtime-target-replay", str(_anchor_path())]) == 0
    replay = json.loads(capsys.readouterr().out)
    assert replay["status"] == "replayed"
    assert replay["runtime_authorized"] is False
    assert replay["mlx_or_metal_actions"] == 0


def test_anchor_file_is_canonical() -> None:
    value = load_canonical_json_file(_anchor_path(), "runtime target anchor")
    assert canonical_json(value) == _anchor_path().read_bytes()
