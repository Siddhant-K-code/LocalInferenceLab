"""Adversarial tests for the physical refusal-only MLX custody plane."""

from __future__ import annotations

import ast
import builtins
import json
import os
import socket
import struct
import time
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

import localinferencelab.mlx_custody as mlx_custody_module
import localinferencelab.mlx_inert_worker as inert_worker_module
from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_json_bytes,
)
from localinferencelab.cli import run
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_custody import (
    DEFAULT_DEADLINE_NS,
    EXPECTED_WORKER_PROGRAM_SHA256,
    PROTOCOL_ID,
    REFUSAL_REASON,
    WORKER_CODE_ID,
    _build_authorization,
    _consume_authorization_at,
    _FrameChannel,
    _open_private_output_root,
    _output_root_binding,
    _revalidate_output_root_path,
    _terminate_and_wait,
    _verify_authorization,
    _verify_refusal,
    _wait_child,
    inert_custody_capability_report,
    inert_custody_spec,
    inspect_inert_custody_bundle,
    replay_inert_custody_bundle,
    run_inert_custody_self_test,
)
from localinferencelab.mlx_runner import build_mlx_prospective_package, mlx_study_spec


def _dict(value: JsonValue) -> dict[str, JsonValue]:
    assert isinstance(value, dict)
    return value


def _list(value: JsonValue) -> list[JsonValue]:
    assert isinstance(value, list)
    return value


def _copy(value: JsonValue) -> dict[str, JsonValue]:
    copied = json.loads(canonical_json(value))
    assert isinstance(copied, dict)
    return cast("dict[str, JsonValue]", copied)


def _private_directory(path: Path) -> Path:
    path.mkdir()
    path.chmod(0o700)
    return path.resolve(strict=True)


@pytest.fixture
def custody_bundle(tmp_path: Path) -> tuple[Path, dict[str, JsonValue]]:
    output_root = _private_directory(tmp_path / "custody")
    bundle, result = run_inert_custody_self_test(output_root)
    _content_root, files = read_closed_bundle(bundle)
    record = load_json_bytes(files["custody-record.json"])
    assert isinstance(record, dict)
    assert result.custody_record_id == record["custody_record_id"]
    return bundle, cast("dict[str, JsonValue]", record)


def _raw_frame(payload: bytes) -> bytes:
    return struct.pack(">I", len(payload)) + payload


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (struct.pack(">I", 0), "frame length"),
        (struct.pack(">I", 1024 * 1024 + 1), "frame length"),
        (struct.pack(">I", 4) + b"{}", "truncated frame payload"),
        (_raw_frame(b'{ "message_type":"x"}'), "canonical JSON"),
        (_raw_frame(b'{"message_type":"x","message_type":"x"}'), "duplicate JSON key"),
    ],
)
def test_frame_decoder_rejects_invalid_lengths_truncation_and_json(
    raw: bytes,
    message: str,
) -> None:
    parent, peer = socket.socketpair()
    try:
        peer.sendall(raw)
        peer.shutdown(socket.SHUT_WR)
        channel = _FrameChannel(parent, time.monotonic_ns() + 500_000_000, [])
        with pytest.raises(ContractError, match=message):
            channel.receive()
    finally:
        parent.close()
        peer.close()


def test_frame_decoder_rejects_deadline_and_peer_eof() -> None:
    parent, peer = socket.socketpair()
    try:
        expired = _FrameChannel(parent, time.monotonic_ns() - 1, [])
        with pytest.raises(ContractError, match="deadline"):
            expired.receive()
        peer.close()
        live = _FrameChannel(parent, time.monotonic_ns() + 500_000_000, [])
        with pytest.raises(ContractError, match="peer EOF"):
            live.receive()
    finally:
        parent.close()


def test_frame_decoder_rejects_extra_output_after_terminal_ack() -> None:
    parent, peer = socket.socketpair()
    try:
        peer.sendall(b"x")
        peer.shutdown(socket.SHUT_WR)
        channel = _FrameChannel(parent, time.monotonic_ns() + 500_000_000, [])
        with pytest.raises(ContractError, match="extra output"):
            channel.expect_eof()
    finally:
        parent.close()
        peer.close()


def _worker_hello() -> dict[str, object]:
    package = build_mlx_prospective_package(mlx_study_spec())
    return {
        "message_type": "parent_hello",
        "sequence": 1,
        "protocol_id": PROTOCOL_ID,
        "worker_code_id": WORKER_CODE_ID,
        "study_spec_id": package["study_spec_id"],
        "package_id": package["package_id"],
        "package_sha256": digest_bytes(canonical_json(package)),
        "interpreter_sha256": "sha256:" + ("2" * 64),
        "worker_program_sha256": EXPECTED_WORKER_PROGRAM_SHA256,
        "parent_nonce": encode_bytes(b"p" * 32),
        "output_root_id": "sha256:" + ("1" * 64),
        "deadline_monotonic_ns": time.monotonic_ns() + DEFAULT_DEADLINE_NS,
    }


def test_worker_canonical_parser_and_channel_are_strict() -> None:
    canonical = b'{"message_type":"fixture","sequence":1}'
    assert inert_worker_module._parse_canonical(canonical)["sequence"] == 1  # noqa: SLF001
    for invalid in (
        b'{ "message_type":"fixture","sequence":1}',
        b'{"message_type":"fixture","message_type":"fixture","sequence":1}',
        b'{"message_type":"fixture","sequence":1.0}',
        b'{"message_type":"fixture","sequence":NaN}',
        b"\xff",
    ):
        with pytest.raises(inert_worker_module.WorkerProtocolError):
            inert_worker_module._parse_canonical(invalid)  # noqa: SLF001
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="keys"):
        inert_worker_module._canonical_json({1: "invalid"})  # type: ignore[dict-item]  # noqa: SLF001
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="unsupported"):
        inert_worker_module._canonical_json({"invalid": object()})  # noqa: SLF001
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="surrogate"):
        inert_worker_module._canonical_json({"invalid": "\ud800"})  # noqa: SLF001

    parent, peer = socket.socketpair()
    try:
        deadline = time.monotonic_ns() + 500_000_000
        reader = inert_worker_module._Channel(parent, deadline)  # noqa: SLF001
        writer = inert_worker_module._Channel(peer, deadline)  # noqa: SLF001
        message = {"message_type": "fixture", "sequence": 1}
        writer.send(message)
        assert reader.receive() == message
        peer.sendall(struct.pack(">I", 0))
        with pytest.raises(inert_worker_module.WorkerProtocolError, match="frame length"):
            reader.receive()
    finally:
        parent.close()
        peer.close()


def test_worker_state_validators_bind_identity_authorization_and_nonces() -> None:
    hello = _worker_hello()
    assert inert_worker_module._verify_hello(hello) == hello  # noqa: SLF001
    wrong_protocol = dict(hello)
    wrong_protocol["protocol_id"] = "sha256:" + ("0" * 64)
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="protocol"):
        inert_worker_module._verify_hello(wrong_protocol)  # noqa: SLF001
    bool_sequence = dict(hello)
    bool_sequence["sequence"] = True
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="integer"):
        inert_worker_module._verify_hello(bool_sequence)  # noqa: SLF001

    worker_nonce = encode_bytes(b"w" * 32)
    authorization = _build_authorization(
        cast("dict[str, JsonValue]", hello),
        worker_nonce,
        time.time_ns(),
    )
    authorize = {
        "message_type": "authorize_once",
        "sequence": 3,
        "authorization": cast("dict[str, object]", authorization),
    }
    verified, authorization_id = inert_worker_module._verify_authorization(  # noqa: SLF001
        authorize,
        hello,
        worker_nonce,
    )
    assert verified["authorization_id"] == authorization_id
    substituted = _copy(authorization)
    substituted["package_id"] = "sha256:" + ("2" * 64)
    substituted_content = dict(substituted)
    del substituted_content["authorization_id"]
    substituted["authorization_id"] = canonical_identity(substituted_content)
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="package_id"):
        inert_worker_module._verify_authorization(  # noqa: SLF001
            {
                "message_type": "authorize_once",
                "sequence": 3,
                "authorization": cast("dict[str, object]", substituted),
            },
            hello,
            worker_nonce,
        )
    invalid_lifetime = _copy(authorization)
    invalid_lifetime["expires_at_unix_ns"] = cast("int", invalid_lifetime["expires_at_unix_ns"]) + 1
    invalid_lifetime_content = dict(invalid_lifetime)
    del invalid_lifetime_content["authorization_id"]
    invalid_lifetime["authorization_id"] = canonical_identity(invalid_lifetime_content)
    with pytest.raises(
        inert_worker_module.WorkerProtocolError,
        match="wall-clock lifetime",
    ):
        inert_worker_module._verify_authorization(  # noqa: SLF001
            {
                "message_type": "authorize_once",
                "sequence": 3,
                "authorization": cast("dict[str, object]", invalid_lifetime),
            },
            hello,
            worker_nonce,
        )

    request_nonce = encode_bytes(b"r" * 32)
    generate = {
        "message_type": "generate_once",
        "sequence": 5,
        "action": "inert_refusal_only",
        "authorization_id": authorization_id,
        "package_id": hello["package_id"],
        "output_root_id": hello["output_root_id"],
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": worker_nonce,
        "request_nonce": request_nonce,
    }
    assert (
        inert_worker_module._verify_generate(  # noqa: SLF001
            generate,
            hello,
            worker_nonce,
            authorization_id,
        )
        == request_nonce
    )
    wrong_request = dict(generate)
    wrong_request["worker_nonce"] = encode_bytes(b"x" * 32)
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="worker_nonce"):
        inert_worker_module._verify_generate(  # noqa: SLF001
            wrong_request,
            hello,
            worker_nonce,
            authorization_id,
        )

    shutdown = {
        "message_type": "shutdown",
        "sequence": 7,
        "parent_nonce": hello["parent_nonce"],
        "worker_nonce": worker_nonce,
        "request_nonce": request_nonce,
    }
    inert_worker_module._verify_shutdown(  # noqa: SLF001
        shutdown,
        hello["parent_nonce"],
        worker_nonce,
        request_nonce,
    )
    shutdown["request_nonce"] = encode_bytes(b"x" * 32)
    with pytest.raises(inert_worker_module.WorkerProtocolError, match="shutdown nonce"):
        inert_worker_module._verify_shutdown(  # noqa: SLF001
            shutdown,
            hello["parent_nonce"],
            worker_nonce,
            request_nonce,
        )


def test_worker_file_identity_descriptor_enumeration_and_main_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    interpreter = inert_worker_module._file_identity(  # noqa: SLF001
        str(Path(os.sys.executable).resolve(strict=True)),
        executable=True,
    )
    worker = inert_worker_module._file_identity(  # noqa: SLF001
        str(Path(inert_worker_module.__file__).resolve(strict=True)),
        executable=False,
    )
    assert interpreter["sha256"].startswith("sha256:")
    assert worker["sha256"] == EXPECTED_WORKER_PROGRAM_SHA256
    assert {0, 1, 2}.issubset(inert_worker_module._open_file_descriptors())  # noqa: SLF001

    monkeypatch.setattr(inert_worker_module.sys, "argv", ["worker", "unexpected"])
    assert inert_worker_module.main() == 2
    monkeypatch.setattr(inert_worker_module.sys, "argv", ["worker"])
    monkeypatch.setattr(inert_worker_module, "_worker_main", lambda: None)
    assert inert_worker_module.main() == 0

    def fail() -> None:
        raise inert_worker_module.WorkerProtocolError("injected")

    monkeypatch.setattr(inert_worker_module, "_worker_main", fail)
    assert inert_worker_module.main() == 2


def test_refusal_validator_rejects_unknown_fields_bool_counts_and_tampering() -> None:
    package = build_mlx_prospective_package(mlx_study_spec())
    parent_nonce = encode_bytes(b"p" * 32)
    worker_nonce = encode_bytes(b"w" * 32)
    hello: dict[str, JsonValue] = {
        "package_id": package["package_id"],
        "package_sha256": digest_bytes(canonical_json(package)),
        "interpreter_sha256": "sha256:" + ("2" * 64),
        "worker_program_sha256": EXPECTED_WORKER_PROGRAM_SHA256,
        "study_spec_id": package["study_spec_id"],
        "parent_nonce": parent_nonce,
        "output_root_id": "sha256:" + ("1" * 64),
        "deadline_monotonic_ns": time.monotonic_ns() + DEFAULT_DEADLINE_NS,
    }
    authorization = _build_authorization(hello, worker_nonce, time.time_ns())
    request_nonce = encode_bytes(b"r" * 32)
    refusal: dict[str, JsonValue] = {
        "message_type": "result_or_terminal_error",
        "sequence": 6,
        "status": "refused",
        "reason": REFUSAL_REASON,
        "generated_result_present": False,
        "authorization_id": authorization["authorization_id"],
        "package_id": package["package_id"],
        "output_root_id": hello["output_root_id"],
        "parent_nonce": parent_nonce,
        "worker_nonce": worker_nonce,
        "request_nonce": request_nonce,
        "mlx_imports": 0,
        "mlx_lm_imports": 0,
        "model_loads": 0,
        "tokenizer_loads": 0,
        "device_queries": 0,
        "metal_initializations": 0,
        "inference_requests": 0,
        "network_actions": 0,
        "cache_mutations": 0,
    }
    _verify_refusal(refusal, authorization=authorization, request_nonce=request_nonce)

    unknown = dict(refusal)
    unknown["unexpected"] = 0
    with pytest.raises(ContractError, match="unknown keys"):
        _verify_refusal(unknown, authorization=authorization, request_nonce=request_nonce)

    confused = dict(refusal)
    confused["inference_requests"] = False
    with pytest.raises(ContractError, match="integer"):
        _verify_refusal(confused, authorization=authorization, request_nonce=request_nonce)

    accepted = dict(refusal)
    accepted["status"] = "accepted"
    accepted["generated_result_present"] = True
    with pytest.raises(ContractError, match="status mismatch"):
        _verify_refusal(accepted, authorization=authorization, request_nonce=request_nonce)


def _authorization_fixture(
    root: Path,
) -> tuple[int, dict[str, JsonValue], dict[str, JsonValue]]:
    descriptor = _open_private_output_root(root)
    output_root = _output_root_binding(descriptor, b"o" * 32)
    package = build_mlx_prospective_package(mlx_study_spec())
    hello: dict[str, JsonValue] = {
        "package_id": package["package_id"],
        "package_sha256": digest_bytes(canonical_json(package)),
        "interpreter_sha256": "sha256:" + ("2" * 64),
        "worker_program_sha256": EXPECTED_WORKER_PROGRAM_SHA256,
        "study_spec_id": package["study_spec_id"],
        "parent_nonce": encode_bytes(b"p" * 32),
        "output_root_id": output_root["output_root_id"],
        "deadline_monotonic_ns": time.monotonic_ns() + DEFAULT_DEADLINE_NS,
    }
    authorization = _build_authorization(
        hello,
        encode_bytes(b"w" * 32),
        time.time_ns(),
    )
    return descriptor, output_root, authorization


def test_authorization_consumption_is_atomic_exactly_once_and_bound(
    tmp_path: Path,
) -> None:
    root = _private_directory(tmp_path / "authorization")
    descriptor, output_root, authorization = _authorization_fixture(root)
    try:
        consumption = _consume_authorization_at(descriptor, output_root, authorization)
        assert consumption["authorization_id"] == authorization["authorization_id"]
        with pytest.raises(ContractError, match="already consumed"):
            _consume_authorization_at(descriptor, output_root, authorization)

        substituted_root = _copy(output_root)
        substituted_root["inode"] = cast("int", substituted_root["inode"]) + 1
        content = dict(substituted_root)
        del content["output_root_id"]
        substituted_root["output_root_id"] = canonical_identity(content)
        with pytest.raises(ContractError, match="output-root identity mismatch"):
            _consume_authorization_at(descriptor, substituted_root, authorization)
    finally:
        os.close(descriptor)


def test_authorization_rejects_expiry_package_and_root_substitution(tmp_path: Path) -> None:
    root = _private_directory(tmp_path / "substitution")
    descriptor, output_root, authorization = _authorization_fixture(root)
    try:
        expired = _copy(authorization)
        expired["created_at_unix_ns"] = 1
        expired["expires_at_unix_ns"] = 1 + DEFAULT_DEADLINE_NS
        expired["deadline_monotonic_ns"] = 1
        content = dict(expired)
        del content["authorization_id"]
        expired["authorization_id"] = canonical_identity(content)
        with pytest.raises(ContractError, match="expired"):
            _verify_authorization(expired, check_current_expiry=True)

        package_substitution = _copy(authorization)
        package_substitution["package_id"] = "sha256:" + ("3" * 64)
        content = dict(package_substitution)
        del content["authorization_id"]
        package_substitution["authorization_id"] = canonical_identity(content)
        verified = _verify_authorization(package_substitution, check_current_expiry=True)
        assert verified["package_id"] != authorization["package_id"]
        wrong_root = _copy(output_root)
        wrong_root["output_root_id"] = "sha256:" + ("4" * 64)
        with pytest.raises(ContractError, match="output-root identity mismatch"):
            _consume_authorization_at(descriptor, wrong_root, package_substitution)
    finally:
        os.close(descriptor)


def test_output_root_rejects_symlink_mode_and_path_replacement(tmp_path: Path) -> None:
    public = tmp_path / "public"
    public.mkdir()
    public.chmod(0o755)
    with pytest.raises(ContractError, match="mode-0700"):
        _open_private_output_root(public)

    physical = _private_directory(tmp_path / "physical")
    link = tmp_path / "link"
    link.symlink_to(physical, target_is_directory=True)
    with pytest.raises(ContractError, match="symlink"):
        _open_private_output_root(link)

    retained = _open_private_output_root(physical)
    moved = tmp_path / "moved"
    physical.rename(moved)
    replacement = _private_directory(physical)
    try:
        with pytest.raises(ContractError, match="replaced"):
            _revalidate_output_root_path(replacement, retained)
    finally:
        os.close(retained)


def test_physical_self_test_exercises_exact_process_socket_and_refusal(
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, record = custody_bundle
    replay = replay_inert_custody_bundle(bundle)
    assert replay.terminal_state == "refused_and_closed"
    assert replay.refusal_reason == REFUSAL_REASON
    assert replay.authorization_consumptions == 1
    assert replay.process_actions == 1
    assert replay.socket_actions == 1
    assert replay.model_actions == 0
    assert replay.network_actions == 0

    action_ledger = _dict(record["action_ledger"])
    assert action_ledger == {
        "attempts": 1,
        "retries": 0,
        "warmups": 0,
        "worker_process_starts": 1,
        "socketpair_creations": 1,
        "authorizations_consumed": 1,
        "parent_frames": 4,
        "worker_frames": 4,
        "generate_once_commands": 1,
        "terminal_refusals": 1,
        "shutdowns": 1,
    }
    assert all(value == 0 for value in _dict(record["non_actions"]).values())
    assert _dict(record["interpreter"])["mode"] == 0o500
    assert _dict(record["worker_program"])["mode"] == 0o400
    assert _dict(record["worker_program"])["sha256"] == EXPECTED_WORKER_PROGRAM_SHA256
    child = _dict(record["child_wait"])
    assert child["wait_owned"] is True
    assert child["exit_code"] == 0
    with pytest.raises(ChildProcessError):
        os.waitpid(cast("int", child["pid"]), os.WNOHANG)

    _root, files = read_closed_bundle(bundle)
    encoded = b"".join(files.values()).lower()
    assert str(bundle.parent).encode().lower() not in encoded
    transcript = _dict(load_json_bytes(files["transcript.json"]))
    frames = _list(transcript["frames"])
    identity_payload = _dict(
        load_json_bytes(decode_bytes(cast("str", _dict(frames[1])["payload_base64"])))
    )
    assert identity_payload["open_file_descriptors"] == [0, 1, 2, 3]
    assert identity_payload["environment_id"] == inert_custody_spec()["launch"]["environment_id"]  # type: ignore[index]
    evidence = _dict(record["parent_process_evidence"])
    assert evidence["child_pid"] == child["pid"] == identity_payload["pid"]
    assert evidence["parent_pid"] == identity_payload["ppid"]
    assert not list(bundle.parent.glob(".localinferencelab-mlx-interpreter-*"))


def test_worker_executes_anonymous_snapshot_after_source_path_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_directory = _private_directory(tmp_path / "launch-source")
    fake_custody = source_directory / "mlx_custody.py"
    fake_custody.write_text("", encoding="utf-8")
    worker_path = source_directory / "mlx_inert_worker.py"
    worker_path.write_bytes(Path(inert_worker_module.__file__).read_bytes())
    original_spawn = mlx_custody_module._spawn_worker  # noqa: SLF001

    def replace_source_then_spawn(
        sealed_interpreter: Path,
        interpreter_argv0: Path,
        interpreter_identity_descriptor: int,
        worker_source_descriptor: int,
        child_endpoint: socket.socket,
    ) -> int:
        worker_path.write_text("raise SystemExit(7)\n", encoding="utf-8")
        return original_spawn(
            sealed_interpreter,
            interpreter_argv0,
            interpreter_identity_descriptor,
            worker_source_descriptor,
            child_endpoint,
        )

    monkeypatch.setattr(mlx_custody_module, "__file__", str(fake_custody))
    monkeypatch.setattr(mlx_custody_module, "_spawn_worker", replace_source_then_spawn)
    output_root = _private_directory(tmp_path / "sealed-launch")
    _bundle, result = run_inert_custody_self_test(output_root)
    assert result.terminal_state == "refused_and_closed"
    assert not list(output_root.glob(".localinferencelab-mlx-worker-*"))
    assert not list(output_root.glob(".localinferencelab-mlx-interpreter-*"))


def test_launch_target_rejects_group_or_world_writable_ancestor(tmp_path: Path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    target = unsafe / "worker.py"
    target.write_text("pass\n", encoding="utf-8")
    with pytest.raises(ContractError, match="not group/world writable"):
        mlx_custody_module._read_launch_target(  # noqa: SLF001
            target,
            "test launch target",
            executable=False,
        )
    target.chmod(0o777)
    identity, data = mlx_custody_module._read_launch_target(  # noqa: SLF001
        target,
        "selected interpreter source",
        executable=True,
        trusted_ancestors=False,
        trusted_source=False,
    )
    assert identity["sha256"] == digest_bytes(data)


def _republish_mutation(
    tmp_path: Path,
    bundle: Path,
    name: str,
    mutate: Callable[[dict[str, bytes]], None],
) -> Path:
    _root, files = read_closed_bundle(bundle)
    content = {
        path: data for path, data in files.items() if path not in {"index.json", "receipt.json"}
    }
    mutate(content)
    destination = _private_directory(tmp_path / name)
    return publish_bundle(content, destination, name_prefix=name)


def _reidentify_transcript_and_record(content: dict[str, bytes]) -> None:
    transcript = _dict(load_json_bytes(content["transcript.json"]))
    transcript_content = dict(transcript)
    del transcript_content["transcript_id"]
    transcript["transcript_id"] = canonical_identity(transcript_content)
    content["transcript.json"] = canonical_json(transcript)
    record = _dict(load_json_bytes(content["custody-record.json"]))
    record["transcript_id"] = transcript["transcript_id"]
    record_content = dict(record)
    del record_content["custody_record_id"]
    record["custody_record_id"] = canonical_identity(record_content)
    content["custody-record.json"] = canonical_json(record)


def _replace_transcript_payload(
    transcript: dict[str, JsonValue],
    index: int,
    payload: dict[str, JsonValue],
) -> None:
    frame = _dict(_list(transcript["frames"])[index])
    payload_bytes = canonical_json(payload)
    frame["payload_base64"] = encode_bytes(payload_bytes)
    frame["payload_sha256"] = digest_bytes(payload_bytes)
    frame["frame_sha256"] = digest_bytes(_raw_frame(payload_bytes))
    frame["size_bytes"] = len(payload_bytes)


def _rewrite_authorization_domain(
    content: dict[str, bytes],
    mutate: Callable[[dict[str, JsonValue]], None],
) -> None:
    authorization = _dict(load_json_bytes(content["authorization.json"]))
    mutate(authorization)
    authorization_content = dict(authorization)
    del authorization_content["authorization_id"]
    authorization["authorization_id"] = canonical_identity(authorization_content)
    content["authorization.json"] = canonical_json(authorization)

    transcript = _dict(load_json_bytes(content["transcript.json"]))
    frames = _list(transcript["frames"])
    authorize = _dict(
        load_json_bytes(decode_bytes(cast("str", _dict(frames[2])["payload_base64"])))
    )
    authorize["authorization"] = authorization
    _replace_transcript_payload(transcript, 2, authorize)
    acknowledgment = _dict(
        load_json_bytes(decode_bytes(cast("str", _dict(frames[3])["payload_base64"])))
    )
    acknowledgment["authorization_id"] = authorization["authorization_id"]
    acknowledgment["parent_nonce"] = authorization["parent_nonce"]
    acknowledgment["worker_nonce"] = authorization["worker_nonce"]
    _replace_transcript_payload(transcript, 3, acknowledgment)
    refusal = _dict(load_json_bytes(decode_bytes(cast("str", _dict(frames[5])["payload_base64"]))))
    refusal["authorization_id"] = authorization["authorization_id"]
    refusal["parent_nonce"] = authorization["parent_nonce"]
    refusal["worker_nonce"] = authorization["worker_nonce"]
    _replace_transcript_payload(transcript, 5, refusal)
    content["transcript.json"] = canonical_json(transcript)

    consumption = _dict(load_json_bytes(content["authorization-consumption.json"]))
    consumption["authorization_id"] = authorization["authorization_id"]
    consumption_content = dict(consumption)
    del consumption_content["consumption_id"]
    consumption["consumption_id"] = canonical_identity(consumption_content)
    content["authorization-consumption.json"] = canonical_json(consumption)

    record = _dict(load_json_bytes(content["custody-record.json"]))
    record["authorization_id"] = authorization["authorization_id"]
    record["consumption_id"] = consumption["consumption_id"]
    content["custody-record.json"] = canonical_json(record)
    _reidentify_transcript_and_record(content)


def test_replay_rejects_missing_extra_tampered_order_and_direction(
    tmp_path: Path,
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, _record = custody_bundle

    def missing(content: dict[str, bytes]) -> None:
        del content["authorization.json"]

    missing_bundle = _republish_mutation(tmp_path, bundle, "missing", missing)
    with pytest.raises(ContractError, match="invalid content set"):
        replay_inert_custody_bundle(missing_bundle)

    def extra(content: dict[str, bytes]) -> None:
        content["extra.json"] = b"{}"

    extra_bundle = _republish_mutation(tmp_path, bundle, "extra", extra)
    with pytest.raises(ContractError, match="invalid content set"):
        replay_inert_custody_bundle(extra_bundle)

    def wrong_direction(content: dict[str, bytes]) -> None:
        transcript = _dict(load_json_bytes(content["transcript.json"]))
        _dict(_list(transcript["frames"])[0])["direction"] = "worker_to_parent"
        content["transcript.json"] = canonical_json(transcript)
        _reidentify_transcript_and_record(content)

    direction_bundle = _republish_mutation(tmp_path, bundle, "direction", wrong_direction)
    with pytest.raises(ContractError, match="order or direction"):
        replay_inert_custody_bundle(direction_bundle)

    def wrong_order(content: dict[str, bytes]) -> None:
        transcript = _dict(load_json_bytes(content["transcript.json"]))
        frames = _list(transcript["frames"])
        frames[0], frames[1] = frames[1], frames[0]
        content["transcript.json"] = canonical_json(transcript)
        _reidentify_transcript_and_record(content)

    order_bundle = _republish_mutation(tmp_path, bundle, "order", wrong_order)
    with pytest.raises(ContractError, match="order or direction"):
        replay_inert_custody_bundle(order_bundle)


def test_replay_rejects_nonce_package_root_refusal_and_consumption_tampering(
    tmp_path: Path,
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, _record = custody_bundle

    mutations: list[tuple[str, str, Callable[[dict[str, bytes]], None]]] = []

    def authorization_nonce(content: dict[str, bytes]) -> None:
        authorization = _dict(load_json_bytes(content["authorization.json"]))
        authorization["parent_nonce"] = encode_bytes(b"x" * 32)
        auth_content = dict(authorization)
        del auth_content["authorization_id"]
        authorization["authorization_id"] = canonical_identity(auth_content)
        content["authorization.json"] = canonical_json(authorization)

    mutations.append(("nonce", "mismatch|substitution", authorization_nonce))

    def root_substitution(content: dict[str, bytes]) -> None:
        root = _dict(load_json_bytes(content["output-root-binding.json"]))
        root["inode"] = cast("int", root["inode"]) + 1
        root_content = dict(root)
        del root_content["output_root_id"]
        root["output_root_id"] = canonical_identity(root_content)
        content["output-root-binding.json"] = canonical_json(root)

    mutations.append(("root", "mismatch|substitution", root_substitution))

    def refusal_tamper(content: dict[str, bytes]) -> None:
        transcript = _dict(load_json_bytes(content["transcript.json"]))
        frame = _dict(_list(transcript["frames"])[5])
        payload = _dict(load_json_bytes(decode_bytes(cast("str", frame["payload_base64"]))))
        payload["reason"] = "tampered_refusal"
        payload_bytes = canonical_json(payload)
        frame["payload_base64"] = encode_bytes(payload_bytes)
        frame["payload_sha256"] = digest_bytes(payload_bytes)
        frame["frame_sha256"] = digest_bytes(_raw_frame(payload_bytes))
        frame["size_bytes"] = len(payload_bytes)
        content["transcript.json"] = canonical_json(transcript)
        _reidentify_transcript_and_record(content)

    mutations.append(("refusal", "reason mismatch", refusal_tamper))

    def consumption_tamper(content: dict[str, bytes]) -> None:
        consumption = _dict(load_json_bytes(content["authorization-consumption.json"]))
        consumption["package_id"] = "sha256:" + ("5" * 64)
        consumption_content = dict(consumption)
        del consumption_content["consumption_id"]
        consumption["consumption_id"] = canonical_identity(consumption_content)
        content["authorization-consumption.json"] = canonical_json(consumption)

    mutations.append(("consumption", "package_id mismatch", consumption_tamper))

    for name, message, mutate in mutations:
        mutated = _republish_mutation(tmp_path, bundle, name, mutate)
        with pytest.raises(ContractError, match=message):
            replay_inert_custody_bundle(mutated)


def test_replay_rejects_coordinated_authorization_session_forgery(
    tmp_path: Path,
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, _record = custody_bundle

    def parent_nonce(content: dict[str, bytes]) -> None:
        _rewrite_authorization_domain(
            content,
            lambda authorization: authorization.__setitem__(
                "parent_nonce",
                encode_bytes(b"z" * 32),
            ),
        )

    forged_nonce = _republish_mutation(tmp_path, bundle, "auth-nonce-domain", parent_nonce)
    with pytest.raises(ContractError, match="parent_nonce session binding mismatch"):
        replay_inert_custody_bundle(forged_nonce)

    def deadline(content: dict[str, bytes]) -> None:
        _rewrite_authorization_domain(
            content,
            lambda authorization: authorization.__setitem__(
                "deadline_monotonic_ns",
                cast("int", authorization["deadline_monotonic_ns"]) + 1,
            ),
        )

    forged_deadline = _republish_mutation(
        tmp_path,
        bundle,
        "auth-deadline-domain",
        deadline,
    )
    with pytest.raises(ContractError, match="deadline_monotonic_ns session binding mismatch"):
        replay_inert_custody_bundle(forged_deadline)


def test_replay_cross_binds_worker_identity_process_evidence_and_wait(
    tmp_path: Path,
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, _record = custody_bundle

    def coordinated_pid(content: dict[str, bytes]) -> None:
        transcript = _dict(load_json_bytes(content["transcript.json"]))
        identity = _dict(
            load_json_bytes(
                decode_bytes(
                    cast(
                        "str",
                        _dict(_list(transcript["frames"])[1])["payload_base64"],
                    )
                )
            )
        )
        forged_pid = cast("int", identity["pid"]) + 1
        identity["pid"] = forged_pid
        _replace_transcript_payload(transcript, 1, identity)
        content["transcript.json"] = canonical_json(transcript)
        record = _dict(load_json_bytes(content["custody-record.json"]))
        _dict(record["parent_process_evidence"])["child_pid"] = forged_pid
        content["custody-record.json"] = canonical_json(record)
        _reidentify_transcript_and_record(content)

    forged = _republish_mutation(tmp_path, bundle, "coordinated-pid", coordinated_pid)
    with pytest.raises(ContractError, match="process evidence and child wait PID mismatch"):
        replay_inert_custody_bundle(forged)


def test_replay_rejects_coordinated_worker_source_identity_forgery(
    tmp_path: Path,
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, _record = custody_bundle

    def coordinated(content: dict[str, bytes]) -> None:
        worker_bytes = content["source/worker-program.py"] + b"\n# coordinated forgery\n"
        forged_digest = digest_bytes(worker_bytes)
        content["source/worker-program.py"] = worker_bytes
        transcript = _dict(load_json_bytes(content["transcript.json"]))
        identity_frame = _dict(_list(transcript["frames"])[1])
        identity = _dict(
            load_json_bytes(decode_bytes(cast("str", identity_frame["payload_base64"])))
        )
        _dict(identity["worker_program"])["sha256"] = forged_digest
        _dict(identity["worker_program"])["size_bytes"] = len(worker_bytes)
        identity_bytes = canonical_json(identity)
        identity_frame["payload_base64"] = encode_bytes(identity_bytes)
        identity_frame["payload_sha256"] = digest_bytes(identity_bytes)
        identity_frame["frame_sha256"] = digest_bytes(_raw_frame(identity_bytes))
        identity_frame["size_bytes"] = len(identity_bytes)
        content["transcript.json"] = canonical_json(transcript)
        record = _dict(load_json_bytes(content["custody-record.json"]))
        _dict(record["worker_program"])["sha256"] = forged_digest
        _dict(record["worker_program"])["size_bytes"] = len(worker_bytes)
        content["custody-record.json"] = canonical_json(record)
        _reidentify_transcript_and_record(content)

    forged = _republish_mutation(tmp_path, bundle, "coordinated-worker", coordinated)
    with pytest.raises(ContractError, match="sealed worker digest"):
        replay_inert_custody_bundle(forged)


def test_inspection_splits_only_proven_blockers(
    custody_bundle: tuple[Path, dict[str, JsonValue]],
) -> None:
    bundle, _record = custody_bundle
    inspection = inspect_inert_custody_bundle(bundle)
    assert inspection["decision"] == "ineligible"
    assert inspection["observed_generation_reachable"] is False
    assert inspection["inert_refusal_observed"] is True
    splits = _list(cast("JsonValue", inspection["closed_or_split_requirements"]))
    legacy = {_dict(item)["legacy"] for item in splits}
    assert legacy == {
        "one_shot_authorization",
        "output_root_physical_binding",
        "production_worker_private_ipc_protocol_and_result_validation_implementation",
        "worker_process_birth_and_executable_binding",
    }
    remaining = set(cast("list[str]", inspection["remaining_requirements"]))
    assert {
        "generated_result_producer_and_validation_implementation",
        "mlx_model_action_one_shot_authorization",
        "parent_observed_running_executable_identity_on_all_supported_platforms",
        "active_backend_device_evidence",
        "strict_model_parameter_key_shape_load_evidence",
    }.issubset(remaining)


def test_inspection_uses_one_verified_bundle_snapshot(
    custody_bundle: tuple[Path, dict[str, JsonValue]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _record = custody_bundle
    original = mlx_custody_module.read_closed_bundle
    calls = 0

    def read_once(path: Path) -> tuple[str, dict[str, bytes]]:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise AssertionError("inspection reopened the bundle")
        return original(path)

    monkeypatch.setattr(mlx_custody_module, "read_closed_bundle", read_once)
    inspection = inspect_inert_custody_bundle(bundle)
    assert inspection["decision"] == "ineligible"
    assert calls == 1


def test_worker_early_exit_and_hang_are_waited_without_zombies() -> None:
    early = os.fork()
    if early == 0:
        os._exit(7)
    early_wait = _wait_child(early, time.monotonic_ns() + 1_000_000_000)
    assert early_wait["exit_code"] == 7
    with pytest.raises(ChildProcessError):
        os.waitpid(early, os.WNOHANG)

    hanging = os.fork()
    if hanging == 0:
        time.sleep(10)
        os._exit(0)
    try:
        with pytest.raises(ContractError, match="deadline"):
            _wait_child(hanging, time.monotonic_ns() + 10_000_000)
    finally:
        _terminate_and_wait(hanging)
    with pytest.raises(ChildProcessError):
        os.waitpid(hanging, os.WNOHANG)


def test_post_spawn_failure_is_reaped_and_terminally_custodied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _private_directory(tmp_path / "failed-closed")

    def reject_identity(*_args: object, **_kwargs: object) -> dict[str, JsonValue]:
        raise ContractError("injected identity rejection")

    monkeypatch.setattr(mlx_custody_module, "_verify_worker_identity", reject_identity)
    with pytest.raises(ContractError, match="identity rejection"):
        run_inert_custody_self_test(root)
    markers = list(root.glob(".localinferencelab-mlx-terminal-*.json"))
    assert len(markers) == 1
    failure = _dict(load_json_bytes(markers[0].read_bytes()))
    assert failure["terminal_state"] == "failed_closed"
    assert failure["phase"] == "worker_identity"
    assert failure["child_reaped"] is True
    ledger = _dict(failure["action_ledger"])
    assert ledger["socketpair_creations"] == 1
    assert ledger["worker_process_starts"] == 1
    assert ledger["authorizations_consumed"] == 0
    assert all(value == 0 for value in _dict(failure["non_actions"]).values())
    encoded = markers[0].read_text(encoding="utf-8")
    assert str(root) not in encoded


def test_actual_run_blocks_mlx_imports_and_has_no_network_or_command_surface(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_import = builtins.__import__

    def guarded_import(
        name: str,
        globals_value: dict[str, object] | None = None,
        locals_value: dict[str, object] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> object:
        if name.split(".", 1)[0] in {"mlx", "mlx_lm"}:
            raise AssertionError("MLX runtime import attempted")
        return original_import(name, globals_value, locals_value, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    root = _private_directory(tmp_path / "guarded")
    _bundle, result = run_inert_custody_self_test(root)
    assert result.model_actions == 0
    assert result.network_actions == 0

    source_root = Path(__file__).parents[1] / "src" / "localinferencelab"
    worker_tree = ast.parse((source_root / "mlx_inert_worker.py").read_text(encoding="utf-8"))
    parent_tree = ast.parse((source_root / "mlx_custody.py").read_text(encoding="utf-8"))
    forbidden_imports = {"mlx", "mlx_lm", "subprocess", "http", "urllib"}
    forbidden_calls = {
        "Popen",
        "run",
        "system",
        "exec",
        "eval",
        "listen",
        "bind",
        "connect",
        "create_connection",
    }
    for tree in (worker_tree, parent_tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(
                    alias.name.split(".", 1)[0] not in forbidden_imports for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".", 1)[0] not in forbidden_imports
            elif isinstance(node, ast.Call):
                function = node.func
                called = (
                    function.attr
                    if isinstance(function, ast.Attribute)
                    else function.id
                    if isinstance(function, ast.Name)
                    else ""
                )
                assert called not in forbidden_calls


def test_capability_report_distinguishes_inert_from_generation_worker() -> None:
    report = inert_custody_capability_report()
    assert report["record_type"] == "mlx_inert_custody_capability_report"
    assert report["worker_launch"] is True
    assert report["private_inherited_af_unix_socketpair"] is True
    assert report["one_shot_authorization"] is True
    assert report["output_root_physical_binding"] is True
    assert report["production_worker_launch"] is False
    assert report["generated_result_producer"] is False
    assert report["process_socket_actions"] == "explicit_command_only"
    assert inert_custody_spec()["protocol_id"] == PROTOCOL_ID
    assert inert_custody_spec()["worker_code_id"] == WORKER_CODE_ID


def test_cli_makes_physical_action_explicit_and_replay_process_free(
    tmp_path: Path,
    capfd: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as exit_info:
        run(["mlx", "--help"])
    assert exit_info.value.code == 0
    help_output = capfd.readouterr()
    assert help_output.err == ""
    assert "start one inert local child/private socket" in help_output.out
    assert "zero model or backend actions" in help_output.out

    root = _private_directory(tmp_path / "cli-custody")
    assert run(["mlx", "custody-self-test", str(root)]) == 0
    created = json.loads(capfd.readouterr().out)
    assert created["status"] == "refused"
    assert created["process_actions"] == 1
    assert created["socket_actions"] == 1
    assert created["model_actions"] == 0
    bundle = root / cast("str", created["path"])

    assert run(["mlx", "custody-replay", str(bundle)]) == 0
    replayed = json.loads(capfd.readouterr().out)
    assert replayed["status"] == "replayed"
    assert replayed["process_actions_during_replay"] == 0
    assert replayed["socket_actions_during_replay"] == 0

    assert run(["mlx", "custody-inspect", str(bundle)]) == 0
    inspected = json.loads(capfd.readouterr().out)
    assert inspected["status"] == "inspected"
    assert inspected["decision"] == "ineligible"
    assert inspected["observed_generation_reachable"] is False
