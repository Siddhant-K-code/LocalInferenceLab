"""Fail-closed prospective contract for a future direct MLX worker."""

from __future__ import annotations

import os
from pathlib import Path
from typing import cast

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    digest_bytes,
    encode_bytes,
    load_canonical_json_file,
)
from localinferencelab.mlx_manifest import (
    SCHEMA_VERSION,
    load_model_manifest,
    load_runtime_manifest,
    verify_model_manifest,
    verify_runtime_manifest,
)

FOUNDATION_COMMIT = "5f8698256dececf764fd5c54597bee0e6f381d36"
MLX_LM_REVISION = "5cfec4cb39deba54210b3ff4d86f2337c7bc10b5"
MLX_REVISION = "0e3ff3643b1c3719f78814b98e0d222afbad867c"
_DIGEST_LENGTH = 71
_MAX_TEXT = 2_048
_CONTROL_LIMIT = 32
_PROMPT = b"Explain why a fixed seed is a control rather than a determinism guarantee."
_NON_ACTION_FIELDS = {
    "mlx_imports",
    "mlx_lm_imports",
    "metal_initializations",
    "device_queries",
    "model_loads",
    "tokenizer_loads",
    "inference_requests",
    "worker_process_starts",
    "subprocess_calls",
    "socket_calls",
    "listener_creations",
    "physical_network_requests",
    "model_downloads",
    "model_cache_mutations",
    "cloud_actions",
    "spend_actions",
    "authorization_nonce_consumptions",
    "output_root_consumptions",
}


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _keys(value: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value) > _MAX_TEXT:
        raise ContractError(f"{label} exceeds maximum length {_MAX_TEXT}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(value: JsonValue, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{label} must be a non-negative integer")
    return value


def _boolean(value: JsonValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _sha256(value: JsonValue, label: str) -> str:
    text = _text(value, label)
    if (
        len(text) != _DIGEST_LENGTH
        or not text.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in text[7:])
    ):
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _source(
    source_id: str,
    project: str,
    revision: str,
    path: str,
    lines: str,
    finding: str,
) -> dict[str, JsonValue]:
    return {
        "source_id": source_id,
        "project": project,
        "revision": revision,
        "url": f"https://github.com/ml-explore/{project}/blob/{revision}/{path}#L{lines}",
        "finding": finding,
    }


def mlx_study_spec() -> dict[str, JsonValue]:
    """Return the immutable direct-worker study contract with execution disabled."""
    prompt_base64 = encode_bytes(_PROMPT)
    return {
        "record_type": "mlx_direct_study_spec",
        "schema_version": SCHEMA_VERSION,
        "contract_binding": {
            "repository": "Siddhant-K-code/LocalInferenceLab",
            "foundation_commit": FOUNDATION_COMMIT,
            "mlx_lm_revision": MLX_LM_REVISION,
            "mlx_revision": MLX_REVISION,
            "claim_scope": "prospective_direct_mlx_runtime_not_per_kernel_gpu_proof",
        },
        "normative_sources": [
            _source(
                "cache_lifecycle",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/models/cache.py",
                "15-L152",
                "prompt cache construction, save/load, trim, and lifecycle controls",
            ),
            _source(
                "device_selection",
                "mlx",
                MLX_REVISION,
                "mlx/device.cpp",
                "1-L42",
                "default device is selected from compiled backend availability",
            ),
            _source(
                "generate_step",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/generate.py",
                "304-L475",
                "prefill, cache quantization, asynchronous evaluation, and token yield",
            ),
            _source(
                "loading",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/utils.py",
                "251-L304",
                "non-local model names enter snapshot resolution without local_files_only",
            ),
            _source(
                "metrics",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/generate.py",
                "658-L756",
                "prompt/generation rates, token IDs, finish handling, and peak memory",
            ),
            _source(
                "prng",
                "mlx",
                MLX_REVISION,
                "python/src/random.cpp",
                "19-L131",
                "implicit random state and seed are thread-local",
            ),
            _source(
                "remote_code",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/utils.py",
                "408-L471",
                "model_file can execute snapshot Python only through an explicit trust gate",
            ),
            _source(
                "sampler",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/sample_utils.py",
                "13-L75",
                "temperature zero selects greedy argmax sampling",
            ),
            _source(
                "synchronization",
                "mlx",
                MLX_REVISION,
                "python/src/stream.cpp",
                "211-L228",
                "stream synchronization waits for queued work completion",
            ),
            _source(
                "tokenizer_loading",
                "mlx-lm",
                MLX_LM_REVISION,
                "mlx_lm/tokenizer_utils.py",
                "660-L697",
                "tokenizer trust configuration is separate from model-code trust",
            ),
        ],
        "threat_model": {
            "trusted": [
                "study_operator",
                "current_owner",
                "operating_system_kernel",
            ],
            "untrusted": [
                "ambient_python_import_paths",
                "arbitrary_worker_output",
                "environment_selected_caches",
                "hugging_face_revision_names",
                "mutable_filesystem_aliases",
                "network_aliases_and_redirects",
            ],
            "remote_or_custom_code": "forbidden",
            "network_resolution": "forbidden",
            "ambient_listener": "forbidden",
        },
        "runtime_closure": {
            "python_executable": "no_follow_regular_file_identity_and_digest",
            "python_implementation_version_abi_platform": "required_exact",
            "supplied_package_root_byte_closure": "complete_for_explicit_root",
            "direct_distribution_metadata": "complete_for_supplied_root",
            "requires_dist_headers": "recorded_not_parsed_or_evaluated",
            "applicable_dependency_distribution_closure": "required_future_not_proven",
            "python_standard_library_closure": "required_future_not_proven",
            "python_native_runtime_and_dynamic_loader_closure": "required_future_not_proven",
            "selected_module_file_declarations": "required_exact_within_supplied_root",
            "worker_program_bytes": "required_exact",
            "environment": "closed_allowlist_execve_style",
            "interpreter_startup_flags": ["-I", "-S", "-E", "-s"],
            "sys_path": "descriptor_bound_runtime_root_only",
            "pythonpath": "forbidden",
            "user_site": "forbidden",
            "editable_installs": "forbidden",
            "namespace_ambiguity": "forbidden",
            "post_authorization_import_drift": "forbidden",
        },
        "model_closure": {
            "source": "explicit_preexisting_local_directory_only",
            "directory_identity": "device_inode_owner_mode",
            "file_manifest": "complete_no_follow_regular_files",
            "required": [
                "config_json",
                "tokenizer_config_json",
                "tokenizer_vocabulary",
                "model_safetensors",
            ],
            "shards": "index_exactly_matches_present_model_safetensors",
            "path_escape": "forbidden",
            "symlinks_and_special_files": "forbidden",
            "remote_and_custom_code": "forbidden",
            "snapshot_resolution_and_download": "forbidden",
        },
        "worker_protocol": {
            "transport": "parent_created_inherited_af_unix_socketpair",
            "discoverable_listener": False,
            "worker_ipc_descriptor": 3,
            "framing": "uint32_be_length_then_canonical_json",
            "max_frame_bytes": 1_048_576,
            "parent_to_worker_messages": [
                "parent_hello",
                "authorize_once",
                "generate_once",
                "shutdown",
            ],
            "worker_to_parent_messages": [
                "worker_identity",
                "authorization_ack",
                "result_or_terminal_error",
                "shutdown_ack",
            ],
            "message_sequence": [
                "parent_hello",
                "worker_identity",
                "authorize_once",
                "authorization_ack",
                "generate_once",
                "result_or_terminal_error",
                "shutdown",
                "shutdown_ack",
            ],
            "arbitrary_commands": "forbidden",
            "shell": "forbidden",
            "dns_proxy_redirect": "forbidden",
            "unrelated_file_descriptors": "close_before_worker_program",
            "lifecycle": "one_parent_owned_worker_per_declared_run",
            "concurrency": 1,
            "attempts_per_run": 1,
            "retries": 0,
            "warmups": 0,
            "selective_reruns": "forbidden",
        },
        "controls": {
            "prompt_base64": prompt_base64,
            "prompt_sha256": digest_bytes(_PROMPT),
            "tokenization": {
                "input": "exact_utf8_prompt_bytes",
                "chat_template": "exact_model_manifest_digest_required",
                "apply_chat_template": True,
                "tokenize": True,
                "add_generation_prompt": True,
                "prompt_token_ids": "required_in_result",
            },
            "sampler": {
                "constructor": "mlx_lm.sample_utils.make_sampler",
                "seed": 424_242,
                "seed_scope": "generation_thread_once_before_sampling",
                "temperature_millionths": 0,
                "top_p_millionths": 1_000_000,
                "min_p_millionths": 0,
                "top_k": 0,
                "xtc_probability_millionths": 0,
                "xtc_threshold_millionths": 0,
                "greedy_semantics": "mx_argmax_no_prng_consumption",
                "seed_is_control_not_determinism_guarantee": True,
            },
            "generation": {
                "api": "generate_step",
                "max_tokens": 64,
                "stop": "tokenizer_eos_token_ids_or_max_tokens",
                "prefill_step_size": 2_048,
                "max_kv_size": None,
                "kv_bits": None,
                "kv_group_size": 64,
                "quantized_kv_start": None,
            },
            "cache": {
                "constructor": "make_prompt_cache",
                "exact_runtime_cache_classes": "required_worker_evidence",
                "fresh_per_worker": True,
                "save": False,
                "load": False,
                "reuse": False,
                "trim": False,
                "rotate": False,
                "quantize": False,
            },
            "memory": {
                "wired_limit_bytes": None,
                "cache_limit_bytes": None,
                "peak_memory_reset_before_generation": True,
                "limits_must_be_exact_before_eligibility": True,
            },
            "synchronization": {
                "first_token_item_evaluation": "required",
                "final_generation_stream_synchronize": "required",
                "async_eval_is_experimental": True,
            },
            "threading": {
                "worker_threads": 1,
                "generation_thread": "worker_main_thread",
                "distributed_launcher": "forbidden",
                "subprocesses_inside_worker": "forbidden",
            },
        },
        "result_contract": {
            "generated_token_ids": "required_exact_sequence",
            "raw_text_base64": "required",
            "raw_text_sha256": "required",
            "finish_reason": "eos_or_length_or_error",
            "prompt_token_count": "native_tokenizer_count",
            "generation_token_count": "yielded_non_eos_token_count",
            "prompt_tps_scope": "prefill_plus_first_decode_step",
            "generation_tps_scope": "cumulative_decode_average_after_first_token",
            "peak_memory_scope": "since_last_explicit_reset",
            "ttft": "unavailable_not_manufactured",
            "final_stream_synchronized": "required",
            "backend_facts": [
                "default_device",
                "metal_is_available",
                "generation_stream_device",
            ],
            "backend_fact_limit": (
                "configuration_and_stream_completion_do_not_prove_per_kernel_gpu_execution"
            ),
        },
        "authorization_and_custody": {
            "output_root": "physical_identity_bound_before_authorization",
            "authorization": "one_shot_nonce_preimage_after_identity_revalidation",
            "action_ledger": "reserve_before_every_future_side_effect",
            "publication": "atomic_no_replace_receipt_last_closed_bundle",
            "terminal_outcomes": [
                "accepted",
                "invalid",
                "refused",
                "interrupted",
            ],
            "raw_worker_output": "bounded_untrusted_artifact",
            "replay": "offline_closed_bundle_only",
        },
        "execution_gate": {
            "production_worker_start_implemented": False,
            "observed_execution_reachable": False,
            "authorization_may_be_consumed": False,
            "reason": (
                "exact runtime, model, memory, process, backend, and authorization evidence "
                "requires a separately reviewed implementation milestone"
            ),
        },
    }


def verify_mlx_study_spec(value: JsonValue) -> dict[str, JsonValue]:
    """Require the exact immutable repository study specification."""
    spec = _mapping(value, "mlx_direct_study_spec")
    expected_fields = set(mlx_study_spec())
    _keys(spec, expected_fields, "mlx_direct_study_spec")
    if spec["record_type"] != "mlx_direct_study_spec" or spec["schema_version"] != SCHEMA_VERSION:
        raise ContractError("unsupported MLX direct study specification")
    if canonical_json(spec) != canonical_json(mlx_study_spec()):
        raise ContractError("MLX direct study specification differs from the pinned contract")
    return dict(spec)


def load_mlx_study_spec(path: Path) -> dict[str, JsonValue]:
    """Load one canonical pinned MLX study specification."""
    return verify_mlx_study_spec(load_canonical_json_file(path, "MLX direct study specification"))


def _non_actions() -> dict[str, JsonValue]:
    return dict.fromkeys(sorted(_NON_ACTION_FIELDS), 0)


def _missing_requirements(
    runtime_manifest: dict[str, JsonValue] | None,
    model_manifest: dict[str, JsonValue] | None,
) -> list[JsonValue]:
    missing = {
        "active_backend_device_evidence",
        "applicable_dependency_distribution_closure",
        "cache_limit_bytes",
        "exact_cache_class_worker_evidence",
        "final_stream_synchronization_evidence",
        "one_shot_authorization",
        "output_root_physical_binding",
        "production_worker_private_ipc_protocol_and_result_validation_implementation",
        "python_native_runtime_and_dynamic_loader_closure",
        "python_standard_library_closure",
        "worker_process_birth_and_executable_binding",
        "worker_reported_imported_module_closure",
        "wired_limit_bytes",
    }
    if runtime_manifest is None:
        missing.add("exact_runtime_manifest")
    elif runtime_manifest["evidence_kind"] == "synthetic_fixture":
        missing.add("non_synthetic_runtime_manifest")
    if model_manifest is None:
        missing.update({"exact_local_model_manifest", "exact_chat_template"})
    else:
        if model_manifest["evidence_kind"] == "synthetic_fixture":
            missing.add("non_synthetic_model_manifest")
        chat_template = _mapping(model_manifest["chat_template"], "chat_template")
        if chat_template["source"] == "absent":
            missing.add("exact_chat_template")
    return cast("list[JsonValue]", sorted(missing))


def build_mlx_prospective_package(
    spec_value: JsonValue,
    *,
    runtime_manifest: JsonValue | None = None,
    model_manifest: JsonValue | None = None,
) -> dict[str, JsonValue]:
    """Build an execution-ineligible prospective package from static records only."""
    spec = verify_mlx_study_spec(spec_value)
    runtime = None if runtime_manifest is None else verify_runtime_manifest(runtime_manifest)
    model = None if model_manifest is None else verify_model_manifest(model_manifest)
    return verify_mlx_prospective_package(_assemble_mlx_prospective_package(spec, runtime, model))


def _assemble_mlx_prospective_package(
    spec: dict[str, JsonValue],
    runtime: dict[str, JsonValue] | None,
    model: dict[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    missing = _missing_requirements(runtime, model)
    eligibility: dict[str, JsonValue] = {
        "record_type": "mlx_direct_eligibility",
        "schema_version": SCHEMA_VERSION,
        "decision": "ineligible",
        "declaration_complete": False,
        "observed_execution_reachable": False,
        "authorization_may_be_consumed": False,
        "worker_process_may_start": False,
        "claim_scope": "prospective_direct_mlx_runtime_not_per_kernel_gpu_proof",
        "missing_requirements": missing,
        "exact_metal_kernel_execution": "unavailable_through_official_programmatic_api",
        "reason": (
            "static supplied-root bytes do not prove applicable dependency, Python standard "
            "library, native runtime, or dynamic-loader closure; production private IPC, "
            "protocol, and result validation are not implemented; future process, imported "
            "runtime, backend, stream, limits, output root, and authorization are unattested"
        ),
    }
    package: dict[str, JsonValue] = {
        "record_type": "mlx_direct_prospective_package",
        "schema_version": SCHEMA_VERSION,
        "study_spec_id": canonical_identity(spec),
        "study_spec": spec,
        "runtime_manifest_id": None if runtime is None else runtime["manifest_id"],
        "runtime_manifest": runtime,
        "model_manifest_id": None if model is None else model["manifest_id"],
        "model_manifest": model,
        "worker_protocol": spec["worker_protocol"],
        "controls": spec["controls"],
        "result_contract": spec["result_contract"],
        "authorization_and_custody": spec["authorization_and_custody"],
        "eligibility": eligibility,
        "non_actions": _non_actions(),
    }
    package["package_id"] = canonical_identity(package)
    return package


def _verify_non_actions(value: JsonValue) -> None:
    actions = _mapping(value, "mlx_direct_prospective_package.non_actions")
    _keys(actions, _NON_ACTION_FIELDS, "mlx_direct_prospective_package.non_actions")
    for name in _NON_ACTION_FIELDS:
        if _integer(actions[name], f"non_actions.{name}") != 0:
            raise ContractError("prospective MLX package must record zero physical actions")


def verify_mlx_prospective_package(value: JsonValue) -> dict[str, JsonValue]:
    """Reject forged eligibility, drift, unknown fields, and nonzero actions."""
    package = _mapping(value, "mlx_direct_prospective_package")
    fields = {
        "record_type",
        "schema_version",
        "study_spec_id",
        "study_spec",
        "runtime_manifest_id",
        "runtime_manifest",
        "model_manifest_id",
        "model_manifest",
        "worker_protocol",
        "controls",
        "result_contract",
        "authorization_and_custody",
        "eligibility",
        "non_actions",
        "package_id",
    }
    _keys(package, fields, "mlx_direct_prospective_package")
    if (
        package["record_type"] != "mlx_direct_prospective_package"
        or package["schema_version"] != SCHEMA_VERSION
    ):
        raise ContractError("unsupported MLX direct prospective package")
    spec = verify_mlx_study_spec(package["study_spec"])
    if _sha256(package["study_spec_id"], "study_spec_id") != canonical_identity(spec):
        raise ContractError("MLX study specification identity mismatch")
    runtime_value = package["runtime_manifest"]
    runtime = None if runtime_value is None else verify_runtime_manifest(runtime_value)
    expected_runtime_id = None if runtime is None else runtime["manifest_id"]
    if package["runtime_manifest_id"] != expected_runtime_id:
        raise ContractError("MLX runtime manifest identity mismatch")
    model_value = package["model_manifest"]
    model = None if model_value is None else verify_model_manifest(model_value)
    expected_model_id = None if model is None else model["manifest_id"]
    if package["model_manifest_id"] != expected_model_id:
        raise ContractError("MLX model manifest identity mismatch")
    _verify_non_actions(package["non_actions"])
    package_id = _sha256(package["package_id"], "mlx_direct_prospective_package.package_id")
    content = dict(package)
    del content["package_id"]
    if package_id != canonical_identity(content):
        raise ContractError("MLX prospective package identity mismatch")
    rebuilt = _assemble_mlx_prospective_package(spec, runtime, model)
    if canonical_json(package) != canonical_json(rebuilt):
        raise ContractError("MLX prospective package semantic or eligibility drift")
    return dict(package)


def write_mlx_prospective_package(path: Path, value: JsonValue) -> None:
    """Write one verified prospective package without replacing a path."""
    package = verify_mlx_prospective_package(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        data = canonical_json(package)
        written = 0
        while written < len(data):
            written += os.write(descriptor, data[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def load_mlx_prospective_package(path: Path) -> dict[str, JsonValue]:
    """Load one canonical MLX prospective package."""
    return verify_mlx_prospective_package(
        load_canonical_json_file(path, "MLX direct prospective package")
    )


def mlx_eligibility_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Return a bounded fail-closed eligibility projection."""
    package = verify_mlx_prospective_package(value)
    eligibility = _mapping(package["eligibility"], "eligibility")
    return {
        "package_id": package["package_id"],
        "study_spec_id": package["study_spec_id"],
        "runtime_manifest_id": package["runtime_manifest_id"],
        "model_manifest_id": package["model_manifest_id"],
        "decision": eligibility["decision"],
        "declaration_complete": eligibility["declaration_complete"],
        "observed_execution_reachable": eligibility["observed_execution_reachable"],
        "authorization_may_be_consumed": eligibility["authorization_may_be_consumed"],
        "worker_process_may_start": eligibility["worker_process_may_start"],
        "missing_requirements": eligibility["missing_requirements"],
        "claim_scope": eligibility["claim_scope"],
        "exact_metal_kernel_execution": eligibility["exact_metal_kernel_execution"],
        "physical_gpu_actions": 0,
        "model_actions": 0,
        "network_actions": 0,
        "process_actions": 0,
    }


def mlx_capability_report() -> dict[str, JsonValue]:
    """Report the implemented contract surface without probing a runtime or device."""
    return {
        "record_type": "mlx_direct_capability_report",
        "schema_version": SCHEMA_VERSION,
        "architecture": "parent_owned_private_inherited_descriptor_worker",
        "runtime_manifest_compiler": True,
        "supplied_package_root_byte_closure": True,
        "applicable_dependency_distribution_closure": False,
        "python_standard_library_closure": False,
        "python_native_runtime_and_dynamic_loader_closure": False,
        "model_manifest_compiler": True,
        "prospective_package": True,
        "offline_fixture_replay": True,
        "production_worker_launch": False,
        "production_worker_private_ipc_protocol_and_result_validation_implementation": False,
        "runtime_import": False,
        "model_load": False,
        "device_query": False,
        "metal_initialization": False,
        "inference": False,
        "network": False,
        "subprocess": False,
        "observed_execution": "disabled_pending_separate_reviewed_attestation",
        "metal_claim": "per_kernel_execution_not_programmatically_provable",
    }


def load_optional_manifests(
    runtime_path: Path | None,
    model_path: Path | None,
) -> tuple[dict[str, JsonValue] | None, dict[str, JsonValue] | None]:
    """Load optional manifest paths without treating their names as identity."""
    runtime = None if runtime_path is None else load_runtime_manifest(runtime_path)
    model = None if model_path is None else load_model_manifest(model_path)
    return runtime, model
