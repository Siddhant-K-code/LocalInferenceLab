"""Strict versioned records for experiment definition and custody."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Literal, TypeAlias, TypeVar, cast

from localinferencelab.canonical import (
    SHA256_ID_LENGTH,
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    validate_json_value,
)

SCHEMA_VERSION = "1.0"
Backend: TypeAlias = Literal["mlx-lm", "llama.cpp", "ollama"]
CacheCohort: TypeAlias = Literal[
    "cold_process_model",
    "cold_model_warm_process",
    "warm_model_cold_prompt_cache",
    "warm_prompt_kv_cache",
    "unsupported",
]
EvidenceKind: TypeAlias = Literal[
    "synthetic_fixture",
    "safe_host_probe",
    "static_artifact_probe",
    "observed_execution",
]
AllowedAction: TypeAlias = Literal["model_process_start", "inference_request"]
_SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_CONTROL_CHARACTER_LIMIT = 32
_PUBLIC_FACT_NAMES = {
    "apple_silicon_eligible",
    "backend_device",
    "fixture_only",
    "metal_device_name",
    "metal_feature_set",
    "probe_method",
}
_PRIVATE_TOKEN_PATTERN = re.compile(
    r"(^|[_\s-])(home|host_?name|serial|user_?name|uuid)([_\s:=.-]|$)",
    re.IGNORECASE,
)
_PRIVATE_PATH_COMPONENT_PATTERN = re.compile(
    r"(^|[/\\])(?:users|home)(?:[/\\])",
    re.IGNORECASE,
)
_UNOBSERVED_VALUES = {
    "n/a",
    "none",
    "not_observed",
    "unavailable",
    "unknown",
    "unobserved",
}


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _keys(data: dict[str, JsonValue], required: set[str], label: str) -> None:
    missing = required - data.keys()
    extra = data.keys() - required
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _string(value: JsonValue, label: str, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value):
        raise ContractError(f"{label} must be a{' non-empty' if not empty else ''} string")
    return value


def _optional_string(value: JsonValue, label: str, *, empty: bool = False) -> str | None:
    if value is None:
        return None
    return _string(value, label, empty=empty)


def _integer(value: JsonValue, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    return value


def _optional_integer(value: JsonValue, label: str, *, minimum: int = 0) -> int | None:
    if value is None:
        return None
    return _integer(value, label, minimum=minimum)


def _boolean(value: JsonValue, label: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{label} must be a boolean")
    return value


def _strings(value: JsonValue, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return tuple(_string(item, f"{label}[]") for item in value)


def _public_text(value: JsonValue, label: str) -> str:
    text = _string(value, label)
    validate_json_value(text, label)
    lowered = text.lower()
    if (
        any(ord(character) < _CONTROL_CHARACTER_LIMIT for character in text)
        or text.startswith(("/", "\\", "~/", "~\\"))
        or "/users/" in lowered
        or "/home/" in lowered
        or "\\users\\" in lowered
        or "file://" in lowered
        or _PRIVATE_PATH_COMPONENT_PATTERN.search(text)
        or _PRIVATE_TOKEN_PATTERN.search(text)
    ):
        raise ContractError(f"{label} contains private or path-like data")
    return text


def _public_strings(value: JsonValue, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return tuple(_public_text(item, f"{label}[]") for item in value)


def _integers(value: JsonValue, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return tuple(_integer(item, f"{label}[]") for item in value)


def _literal(value: str, allowed: set[str], label: str) -> str:
    if value not in allowed:
        raise ContractError(f"{label} must be one of: {', '.join(sorted(allowed))}")
    return value


def _sha256(value: JsonValue, label: str) -> str:
    text = _string(value, label)
    if len(text) != SHA256_ID_LENGTH or _SHA256_PATTERN.fullmatch(text) is None:
        raise ContractError(f"{label} must be a lowercase prefixed SHA-256 digest")
    return text


def _optional_sha256(value: JsonValue, label: str) -> str | None:
    if value is None:
        return None
    return _sha256(value, label)


def _versioned(data: dict[str, JsonValue], record_type: str, required: set[str]) -> None:
    _keys(data, required | {"schema_version", "record_type"}, record_type)
    if data["schema_version"] != SCHEMA_VERSION:
        raise ContractError(f"{record_type} schema_version must be {SCHEMA_VERSION}")
    if data["record_type"] != record_type:
        raise ContractError(f"record_type must be {record_type}")


def _record_dict(record: object) -> dict[str, JsonValue]:
    value = validate_json_value(asdict(cast("Any", record)))
    if not isinstance(value, dict):
        raise ContractError("record serialization must produce an object")
    return value


@dataclass(frozen=True, slots=True)
class Fact:
    """A privacy-reviewed host or capability fact."""

    name: str
    value: str

    @classmethod
    def from_value(cls, value: JsonValue, label: str) -> Fact:
        data = _mapping(value, label)
        _keys(data, {"name", "value"}, label)
        fact = cls(
            _string(data["name"], f"{label}.name"),
            _public_text(data["value"], f"{label}.value"),
        )
        if fact.name not in _PUBLIC_FACT_NAMES:
            raise ContractError(f"{label}.name is not an allowed public fact")
        return fact


def _facts(value: JsonValue, label: str) -> tuple[Fact, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return tuple(Fact.from_value(item, f"{label}[]") for item in value)


@dataclass(frozen=True, slots=True)
class HostIdentity:
    """Privacy-preserving host identity."""

    record_type: Literal["host_identity"]
    schema_version: str
    evidence_kind: Literal["synthetic_fixture", "safe_host_probe"]
    host_class: Literal["apple_silicon", "non_apple_ci"]
    architecture: str
    chip: str
    physical_cores: int | None
    logical_cores: int
    memory_bytes: int
    os_name: str
    os_version: str
    os_build: str
    device_facts: tuple[Fact, ...]

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> HostIdentity:
        fields = {
            "evidence_kind",
            "host_class",
            "architecture",
            "chip",
            "physical_cores",
            "logical_cores",
            "memory_bytes",
            "os_name",
            "os_version",
            "os_build",
            "device_facts",
        }
        _versioned(data, "host_identity", fields)
        evidence = _literal(
            _string(data["evidence_kind"], "host_identity.evidence_kind"),
            {"synthetic_fixture", "safe_host_probe"},
            "host_identity.evidence_kind",
        )
        host_class = _literal(
            _string(data["host_class"], "host_identity.host_class"),
            {"apple_silicon", "non_apple_ci"},
            "host_identity.host_class",
        )
        record = cls(
            "host_identity",
            SCHEMA_VERSION,
            cast("Any", evidence),
            cast("Any", host_class),
            _public_text(data["architecture"], "host_identity.architecture"),
            _public_text(data["chip"], "host_identity.chip"),
            _optional_integer(data["physical_cores"], "host_identity.physical_cores", minimum=1),
            _integer(data["logical_cores"], "host_identity.logical_cores", minimum=1),
            _integer(data["memory_bytes"], "host_identity.memory_bytes", minimum=1),
            _public_text(data["os_name"], "host_identity.os_name"),
            _public_text(data["os_version"], "host_identity.os_version"),
            _public_text(data["os_build"], "host_identity.os_build"),
            _facts(data["device_facts"], "host_identity.device_facts"),
        )
        if record.physical_cores is not None and record.logical_cores < record.physical_cores:
            raise ContractError("logical_cores cannot be less than physical_cores")
        if record.evidence_kind == "synthetic_fixture" and record.host_class != "non_apple_ci":
            raise ContractError("synthetic hosts cannot claim Apple Silicon evidence")
        return record

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class RuntimeFact:
    """One structured runtime capability selection."""

    name: Literal["runner", "metal", "build_info", "mlx_version", "mlx_lm_version"]
    value: str

    def __post_init__(self) -> None:
        """Validate direct construction as strictly as loaded JSON."""
        if self.name not in {
            "runner",
            "metal",
            "build_info",
            "mlx_version",
            "mlx_lm_version",
        }:
            raise ContractError("runtime fact name is not supported")
        _public_text(self.value, "runtime_fact.value")

    @classmethod
    def from_value(cls, value: JsonValue, label: str) -> RuntimeFact:
        data = _mapping(value, label)
        _keys(data, {"name", "value"}, label)
        name = _literal(
            _string(data["name"], f"{label}.name"),
            {"runner", "metal", "build_info", "mlx_version", "mlx_lm_version"},
            f"{label}.name",
        )
        return cls(cast("Any", name), _public_text(data["value"], f"{label}.value"))


@dataclass(frozen=True, slots=True)
class RuntimeIdentity:
    """Immutable runtime identity without executing the runtime."""

    record_type: Literal["runtime_identity"]
    schema_version: str
    backend: Backend
    evidence_kind: EvidenceKind
    executable_name: str | None
    package_name: str | None
    version: str
    commit: str | None
    artifact_sha256: str | None
    install_manifest_sha256: str | None
    capability_facts: tuple[RuntimeFact, ...]
    identity_complete: bool

    def __post_init__(self) -> None:
        """Validate direct construction as strictly as loaded JSON."""
        for label, value in (
            ("runtime_identity.executable_name", self.executable_name),
            ("runtime_identity.package_name", self.package_name),
            ("runtime_identity.version", self.version),
            ("runtime_identity.commit", self.commit),
        ):
            if value is not None:
                _public_text(value, label)
        if self.executable_name is not None and (
            "/" in self.executable_name or "\\" in self.executable_name
        ):
            raise ContractError("runtime_identity.executable_name must not contain a path")
        if not all(isinstance(fact, RuntimeFact) for fact in self.capability_facts):
            raise ContractError("runtime_identity.capability_facts must contain runtime facts")
        _validate_runtime_facts(self)
        if self.identity_complete != _runtime_identity_complete(self):
            raise ContractError(
                "runtime_identity.identity_complete does not match supplied evidence"
            )
        if self.evidence_kind == "observed_execution" and not self.identity_complete:
            raise ContractError("observed execution requires a complete runtime identity")

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> RuntimeIdentity:
        fields = {
            "backend",
            "evidence_kind",
            "executable_name",
            "package_name",
            "version",
            "commit",
            "artifact_sha256",
            "install_manifest_sha256",
            "capability_facts",
            "identity_complete",
        }
        _versioned(data, "runtime_identity", fields)
        backend = _literal(
            _string(data["backend"], "runtime_identity.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "runtime_identity.backend",
        )
        evidence = _literal(
            _string(data["evidence_kind"], "runtime_identity.evidence_kind"),
            {
                "synthetic_fixture",
                "safe_host_probe",
                "static_artifact_probe",
                "observed_execution",
            },
            "runtime_identity.evidence_kind",
        )
        executable_name = (
            None
            if data["executable_name"] is None
            else _public_text(data["executable_name"], "runtime_identity.executable_name")
        )
        if executable_name is not None and ("/" in executable_name or "\\" in executable_name):
            raise ContractError("runtime_identity.executable_name must not contain a path")
        record = cls(
            "runtime_identity",
            SCHEMA_VERSION,
            cast("Any", backend),
            cast("Any", evidence),
            executable_name,
            (
                None
                if data["package_name"] is None
                else _public_text(data["package_name"], "runtime_identity.package_name")
            ),
            _public_text(data["version"], "runtime_identity.version"),
            (
                None
                if data["commit"] is None
                else _public_text(data["commit"], "runtime_identity.commit")
            ),
            _optional_sha256(data["artifact_sha256"], "runtime_identity.artifact_sha256"),
            _optional_sha256(
                data["install_manifest_sha256"],
                "runtime_identity.install_manifest_sha256",
            ),
            tuple(
                RuntimeFact.from_value(item, "runtime_identity.capability_facts[]")
                for item in _as_list(
                    data["capability_facts"],
                    "runtime_identity.capability_facts",
                )
            ),
            _boolean(data["identity_complete"], "runtime_identity.identity_complete"),
        )
        _validate_runtime_facts(record)
        computed_complete = _runtime_identity_complete(record)
        if record.identity_complete != computed_complete:
            raise ContractError(
                "runtime_identity.identity_complete does not match supplied evidence"
            )
        if record.evidence_kind == "observed_execution" and not record.identity_complete:
            raise ContractError("observed execution requires a complete runtime identity")
        return record

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


def _runtime_fact(record: RuntimeIdentity, name: str) -> str | None:
    return next((fact.value for fact in record.capability_facts if fact.name == name), None)


def _validate_runtime_facts(record: RuntimeIdentity) -> None:
    names = [fact.name for fact in record.capability_facts]
    if len(names) != len(set(names)):
        raise ContractError("runtime_identity.capability_facts names must be unique")
    required = {"runner", "metal"}
    if not required.issubset(names):
        raise ContractError("runtime identity requires exactly one runner and one Metal fact")
    allowed_names = {
        "mlx-lm": {"runner", "metal", "mlx_version", "mlx_lm_version"},
        "llama.cpp": {"runner", "metal", "build_info"},
        "ollama": {"runner", "metal", "build_info"},
    }[record.backend]
    if not set(names).issubset(allowed_names):
        raise ContractError(f"runtime identity contains facts unsupported by {record.backend}")
    runner = _runtime_fact(record, "runner")
    allowed_runners = {
        "mlx-lm": {"mlx", "unobserved"},
        "llama.cpp": {"llama.cpp", "unobserved"},
        "ollama": {"mlx", "llama.cpp", "unobserved"},
    }[record.backend]
    if runner not in allowed_runners:
        raise ContractError(f"runtime identity has an invalid runner for {record.backend}")
    if _runtime_fact(record, "metal") not in {
        "enabled",
        "disabled",
        "not_applicable",
        "unobserved",
    }:
        raise ContractError("runtime identity has an invalid Metal state")


def _runtime_identity_complete(record: RuntimeIdentity) -> bool:
    if record.evidence_kind != "observed_execution":
        return False
    if not _is_observed_value(record.version):
        return False
    if record.backend == "mlx-lm":
        return bool(
            record.package_name == "mlx-lm"
            and record.install_manifest_sha256
            and _runtime_fact(record, "runner") == "mlx"
            and _runtime_fact(record, "metal") in {"enabled", "disabled"}
            and _is_observed_value(_runtime_fact(record, "mlx_version"))
            and _is_observed_value(_runtime_fact(record, "mlx_lm_version"))
        )
    if record.backend == "llama.cpp":
        return bool(
            record.executable_name
            and record.artifact_sha256
            and _is_observed_value(record.commit)
            and _runtime_fact(record, "runner") == "llama.cpp"
            and _runtime_fact(record, "metal") in {"enabled", "disabled"}
            and _is_observed_value(_runtime_fact(record, "build_info"))
        )
    return bool(
        (record.executable_name or record.package_name)
        and (record.artifact_sha256 or record.install_manifest_sha256)
        and _runtime_fact(record, "runner") in {"mlx", "llama.cpp"}
        and _runtime_fact(record, "metal") in {"enabled", "disabled", "not_applicable"}
        and _is_observed_value(_runtime_fact(record, "build_info"))
    )


def _is_observed_value(value: str | None) -> bool:
    return value is not None and value.strip().casefold() not in _UNOBSERVED_VALUES


@dataclass(frozen=True, slots=True)
class ModelIdentity:
    """Backend-specific model representation identity."""

    record_type: Literal["model_identity"]
    schema_version: str
    backend: Backend
    representation: Literal["mlx_snapshot", "gguf", "ollama_manifest"]
    evidence_kind: Literal[
        "synthetic_fixture",
        "static_artifact_probe",
        "observed_execution",
    ]
    label: str
    content_sha256: str | None
    manifest_sha256: str | None
    config_sha256: str | None
    tokenizer_sha256: str | None
    metadata_sha256: str | None
    cross_representation_equivalence: Literal["unproven"]

    def __post_init__(self) -> None:
        """Keep cross-representation mapping unavailable in v1."""
        if self.cross_representation_equivalence != "unproven":
            raise ContractError("v1 model representation equivalence is always unproven")

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> ModelIdentity:
        fields = {
            "backend",
            "representation",
            "evidence_kind",
            "label",
            "content_sha256",
            "manifest_sha256",
            "config_sha256",
            "tokenizer_sha256",
            "metadata_sha256",
            "cross_representation_equivalence",
        }
        _versioned(data, "model_identity", fields)
        backend = _literal(
            _string(data["backend"], "model_identity.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "model_identity.backend",
        )
        representation = _literal(
            _string(data["representation"], "model_identity.representation"),
            {"mlx_snapshot", "gguf", "ollama_manifest"},
            "model_identity.representation",
        )
        expected = {
            "mlx-lm": "mlx_snapshot",
            "llama.cpp": "gguf",
            "ollama": "ollama_manifest",
        }[backend]
        if representation != expected:
            raise ContractError(f"{backend} requires representation {expected}")
        evidence = _literal(
            _string(data["evidence_kind"], "model_identity.evidence_kind"),
            {"synthetic_fixture", "static_artifact_probe", "observed_execution"},
            "model_identity.evidence_kind",
        )
        equivalence = _literal(
            _string(
                data["cross_representation_equivalence"],
                "model_identity.cross_representation_equivalence",
            ),
            {"unproven"},
            "model_identity.cross_representation_equivalence",
        )
        record = cls(
            "model_identity",
            SCHEMA_VERSION,
            cast("Any", backend),
            cast("Any", representation),
            cast("Any", evidence),
            _public_text(data["label"], "model_identity.label"),
            _optional_sha256(data["content_sha256"], "model_identity.content_sha256"),
            _optional_sha256(data["manifest_sha256"], "model_identity.manifest_sha256"),
            _optional_sha256(data["config_sha256"], "model_identity.config_sha256"),
            _optional_sha256(data["tokenizer_sha256"], "model_identity.tokenizer_sha256"),
            _optional_sha256(data["metadata_sha256"], "model_identity.metadata_sha256"),
            cast("Any", equivalence),
        )
        if record.representation == "mlx_snapshot" and not all(
            (record.manifest_sha256, record.config_sha256, record.tokenizer_sha256),
        ):
            raise ContractError("MLX snapshot identity requires manifest, config, and tokenizer")
        if record.representation == "gguf" and not all(
            (record.content_sha256, record.metadata_sha256, record.tokenizer_sha256),
        ):
            raise ContractError("GGUF identity requires content, metadata, and tokenizer metadata")
        if record.representation == "ollama_manifest" and record.manifest_sha256 is None:
            raise ContractError("Ollama identity requires a manifest digest")
        return record

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


StateEvidence: TypeAlias = Literal["synthetic_fixture", "observed_execution"]


@dataclass(frozen=True, slots=True)
class ProcessInstance:
    """Exact process instance used by one or more scheduled runs."""

    record_type: Literal["process_instance"]
    schema_version: str
    backend: Backend
    runtime_id: str
    host_id: str
    evidence_kind: StateEvidence
    instance_label: str
    max_concurrency: int

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> ProcessInstance:
        fields = {
            "backend",
            "runtime_id",
            "host_id",
            "evidence_kind",
            "instance_label",
            "max_concurrency",
        }
        _versioned(data, "process_instance", fields)
        backend = _literal(
            _string(data["backend"], "process_instance.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "process_instance.backend",
        )
        evidence = _literal(
            _string(data["evidence_kind"], "process_instance.evidence_kind"),
            {"synthetic_fixture", "observed_execution"},
            "process_instance.evidence_kind",
        )
        return cls(
            "process_instance",
            SCHEMA_VERSION,
            cast("Any", backend),
            _sha256(data["runtime_id"], "process_instance.runtime_id"),
            _sha256(data["host_id"], "process_instance.host_id"),
            cast("Any", evidence),
            _public_text(data["instance_label"], "process_instance.instance_label"),
            _integer(data["max_concurrency"], "process_instance.max_concurrency", minimum=1),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class ModelInstance:
    """Exact loaded model instance within a process."""

    record_type: Literal["model_instance"]
    schema_version: str
    backend: Backend
    process_instance_id: str
    model_id: str
    evidence_kind: StateEvidence
    instance_label: str
    context_tokens: int
    batch_size: int
    gpu_layers: int | None

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> ModelInstance:
        fields = {
            "backend",
            "process_instance_id",
            "model_id",
            "evidence_kind",
            "instance_label",
            "context_tokens",
            "batch_size",
            "gpu_layers",
        }
        _versioned(data, "model_instance", fields)
        backend = _literal(
            _string(data["backend"], "model_instance.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "model_instance.backend",
        )
        evidence = _literal(
            _string(data["evidence_kind"], "model_instance.evidence_kind"),
            {"synthetic_fixture", "observed_execution"},
            "model_instance.evidence_kind",
        )
        return cls(
            "model_instance",
            SCHEMA_VERSION,
            cast("Any", backend),
            _sha256(data["process_instance_id"], "model_instance.process_instance_id"),
            _sha256(data["model_id"], "model_instance.model_id"),
            cast("Any", evidence),
            _public_text(data["instance_label"], "model_instance.instance_label"),
            _integer(data["context_tokens"], "model_instance.context_tokens", minimum=1),
            _integer(data["batch_size"], "model_instance.batch_size", minimum=1),
            _optional_integer(data["gpu_layers"], "model_instance.gpu_layers"),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class CachePreparation:
    """Content-addressed cache state preparation and lineage."""

    record_type: Literal["cache_preparation"]
    schema_version: str
    backend: Backend
    model_instance_id: str
    evidence_kind: StateEvidence
    cache_cohort: CacheCohort
    parent_preparation_id: str | None
    preparation_actions: tuple[
        Literal[
            "new_process",
            "load_model",
            "reuse_process",
            "reuse_model",
            "clear_prompt_cache",
            "prefill_prompt_cache",
            "reuse_prompt_kv_cache",
        ],
        ...,
    ]
    warmup_request_sha256: tuple[str, ...]
    context_shift_count: int
    prompt_cache_tokens: int
    kv_cache_tokens: int

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> CachePreparation:
        fields = {
            "backend",
            "model_instance_id",
            "evidence_kind",
            "cache_cohort",
            "parent_preparation_id",
            "preparation_actions",
            "warmup_request_sha256",
            "context_shift_count",
            "prompt_cache_tokens",
            "kv_cache_tokens",
        }
        _versioned(data, "cache_preparation", fields)
        backend = _literal(
            _string(data["backend"], "cache_preparation.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "cache_preparation.backend",
        )
        evidence = _literal(
            _string(data["evidence_kind"], "cache_preparation.evidence_kind"),
            {"synthetic_fixture", "observed_execution"},
            "cache_preparation.evidence_kind",
        )
        cohort = _literal(
            _string(data["cache_cohort"], "cache_preparation.cache_cohort"),
            {
                "cold_process_model",
                "cold_model_warm_process",
                "warm_model_cold_prompt_cache",
                "warm_prompt_kv_cache",
                "unsupported",
            },
            "cache_preparation.cache_cohort",
        )
        actions = _strings(
            data["preparation_actions"],
            "cache_preparation.preparation_actions",
        )
        allowed_actions = {
            "new_process",
            "load_model",
            "reuse_process",
            "reuse_model",
            "clear_prompt_cache",
            "prefill_prompt_cache",
            "reuse_prompt_kv_cache",
        }
        if not actions or len(actions) != len(set(actions)):
            raise ContractError("cache preparation actions must be non-empty and unique")
        for action in actions:
            _literal(action, allowed_actions, "cache_preparation.preparation_actions[]")
        warmups = tuple(
            _sha256(item, "cache_preparation.warmup_request_sha256[]")
            for item in _as_list(
                data["warmup_request_sha256"],
                "cache_preparation.warmup_request_sha256",
            )
        )
        if len(warmups) != len(set(warmups)):
            raise ContractError("cache preparation warm-up requests must be unique")
        record = cls(
            "cache_preparation",
            SCHEMA_VERSION,
            cast("Any", backend),
            _sha256(data["model_instance_id"], "cache_preparation.model_instance_id"),
            cast("Any", evidence),
            cast("Any", cohort),
            _optional_sha256(
                data["parent_preparation_id"],
                "cache_preparation.parent_preparation_id",
            ),
            cast("Any", actions),
            warmups,
            _integer(data["context_shift_count"], "cache_preparation.context_shift_count"),
            _integer(data["prompt_cache_tokens"], "cache_preparation.prompt_cache_tokens"),
            _integer(data["kv_cache_tokens"], "cache_preparation.kv_cache_tokens"),
        )
        expected_actions = {
            "cold_process_model": (
                "new_process",
                "load_model",
                "clear_prompt_cache",
            ),
            "cold_model_warm_process": (
                "reuse_process",
                "load_model",
                "clear_prompt_cache",
            ),
            "warm_model_cold_prompt_cache": (
                "reuse_process",
                "reuse_model",
                "clear_prompt_cache",
            ),
            "warm_prompt_kv_cache": (
                "reuse_process",
                "reuse_model",
                "prefill_prompt_cache",
                "reuse_prompt_kv_cache",
            ),
            "unsupported": ("clear_prompt_cache",),
        }[record.cache_cohort]
        if record.preparation_actions != expected_actions:
            raise ContractError("cache preparation actions do not match the declared cache cohort")
        if record.cache_cohort == "cold_process_model" and (
            record.parent_preparation_id is not None
            or record.warmup_request_sha256
            or record.context_shift_count
            or record.prompt_cache_tokens
            or record.kv_cache_tokens
            or "new_process" not in record.preparation_actions
            or "load_model" not in record.preparation_actions
        ):
            raise ContractError("cold process/model preparation must begin with empty cache state")
        if record.cache_cohort == "cold_model_warm_process" and (
            record.parent_preparation_id is not None
            or record.warmup_request_sha256
            or record.context_shift_count
            or record.prompt_cache_tokens
            or record.kv_cache_tokens
        ):
            raise ContractError(
                "cold model/warm process preparation must begin without model cache"
            )
        if record.cache_cohort == "warm_prompt_kv_cache" and (
            record.parent_preparation_id is None
            or not record.warmup_request_sha256
            or "reuse_prompt_kv_cache" not in record.preparation_actions
            or record.prompt_cache_tokens == 0
            or record.kv_cache_tokens == 0
        ):
            raise ContractError("warm prompt/KV preparation requires parent and warm-up lineage")
        if record.cache_cohort == "warm_model_cold_prompt_cache" and (
            record.parent_preparation_id is None
            or record.warmup_request_sha256
            or record.prompt_cache_tokens
            or record.kv_cache_tokens
        ):
            raise ContractError("warm model/cold prompt preparation requires empty prompt/KV state")
        if record.cache_cohort == "unsupported" and (
            record.parent_preparation_id is not None
            or record.warmup_request_sha256
            or record.context_shift_count
            or record.prompt_cache_tokens
            or record.kv_cache_tokens
        ):
            raise ContractError("unsupported cache preparation cannot claim cache state")
        return record

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class ConcurrencyIdentity:
    """Effective concurrency state shared by comparable runs."""

    record_type: Literal["concurrency_identity"]
    schema_version: str
    max_concurrency: int
    active_peers: int
    worker_slot: int
    scheduling_policy: Literal["serial", "fixed_wave"]
    peer_request_sha256: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> ConcurrencyIdentity:
        fields = {
            "max_concurrency",
            "active_peers",
            "worker_slot",
            "scheduling_policy",
            "peer_request_sha256",
        }
        _versioned(data, "concurrency_identity", fields)
        max_concurrency = _integer(
            data["max_concurrency"],
            "concurrency_identity.max_concurrency",
            minimum=1,
        )
        active_peers = _integer(data["active_peers"], "concurrency_identity.active_peers")
        worker_slot = _integer(data["worker_slot"], "concurrency_identity.worker_slot")
        if active_peers >= max_concurrency or worker_slot >= max_concurrency:
            raise ContractError("concurrency identity exceeds its maximum concurrency")
        policy = _literal(
            _string(data["scheduling_policy"], "concurrency_identity.scheduling_policy"),
            {"serial", "fixed_wave"},
            "concurrency_identity.scheduling_policy",
        )
        if policy == "serial" and (max_concurrency != 1 or active_peers != 0 or worker_slot != 0):
            raise ContractError("serial concurrency identity must have one unopposed worker")
        peer_requests = tuple(
            _sha256(item, "concurrency_identity.peer_request_sha256[]")
            for item in _as_list(
                data["peer_request_sha256"],
                "concurrency_identity.peer_request_sha256",
            )
        )
        if peer_requests != tuple(sorted(peer_requests)) or len(peer_requests) != active_peers:
            raise ContractError(
                "concurrency identity peer requests must be sorted and match active peers"
            )
        return cls(
            "concurrency_identity",
            SCHEMA_VERSION,
            max_concurrency,
            active_peers,
            worker_slot,
            cast("Any", policy),
            peer_requests,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class RunScheduleEntry:
    """One exact planned run slot embedded in the protocol."""

    sequence: int
    run_id: str
    backend: Backend
    runtime_id: str
    model_id: str
    host_id: str
    process_instance_id: str
    model_instance_id: str
    cache_preparation_id: str
    concurrency_id: str
    concurrency_wave: int
    cache_cohort: CacheCohort
    request_sha256: str

    @classmethod
    def from_value(cls, value: JsonValue) -> RunScheduleEntry:
        data = _mapping(value, "protocol.run_schedule[]")
        fields = {
            "sequence",
            "run_id",
            "backend",
            "runtime_id",
            "model_id",
            "host_id",
            "process_instance_id",
            "model_instance_id",
            "cache_preparation_id",
            "concurrency_id",
            "concurrency_wave",
            "cache_cohort",
            "request_sha256",
        }
        _keys(data, fields, "protocol.run_schedule[]")
        backend = _literal(
            _string(data["backend"], "protocol.run_schedule[].backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "protocol.run_schedule[].backend",
        )
        cohort = _literal(
            _string(data["cache_cohort"], "protocol.run_schedule[].cache_cohort"),
            {
                "cold_process_model",
                "cold_model_warm_process",
                "warm_model_cold_prompt_cache",
                "warm_prompt_kv_cache",
                "unsupported",
            },
            "protocol.run_schedule[].cache_cohort",
        )
        return cls(
            _integer(data["sequence"], "protocol.run_schedule[].sequence", minimum=1),
            _public_text(data["run_id"], "protocol.run_schedule[].run_id"),
            cast("Any", backend),
            _sha256(data["runtime_id"], "protocol.run_schedule[].runtime_id"),
            _sha256(data["model_id"], "protocol.run_schedule[].model_id"),
            _sha256(data["host_id"], "protocol.run_schedule[].host_id"),
            _sha256(
                data["process_instance_id"],
                "protocol.run_schedule[].process_instance_id",
            ),
            _sha256(
                data["model_instance_id"],
                "protocol.run_schedule[].model_instance_id",
            ),
            _sha256(
                data["cache_preparation_id"],
                "protocol.run_schedule[].cache_preparation_id",
            ),
            _sha256(data["concurrency_id"], "protocol.run_schedule[].concurrency_id"),
            _integer(
                data["concurrency_wave"],
                "protocol.run_schedule[].concurrency_wave",
                minimum=1,
            ),
            cast("Any", cohort),
            _sha256(data["request_sha256"], "protocol.run_schedule[].request_sha256"),
        )


@dataclass(frozen=True, slots=True)
class SamplerControls:
    """Integer-unit sampler controls."""

    seed: int
    temperature_millionths: int
    top_p_millionths: int
    top_k: int
    min_p_millionths: int
    repetition_penalty_millionths: int

    @classmethod
    def from_value(cls, value: JsonValue) -> SamplerControls:
        data = _mapping(value, "sampler")
        fields = {
            "seed",
            "temperature_millionths",
            "top_p_millionths",
            "top_k",
            "min_p_millionths",
            "repetition_penalty_millionths",
        }
        _keys(data, fields, "sampler")
        return cls(
            _integer(data["seed"], "sampler.seed", minimum=-1),
            _integer(data["temperature_millionths"], "sampler.temperature_millionths"),
            _integer(data["top_p_millionths"], "sampler.top_p_millionths"),
            _integer(data["top_k"], "sampler.top_k"),
            _integer(data["min_p_millionths"], "sampler.min_p_millionths"),
            _integer(
                data["repetition_penalty_millionths"],
                "sampler.repetition_penalty_millionths",
            ),
        )


@dataclass(frozen=True, slots=True)
class Protocol:
    """Exact prospective experiment protocol."""

    record_type: Literal["protocol"]
    schema_version: str
    name: str
    prompt_base64: str
    prompt_sha256: str
    chat_template_sha256: str
    sampler: SamplerControls
    max_output_tokens: int
    context_tokens: int
    cache_cohorts: tuple[CacheCohort, ...]
    repeats_per_cohort: int
    ordering: Literal["backend_blocked"]
    backend_order: tuple[Backend, ...]
    concurrency: int
    timeout_ms: int
    retry_count: int
    allowed_runtime_ids: tuple[str, ...]
    allowed_model_ids: tuple[str, ...]
    allowed_host_ids: tuple[str, ...]
    run_schedule: tuple[RunScheduleEntry, ...]

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> Protocol:
        fields = {
            "name",
            "prompt_base64",
            "prompt_sha256",
            "chat_template_sha256",
            "sampler",
            "max_output_tokens",
            "context_tokens",
            "cache_cohorts",
            "repeats_per_cohort",
            "ordering",
            "backend_order",
            "concurrency",
            "timeout_ms",
            "retry_count",
            "allowed_runtime_ids",
            "allowed_model_ids",
            "allowed_host_ids",
            "run_schedule",
        }
        _versioned(data, "protocol", fields)
        prompt_base64 = _string(data["prompt_base64"], "protocol.prompt_base64", empty=True)
        prompt_sha256 = _sha256(data["prompt_sha256"], "protocol.prompt_sha256")
        if digest_bytes(decode_bytes(prompt_base64)) != prompt_sha256:
            raise ContractError("protocol prompt digest does not match prompt bytes")
        cohorts = _strings(data["cache_cohorts"], "protocol.cache_cohorts")
        if not cohorts or len(set(cohorts)) != len(cohorts):
            raise ContractError("protocol.cache_cohorts must be non-empty and unique")
        for cohort in cohorts:
            _literal(
                cohort,
                {
                    "cold_process_model",
                    "cold_model_warm_process",
                    "warm_model_cold_prompt_cache",
                    "warm_prompt_kv_cache",
                    "unsupported",
                },
                "protocol.cache_cohorts[]",
            )
        backends = _strings(data["backend_order"], "protocol.backend_order")
        if not backends or len(set(backends)) != len(backends):
            raise ContractError("protocol.backend_order must be non-empty and unique")
        for backend in backends:
            _literal(backend, {"mlx-lm", "llama.cpp", "ollama"}, "protocol.backend_order[]")
        ordering = _literal(
            _string(data["ordering"], "protocol.ordering"),
            {"backend_blocked"},
            "protocol.ordering",
        )
        allowed_runtime_ids = tuple(
            _sha256(item, "protocol.allowed_runtime_ids[]")
            for item in _as_list(data["allowed_runtime_ids"], "protocol.allowed_runtime_ids")
        )
        allowed_model_ids = tuple(
            _sha256(item, "protocol.allowed_model_ids[]")
            for item in _as_list(data["allowed_model_ids"], "protocol.allowed_model_ids")
        )
        allowed_host_ids = tuple(
            _sha256(item, "protocol.allowed_host_ids[]")
            for item in _as_list(data["allowed_host_ids"], "protocol.allowed_host_ids")
        )
        for label, identities in (
            ("allowed_runtime_ids", allowed_runtime_ids),
            ("allowed_model_ids", allowed_model_ids),
            ("allowed_host_ids", allowed_host_ids),
        ):
            if not identities or identities != tuple(sorted(set(identities))):
                raise ContractError(f"protocol.{label} must be non-empty, unique, and sorted")
        schedule = tuple(
            RunScheduleEntry.from_value(item)
            for item in _as_list(data["run_schedule"], "protocol.run_schedule")
        )
        if not schedule:
            raise ContractError("protocol.run_schedule must be non-empty")
        if tuple(entry.sequence for entry in schedule) != tuple(range(1, len(schedule) + 1)):
            raise ContractError("protocol.run_schedule sequences must be ordered and contiguous")
        run_ids = tuple(entry.run_id for entry in schedule)
        if len(run_ids) != len(set(run_ids)):
            raise ContractError("protocol.run_schedule run IDs must be unique")
        waves = tuple(entry.concurrency_wave for entry in schedule)
        if waves != tuple(sorted(waves)) or set(waves) != set(range(1, max(waves) + 1)):
            raise ContractError(
                "protocol.run_schedule concurrency waves must be ordered and contiguous"
            )
        if {entry.runtime_id for entry in schedule} != set(allowed_runtime_ids):
            raise ContractError("protocol schedule runtime identities must match its allowlist")
        if {entry.model_id for entry in schedule} != set(allowed_model_ids):
            raise ContractError("protocol schedule model identities must match its allowlist")
        if {entry.host_id for entry in schedule} != set(allowed_host_ids):
            raise ContractError("protocol schedule host identities must match its allowlist")
        if {entry.cache_cohort for entry in schedule} != set(cohorts):
            raise ContractError("protocol schedule cache cohorts must match its declared cohorts")
        if {entry.backend for entry in schedule} != set(backends):
            raise ContractError("protocol schedule backends must match its backend order")
        backend_positions = {backend: index for index, backend in enumerate(backends)}
        if [entry.backend for entry in schedule] != sorted(
            (entry.backend for entry in schedule),
            key=backend_positions.__getitem__,
        ):
            raise ContractError("protocol schedule violates backend_blocked ordering")
        repeat_counts: dict[
            tuple[str, str, str, str, str, str, str, str, str, str],
            int,
        ] = {}
        for entry in schedule:
            repeat_key = (
                entry.backend,
                entry.runtime_id,
                entry.model_id,
                entry.host_id,
                entry.process_instance_id,
                entry.model_instance_id,
                entry.cache_preparation_id,
                entry.concurrency_id,
                entry.cache_cohort,
                entry.request_sha256,
            )
            repeat_counts[repeat_key] = repeat_counts.get(repeat_key, 0) + 1
        repeats = _integer(
            data["repeats_per_cohort"],
            "protocol.repeats_per_cohort",
            minimum=2,
        )
        if any(count != repeats for count in repeat_counts.values()):
            raise ContractError("protocol schedule repeat count does not match its declaration")
        return cls(
            "protocol",
            SCHEMA_VERSION,
            _string(data["name"], "protocol.name"),
            prompt_base64,
            prompt_sha256,
            _sha256(data["chat_template_sha256"], "protocol.chat_template_sha256"),
            SamplerControls.from_value(data["sampler"]),
            _integer(data["max_output_tokens"], "protocol.max_output_tokens", minimum=1),
            _integer(data["context_tokens"], "protocol.context_tokens", minimum=1),
            cast("Any", cohorts),
            repeats,
            cast("Any", ordering),
            cast("Any", backends),
            _integer(data["concurrency"], "protocol.concurrency", minimum=1),
            _integer(data["timeout_ms"], "protocol.timeout_ms", minimum=1),
            _integer(data["retry_count"], "protocol.retry_count"),
            allowed_runtime_ids,
            allowed_model_ids,
            allowed_host_ids,
            schedule,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


def _as_list(value: JsonValue, label: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    return value


@dataclass(frozen=True, slots=True)
class ActionBudget:
    """Maximum side effects authorized by a declaration."""

    model_process_starts: int
    inference_requests: int
    network_requests: int
    downloads: int

    @classmethod
    def from_value(cls, value: JsonValue) -> ActionBudget:
        data = _mapping(value, "action_budget")
        fields = {"model_process_starts", "inference_requests", "network_requests", "downloads"}
        _keys(data, fields, "action_budget")
        return cls(
            _integer(data["model_process_starts"], "action_budget.model_process_starts"),
            _integer(data["inference_requests"], "action_budget.inference_requests"),
            _integer(data["network_requests"], "action_budget.network_requests"),
            _integer(data["downloads"], "action_budget.downloads"),
        )

    def is_zero(self) -> bool:
        return not any(asdict(self).values())


@dataclass(frozen=True, slots=True)
class ExecutionDeclaration:
    """Content-addressed pre-action execution authorization."""

    record_type: Literal["execution_declaration"]
    schema_version: str
    disposition: Literal["model_execution_forbidden", "authorized"]
    protocol_id: str
    backend: Backend
    runtime_id: str
    model_id: str
    host_policy: Literal["exact_identity", "host_class"]
    host_id: str | None
    host_class: str
    output_root_id: str
    action_budget: ActionBudget

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> ExecutionDeclaration:
        fields = {
            "disposition",
            "protocol_id",
            "backend",
            "runtime_id",
            "model_id",
            "host_policy",
            "host_id",
            "host_class",
            "output_root_id",
            "action_budget",
        }
        _versioned(data, "execution_declaration", fields)
        disposition = _literal(
            _string(data["disposition"], "execution_declaration.disposition"),
            {"model_execution_forbidden", "authorized"},
            "execution_declaration.disposition",
        )
        backend = _literal(
            _string(data["backend"], "execution_declaration.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "execution_declaration.backend",
        )
        host_policy = _literal(
            _string(data["host_policy"], "execution_declaration.host_policy"),
            {"exact_identity", "host_class"},
            "execution_declaration.host_policy",
        )
        host_id = _optional_sha256(data["host_id"], "execution_declaration.host_id")
        if host_policy == "exact_identity" and host_id is None:
            raise ContractError("exact_identity policy requires host_id")
        budget = ActionBudget.from_value(data["action_budget"])
        if budget.network_requests != 0 or budget.downloads != 0:
            raise ContractError("v1 declarations cannot authorize network requests or downloads")
        if disposition == "model_execution_forbidden" and not budget.is_zero():
            raise ContractError("forbidden execution requires a zero action budget")
        if disposition == "authorized" and budget.inference_requests == 0:
            raise ContractError("authorized execution requires a positive inference budget")
        return cls(
            "execution_declaration",
            SCHEMA_VERSION,
            cast("Any", disposition),
            _sha256(data["protocol_id"], "execution_declaration.protocol_id"),
            cast("Any", backend),
            _sha256(data["runtime_id"], "execution_declaration.runtime_id"),
            _sha256(data["model_id"], "execution_declaration.model_id"),
            cast("Any", host_policy),
            host_id,
            _string(data["host_class"], "execution_declaration.host_class"),
            _sha256(data["output_root_id"], "execution_declaration.output_root_id"),
            budget,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class Eligibility:
    """Evaluation result linking a declaration to exact identities."""

    record_type: Literal["eligibility"]
    schema_version: str
    decision: Literal["model_execution_forbidden", "eligible"]
    declaration_id: str
    protocol_id: str
    runtime_id: str
    model_id: str
    host_id: str
    allowed_actions: tuple[AllowedAction, ...]
    reasons: tuple[str, ...]

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> Eligibility:
        fields = {
            "decision",
            "declaration_id",
            "protocol_id",
            "runtime_id",
            "model_id",
            "host_id",
            "allowed_actions",
            "reasons",
        }
        _versioned(data, "eligibility", fields)
        decision = _literal(
            _string(data["decision"], "eligibility.decision"),
            {"model_execution_forbidden", "eligible"},
            "eligibility.decision",
        )
        allowed = _strings(data["allowed_actions"], "eligibility.allowed_actions")
        for action in allowed:
            _literal(
                action,
                {"model_process_start", "inference_request"},
                "eligibility.allowed_actions[]",
            )
        if allowed != tuple(sorted(set(allowed))):
            raise ContractError("eligibility.allowed_actions must be unique and sorted")
        if decision == "model_execution_forbidden" and allowed:
            raise ContractError("forbidden eligibility cannot allow actions")
        reasons = _strings(data["reasons"], "eligibility.reasons")
        if not reasons:
            raise ContractError("eligibility.reasons cannot be empty")
        return cls(
            "eligibility",
            SCHEMA_VERSION,
            cast("Any", decision),
            _sha256(data["declaration_id"], "eligibility.declaration_id"),
            _sha256(data["protocol_id"], "eligibility.protocol_id"),
            _sha256(data["runtime_id"], "eligibility.runtime_id"),
            _sha256(data["model_id"], "eligibility.model_id"),
            _sha256(data["host_id"], "eligibility.host_id"),
            cast("Any", allowed),
            reasons,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class FixtureSource:
    """Strict source intent for the built-in synthetic bundle."""

    record_type: Literal["fixture_source"]
    schema_version: str
    fixture_name: Literal["synthetic-two-backend-repeatability-v1"]
    model_execution: Literal["model_execution_forbidden"]
    model_process_starts: int
    inference_requests: int
    network_requests: int
    downloads: int
    evidence_status: Literal["synthetic_not_hardware_evidence"]
    expected_run_count: int
    expected_exact_groups: int
    expected_divergent_groups: int
    expected_incomplete_groups: int
    expected_not_comparable_groups: int
    expected_representation_equivalence: tuple[Literal["unproven"], ...]

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> FixtureSource:
        fields = {
            "fixture_name",
            "model_execution",
            "model_process_starts",
            "inference_requests",
            "network_requests",
            "downloads",
            "evidence_status",
            "expected_run_count",
            "expected_exact_groups",
            "expected_divergent_groups",
            "expected_incomplete_groups",
            "expected_not_comparable_groups",
            "expected_representation_equivalence",
        }
        _versioned(data, "fixture_source", fields)
        if data["fixture_name"] != "synthetic-two-backend-repeatability-v1":
            raise ContractError("unsupported fixture source name")
        if data["model_execution"] != "model_execution_forbidden":
            raise ContractError("fixture source must forbid model execution")
        if data["evidence_status"] != "synthetic_not_hardware_evidence":
            raise ContractError("fixture source must remain synthetic evidence")
        equivalence = _strings(
            data["expected_representation_equivalence"],
            "fixture_source.expected_representation_equivalence",
        )
        if not equivalence or equivalence != tuple(sorted(set(equivalence))):
            raise ContractError("fixture source equivalence values must be unique and sorted")
        for item in equivalence:
            _literal(
                item,
                {"unproven"},
                "fixture_source.expected_representation_equivalence[]",
            )
        record = cls(
            "fixture_source",
            SCHEMA_VERSION,
            "synthetic-two-backend-repeatability-v1",
            "model_execution_forbidden",
            _integer(data["model_process_starts"], "fixture_source.model_process_starts"),
            _integer(data["inference_requests"], "fixture_source.inference_requests"),
            _integer(data["network_requests"], "fixture_source.network_requests"),
            _integer(data["downloads"], "fixture_source.downloads"),
            "synthetic_not_hardware_evidence",
            _integer(data["expected_run_count"], "fixture_source.expected_run_count", minimum=1),
            _integer(data["expected_exact_groups"], "fixture_source.expected_exact_groups"),
            _integer(
                data["expected_divergent_groups"],
                "fixture_source.expected_divergent_groups",
            ),
            _integer(
                data["expected_incomplete_groups"],
                "fixture_source.expected_incomplete_groups",
            ),
            _integer(
                data["expected_not_comparable_groups"],
                "fixture_source.expected_not_comparable_groups",
            ),
            cast("Any", equivalence),
        )
        if any(
            (
                record.model_process_starts,
                record.inference_requests,
                record.network_requests,
                record.downloads,
            ),
        ):
            raise ContractError("fixture source action counts must all be zero")
        return record

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


@dataclass(frozen=True, slots=True)
class NativeMetric:
    """A backend-native counter with explicit availability."""

    name: str
    value: int | None
    unit: str
    availability: Literal["synthetic", "observed", "unavailable"]
    reason: str | None

    @classmethod
    def from_value(cls, value: JsonValue, label: str) -> NativeMetric:
        data = _mapping(value, label)
        _keys(data, {"name", "value", "unit", "availability", "reason"}, label)
        availability = _literal(
            _string(data["availability"], f"{label}.availability"),
            {"synthetic", "observed", "unavailable"},
            f"{label}.availability",
        )
        metric_value = None if data["value"] is None else _integer(data["value"], f"{label}.value")
        reason = _optional_string(data["reason"], f"{label}.reason")
        if availability in {"synthetic", "observed"} and (
            metric_value is None or reason is not None
        ):
            raise ContractError(f"{label}: available metric requires a value and no reason")
        if availability == "unavailable" and (metric_value is not None or reason is None):
            raise ContractError(f"{label}: unavailable metric requires a reason and no value")
        return cls(
            _string(data["name"], f"{label}.name"),
            metric_value,
            _string(data["unit"], f"{label}.unit"),
            cast("Any", availability),
            reason,
        )


@dataclass(frozen=True, slots=True)
class Measurement:
    """A named resource measurement and method."""

    kind: Literal["memory", "energy"]
    method: str
    value: int | None
    unit: str
    availability: Literal["observed", "unavailable"]
    reason: str | None

    @classmethod
    def from_value(cls, value: JsonValue, label: str) -> Measurement:
        data = _mapping(value, label)
        _keys(data, {"kind", "method", "value", "unit", "availability", "reason"}, label)
        kind = _literal(
            _string(data["kind"], f"{label}.kind"),
            {"memory", "energy"},
            f"{label}.kind",
        )
        availability = _literal(
            _string(data["availability"], f"{label}.availability"),
            {"observed", "unavailable"},
            f"{label}.availability",
        )
        measurement_value = (
            None if data["value"] is None else _integer(data["value"], f"{label}.value")
        )
        reason = _optional_string(data["reason"], f"{label}.reason")
        if availability == "observed" and (measurement_value is None or reason is not None):
            raise ContractError(f"{label}: observed measurement requires a value")
        if availability == "unavailable" and (measurement_value is not None or reason is None):
            raise ContractError(f"{label}: unavailable measurement requires a reason")
        return cls(
            cast("Any", kind),
            _string(data["method"], f"{label}.method"),
            measurement_value,
            _string(data["unit"], f"{label}.unit"),
            cast("Any", availability),
            reason,
        )


@dataclass(frozen=True, slots=True)
class RunRecord:
    """One ordered inference observation or digest-safe invalid record."""

    record_type: Literal["run_record"]
    schema_version: str
    run_id: str
    run_order: int
    backend: Backend
    protocol_id: str
    runtime_id: str
    model_id: str
    host_id: str
    declaration_id: str
    process_instance_id: str
    model_instance_id: str
    cache_preparation_id: str
    concurrency_id: str
    concurrency_wave: int
    cache_cohort: CacheCohort
    evidence_kind: Literal["synthetic_fixture", "observed_execution"]
    validity: Literal["valid", "invalid"]
    invalid_reason_sha256: str | None
    model_process_start_count: int
    inference_request_count: int
    request_base64: str
    request_sha256: str
    raw_response_base64: str | None
    raw_response_sha256: str | None
    text_utf8: str | None
    text_sha256: str | None
    token_ids: tuple[int, ...] | None
    token_ids_sha256: str | None
    finish_reason: str | None
    envelope_base64: str | None
    envelope_sha256: str | None
    native_metrics: tuple[NativeMetric, ...]
    measurements: tuple[Measurement, ...]

    @classmethod
    def from_dict(cls, data: dict[str, JsonValue]) -> RunRecord:
        fields = {
            "run_id",
            "run_order",
            "backend",
            "protocol_id",
            "runtime_id",
            "model_id",
            "host_id",
            "declaration_id",
            "process_instance_id",
            "model_instance_id",
            "cache_preparation_id",
            "concurrency_id",
            "concurrency_wave",
            "cache_cohort",
            "evidence_kind",
            "validity",
            "invalid_reason_sha256",
            "model_process_start_count",
            "inference_request_count",
            "request_base64",
            "request_sha256",
            "raw_response_base64",
            "raw_response_sha256",
            "text_utf8",
            "text_sha256",
            "token_ids",
            "token_ids_sha256",
            "finish_reason",
            "envelope_base64",
            "envelope_sha256",
            "native_metrics",
            "measurements",
        }
        _versioned(data, "run_record", fields)
        backend = _literal(
            _string(data["backend"], "run_record.backend"),
            {"mlx-lm", "llama.cpp", "ollama"},
            "run_record.backend",
        )
        cohort = _literal(
            _string(data["cache_cohort"], "run_record.cache_cohort"),
            {
                "cold_process_model",
                "cold_model_warm_process",
                "warm_model_cold_prompt_cache",
                "warm_prompt_kv_cache",
                "unsupported",
            },
            "run_record.cache_cohort",
        )
        evidence = _literal(
            _string(data["evidence_kind"], "run_record.evidence_kind"),
            {"synthetic_fixture", "observed_execution"},
            "run_record.evidence_kind",
        )
        validity = _literal(
            _string(data["validity"], "run_record.validity"),
            {"valid", "invalid"},
            "run_record.validity",
        )
        process_starts = _integer(
            data["model_process_start_count"],
            "run_record.model_process_start_count",
        )
        inference_requests = _integer(
            data["inference_request_count"],
            "run_record.inference_request_count",
        )
        if process_starts > 1 or inference_requests > 1:
            raise ContractError("one run can account for at most one process start and request")
        if evidence == "synthetic_fixture" and (process_starts or inference_requests):
            raise ContractError("synthetic runs cannot account for model actions")
        if evidence == "observed_execution" and inference_requests != 1:
            raise ContractError("observed runs must account for exactly one inference request")
        request_base64 = _string(
            data["request_base64"],
            "run_record.request_base64",
            empty=True,
        )
        request_sha = _sha256(data["request_sha256"], "run_record.request_sha256")
        if digest_bytes(decode_bytes(request_base64)) != request_sha:
            raise ContractError("request digest mismatch")
        raw_base64 = _optional_string(
            data["raw_response_base64"],
            "run_record.raw_response_base64",
            empty=True,
        )
        raw_sha = _optional_sha256(data["raw_response_sha256"], "run_record.raw_response_sha256")
        text = _optional_string(data["text_utf8"], "run_record.text_utf8", empty=True)
        text_sha = _optional_sha256(data["text_sha256"], "run_record.text_sha256")
        envelope_base64 = _optional_string(data["envelope_base64"], "run_record.envelope_base64")
        envelope_sha = _optional_sha256(data["envelope_sha256"], "run_record.envelope_sha256")
        token_value = data["token_ids"]
        tokens = None if token_value is None else _integers(token_value, "run_record.token_ids")
        token_sha = _optional_sha256(data["token_ids_sha256"], "run_record.token_ids_sha256")
        finish_reason = _optional_string(data["finish_reason"], "run_record.finish_reason")
        invalid_sha = _optional_sha256(
            data["invalid_reason_sha256"],
            "run_record.invalid_reason_sha256",
        )
        if validity == "valid":
            if invalid_sha is not None:
                raise ContractError("valid run cannot have invalid_reason_sha256")
            required_values = (raw_base64, raw_sha, text, text_sha, envelope_base64, envelope_sha)
            if any(value is None for value in required_values):
                raise ContractError("valid run requires raw, text, and envelope custody")
            if finish_reason is None:
                raise ContractError("valid run requires a finish reason")
            if digest_bytes(decode_bytes(cast("str", raw_base64))) != raw_sha:
                raise ContractError("raw response digest mismatch")
            if digest_bytes(cast("str", text).encode("utf-8")) != text_sha:
                raise ContractError("text digest mismatch")
            if digest_bytes(decode_bytes(cast("str", envelope_base64))) != envelope_sha:
                raise ContractError("response envelope digest mismatch")
            if tokens is None and token_sha is not None:
                raise ContractError("token digest cannot exist without token IDs")
            if tokens is not None and canonical_identity(list(tokens)) != token_sha:
                raise ContractError("token ID digest mismatch")
        else:
            if invalid_sha is None:
                raise ContractError("invalid run requires invalid_reason_sha256")
            if any(
                value is not None
                for value in (
                    raw_base64,
                    raw_sha,
                    text,
                    text_sha,
                    tokens,
                    token_sha,
                    finish_reason,
                    envelope_base64,
                    envelope_sha,
                )
            ):
                raise ContractError("invalid run must use digest-safe custody only")
        native_values = _as_list(data["native_metrics"], "run_record.native_metrics")
        measurement_values = _as_list(data["measurements"], "run_record.measurements")
        metrics = tuple(
            NativeMetric.from_value(item, "run_record.native_metrics[]") for item in native_values
        )
        if len({metric.name for metric in metrics}) != len(metrics):
            raise ContractError("native metric names must be unique")
        measurements = tuple(
            Measurement.from_value(item, "run_record.measurements[]") for item in measurement_values
        )
        expected_availability = "synthetic" if evidence == "synthetic_fixture" else "observed"
        if any(
            metric.availability not in {expected_availability, "unavailable"} for metric in metrics
        ):
            raise ContractError("native metric evidence does not match run evidence")
        if evidence == "synthetic_fixture" and any(
            measurement.availability == "observed" for measurement in measurements
        ):
            raise ContractError("synthetic runs cannot contain observed measurements")
        return cls(
            "run_record",
            SCHEMA_VERSION,
            _string(data["run_id"], "run_record.run_id"),
            _integer(data["run_order"], "run_record.run_order", minimum=1),
            cast("Any", backend),
            _sha256(data["protocol_id"], "run_record.protocol_id"),
            _sha256(data["runtime_id"], "run_record.runtime_id"),
            _sha256(data["model_id"], "run_record.model_id"),
            _sha256(data["host_id"], "run_record.host_id"),
            _sha256(data["declaration_id"], "run_record.declaration_id"),
            _sha256(
                data["process_instance_id"],
                "run_record.process_instance_id",
            ),
            _sha256(data["model_instance_id"], "run_record.model_instance_id"),
            _sha256(
                data["cache_preparation_id"],
                "run_record.cache_preparation_id",
            ),
            _sha256(data["concurrency_id"], "run_record.concurrency_id"),
            _integer(data["concurrency_wave"], "run_record.concurrency_wave", minimum=1),
            cast("Any", cohort),
            cast("Any", evidence),
            cast("Any", validity),
            invalid_sha,
            process_starts,
            inference_requests,
            request_base64,
            request_sha,
            raw_base64,
            raw_sha,
            text,
            text_sha,
            tokens,
            token_sha,
            finish_reason,
            envelope_base64,
            envelope_sha,
            metrics,
            measurements,
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return _record_dict(self)


Record: TypeAlias = (
    HostIdentity
    | RuntimeIdentity
    | ModelIdentity
    | ProcessInstance
    | ModelInstance
    | CachePreparation
    | ConcurrencyIdentity
    | Protocol
    | ExecutionDeclaration
    | Eligibility
    | FixtureSource
    | RunRecord
)
RecordType = TypeVar("RecordType", bound=Record)

RECORD_LOADERS: dict[str, type[Record]] = {
    "host_identity": HostIdentity,
    "runtime_identity": RuntimeIdentity,
    "model_identity": ModelIdentity,
    "process_instance": ProcessInstance,
    "model_instance": ModelInstance,
    "cache_preparation": CachePreparation,
    "concurrency_identity": ConcurrencyIdentity,
    "protocol": Protocol,
    "execution_declaration": ExecutionDeclaration,
    "eligibility": Eligibility,
    "fixture_source": FixtureSource,
    "run_record": RunRecord,
}


def parse_record(value: JsonValue) -> Record:
    """Parse a strict known record."""
    data = _mapping(value, "record")
    record_type = _string(data.get("record_type"), "record.record_type")
    loader = RECORD_LOADERS.get(record_type)
    if loader is None:
        raise ContractError(f"unknown record_type: {record_type}")
    return loader.from_dict(data)


def record_bytes(record: Record) -> bytes:
    """Canonical bytes for a validated record."""
    return canonical_json(record.to_dict())


def record_id(record: Record) -> str:
    """Canonical identity for a validated record."""
    return canonical_identity(record.to_dict())
