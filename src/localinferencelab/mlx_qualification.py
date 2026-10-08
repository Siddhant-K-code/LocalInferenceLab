"""Deterministic static qualification for proposed future MLX runtimes."""

from __future__ import annotations

import ast
import io
import os
import re
import textwrap
import zipfile
from dataclasses import dataclass
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import NamedTuple, cast
from urllib.parse import urlsplit

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    encode_bytes,
    load_canonical_json_file,
    load_json_bytes,
)
from localinferencelab.custody import publish_bundle, read_closed_bundle
from localinferencelab.mlx_runtime_preflight import (
    EXPECTED_OBSERVED_LOCK_ID,
    EXPECTED_OBSERVED_NEGATIVE_PROJECTION_ID,
    OBSERVED_AUTHORIZATION_ID,
    OBSERVED_CONSUMPTION_ID,
    OBSERVED_FAILURE_ID,
)
from localinferencelab.mlx_runtime_target import (
    EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
    target_environment_binding,
)

SCHEMA_VERSION = "1.0"
ELIGIBLE = "eligible_for_new_observed_authorization"
INELIGIBLE = "ineligible"
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_MAX_METADATA_HEADERS = 4096
_MIN_RELEASE_COMPONENTS = 2
_MAX_METADATA_BYTES = 256 * 1024
_MAX_SOURCE_BYTES = 256 * 1024
_MAX_SOURCE_EXCERPT_BYTES = 16 * 1024
_MAX_WHEEL_BYTES = 64 * 1024 * 1024
_MAX_WHEEL_ENTRIES = 20_000
_PACKAGE_DOMAINS = {"files.pythonhosted.org"}
_SOURCE_DOMAINS = {"github.com"}
_SYNTHETIC_DOMAIN = "fixtures.localinferencelab.invalid"
_NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_VERSION_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}$")
_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_TAG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_WHEEL_TAG_PATTERN = re.compile(
    r"^(?P<python>[A-Za-z0-9.]+)-(?P<abi>[A-Za-z0-9.]+)-(?P<platform>[A-Za-z0-9_.]+)$"
)
_CPYTHON_TAG_PATTERN = re.compile(r"^cp(?P<major>[1-9])(?P<minor>[0-9]{1,2})$")
_MACOS_PLATFORM_PATTERN = re.compile(
    r"^macosx_(?P<major>[0-9]+)_(?P<minor>[0-9]+)_(?P<arch>arm64|x86_64|universal2)$"
)
_MARKER_CLAUSE_PATTERN = re.compile(
    r"^(?P<variable>"
    r"implementation_name|os_name|platform_machine|platform_system|python_full_version|"
    r'python_version|sys_platform|extra) (?P<operator>not in|in|==|!=|<=|>=|<|>) "'
    r'(?P<value>[^"]+)"$'
)
_SPECIFIER_PATTERN = re.compile(
    r"(?P<operator>===|==|!=|~=|<=|>=|<|>)(?P<version>"
    r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3})"
)
_SUPPORTED_METADATA_VERSIONS = {"2.1", "2.2", "2.3", "2.4"}
_METADATA_POLICY = policy.default.clone(
    utf8=True,
    refold_source="none",
    raise_on_defect=False,
)
_REQUIREMENT_HEAD_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[a-z0-9][a-z0-9._-]*(?:,[a-z0-9][a-z0-9._-]*)*)\])?"
    r"(?P<specifiers>.*)$"
)
_EXPECTED_API_EVIDENCE: dict[str, tuple[str, str]] = {
    "default_device": ("mlx", "mlx.core.default_device"),
    "default_stream": ("mlx", "mlx.core.default_stream"),
    "distribution_versions": ("mlx-lm", "METADATA.Version"),
    "import_mlx": ("mlx", "mlx.core"),
    "import_mlx_lm": ("mlx-lm", "mlx_lm"),
    "metal_is_available": ("mlx", "mlx.core.metal.is_available"),
    "synchronize": ("mlx", "mlx.core.synchronize"),
}
_API_EVIDENCE_DOES_NOT_PROVE: list[JsonValue] = [
    "backend_or_device_availability",
    "installation_success",
    "metal_availability",
    "native_loader_success",
    "runtime_executability",
    "runtime_import_success",
    "stream_synchronization_success",
]
_EXPECTED_API_SEMANTICS: dict[str, dict[str, JsonValue]] = {
    "default_device": {
        "access_form": "mlx.core.default_device()",
        "callable": True,
        "module": "mlx.core",
        "static_signature": "() -> Device",
        "surface_kind": "nanobind_callable",
    },
    "default_stream": {
        "access_form": "mlx.core.default_stream(device)",
        "callable": True,
        "module": "mlx.core",
        "static_signature": "(device: Device) -> Stream",
        "surface_kind": "nanobind_callable",
    },
    "distribution_versions": {
        "access_form": "importlib.metadata.version(distribution_name)",
        "callable": True,
        "module": "importlib.metadata",
        "static_signature": "(distribution_name: str) -> str",
        "surface_kind": "stdlib_callable",
    },
    "import_mlx": {
        "access_form": 'importlib.import_module("mlx.core")',
        "callable": False,
        "module": "mlx.core",
        "static_signature": "module mlx.core",
        "surface_kind": "module_import_declaration",
    },
    "import_mlx_lm": {
        "access_form": 'importlib.import_module("mlx_lm")',
        "callable": False,
        "module": "mlx_lm",
        "static_signature": "package mlx_lm",
        "surface_kind": "module_import_declaration",
    },
    "metal_is_available": {
        "access_form": "mlx.core.metal.is_available()",
        "callable": True,
        "module": "mlx.core.metal",
        "static_signature": "() -> bool",
        "surface_kind": "nanobind_callable",
    },
    "synchronize": {
        "access_form": "mlx.core.synchronize()",
        "callable": True,
        "module": "mlx.core",
        "static_signature": "(stream: Stream | None = None) -> None",
        "surface_kind": "nanobind_callable",
    },
}
_MLX_REPOSITORY = "https://github.com/ml-explore/mlx"
_MLX_TAG = "v0.30.4"
_MLX_REVISION = "2f324cc3b200700b422db4811ae3ff8bd5bf48b4"
_MLX_LM_REPOSITORY = "https://github.com/ml-explore/mlx-lm"
_MLX_LM_TAG = "v0.30.6"
_MLX_LM_REVISION = "f18526f8d66f74728072e96d55acb6c451e92e88"
_CPYTHON_REPOSITORY = "https://github.com/python/cpython"
_CPYTHON_TAG = "v3.13.0"
_CPYTHON_REVISION = "60403a5409ff2c3f3b07dd2ca91a7a3e096839c7"
_REVIEWED_API_SOURCE_FILES: dict[tuple[str, str], tuple[str, str, str]] = {
    (_CPYTHON_REPOSITORY, "Lib/importlib/metadata/__init__.py"): (
        _CPYTHON_TAG,
        _CPYTHON_REVISION,
        "sha256:5476c7c22a65f9e8b5a07b799336d87fa70e792758fd95b161b53b530e3b2654",
    ),
    (_MLX_REPOSITORY, "mlx/backend/metal/metal.h"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:d945d18236b8af528bc74161f72c067cc115d49026bd4ea71b84857c95c18870",
    ),
    (_MLX_REPOSITORY, "mlx/device.h"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:d00a0b67d10728666acf3b82838530471b29151a50212aec0cf960ea3d8fd814",
    ),
    (_MLX_REPOSITORY, "mlx/stream.h"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:a9281c4a7301a3d1af7a817a19e95f5c1c22ce7f7f5a9e25e5113d314ed0b824",
    ),
    (_MLX_LM_REPOSITORY, "mlx_lm/__init__.py"): (
        _MLX_LM_TAG,
        _MLX_LM_REVISION,
        "sha256:f9ffa88772d26e537a98aa39ab16488a7a0d13cc1fac5d665376132c94b49608",
    ),
    (_MLX_REPOSITORY, "python/src/device.cpp"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:aea762cc90ced0d4d3274c2f3cdd48435de8219ff2b4d5e5b782982b05c362b9",
    ),
    (_MLX_REPOSITORY, "python/src/metal.cpp"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:4e077805ef4db09e62479e3ff1d90b92c89caaca5d1af6245215169a4df4dce9",
    ),
    (_MLX_REPOSITORY, "python/src/mlx.cpp"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:e339e58d45f679b662bb06a96b42b015c59f1590a2af9b8fb12caac85f15097b",
    ),
    (_MLX_REPOSITORY, "python/src/stream.cpp"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:4d80cae66d2aa75c076ed9555e1439a41dbc2e4578d8faadefa957d567a97e63",
    ),
    (_MLX_REPOSITORY, "setup.py"): (
        _MLX_TAG,
        _MLX_REVISION,
        "sha256:ef7f790742fbf7ec8f7760721c7684048d595f29503936021c7da3740f24c1ba",
    ),
    (_MLX_LM_REPOSITORY, "setup.py"): (
        _MLX_LM_TAG,
        _MLX_LM_REVISION,
        "sha256:68025286dfcf40efc18aa0ca42427d1d697ba631ca3fbe7e54e0f4bbe74a36e3",
    ),
}
_REVIEWED_API_SOURCE_RANGES: dict[
    str,
    tuple[tuple[str, str, int, int], ...],
] = {
    "default_device": (
        (_MLX_REPOSITORY, "mlx/device.h", 28, 28),
        (_MLX_REPOSITORY, "python/src/device.cpp", 54, 57),
    ),
    "default_stream": (
        (_MLX_REPOSITORY, "mlx/stream.h", 16, 17),
        (_MLX_REPOSITORY, "python/src/stream.cpp", 66, 70),
    ),
    "distribution_versions": (
        (_CPYTHON_REPOSITORY, "Lib/importlib/metadata/__init__.py", 483, 486),
        (_CPYTHON_REPOSITORY, "Lib/importlib/metadata/__init__.py", 980, 987),
    ),
    "import_mlx": (
        (_MLX_REPOSITORY, "python/src/mlx.cpp", 27, 46),
        (_MLX_REPOSITORY, "setup.py", 207, 226),
    ),
    "import_mlx_lm": (
        (_MLX_LM_REPOSITORY, "mlx_lm/__init__.py", 1, 20),
        (_MLX_LM_REPOSITORY, "setup.py", 35, 42),
    ),
    "metal_is_available": (
        (_MLX_REPOSITORY, "mlx/backend/metal/metal.h", 11, 14),
        (_MLX_REPOSITORY, "python/src/metal.cpp", 28, 35),
    ),
    "synchronize": (
        (_MLX_REPOSITORY, "mlx/stream.h", 36, 40),
        (_MLX_REPOSITORY, "python/src/stream.cpp", 133, 146),
    ),
}
_REVIEWED_WORKER_API_EVIDENCE_ANCHORS = [
    "sha256:10ab50cbfb94890bae1dd8c57180645d5781e454b1a8171b158c4d932121d9dd",
]
_ZERO_ACTION_COUNTERS: dict[str, int] = {
    "authorization_creations": 0,
    "authorization_consumptions": 0,
    "backend_queries": 0,
    "benchmark_actions": 0,
    "cache_actions": 0,
    "cloud_actions": 0,
    "device_queries": 0,
    "generation_requests": 0,
    "inference_requests": 0,
    "metal_queries": 0,
    "model_discoveries": 0,
    "model_loads": 0,
    "package_installations": 0,
    "package_network_requests": 0,
    "process_starts": 0,
    "prompt_actions": 0,
    "runtime_imports": 0,
    "socket_creations": 0,
    "spend_actions": 0,
    "synchronizations": 0,
    "tokenizer_discoveries": 0,
    "tokenizer_loads": 0,
}
_CLAIMS: dict[str, JsonValue] = {
    "authorization_created": False,
    "authorization_consumed": False,
    "dependency_closure_scope": "supplied_canonical_distribution_metadata_only",
    "gate_executes_candidate": False,
    "native_loader_semantic_completeness": False,
    "permission_to_install_import_or_execute": False,
    "runtime_executability_proven": False,
    "standard_library_semantic_completeness": False,
}
_HISTORICAL_PROTOCOL_ID = "sha256:c3df6f0eb9a67a00e1f1f180b0e34fd9b5ac5dd662b430f86ec29c87dd30727a"
_HISTORICAL_WORKER_CODE_ID = (
    "sha256:bfd840635879dfae9a57fb11cae0e6ddef4f3f5f3b9b81f39e8e1cec51539fe3"
)
_REVIEWED_CANDIDATE_ANCHORS = [
    "sha256:e4bd7b6f5ce7656d1a490a6e4b39e23e1b9a6acaee55084744a8a267f0007f2c"
]


class Requirement(NamedTuple):
    """Parsed bounded requirement grammar."""

    raw: str
    name: str
    extras: tuple[str, ...]
    specifiers: tuple[tuple[str, str], ...]
    marker: str | None


class MetadataEvidence(NamedTuple):
    """Strictly parsed distribution metadata bound to its exact source bytes."""

    scope: str
    requirements: tuple[Requirement, ...]
    requires_python: str | None
    requires_python_specifiers: tuple[tuple[str, str], ...]
    data: bytes


@dataclass(frozen=True, slots=True)
class QualificationReplayResult:
    """Verified summary of the deterministic qualification fixture."""

    bundle_root: str
    eligible_record_id: str
    ineligible_record_id: str
    eligible_decision: str
    ineligible_decision: str
    package_installations: int
    process_starts: int
    runtime_imports: int
    authorization_creations: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "bundle_root": self.bundle_root,
            "eligible_record_id": self.eligible_record_id,
            "ineligible_record_id": self.ineligible_record_id,
            "eligible_decision": self.eligible_decision,
            "ineligible_decision": self.ineligible_decision,
            "package_installations": self.package_installations,
            "process_starts": self.process_starts,
            "runtime_imports": self.runtime_imports,
            "authorization_creations": self.authorization_creations,
        }


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int = 512) -> list[JsonValue]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    if len(value) > maximum:
        raise ContractError(f"{label} exceeds maximum count {maximum}")
    return value


def _keys(value: dict[str, JsonValue], expected: set[str], label: str) -> None:
    missing = expected - value.keys()
    extra = value.keys() - expected
    if missing:
        raise ContractError(f"{label} missing keys: {', '.join(sorted(missing))}")
    if extra:
        raise ContractError(f"{label} unknown keys: {', '.join(sorted(extra))}")


def _text(value: JsonValue, label: str, *, maximum: int = 4096) -> str:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{label} must be a non-empty string")
    if len(value.encode("utf-8")) > maximum:
        raise ContractError(f"{label} exceeds maximum length {maximum}")
    if any(ord(character) < _CONTROL_LIMIT for character in value):
        raise ContractError(f"{label} contains control characters")
    return value


def _integer(
    value: JsonValue,
    label: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ContractError(f"{label} must be an integer >= {minimum}")
    if maximum is not None and value > maximum:
        raise ContractError(f"{label} must be <= {maximum}")
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


def _normalize_name(value: JsonValue, label: str) -> str:
    name = _text(value, label, maximum=128).lower().replace("_", "-").replace(".", "-")
    name = re.sub(r"-+", "-", name)
    if _NAME_PATTERN.fullmatch(name) is None:
        raise ContractError(f"{label} is not a canonical distribution name")
    return name


def _version(value: JsonValue, label: str) -> str:
    version = _text(value, label, maximum=64)
    if _VERSION_PATTERN.fullmatch(version) is None:
        raise ContractError(f"{label} must use the supported canonical release-version grammar")
    return version


def _relative_path(value: JsonValue, label: str) -> str:
    text = _text(value, label, maximum=1024)
    path = PurePosixPath(text)
    if (
        "\\" in text
        or path.is_absolute()
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != text
    ):
        raise ContractError(f"{label} must be a canonical relative path")
    return text


def _url(
    value: JsonValue,
    label: str,
    *,
    allowed_domains: set[str],
    expected_filename: str | None = None,
) -> str:
    url = _text(value, label, maximum=2048)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_domains
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ContractError(f"{label} is not an allowed credential-free immutable URL")
    if expected_filename is not None and not parsed.path.endswith(f"/{expected_filename}"):
        raise ContractError(f"{label} does not end with the exact wheel filename")
    return url


def _frozen_negative_relationship() -> dict[str, JsonValue]:
    return {
        "authorization_id": OBSERVED_AUTHORIZATION_ID,
        "consumption_id": OBSERVED_CONSUMPTION_ID,
        "historical_protocol_id": _HISTORICAL_PROTOCOL_ID,
        "historical_worker_code_id": _HISTORICAL_WORKER_CODE_ID,
        "ids_modified": False,
        "negative_projection_id": EXPECTED_OBSERVED_NEGATIVE_PROJECTION_ID,
        "retry_authorized": False,
        "runtime_lock_id": EXPECTED_OBSERVED_LOCK_ID,
        "schema_1_0_state": "permanently_disabled",
        "terminal_failure_id": OBSERVED_FAILURE_ID,
    }


def worker_api_evidence_spec() -> dict[str, JsonValue]:
    """Return the source-only worker API evidence contract."""
    reviewed_sources: list[JsonValue] = []
    for (repository_url, path), (tag, revision, file_sha256) in sorted(
        _REVIEWED_API_SOURCE_FILES.items()
    ):
        reviewed_sources.append(
            {
                "file_sha256": file_sha256,
                "path": path,
                "repository_url": repository_url,
                "revision": revision,
                "tag": tag,
            }
        )
    expected_surfaces: list[JsonValue] = []
    for probe, (distribution, symbol) in sorted(_EXPECTED_API_EVIDENCE.items()):
        expected_surfaces.append(
            {
                "distribution": distribution,
                "probe": probe,
                "symbol": symbol,
                **_EXPECTED_API_SEMANTICS[probe],
            }
        )
    content: dict[str, JsonValue] = {
        "record_type": "mlx_worker_api_evidence_spec",
        "schema_version": SCHEMA_VERSION,
        "claim_scope": "source_surface_availability_only",
        "does_not_prove": list(_API_EVIDENCE_DOES_NOT_PROVE),
        "expected_surfaces": expected_surfaces,
        "offline_verification": {
            "ambiguous_duplicate_definitions_rejected": True,
            "coordinated_rehashing_rejected_by_reviewed_anchor": True,
            "dynamic_generation_or_aliasing_rejected": True,
            "exact_bounded_source_excerpt_bytes_required": True,
            "exact_file_hash_required": True,
            "exact_path_revision_and_tag_required": True,
            "self_attested_anchors_accepted": False,
        },
        "reviewed_evidence_anchors": list(_REVIEWED_WORKER_API_EVIDENCE_ANCHORS),
        "reviewed_sources": reviewed_sources,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def qualification_spec() -> dict[str, JsonValue]:
    """Return the canonical process-free qualification specification."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_qualification_spec",
        "schema_version": SCHEMA_VERSION,
        "action": "static_runtime_qualification_only",
        "candidate_target": "future_separately_reviewed_mlx_runtime_preflight_schema_1_1",
        "decisions": [ELIGIBLE, INELIGIBLE],
        "eligibility_meaning": (
            "eligible_only_for_human_review_and_possible_new_explicit_observed_authorization"
        ),
        "eligibility_does_not_prove": [
            "backend_or_device_availability",
            "installation_success",
            "metal_availability",
            "model_support",
            "native_loader_or_standard_library_semantic_completeness",
            "runtime_executability",
            "runtime_import_success",
            "stream_synchronization",
        ],
        "expected_worker_api_evidence": [
            {
                "probe": probe,
                "distribution": distribution,
                "symbol": symbol,
                **_EXPECTED_API_SEMANTICS[probe],
            }
            for probe, (distribution, symbol) in sorted(_EXPECTED_API_EVIDENCE.items())
        ],
        "extras_policy": "forbid_all_extras",
        "frozen_schema_1_0_negative": _frozen_negative_relationship(),
        "required_top_level_distributions": ["mlx", "mlx-lm"],
        "reviewed_candidate_anchors": list(_REVIEWED_CANDIDATE_ANCHORS),
        "worker_api_evidence_spec_id": worker_api_evidence_spec()["spec_id"],
        "runtime_target_anchor_id": EXPECTED_RUNTIME_TARGET_ANCHOR_ID,
        "runtime_target_policy": {
            "development_host_observation_is_runtime_evidence": False,
            "exact_anchor_required_for_reviewed_candidate": True,
            "future_independent_observation_required": True,
            "target_drift_accepted": False,
        },
        "requirement_grammar": (
            "canonical_release_versions_with_comma_conjoined_specifiers_and_"
            "and_conjoined_environment_markers"
        ),
        "requires_python_policy": (
            "exactly_one_bounded_specifier_set_required_for_complete_metadata"
        ),
        "required_next_milestone": (
            "distinct_schema_1_1_protocol_spec_worker_review_and_fresh_explicit_authorization"
        ),
        "top_level_requirement_policy": (
            "exact_single_double_equals_pin_matching_each_selected_mlx_and_mlx_lm_version"
        ),
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def _verify_spec(value: JsonValue) -> dict[str, JsonValue]:
    spec = _mapping(value, "mlx_runtime_qualification_spec")
    if canonical_json(spec) != canonical_json(qualification_spec()):
        raise ContractError("MLX runtime qualification specification content drift")
    return dict(spec)


def _parse_version(value: str) -> tuple[int, ...]:
    if _VERSION_PATTERN.fullmatch(value) is None:
        raise ContractError("unsupported release version")
    return tuple(int(component) for component in value.split("."))


def _padded_version(value: str, width: int = 4) -> tuple[int, ...]:
    parsed = _parse_version(value)
    return parsed + (0,) * (width - len(parsed))


def _specifier_identity(
    specifiers: tuple[tuple[str, str], ...],
) -> tuple[tuple[str, str], ...]:
    return tuple(
        sorted(
            (
                operator,
                version
                if operator == "==="
                else ".".join(str(component) for component in _padded_version(version)),
            )
            for operator, version in specifiers
        )
    )


def _marker_identity(marker: str | None) -> tuple[tuple[str, str, str], ...] | None:
    if marker is None:
        return None
    identities: list[tuple[str, str, str]] = []
    for clause in marker.split(" and "):
        match = _MARKER_CLAUSE_PATTERN.fullmatch(clause)
        if match is None:
            raise ContractError("environment marker uses unsupported or ambiguous grammar")
        variable = match.group("variable")
        value = match.group("value")
        if variable in {"python_version", "python_full_version"}:
            value = ".".join(str(component) for component in _padded_version(value))
        identities.append((variable, match.group("operator"), value))
    if len(identities) != len(set(identities)):
        raise ContractError("environment marker contains duplicate clauses")
    return tuple(sorted(identities))


def _parse_specifiers(
    value: str,
    label: str,
    *,
    required: bool = False,
) -> tuple[tuple[str, str], ...]:
    if not value:
        if required:
            raise ContractError(f"{label} must contain at least one version specifier")
        return ()
    specifiers: list[tuple[str, str]] = []
    for piece in value.split(","):
        specifier = _SPECIFIER_PATTERN.fullmatch(piece)
        if specifier is None:
            raise ContractError(f"{label} uses unsupported version specifier grammar")
        specifiers.append((specifier.group("operator"), specifier.group("version")))
    parsed = tuple(specifiers)
    if len(parsed) != len(set(_specifier_identity(parsed))):
        raise ContractError(f"{label} contains duplicate version specifiers")
    return parsed


def _parse_requirement(value: JsonValue, label: str) -> Requirement:
    raw = _text(value, label, maximum=512)
    if raw.count(";") > 1:
        raise ContractError(f"{label} has ambiguous marker separators")
    if ";" in raw:
        head, marker = raw.split(";", 1)
        if not marker.startswith(" ") or marker != f" {marker.strip()}":
            raise ContractError(f"{label} must use one canonical space after ';'")
        marker = marker[1:]
    else:
        head = raw
        marker = None
    match = _REQUIREMENT_HEAD_PATTERN.fullmatch(head)
    if match is None:
        raise ContractError(f"{label} uses unsupported requirement grammar")
    name = _normalize_name(match.group("name"), f"{label}.name")
    extras_text = match.group("extras")
    extras = () if extras_text is None else tuple(extras_text.split(","))
    if extras != tuple(sorted(set(extras))):
        raise ContractError(f"{label} extras must be unique and sorted")
    specifiers = _parse_specifiers(match.group("specifiers"), f"{label}.specifiers")
    if marker is not None:
        _evaluate_marker(marker, _canonical_marker_test_environment(), validate_only=True)
        _marker_identity(marker)
    return Requirement(raw, name, extras, specifiers, marker)


def _canonical_marker_test_environment() -> dict[str, str]:
    return {
        "implementation_name": "cpython",
        "os_name": "posix",
        "platform_machine": "arm64",
        "platform_system": "Darwin",
        "python_full_version": "3.12.0",
        "python_version": "3.12",
        "sys_platform": "darwin",
        "extra": "",
    }


def _compare_marker_values(  # noqa: PLR0911
    variable: str,
    left: str,
    operator: str,
    right: str,
) -> bool:
    if variable in {"python_version", "python_full_version"}:
        left_version = _padded_version(left)
        right_version = _padded_version(right)
        if operator == "==":
            return left_version == right_version
        if operator == "!=":
            return left_version != right_version
        if operator == "<":
            return left_version < right_version
        if operator == "<=":
            return left_version <= right_version
        if operator == ">":
            return left_version > right_version
        if operator == ">=":
            return left_version >= right_version
        raise ContractError("version marker does not support membership operators")
    if operator == "==":
        return left == right
    if operator == "!=":
        return left != right
    if operator == "<":
        return left < right
    if operator == "<=":
        return left <= right
    if operator == ">":
        return left > right
    if operator == ">=":
        return left >= right
    if operator == "in":
        return left in right
    if operator == "not in":
        return left not in right
    raise ContractError("unsupported marker operator")


def _evaluate_marker(
    marker: str,
    environment: dict[str, str],
    *,
    validate_only: bool = False,
) -> tuple[bool, str]:
    clauses = marker.split(" and ")
    if not clauses or any(not clause for clause in clauses):
        raise ContractError("environment marker has empty clauses")
    results: list[bool] = []
    for clause in clauses:
        match = _MARKER_CLAUSE_PATTERN.fullmatch(clause)
        if match is None:
            raise ContractError("environment marker uses unsupported or ambiguous grammar")
        variable = match.group("variable")
        if variable not in environment:
            raise ContractError(f"environment marker variable is unavailable: {variable}")
        result = _compare_marker_values(
            variable,
            environment[variable],
            match.group("operator"),
            match.group("value"),
        )
        results.append(result)
    applicable = all(results)
    if validate_only:
        return applicable, "validated"
    return (
        applicable,
        f"marker {marker!r} evaluated {'true' if applicable else 'false'} "
        "against the exact target environment",
    )


def _satisfies(  # noqa: PLR0911
    version: str,
    specifiers: tuple[tuple[str, str], ...],
) -> bool:
    selected = _padded_version(version)
    for operator, required_version in specifiers:
        required = _padded_version(required_version)
        if operator == "===" and version != required_version:
            return False
        if operator == "==" and selected != required:
            return False
        if operator == "!=" and selected == required:
            return False
        if operator == "<" and not selected < required:
            return False
        if operator == "<=" and not selected <= required:
            return False
        if operator == ">" and not selected > required:
            return False
        if operator == ">=" and not selected >= required:
            return False
        if operator == "~=":
            release = _parse_version(required_version)
            if len(release) < _MIN_RELEASE_COMPONENTS:
                raise ContractError("compatible-release specifier requires at least two components")
            upper_prefix = release[:-1]
            upper = upper_prefix[:-1] + (upper_prefix[-1] + 1,)
            upper_padded = upper + (0,) * (4 - len(upper))
            if selected < required or selected >= upper_padded:
                return False
    return True


def _metadata_bytes(
    name: str,
    version: str,
    requirements: list[str],
    *,
    requires_python: str | None,
) -> bytes:
    lines = ["Metadata-Version: 2.3", f"Name: {name}", f"Version: {version}"]
    if requires_python is not None:
        lines.append(f"Requires-Python: {requires_python}")
    lines.extend(f"Requires-Dist: {requirement}" for requirement in sorted(requirements))
    return ("\n".join(lines) + "\n\n").encode("ascii")


def _metadata_header_values(message: Message, name: str) -> list[str]:
    values = message.get_all(name, [])
    return [str(value) for value in values]


def _single_metadata_header(message: Message, name: str, label: str) -> str:
    values = _metadata_header_values(message, name)
    if len(values) != 1:
        raise ContractError(f"{label} must contain exactly one {name} header")
    return _text(values[0], f"{label}.{name}", maximum=512)


def _parse_core_metadata(
    data: bytes,
    *,
    expected_name: str,
    expected_version: str,
    label: str,
) -> tuple[list[str], str | None]:
    if b"\x00" in data:
        raise ContractError(f"{label} contains a NUL byte")
    try:
        data.decode("utf-8")
        message = BytesParser(policy=_METADATA_POLICY).parsebytes(data)
    except (UnicodeDecodeError, ValueError) as error:
        raise ContractError(f"{label} is not parseable Core Metadata") from error
    if message.defects:
        names = ",".join(sorted(type(defect).__name__ for defect in message.defects))
        raise ContractError(f"{label} contains Core Metadata defects: {names}")
    raw_headers = list(message.raw_items())
    if not raw_headers or len(raw_headers) > _MAX_METADATA_HEADERS:
        raise ContractError(f"{label} has an invalid header count")
    critical_headers = {
        "metadata-version",
        "name",
        "version",
        "requires-dist",
        "requires-python",
    }
    for header_name, raw_value in raw_headers:
        if header_name.lower() in critical_headers and ("\n" in raw_value or "\r" in raw_value):
            raise ContractError(f"{label} may not fold {header_name} values")
    for header_name in message:
        for header in message.get_all(header_name, []):
            defects = getattr(header, "defects", ())
            if defects:
                names = ",".join(sorted(type(defect).__name__ for defect in defects))
                raise ContractError(
                    f"{label}.{header_name} contains Core Metadata defects: {names}"
                )
    metadata_version = _single_metadata_header(message, "Metadata-Version", label)
    if metadata_version not in _SUPPORTED_METADATA_VERSIONS:
        raise ContractError(f"{label} has unsupported Metadata-Version {metadata_version}")
    metadata_name = _normalize_name(
        _single_metadata_header(message, "Name", label), f"{label}.Name"
    )
    metadata_version_value = _version(
        _single_metadata_header(message, "Version", label),
        f"{label}.Version",
    )
    if metadata_name != expected_name or metadata_version_value != expected_version:
        raise ContractError(f"{label} normalized name or version differs from the distribution")
    requires_python_values = _metadata_header_values(message, "Requires-Python")
    if len(requires_python_values) > 1:
        raise ContractError(f"{label} must contain at most one Requires-Python header")
    requires_python = (
        None
        if not requires_python_values
        else _text(
            requires_python_values[0],
            f"{label}.Requires-Python",
            maximum=512,
        )
    )
    requirement_lines = [
        _text(value, f"{label}.Requires-Dist", maximum=512)
        for value in _metadata_header_values(message, "Requires-Dist")
    ]
    return requirement_lines, requires_python


def _parse_metadata(
    value: JsonValue,
    *,
    expected_name: str,
    expected_version: str,
    label: str,
) -> MetadataEvidence:
    metadata = _mapping(value, label)
    _keys(metadata, {"bytes_base64", "evidence_scope", "sha256"}, label)
    scope = _text(metadata["evidence_scope"], f"{label}.evidence_scope", maximum=64)
    if scope not in {
        "complete_synthetic_metadata",
        "complete_wheel_metadata",
        "historical_requirement_projection",
    }:
        raise ContractError(f"{label} evidence scope is unsupported")
    encoded = _text(metadata["bytes_base64"], f"{label}.bytes_base64", maximum=400_000)
    try:
        data = decode_bytes(encoded)
    except ContractError as error:
        raise ContractError(f"{label}.bytes_base64 is not canonical") from error
    if not data or len(data) > _MAX_METADATA_BYTES:
        raise ContractError(f"{label} has invalid byte length")
    if digest_bytes(data) != _sha256(metadata["sha256"], f"{label}.sha256"):
        raise ContractError(f"{label} digest mismatch")
    requirement_lines, requires_python = _parse_core_metadata(
        data,
        expected_name=expected_name,
        expected_version=expected_version,
        label=label,
    )
    requirements = tuple(
        _parse_requirement(requirement, f"{label}.Requires-Dist[{index}]")
        for index, requirement in enumerate(requirement_lines)
    )
    requirement_identities = [
        (
            requirement.name,
            requirement.extras,
            _specifier_identity(requirement.specifiers),
            _marker_identity(requirement.marker),
        )
        for requirement in requirements
    ]
    if len(requirement_identities) != len(set(requirement_identities)):
        raise ContractError(f"{label} Requires-Dist entries must be unique")
    requires_python_specifiers = (
        ()
        if requires_python is None
        else _parse_specifiers(
            requires_python,
            f"{label}.Requires-Python",
            required=True,
        )
    )
    if (
        scope in {"complete_synthetic_metadata", "complete_wheel_metadata"}
        and requires_python is None
    ):
        raise ContractError(f"{label} complete metadata requires Requires-Python")
    if scope != "complete_wheel_metadata":
        canonical = _metadata_bytes(
            expected_name,
            expected_version,
            requirement_lines,
            requires_python=requires_python,
        )
        if data != canonical:
            raise ContractError(f"{label} bytes are not canonical")
    return MetadataEvidence(
        scope,
        requirements,
        requires_python,
        requires_python_specifiers,
        data,
    )


def _parse_wheel_filename(filename: str) -> tuple[str, str, str, str, str]:
    if not filename.endswith(".whl"):
        raise ContractError("wheel filename must end in .whl")
    try:
        name_version, python_tag, abi_tag, platform_tag = filename[:-4].rsplit("-", 3)
        name_part, version = name_version.rsplit("-", 1)
    except ValueError as error:
        raise ContractError("wheel filename does not have the supported five-part form") from error
    name = _normalize_name(name_part, "wheel filename distribution")
    parsed_version = _version(version, "wheel filename version")
    tag = f"{python_tag}-{abi_tag}-{platform_tag}"
    if _WHEEL_TAG_PATTERN.fullmatch(tag) is None:
        raise ContractError("wheel filename contains unsupported tags")
    return name, parsed_version, python_tag, abi_tag, platform_tag


def _verify_target(
    value: JsonValue,
    *,
    candidate_kind: str,
) -> dict[str, JsonValue]:
    target = _mapping(value, "qualification_package.target_environment")
    fields = {
        "implementation_name",
        "macos_version",
        "os_name",
        "platform_machine",
        "platform_system",
        "python_abi",
        "python_full_version",
        "python_version",
        "sys_platform",
    }
    if candidate_kind == "reviewed_candidate":
        fields.add("runtime_target_anchor_id")
    _keys(target, fields, "qualification_package.target_environment")
    exact_text = {
        name: _text(
            target[name],
            f"target_environment.{name}",
            maximum=128 if name == "runtime_target_anchor_id" else 64,
        )
        for name in fields
    }
    if (
        exact_text["implementation_name"] != "cpython"
        or exact_text["os_name"] != "posix"
        or exact_text["platform_system"] != "Darwin"
        or exact_text["sys_platform"] != "darwin"
        or exact_text["platform_machine"] != "arm64"
    ):
        raise ContractError(
            "qualification target must be an explicit CPython macOS arm64 environment"
        )
    python_version = _version(exact_text["python_version"], "target_environment.python_version")
    full_version = _version(
        exact_text["python_full_version"],
        "target_environment.python_full_version",
    )
    if len(python_version.split(".")) != _MIN_RELEASE_COMPONENTS or not full_version.startswith(
        f"{python_version}."
    ):
        raise ContractError("target Python version fields disagree")
    expected_abi = f"cp{python_version.replace('.', '')}"
    if exact_text["python_abi"] != expected_abi:
        raise ContractError("target Python ABI differs from the target Python version")
    macos_version = _version(exact_text["macos_version"], "target_environment.macos_version")
    if len(macos_version.split(".")) < _MIN_RELEASE_COMPONENTS:
        raise ContractError("target macOS version must contain at least major and minor components")
    if candidate_kind == "reviewed_candidate":
        anchor_id = _sha256(
            target["runtime_target_anchor_id"],
            "target_environment.runtime_target_anchor_id",
        )
        if anchor_id != EXPECTED_RUNTIME_TARGET_ANCHOR_ID:
            raise ContractError("reviewed qualification target anchor identity drift")
        if canonical_json(target) != canonical_json(target_environment_binding()):
            raise ContractError("reviewed qualification target environment drift")
    return dict(target)


def _verify_source(
    value: JsonValue,
    *,
    candidate_kind: str,
    label: str,
) -> dict[str, JsonValue]:
    source = _mapping(value, label)
    _keys(
        source,
        {"provenance", "repository_url", "revision", "tag"},
        label,
    )
    provenance = _text(source["provenance"], f"{label}.provenance", maximum=64)
    expected_provenance = (
        "synthetic_revision_and_tag"
        if candidate_kind == "synthetic_fixture"
        else "reviewed_git_revision_and_tag"
    )
    if provenance != expected_provenance:
        raise ContractError(f"{label} provenance differs from the candidate kind")
    allowed_domains = (
        {_SYNTHETIC_DOMAIN} if candidate_kind == "synthetic_fixture" else _SOURCE_DOMAINS
    )
    _url(source["repository_url"], f"{label}.repository_url", allowed_domains=allowed_domains)
    revision = _text(source["revision"], f"{label}.revision", maximum=40)
    if _REVISION_PATTERN.fullmatch(revision) is None:
        raise ContractError(f"{label}.revision must be an exact lowercase 40-hex revision")
    tag = _text(source["tag"], f"{label}.tag", maximum=128)
    if _TAG_PATTERN.fullmatch(tag) is None:
        raise ContractError(f"{label}.tag is not a bounded immutable tag")
    return dict(source)


def _verify_wheel(
    value: JsonValue,
    *,
    candidate_kind: str,
    expected_name: str,
    expected_version: str,
    label: str,
) -> tuple[dict[str, JsonValue], bytes | None]:
    wheel = _mapping(value, label)
    fields = {
        "abi_tag",
        "bytes_base64",
        "filename",
        "platform_tag",
        "provenance",
        "python_tag",
        "sha256",
        "size_bytes",
        "url",
    }
    _keys(wheel, fields, label)
    filename = _text(wheel["filename"], f"{label}.filename", maximum=255)
    parsed_name, parsed_version, python_tag, abi_tag, platform_tag = _parse_wheel_filename(filename)
    if parsed_name != expected_name or parsed_version != expected_version:
        raise ContractError(f"{label} filename distribution or version drift")
    for field, expected in (
        ("python_tag", python_tag),
        ("abi_tag", abi_tag),
        ("platform_tag", platform_tag),
    ):
        if _text(wheel[field], f"{label}.{field}", maximum=128) != expected:
            raise ContractError(f"{label}.{field} differs from the exact filename")
    provenance = _text(wheel["provenance"], f"{label}.provenance", maximum=64)
    expected_provenance = (
        "synthetic_fixture_artifact"
        if candidate_kind == "synthetic_fixture"
        else "reviewed_pypi_artifact"
    )
    if provenance != expected_provenance:
        raise ContractError(f"{label} provenance differs from the candidate kind")
    allowed_domains = (
        {_SYNTHETIC_DOMAIN} if candidate_kind == "synthetic_fixture" else _PACKAGE_DOMAINS
    )
    _url(
        wheel["url"],
        f"{label}.url",
        allowed_domains=allowed_domains,
        expected_filename=filename,
    )
    size_bytes = _integer(wheel["size_bytes"], f"{label}.size_bytes", minimum=1)
    sha256 = _sha256(wheel["sha256"], f"{label}.sha256")
    encoded = wheel["bytes_base64"]
    if encoded is None:
        if candidate_kind != "historical_negative_projection":
            raise ContractError(f"{label} must supply exact wheel bytes")
        return dict(wheel), None
    if not isinstance(encoded, str) or not encoded:
        raise ContractError(f"{label}.bytes_base64 must be a non-empty string or null")
    try:
        wheel_bytes = decode_bytes(encoded)
    except ContractError as error:
        raise ContractError(f"{label}.bytes_base64 is not canonical") from error
    if not wheel_bytes or len(wheel_bytes) > _MAX_WHEEL_BYTES:
        raise ContractError(f"{label} wheel bytes exceed the supported bounds")
    if len(wheel_bytes) != size_bytes or digest_bytes(wheel_bytes) != sha256:
        raise ContractError(f"{label} wheel byte size or digest mismatch")
    exact_tag = f"{python_tag}-{abi_tag}-{platform_tag}"
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes)) as archive:
            entries = archive.infolist()
            if not entries or len(entries) > _MAX_WHEEL_ENTRIES:
                raise ContractError(f"{label} wheel archive entry count is invalid")
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)):
                raise ContractError(f"{label} wheel archive contains duplicate paths")
            for name in names:
                path = PurePosixPath(name)
                if (
                    "\\" in name
                    or path.is_absolute()
                    or not path.parts
                    or any(part in {"", ".", ".."} for part in path.parts)
                ):
                    raise ContractError(f"{label} wheel archive contains an unsafe path")
            metadata_entries = [
                entry for entry in entries if entry.filename.endswith(".dist-info/METADATA")
            ]
            wheel_entries = [
                entry for entry in entries if entry.filename.endswith(".dist-info/WHEEL")
            ]
            if len(metadata_entries) != 1 or len(wheel_entries) != 1:
                raise ContractError(
                    f"{label} wheel archive must contain one METADATA and one WHEEL"
                )
            metadata_entry = metadata_entries[0]
            wheel_entry = wheel_entries[0]
            if (
                metadata_entry.file_size > _MAX_METADATA_BYTES
                or wheel_entry.file_size > _MAX_METADATA_BYTES
            ):
                raise ContractError(f"{label} wheel metadata entries exceed bounds")
            metadata_prefix = metadata_entry.filename.removesuffix("/METADATA")
            wheel_prefix = wheel_entry.filename.removesuffix("/WHEEL")
            if metadata_prefix != wheel_prefix or not metadata_prefix.endswith(".dist-info"):
                raise ContractError(f"{label} wheel metadata directory mismatch")
            dist_info = PurePosixPath(metadata_prefix).name.removesuffix(".dist-info")
            try:
                dist_name, dist_version = dist_info.rsplit("-", 1)
            except ValueError as error:
                raise ContractError(f"{label} wheel metadata directory is malformed") from error
            if (
                _normalize_name(dist_name, f"{label}.dist_info_name") != expected_name
                or _version(dist_version, f"{label}.dist_info_version") != expected_version
            ):
                raise ContractError(f"{label} wheel metadata directory identity drift")
            embedded_metadata = archive.read(metadata_entry)
            wheel_control = archive.read(wheel_entry)
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ContractError(f"{label} wheel bytes are not a readable ZIP archive") from error
    try:
        wheel_text = wheel_control.decode("ascii")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} WHEEL metadata must be ASCII") from error
    tags = sorted(line[5:] for line in wheel_text.splitlines() if line.startswith("Tag: "))
    if tags != sorted(set(tags)) or exact_tag not in tags:
        raise ContractError(f"{label} WHEEL metadata does not bind the filename tag")
    return dict(wheel), embedded_metadata


def _verify_distribution(
    value: JsonValue,
    *,
    candidate_kind: str,
    index: int,
) -> tuple[dict[str, JsonValue], str, list[Requirement]]:
    label = f"qualification_package.distributions[{index}]"
    distribution = _mapping(value, label)
    _keys(
        distribution,
        {"metadata", "name", "role", "source", "version", "wheel"},
        label,
    )
    name = _normalize_name(distribution["name"], f"{label}.name")
    if distribution["name"] != name:
        raise ContractError(f"{label}.name must already be normalized")
    version = _version(distribution["version"], f"{label}.version")
    role = _text(distribution["role"], f"{label}.role", maximum=32)
    if role not in {"top_level", "transitive"}:
        raise ContractError(f"{label}.role is unsupported")
    expected_scope = {
        "historical_negative_projection": "historical_requirement_projection",
        "reviewed_candidate": "complete_wheel_metadata",
        "synthetic_fixture": "complete_synthetic_metadata",
    }[candidate_kind]
    declared_metadata = _mapping(distribution["metadata"], f"{label}.metadata")
    declared_scope = _text(
        declared_metadata.get("evidence_scope"),
        f"{label}.metadata.evidence_scope",
        maximum=64,
    )
    if declared_scope != expected_scope:
        raise ContractError(f"{label} metadata scope differs from the candidate kind")
    _verify_source(distribution["source"], candidate_kind=candidate_kind, label=f"{label}.source")
    _wheel_value, embedded_metadata = _verify_wheel(
        distribution["wheel"],
        candidate_kind=candidate_kind,
        expected_name=name,
        expected_version=version,
        label=f"{label}.wheel",
    )
    metadata_evidence = _parse_metadata(
        distribution["metadata"],
        expected_name=name,
        expected_version=version,
        label=f"{label}.metadata",
    )
    if embedded_metadata is not None and embedded_metadata != metadata_evidence.data:
        raise ContractError(f"{label} wheel METADATA bytes differ from the candidate metadata")
    if metadata_evidence.scope != expected_scope:
        raise ContractError(f"{label} metadata scope differs from the candidate kind")
    return dict(distribution), metadata_evidence.scope, list(metadata_evidence.requirements)


def _marker_environment(target: dict[str, JsonValue]) -> dict[str, str]:
    return {
        "implementation_name": cast("str", target["implementation_name"]),
        "os_name": cast("str", target["os_name"]),
        "platform_machine": cast("str", target["platform_machine"]),
        "platform_system": cast("str", target["platform_system"]),
        "python_full_version": cast("str", target["python_full_version"]),
        "python_version": cast("str", target["python_version"]),
        "sys_platform": cast("str", target["sys_platform"]),
        "extra": "",
    }


def _verify_synthetic_api_evidence(
    value: JsonValue,
    *,
    distributions: dict[str, dict[str, JsonValue]],
    index: int,
) -> dict[str, JsonValue]:
    label = f"qualification_package.worker_api_evidence[{index}]"
    evidence = _mapping(value, label)
    fields = {
        "distribution",
        "probe",
        "source_bytes_base64",
        "source_path",
        "source_revision",
        "source_sha256",
        "symbol",
        "symbol_token",
    }
    _keys(evidence, fields, label)
    probe = _text(evidence["probe"], f"{label}.probe", maximum=64)
    if probe not in _EXPECTED_API_EVIDENCE:
        raise ContractError(f"{label}.probe is not expected by the future preflight")
    expected_distribution, expected_symbol = _EXPECTED_API_EVIDENCE[probe]
    distribution = _normalize_name(evidence["distribution"], f"{label}.distribution")
    symbol = _text(evidence["symbol"], f"{label}.symbol", maximum=256)
    if distribution != expected_distribution or symbol != expected_symbol:
        raise ContractError(f"{label} probe-to-API mapping drift")
    if distribution not in distributions:
        raise ContractError(f"{label} references an unsupplied distribution")
    source = _mapping(distributions[distribution]["source"], f"{label}.distribution_source")
    revision = _text(evidence["source_revision"], f"{label}.source_revision", maximum=40)
    if revision != source["revision"]:
        raise ContractError(f"{label} source revision differs from the distribution")
    _relative_path(evidence["source_path"], f"{label}.source_path")
    encoded = _text(
        evidence["source_bytes_base64"],
        f"{label}.source_bytes_base64",
        maximum=400_000,
    )
    try:
        source_bytes = decode_bytes(encoded)
    except ContractError as error:
        raise ContractError(f"{label}.source_bytes_base64 is not canonical") from error
    if not source_bytes or len(source_bytes) > _MAX_SOURCE_BYTES:
        raise ContractError(f"{label} source evidence has invalid byte length")
    if digest_bytes(source_bytes) != _sha256(
        evidence["source_sha256"],
        f"{label}.source_sha256",
    ):
        raise ContractError(f"{label} source evidence digest mismatch")
    token = _text(evidence["symbol_token"], f"{label}.symbol_token", maximum=256)
    if token != expected_symbol:
        raise ContractError(f"{label}.symbol_token differs from the pinned probe symbol")
    token_bytes = token.encode("utf-8")
    if source_bytes.count(token_bytes) != 1:
        raise ContractError(f"{label} source evidence must contain the exact token once")
    return dict(evidence)


def _verify_reviewed_api_source(
    value: JsonValue,
    *,
    probe: str,
    index: int,
) -> tuple[dict[str, JsonValue], str]:
    label = f"qualification_package.worker_api_evidence.{probe}.sources[{index}]"
    source = _mapping(value, label)
    fields = {
        "excerpt_bytes_base64",
        "excerpt_end_line",
        "excerpt_sha256",
        "excerpt_start_line",
        "file_sha256",
        "path",
        "repository_url",
        "revision",
        "source_id",
        "tag",
    }
    _keys(source, fields, label)
    repository_url = _url(
        source["repository_url"],
        f"{label}.repository_url",
        allowed_domains=_SOURCE_DOMAINS,
    )
    path = _relative_path(source["path"], f"{label}.path")
    expected = _REVIEWED_API_SOURCE_FILES.get((repository_url, path))
    if expected is None:
        raise ContractError(f"{label} is not an accepted reviewed source file")
    expected_tag, expected_revision, expected_file_sha256 = expected
    tag = _text(source["tag"], f"{label}.tag", maximum=128)
    revision = _text(source["revision"], f"{label}.revision", maximum=40)
    file_sha256 = _sha256(source["file_sha256"], f"{label}.file_sha256")
    if tag != expected_tag or revision != expected_revision or file_sha256 != expected_file_sha256:
        raise ContractError(f"{label} tag, revision, or full-file hash drift")
    start_line = _integer(
        source["excerpt_start_line"],
        f"{label}.excerpt_start_line",
        minimum=1,
        maximum=1_000_000,
    )
    end_line = _integer(
        source["excerpt_end_line"],
        f"{label}.excerpt_end_line",
        minimum=start_line,
        maximum=1_000_000,
    )
    encoded = _text(
        source["excerpt_bytes_base64"],
        f"{label}.excerpt_bytes_base64",
        maximum=32_000,
    )
    try:
        excerpt_bytes = decode_bytes(encoded)
    except ContractError as error:
        raise ContractError(f"{label}.excerpt_bytes_base64 is not canonical") from error
    if not excerpt_bytes or len(excerpt_bytes) > _MAX_SOURCE_EXCERPT_BYTES:
        raise ContractError(f"{label} excerpt has invalid byte length")
    if digest_bytes(excerpt_bytes) != _sha256(
        source["excerpt_sha256"],
        f"{label}.excerpt_sha256",
    ):
        raise ContractError(f"{label} excerpt digest mismatch")
    try:
        excerpt = excerpt_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} excerpt must be UTF-8 source text") from error
    if len(excerpt.splitlines()) != end_line - start_line + 1:
        raise ContractError(f"{label} excerpt line bounds do not match its bytes")
    source_identity = _sha256(source["source_id"], f"{label}.source_id")
    source_content = dict(source)
    del source_content["source_id"]
    if source_identity != canonical_identity(source_content):
        raise ContractError(f"{label} source identity mismatch")
    return dict(source), excerpt


def _source_excerpt(
    sources: dict[tuple[str, str, int, int], str],
    *,
    repository_url: str,
    path: str,
    start_line: int,
    end_line: int,
    probe: str,
) -> str:
    key = (repository_url, path, start_line, end_line)
    try:
        return sources[key]
    except KeyError as error:
        raise ContractError(f"{probe} is missing its exact reviewed source excerpt") from error


def _require_exact_count(text: str, token: str, count: int, label: str) -> None:
    actual = text.count(token)
    if actual != count:
        raise ContractError(
            f"{label} must contain {token!r} exactly {count} time(s), found {actual}"
        )


def _is_name(node: ast.AST | None, identifier: str) -> bool:
    return isinstance(node, ast.Name) and node.id == identifier


def _verify_distribution_version_semantics(
    sources: dict[tuple[str, str, int, int], str],
) -> None:
    property_text = _source_excerpt(
        sources,
        repository_url=_CPYTHON_REPOSITORY,
        path="Lib/importlib/metadata/__init__.py",
        start_line=483,
        end_line=486,
        probe="distribution_versions",
    )
    function_text = _source_excerpt(
        sources,
        repository_url=_CPYTHON_REPOSITORY,
        path="Lib/importlib/metadata/__init__.py",
        start_line=980,
        end_line=987,
        probe="distribution_versions",
    )
    try:
        property_tree = ast.parse(textwrap.dedent(property_text))
        function_tree = ast.parse(textwrap.dedent(function_text))
    except SyntaxError as error:
        raise ContractError("distribution_versions evidence is not static Python source") from error
    property_functions = [node for node in property_tree.body if isinstance(node, ast.FunctionDef)]
    public_functions = [node for node in function_tree.body if isinstance(node, ast.FunctionDef)]
    if len(property_functions) != 1 or len(public_functions) != 1:
        raise ContractError("distribution_versions evidence has ambiguous duplicate definitions")
    property_function = property_functions[0]
    public_function = public_functions[0]
    if (
        property_function.name != "version"
        or len(property_function.decorator_list) != 1
        or not _is_name(property_function.decorator_list[0], "property")
        or len(property_function.args.args) != 1
        or property_function.args.args[0].arg != "self"
        or not _is_name(property_function.returns, "str")
        or public_function.name != "version"
        or len(public_function.args.args) != 1
        or public_function.args.args[0].arg != "distribution_name"
        or not _is_name(public_function.args.args[0].annotation, "str")
        or not _is_name(public_function.returns, "str")
    ):
        raise ContractError("distribution_versions static signature drift")
    property_returns = [
        node for node in ast.walk(property_function) if isinstance(node, ast.Return)
    ]
    public_returns = [node for node in ast.walk(public_function) if isinstance(node, ast.Return)]
    if len(property_returns) != 1 or len(public_returns) != 1:
        raise ContractError("distribution_versions return path is ambiguous")
    property_value = property_returns[0].value
    if not (
        isinstance(property_value, ast.Subscript)
        and isinstance(property_value.value, ast.Attribute)
        and _is_name(property_value.value.value, "self")
        and property_value.value.attr == "metadata"
        and isinstance(property_value.slice, ast.Constant)
        and property_value.slice.value == "Version"
    ):
        raise ContractError("distribution_versions no longer reads the METADATA Version field")
    public_value = public_returns[0].value
    if not (
        isinstance(public_value, ast.Attribute)
        and public_value.attr == "version"
        and isinstance(public_value.value, ast.Call)
        and _is_name(public_value.value.func, "distribution")
        and len(public_value.value.args) == 1
        and _is_name(public_value.value.args[0], "distribution_name")
        and not public_value.value.keywords
    ):
        raise ContractError("distribution_versions public lookup mechanism drift")


def _verify_import_mlx_semantics(
    sources: dict[tuple[str, str, int, int], str],
) -> None:
    setup_text = _source_excerpt(
        sources,
        repository_url=_MLX_REPOSITORY,
        path="setup.py",
        start_line=207,
        end_line=226,
        probe="import_mlx",
    )
    module_text = _source_excerpt(
        sources,
        repository_url=_MLX_REPOSITORY,
        path="python/src/mlx.cpp",
        start_line=27,
        end_line=46,
        probe="import_mlx",
    )
    try:
        setup_tree = ast.parse(textwrap.dedent(setup_text))
    except SyntaxError as error:
        raise ContractError("import_mlx setup evidence is not static Python source") from error
    ext_keywords = [
        keyword
        for node in ast.walk(setup_tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "ext_modules"
    ]
    if len(ext_keywords) != 1 or not isinstance(ext_keywords[0].value, ast.List):
        raise ContractError("import_mlx extension declaration is missing or ambiguous")
    elements = ext_keywords[0].value.elts
    if len(elements) != 1 or not isinstance(elements[0], ast.Call):
        raise ContractError("import_mlx extension declaration must be one literal call")
    extension_call = elements[0]
    if not (
        _is_name(extension_call.func, "CMakeExtension")
        and len(extension_call.args) == 1
        and isinstance(extension_call.args[0], ast.Constant)
        and extension_call.args[0].value == "mlx.core"
        and not extension_call.keywords
    ):
        raise ContractError("import_mlx extension module name is dynamic or has drifted")
    _require_exact_count(module_text, "NB_MODULE(core, m)", 1, "import_mlx module declaration")
    if "NB_MODULE(" in module_text.replace("NB_MODULE(core, m)", ""):
        raise ContractError("import_mlx module declaration is ambiguous")


def _verify_import_mlx_lm_semantics(
    sources: dict[tuple[str, str, int, int], str],
) -> None:
    setup_text = _source_excerpt(
        sources,
        repository_url=_MLX_LM_REPOSITORY,
        path="setup.py",
        start_line=35,
        end_line=42,
        probe="import_mlx_lm",
    )
    init_text = _source_excerpt(
        sources,
        repository_url=_MLX_LM_REPOSITORY,
        path="mlx_lm/__init__.py",
        start_line=1,
        end_line=20,
        probe="import_mlx_lm",
    )
    try:
        setup_tree = ast.parse(f"setup(\n{textwrap.dedent(setup_text)})\n")
        init_tree = ast.parse(init_text)
    except SyntaxError as error:
        raise ContractError("import_mlx_lm evidence is not static Python source") from error
    package_keywords = [
        keyword
        for node in ast.walk(setup_tree)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
        if keyword.arg == "packages"
    ]
    if len(package_keywords) != 1 or not isinstance(package_keywords[0].value, ast.List):
        raise ContractError("import_mlx_lm package declaration is missing or ambiguous")
    package_names: list[str] = []
    for item in package_keywords[0].value.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            raise ContractError("import_mlx_lm package declaration uses dynamic generation")
        package_names.append(item.value)
    if package_names.count("mlx_lm") != 1:
        raise ContractError("import_mlx_lm package name is missing or ambiguous")
    forbidden_dynamic_names = {"__import__", "eval", "exec"}
    for node in ast.walk(init_tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "__getattr__":
            raise ContractError(
                "import_mlx_lm package uses unsupported dynamic attribute generation"
            )
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in forbidden_dynamic_names)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
        ):
            raise ContractError("import_mlx_lm package uses unsupported dynamic import generation")


def _verify_reviewed_api_semantics(
    probe: str,
    sources: dict[tuple[str, str, int, int], str],
) -> None:
    if probe == "distribution_versions":
        _verify_distribution_version_semantics(sources)
        return
    if probe == "import_mlx":
        _verify_import_mlx_semantics(sources)
        return
    if probe == "import_mlx_lm":
        _verify_import_mlx_lm_semantics(sources)
        return
    source_text = "\n".join(sources.values())
    if probe == "default_device":
        _require_exact_count(source_text, '"default_device"', 1, probe)
        _require_exact_count(source_text, "&mx::default_device", 1, probe)
        _require_exact_count(source_text, "MLX_API const Device& default_device();", 1, probe)
    elif probe == "default_stream":
        _require_exact_count(source_text, '"default_stream"', 1, probe)
        _require_exact_count(source_text, "&mx::default_stream", 1, probe)
        _require_exact_count(source_text, '"device"_a', 1, probe)
        _require_exact_count(source_text, "MLX_API Stream default_stream(Device d);", 1, probe)
    elif probe == "metal_is_available":
        _require_exact_count(source_text, 'm.def_submodule("metal"', 1, probe)
        _require_exact_count(source_text, '"is_available"', 1, probe)
        _require_exact_count(source_text, "&mx::metal::is_available", 1, probe)
        _require_exact_count(source_text, "MLX_API bool is_available();", 1, probe)
    elif probe == "synchronize":
        _require_exact_count(source_text, '"synchronize"', 1, probe)
        _require_exact_count(source_text, "std::optional<mx::Stream>", 1, probe)
        _require_exact_count(source_text, '"stream"_a = nb::none()', 1, probe)
        _require_exact_count(source_text, "MLX_API void synchronize();", 1, probe)
        _require_exact_count(source_text, "MLX_API void synchronize(Stream);", 1, probe)
        _require_exact_count(
            source_text,
            "s ? mx::synchronize(s.value()) : mx::synchronize();",
            1,
            probe,
        )
    else:
        raise ContractError(f"unsupported reviewed API evidence probe {probe}")


def _verify_reviewed_api_evidence(
    value: JsonValue,
    *,
    distributions: dict[str, dict[str, JsonValue]],
    index: int,
) -> dict[str, JsonValue]:
    label = f"qualification_package.worker_api_evidence[{index}]"
    evidence = _mapping(value, label)
    fields = {
        "access_form",
        "callable",
        "claim_scope",
        "distribution",
        "does_not_prove",
        "evidence_id",
        "module",
        "probe",
        "sources",
        "static_signature",
        "surface_kind",
        "symbol",
    }
    _keys(evidence, fields, label)
    probe = _text(evidence["probe"], f"{label}.probe", maximum=64)
    if probe not in _EXPECTED_API_EVIDENCE:
        raise ContractError(f"{label}.probe is not expected by the future preflight")
    expected_distribution, expected_symbol = _EXPECTED_API_EVIDENCE[probe]
    distribution = _normalize_name(evidence["distribution"], f"{label}.distribution")
    if distribution not in distributions:
        raise ContractError(f"{label} references an unsupplied distribution")
    if distribution != expected_distribution or evidence["symbol"] != expected_symbol:
        raise ContractError(f"{label} probe-to-API mapping drift")
    expected_semantics = _EXPECTED_API_SEMANTICS[probe]
    for field in ("access_form", "module", "static_signature", "surface_kind"):
        _text(evidence[field], f"{label}.{field}", maximum=256)
        if evidence[field] != expected_semantics[field]:
            raise ContractError(f"{label}.{field} semantic claim drift")
    callable_value = _boolean(evidence["callable"], f"{label}.callable")
    if callable_value is not expected_semantics["callable"]:
        raise ContractError(f"{label}.callable semantic claim drift")
    if evidence["claim_scope"] != "source_surface_availability_only":
        raise ContractError(f"{label} claim exceeds source-surface evidence")
    does_not_prove = _array(
        evidence["does_not_prove"],
        f"{label}.does_not_prove",
        maximum=len(_API_EVIDENCE_DOES_NOT_PROVE),
    )
    if canonical_json(does_not_prove) != canonical_json(_API_EVIDENCE_DOES_NOT_PROVE):
        raise ContractError(f"{label}.does_not_prove attempts to expand the evidence claim")
    source_values = _array(evidence["sources"], f"{label}.sources", maximum=4)
    sources: dict[tuple[str, str, int, int], str] = {}
    actual_ranges: list[tuple[str, str, int, int]] = []
    previous_order: tuple[str, str, int, int] | None = None
    for source_index, source_value in enumerate(source_values):
        source, excerpt = _verify_reviewed_api_source(
            source_value,
            probe=probe,
            index=source_index,
        )
        key = (
            cast("str", source["repository_url"]),
            cast("str", source["path"]),
            cast("int", source["excerpt_start_line"]),
            cast("int", source["excerpt_end_line"]),
        )
        if previous_order is not None and key <= previous_order:
            raise ContractError(f"{label}.sources must be unique and canonically sorted")
        previous_order = key
        sources[key] = excerpt
        actual_ranges.append(key)
    if tuple(actual_ranges) != _REVIEWED_API_SOURCE_RANGES[probe]:
        raise ContractError(f"{label}.sources path or line-range drift")
    distribution_source = _mapping(
        distributions[distribution]["source"],
        f"{label}.distribution_source",
    )
    candidate_source_keys = [
        key for key in sources if key[0] == distribution_source["repository_url"]
    ]
    if probe != "distribution_versions" and not candidate_source_keys:
        raise ContractError(f"{label} is not bound to the candidate distribution source")
    if any(
        _REVIEWED_API_SOURCE_FILES[(repository_url, path)][:2]
        != (distribution_source["tag"], distribution_source["revision"])
        for repository_url, path, _start_line, _end_line in candidate_source_keys
    ):
        raise ContractError(f"{label} differs from the candidate distribution tag or revision")
    _verify_reviewed_api_semantics(probe, sources)
    evidence_identity = _sha256(evidence["evidence_id"], f"{label}.evidence_id")
    evidence_content = dict(evidence)
    del evidence_content["evidence_id"]
    if evidence_identity != canonical_identity(evidence_content):
        raise ContractError(f"{label} evidence identity mismatch")
    return dict(evidence)


def _verify_api_evidence(
    value: JsonValue,
    *,
    candidate_kind: str,
    distributions: dict[str, dict[str, JsonValue]],
    index: int,
) -> dict[str, JsonValue]:
    if candidate_kind == "reviewed_candidate":
        return _verify_reviewed_api_evidence(
            value,
            distributions=distributions,
            index=index,
        )
    return _verify_synthetic_api_evidence(
        value,
        distributions=distributions,
        index=index,
    )


def _verify_fixed_claims(value: JsonValue) -> None:
    claims = _mapping(value, "qualification_package.claims")
    _keys(claims, set(_CLAIMS), "qualification_package.claims")
    if canonical_json(claims) != canonical_json(_CLAIMS):
        raise ContractError("qualification package attempts to expand static claim scope")


def _verify_zero_actions(value: JsonValue, label: str) -> None:
    counters = _mapping(value, label)
    _keys(counters, set(_ZERO_ACTION_COUNTERS), label)
    for name in sorted(_ZERO_ACTION_COUNTERS):
        if _integer(counters[name], f"{label}.{name}") != 0:
            raise ContractError(f"{label}.{name} must remain zero")


def verify_qualification_package(value: JsonValue) -> dict[str, JsonValue]:
    """Strictly verify one static candidate package without environment action."""
    package = _mapping(value, "mlx_runtime_qualification_package")
    fields = {
        "candidate_kind",
        "candidate_name",
        "claims",
        "distributions",
        "extras_policy",
        "frozen_schema_1_0_negative",
        "package_id",
        "qualification_spec_id",
        "record_type",
        "schema_version",
        "static_action_counters",
        "target_environment",
        "top_level_requirements",
        "worker_api_evidence",
        "worker_api_evidence_anchor_id",
        "worker_api_evidence_spec_id",
    }
    _keys(package, fields, "mlx_runtime_qualification_package")
    candidate_kind = _text(package["candidate_kind"], "qualification_package.candidate_kind")
    if (
        package["record_type"] != "mlx_runtime_qualification_package"
        or package["schema_version"] != SCHEMA_VERSION
        or candidate_kind
        not in {"historical_negative_projection", "reviewed_candidate", "synthetic_fixture"}
    ):
        raise ContractError("unsupported MLX runtime qualification package")
    if package["qualification_spec_id"] != qualification_spec()["spec_id"]:
        raise ContractError("qualification package specification identity mismatch")
    _text(package["candidate_name"], "qualification_package.candidate_name", maximum=128)
    target = _verify_target(
        package["target_environment"],
        candidate_kind=candidate_kind,
    )
    extras = _mapping(package["extras_policy"], "qualification_package.extras_policy")
    _keys(extras, {"mode", "requested"}, "qualification_package.extras_policy")
    if extras["mode"] != "forbid_all_extras" or extras["requested"] != []:
        raise ContractError("qualification package extras policy must forbid every extra")
    top_level = [
        _parse_requirement(item, f"qualification_package.top_level_requirements[{index}]")
        for index, item in enumerate(
            _array(
                package["top_level_requirements"],
                "qualification_package.top_level_requirements",
                maximum=16,
            )
        )
    ]
    top_names = [requirement.name for requirement in top_level]
    if top_names != sorted(set(top_names)):
        raise ContractError("top-level requirement names must be unique and sorted")
    for requirement in top_level:
        if requirement.extras or requirement.marker is not None:
            raise ContractError("top-level requirements may not contain extras or markers")
    distributions: dict[str, dict[str, JsonValue]] = {}
    metadata: dict[str, tuple[str, list[Requirement]]] = {}
    distribution_values = _array(
        package["distributions"],
        "qualification_package.distributions",
        maximum=256,
    )
    for index, item in enumerate(distribution_values):
        distribution, scope, requirements = _verify_distribution(
            item,
            candidate_kind=candidate_kind,
            index=index,
        )
        name = cast("str", distribution["name"])
        if name in distributions:
            raise ContractError("qualification package distribution names must be unique")
        distributions[name] = distribution
        metadata[name] = (scope, requirements)
    if list(distributions) != sorted(distributions):
        raise ContractError("qualification package distributions must be sorted by name")
    api_evidence: dict[str, dict[str, JsonValue]] = {}
    for index, item in enumerate(
        _array(
            package["worker_api_evidence"],
            "qualification_package.worker_api_evidence",
            maximum=len(_EXPECTED_API_EVIDENCE),
        )
    ):
        evidence = _verify_api_evidence(
            item,
            candidate_kind=candidate_kind,
            distributions=distributions,
            index=index,
        )
        probe = cast("str", evidence["probe"])
        if probe in api_evidence:
            raise ContractError("worker API evidence probes must be unique")
        api_evidence[probe] = evidence
    if list(api_evidence) != sorted(api_evidence):
        raise ContractError("worker API evidence must be sorted by probe")
    if package["worker_api_evidence_spec_id"] != worker_api_evidence_spec()["spec_id"]:
        raise ContractError("worker API evidence specification identity mismatch")
    api_evidence_anchor = _sha256(
        package["worker_api_evidence_anchor_id"],
        "qualification_package.worker_api_evidence_anchor_id",
    )
    if api_evidence_anchor != canonical_identity(package["worker_api_evidence"]):
        raise ContractError("worker API evidence anchor identity mismatch")
    reviewed_api_anchors = cast(
        "list[JsonValue]",
        worker_api_evidence_spec()["reviewed_evidence_anchors"],
    )
    if candidate_kind == "reviewed_candidate" and api_evidence_anchor not in reviewed_api_anchors:
        raise ContractError("worker API evidence anchor was not independently reviewed")
    if canonical_json(package["frozen_schema_1_0_negative"]) != canonical_json(
        _frozen_negative_relationship()
    ):
        raise ContractError("frozen schema-1.0 negative relationship drift")
    _verify_fixed_claims(package["claims"])
    _verify_zero_actions(
        package["static_action_counters"],
        "qualification_package.static_action_counters",
    )
    identity = _sha256(package["package_id"], "qualification_package.package_id")
    content = dict(package)
    del content["package_id"]
    if identity != canonical_identity(content):
        raise ContractError("qualification package identity mismatch")
    _marker_environment(target)
    return dict(package)


def load_qualification_package(path: Path) -> dict[str, JsonValue]:
    """Load one canonical static candidate package."""
    return verify_qualification_package(
        load_canonical_json_file(path, "MLX runtime qualification package")
    )


def _wheel_compatibility(
    wheel: dict[str, JsonValue],
    target: dict[str, JsonValue],
) -> tuple[bool, str]:
    python_tag = cast("str", wheel["python_tag"])
    abi_tag = cast("str", wheel["abi_tag"])
    platform_tag = cast("str", wheel["platform_tag"])
    exact_tag = f"{python_tag}-{abi_tag}-{platform_tag}"
    target_abi = cast("str", target["python_abi"])
    if (python_tag == "py3" and abi_tag == "none") or (
        python_tag == target_abi and abi_tag == target_abi
    ):
        python_compatible = True
    elif python_tag.startswith("cp") and abi_tag == "abi3":
        wheel_python = _CPYTHON_TAG_PATTERN.fullmatch(python_tag)
        target_python = _CPYTHON_TAG_PATTERN.fullmatch(target_abi)
        python_compatible = (
            wheel_python is not None
            and target_python is not None
            and wheel_python.group("major") == target_python.group("major")
            and int(wheel_python.group("minor")) <= int(target_python.group("minor"))
        )
    else:
        python_compatible = False
    if platform_tag == "any":
        platform_compatible = True
    else:
        platform_match = _MACOS_PLATFORM_PATTERN.fullmatch(platform_tag)
        if platform_match is None:
            platform_compatible = False
        else:
            minimum = (
                int(platform_match.group("major")),
                int(platform_match.group("minor")),
            )
            target_version = tuple(
                int(component) for component in cast("str", target["macos_version"]).split(".")
            )
            arch = platform_match.group("arch")
            platform_compatible = minimum <= target_version and arch in {
                cast("str", target["platform_machine"]),
                "universal2",
            }
    compatible = python_compatible and platform_compatible
    return (
        compatible,
        f"wheel tag {exact_tag} is "
        f"{'compatible' if compatible else 'incompatible'} with target "
        f"{target_abi}/{target['macos_version']}/{target['platform_machine']}",
    )


def _requirement_assessment(
    requesting_distribution: str,
    requirement: Requirement,
    *,
    selected: dict[str, dict[str, JsonValue]],
    environment: dict[str, str],
) -> tuple[dict[str, JsonValue], str | None, str | None]:
    if requirement.marker is None:
        applicable = True
        marker_explanation = "requirement has no environment marker"
    else:
        applicable, marker_explanation = _evaluate_marker(requirement.marker, environment)
    selected_distribution = selected.get(requirement.name)
    selected_value: JsonValue = (
        None
        if selected_distribution is None
        else f"{requirement.name}=={selected_distribution['version']}"
    )
    blocker: str | None = None
    edge: str | None = requirement.name if applicable else None
    if not applicable:
        status = "inapplicable"
        satisfied = True
        explanation = "environment marker is false; no dependency is selected"
    elif requirement.extras:
        status = "unsatisfied"
        satisfied = False
        extras = ",".join(requirement.extras)
        explanation = f"requested dependency extras [{extras}] are forbidden by policy"
        blocker = f"dependency_extras_forbidden:{requesting_distribution}:{requirement.raw}"
    elif selected_distribution is None:
        status = "unsatisfied"
        satisfied = False
        explanation = "applicable dependency is absent from the supplied distribution closure"
        blocker = f"dependency_missing:{requesting_distribution}:{requirement.raw}"
    else:
        selected_version = cast("str", selected_distribution["version"])
        satisfied = _satisfies(selected_version, requirement.specifiers)
        status = "satisfied" if satisfied else "unsatisfied"
        explanation = (
            f"selected {requirement.name}=={selected_version} "
            f"{'satisfies' if satisfied else 'does not satisfy'} "
            f"{requirement.raw}"
        )
        if not satisfied:
            blocker = (
                f"dependency_unsatisfied:{requesting_distribution}:{requirement.raw}:"
                f"selected={requirement.name}=={selected_version}"
            )
    assessment: dict[str, JsonValue] = {
        "applicable": applicable,
        "explanation": explanation,
        "marker_explanation": marker_explanation,
        "requesting_distribution": requesting_distribution,
        "requirement": requirement.raw,
        "satisfied": satisfied,
        "selected_distribution": selected_value,
        "status": status,
    }
    return assessment, blocker, edge


def _qualification_assessment(package: dict[str, JsonValue]) -> dict[str, JsonValue]:
    target = _mapping(package["target_environment"], "qualification target")
    environment = _marker_environment(target)
    distributions = {
        cast("str", _mapping(item, "qualification distribution")["name"]): _mapping(
            item,
            "qualification distribution",
        )
        for item in cast("list[JsonValue]", package["distributions"])
    }
    blockers: list[str] = []
    candidate_kind = cast("str", package["candidate_kind"])
    if candidate_kind == "historical_negative_projection":
        blockers.append("historical_negative_projection_is_never_eligible")
    review_anchor_projection: dict[str, JsonValue] = {
        "candidate_name": package["candidate_name"],
        "target_environment": package["target_environment"],
        "distributions": [
            {
                "name": _mapping(item, "qualification distribution")["name"],
                "version": _mapping(item, "qualification distribution")["version"],
                "source": _mapping(item, "qualification distribution")["source"],
                "wheel": {
                    key: value
                    for key, value in _mapping(
                        _mapping(item, "qualification distribution")["wheel"],
                        "qualification wheel",
                    ).items()
                    if key != "bytes_base64"
                },
                "metadata": {
                    key: value
                    for key, value in _mapping(
                        _mapping(item, "qualification distribution")["metadata"],
                        "qualification metadata",
                    ).items()
                    if key != "bytes_base64"
                },
            }
            for item in cast("list[JsonValue]", package["distributions"])
        ],
        "worker_api_evidence": [
            {
                key: value
                for key, value in _mapping(item, "worker API evidence").items()
                if key != "source_bytes_base64"
            }
            for item in cast("list[JsonValue]", package["worker_api_evidence"])
        ],
        "worker_api_evidence_anchor_id": package["worker_api_evidence_anchor_id"],
        "worker_api_evidence_spec_id": package["worker_api_evidence_spec_id"],
    }
    review_anchor_id = canonical_identity(review_anchor_projection)
    reviewed_anchors = cast(
        "list[JsonValue]",
        qualification_spec()["reviewed_candidate_anchors"],
    )
    if candidate_kind == "reviewed_candidate" and review_anchor_id not in reviewed_anchors:
        blockers.append(f"reviewed_candidate_not_committed_in_spec:{review_anchor_id}")
    top_requirements = [
        _parse_requirement(item, "top-level requirement")
        for item in cast("list[JsonValue]", package["top_level_requirements"])
    ]
    top_names = [requirement.name for requirement in top_requirements]
    required_roots = ["mlx", "mlx-lm"]
    blockers.extend(
        f"missing_top_level_requirement:{root}" for root in required_roots if root not in top_names
    )
    blockers.extend(
        f"unexpected_top_level_requirement:{name}"
        for name in top_names
        if name not in required_roots
    )
    top_level_assessments: list[JsonValue] = []
    for requirement in top_requirements:
        selected_distribution = distributions.get(requirement.name)
        if requirement.name in required_roots and (
            selected_distribution is None
            or requirement.specifiers != (("==", cast("str", selected_distribution["version"])),)
        ):
            selected_pin = (
                "missing"
                if selected_distribution is None
                else f"{requirement.name}=={selected_distribution['version']}"
            )
            blockers.append(
                f"top_level_requirement_not_exact_pin:{requirement.raw}:selected={selected_pin}"
            )
        assessment, blocker, _edge = _requirement_assessment(
            "top-level",
            requirement,
            selected=distributions,
            environment=environment,
        )
        top_level_assessments.append(assessment)
        if blocker is not None:
            blockers.append(blocker)
    dependency_assessments: list[JsonValue] = []
    edges: dict[str, list[str]] = {name: [] for name in distributions}
    metadata_scopes: list[JsonValue] = []
    requires_python_assessments: list[JsonValue] = []
    wheel_assessments: list[JsonValue] = []
    for name, distribution in distributions.items():
        role = cast("str", distribution["role"])
        expected_role = "top_level" if name in top_names else "transitive"
        if role != expected_role:
            blockers.append(f"distribution_role_mismatch:{name}:expected={expected_role}")
        metadata = _mapping(distribution["metadata"], f"{name} metadata")
        metadata_evidence = _parse_metadata(
            metadata,
            expected_name=name,
            expected_version=cast("str", distribution["version"]),
            label=f"{name}.metadata",
        )
        scope = metadata_evidence.scope
        requirements = metadata_evidence.requirements
        complete = scope in {"complete_synthetic_metadata", "complete_wheel_metadata"}
        metadata_scopes.append(
            {
                "complete_for_supplied_closure": complete,
                "distribution": name,
                "evidence_scope": scope,
            }
        )
        if not complete:
            blockers.append(f"incomplete_metadata_evidence:{name}:{scope}")
        requires_python = metadata_evidence.requires_python
        if requires_python is None:
            requires_python_assessments.append(
                {
                    "distribution": name,
                    "explanation": "Requires-Python is absent from incomplete metadata evidence",
                    "requires_python": None,
                    "satisfied": not complete,
                    "selected_python": target["python_full_version"],
                    "status": "missing" if complete else "not_supplied_in_incomplete_projection",
                }
            )
            if complete:
                blockers.append(f"requires_python_missing:{name}")
        else:
            selected_python = cast("str", target["python_full_version"])
            python_satisfied = _satisfies(
                selected_python,
                metadata_evidence.requires_python_specifiers,
            )
            requires_python_assessments.append(
                {
                    "distribution": name,
                    "explanation": (
                        f"target Python {selected_python} "
                        f"{'satisfies' if python_satisfied else 'does not satisfy'} "
                        f"Requires-Python {requires_python}"
                    ),
                    "requires_python": requires_python,
                    "satisfied": python_satisfied,
                    "selected_python": selected_python,
                    "status": "satisfied" if python_satisfied else "unsatisfied",
                }
            )
            if not python_satisfied:
                blockers.append(
                    f"requires_python_unsatisfied:{name}:{requires_python}:"
                    f"selected={selected_python}"
                )
        wheel = _mapping(distribution["wheel"], f"{name} wheel")
        if wheel["bytes_base64"] is None:
            blockers.append(f"wheel_bytes_not_supplied:{name}")
        compatible, explanation = _wheel_compatibility(wheel, target)
        tag = f"{wheel['python_tag']}-{wheel['abi_tag']}-{wheel['platform_tag']}"
        wheel_assessments.append(
            {
                "compatible": compatible,
                "distribution": name,
                "explanation": explanation,
                "tag": tag,
            }
        )
        if not compatible:
            blockers.append(f"wheel_tag_incompatible:{name}:{tag}")
        for requirement in requirements:
            assessment, blocker, edge = _requirement_assessment(
                name,
                requirement,
                selected=distributions,
                environment=environment,
            )
            dependency_assessments.append(assessment)
            if blocker is not None:
                blockers.append(blocker)
            if edge is not None:
                edges[name].append(edge)
    reachable: set[str] = set()
    pending = list(required_roots)
    while pending:
        name = pending.pop()
        if name in reachable or name not in distributions:
            continue
        reachable.add(name)
        pending.extend(edges[name])
    supplied = sorted(distributions)
    missing_roots = sorted(set(required_roots) - set(distributions))
    blockers.extend(f"missing_required_distribution:{name}" for name in missing_roots)
    unreachable = sorted(set(supplied) - reachable)
    blockers.extend(f"unreachable_supplied_distribution:{name}" for name in unreachable)
    evidence_by_probe = {
        cast("str", _mapping(item, "worker API evidence")["probe"]): _mapping(
            item,
            "worker API evidence",
        )
        for item in cast("list[JsonValue]", package["worker_api_evidence"])
    }
    api_assessments: list[JsonValue] = []
    for probe, (api_distribution, symbol) in sorted(_EXPECTED_API_EVIDENCE.items()):
        present = probe in evidence_by_probe
        api_assessment: dict[str, JsonValue] = {
            "distribution": api_distribution,
            "evidence_present": present,
            "probe": probe,
            "symbol": symbol,
        }
        if present:
            evidence = evidence_by_probe[probe]
            api_assessment.update(
                {
                    "access_form": evidence.get("access_form"),
                    "claim_scope": evidence.get(
                        "claim_scope",
                        "synthetic_static_contract_fixture",
                    ),
                    "evidence_id": evidence.get("evidence_id"),
                    "static_signature": evidence.get("static_signature"),
                }
            )
        api_assessments.append(api_assessment)
        if not present:
            blockers.append(f"missing_worker_api_evidence:{probe}:{api_distribution}:{symbol}")
    sorted_blockers = sorted(set(blockers))
    decision = ELIGIBLE if not sorted_blockers else INELIGIBLE
    graph: list[JsonValue] = [
        {
            "dependencies": cast("list[JsonValue]", sorted(set(edges[name]))),
            "distribution": name,
        }
        for name in sorted(edges)
    ]
    return {
        "authorization_state": {
            "authorization_created": False,
            "authorization_consumed": False,
            "permission_to_execute": False,
        },
        "blockers": cast("list[JsonValue]", sorted_blockers),
        "closure": {
            "applicable_dependency_graph": graph,
            "missing_required_distributions": cast("list[JsonValue]", missing_roots),
            "native_loader_semantic_completeness_claimed": False,
            "reachable_distributions": cast("list[JsonValue]", sorted(reachable)),
            "required_roots": cast("list[JsonValue]", required_roots),
            "standard_library_semantic_completeness_claimed": False,
            "supplied_distributions": cast("list[JsonValue]", supplied),
            "unreachable_supplied_distributions": cast("list[JsonValue]", unreachable),
        },
        "decision": decision,
        "dependency_assessments": sorted(
            dependency_assessments,
            key=lambda item: (
                cast("str", _mapping(item, "dependency assessment")["requesting_distribution"]),
                cast("str", _mapping(item, "dependency assessment")["requirement"]),
            ),
        ),
        "eligibility_scope": (
            "human_review_for_new_schema_1_1_observed_authorization_only"
            if decision == ELIGIBLE
            else "not_eligible_for_new_observed_authorization"
        ),
        "metadata_assessments": metadata_scopes,
        "next_required_step": (
            "distinct_schema_1_1_protocol_spec_worker_review_and_fresh_explicit_authorization"
        ),
        "review_anchor_id": review_anchor_id,
        "requires_python_assessments": requires_python_assessments,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
        "top_level_assessments": top_level_assessments,
        "wheel_assessments": wheel_assessments,
        "worker_api_assessments": api_assessments,
    }


def build_qualification_record(package_value: JsonValue) -> dict[str, JsonValue]:
    """Build the sole deterministic static decision for one candidate package."""
    package = verify_qualification_package(package_value)
    assessment = _qualification_assessment(package)
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_qualification_record",
        "schema_version": SCHEMA_VERSION,
        "qualification_spec_id": qualification_spec()["spec_id"],
        "qualification_package": package,
        "qualification_package_id": package["package_id"],
        "assessment": assessment,
        "decision": assessment["decision"],
        "blockers": assessment["blockers"],
        "eligibility_meaning": (
            "eligible_only_for_human_review_and_possible_new_explicit_observed_authorization"
        ),
        "schema_1_0_remains_permanently_disabled": True,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    record["record_id"] = canonical_identity(record)
    return record


def verify_qualification_record(value: JsonValue) -> dict[str, JsonValue]:
    """Reject forged decisions, blockers, counters, and coordinated rehashing."""
    record = _mapping(value, "mlx_runtime_qualification_record")
    fields = {
        "assessment",
        "blockers",
        "decision",
        "eligibility_meaning",
        "qualification_package",
        "qualification_package_id",
        "qualification_spec_id",
        "record_id",
        "record_type",
        "schema_1_0_remains_permanently_disabled",
        "schema_version",
        "static_action_counters",
    }
    _keys(record, fields, "mlx_runtime_qualification_record")
    if (
        record["record_type"] != "mlx_runtime_qualification_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["qualification_spec_id"] != qualification_spec()["spec_id"]
        or record["schema_1_0_remains_permanently_disabled"] is not True
    ):
        raise ContractError("unsupported MLX runtime qualification record")
    if record["decision"] not in {ELIGIBLE, INELIGIBLE}:
        raise ContractError("qualification record has an unsupported decision")
    _verify_zero_actions(
        record["static_action_counters"],
        "qualification_record.static_action_counters",
    )
    package = verify_qualification_package(record["qualification_package"])
    if record["qualification_package_id"] != package["package_id"]:
        raise ContractError("qualification record package identity mismatch")
    identity = _sha256(record["record_id"], "qualification_record.record_id")
    content = dict(record)
    del content["record_id"]
    if identity != canonical_identity(content):
        raise ContractError("qualification record identity mismatch")
    rebuilt = build_qualification_record(package)
    if canonical_json(rebuilt) != canonical_json(record):
        raise ContractError("qualification record semantic reconstruction mismatch")
    return dict(record)


def write_qualification_record(path: Path, value: JsonValue) -> None:
    """Write one verified qualification record without replacing a file."""
    record = verify_qualification_record(value)
    with path.open("xb") as output:
        output.write(canonical_json(record))
        output.flush()
        os.fsync(output.fileno())


def load_qualification_record(path: Path) -> dict[str, JsonValue]:
    """Load one canonical qualification record."""
    return verify_qualification_record(
        load_canonical_json_file(path, "MLX runtime qualification record")
    )


def qualification_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Return a bounded static decision projection."""
    record = verify_qualification_record(value)
    assessment = _mapping(record["assessment"], "qualification assessment")
    package = _mapping(record["qualification_package"], "qualification package")
    return {
        "record_id": record["record_id"],
        "package_id": record["qualification_package_id"],
        "candidate_kind": package["candidate_kind"],
        "candidate_name": package["candidate_name"],
        "decision": record["decision"],
        "blockers": record["blockers"],
        "eligibility_scope": assessment["eligibility_scope"],
        "schema_1_0_remains_permanently_disabled": True,
        "next_required_step": assessment["next_required_step"],
        "worker_api_evidence_anchor_id": package["worker_api_evidence_anchor_id"],
        "worker_api_evidence_spec_id": package["worker_api_evidence_spec_id"],
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }


def worker_api_evidence_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Verify and project committed source-only worker API evidence."""
    package = verify_qualification_package(value)
    evidence: list[JsonValue] = [
        {
            "access_form": item.get("access_form"),
            "evidence_id": item.get("evidence_id"),
            "probe": item["probe"],
            "static_signature": item.get("static_signature"),
            "symbol": item["symbol"],
        }
        for item in (
            _mapping(entry, "worker API evidence")
            for entry in cast("list[JsonValue]", package["worker_api_evidence"])
        )
    ]
    return {
        "candidate_name": package["candidate_name"],
        "claim_scope": "source_surface_availability_only",
        "evidence": evidence,
        "evidence_anchor_id": package["worker_api_evidence_anchor_id"],
        "evidence_spec_id": package["worker_api_evidence_spec_id"],
        "package_id": package["package_id"],
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }


def _source(
    *,
    candidate_kind: str,
    repository: str,
    revision: str,
    tag: str,
) -> dict[str, JsonValue]:
    return {
        "provenance": (
            "synthetic_revision_and_tag"
            if candidate_kind == "synthetic_fixture"
            else "reviewed_git_revision_and_tag"
        ),
        "repository_url": repository,
        "revision": revision,
        "tag": tag,
    }


def _wheel(
    *,
    candidate_kind: str,
    name: str,
    version: str,
    python_tag: str,
    abi_tag: str,
    platform_tag: str,
    requirements: list[str],
    requires_python: str,
    url_prefix: str,
) -> dict[str, JsonValue]:
    filename = f"{name.replace('-', '_')}-{version}-{python_tag}-{abi_tag}-{platform_tag}.whl"
    wheel_bytes = _synthetic_wheel_bytes(
        name=name,
        version=version,
        tag=f"{python_tag}-{abi_tag}-{platform_tag}",
        requirements=requirements,
        requires_python=requires_python,
    )
    return {
        "abi_tag": abi_tag,
        "bytes_base64": encode_bytes(wheel_bytes),
        "filename": filename,
        "platform_tag": platform_tag,
        "provenance": (
            "synthetic_fixture_artifact"
            if candidate_kind == "synthetic_fixture"
            else "reviewed_pypi_artifact"
        ),
        "python_tag": python_tag,
        "sha256": digest_bytes(wheel_bytes),
        "size_bytes": len(wheel_bytes),
        "url": f"{url_prefix}/{filename}",
    }


def _synthetic_wheel_bytes(
    *,
    name: str,
    version: str,
    tag: str,
    requirements: list[str],
    requires_python: str | None,
    metadata_bytes: bytes | None = None,
) -> bytes:
    output = io.BytesIO()
    dist_info = f"{name.replace('-', '_')}-{version}.dist-info"
    metadata = (
        _metadata_bytes(
            name,
            version,
            requirements,
            requires_python=requires_python,
        )
        if metadata_bytes is None
        else metadata_bytes
    )
    wheel = (
        "Wheel-Version: 1.0\n"
        "Generator: LocalInferenceLab static synthetic fixture\n"
        "Root-Is-Purelib: false\n"
        f"Tag: {tag}\n\n"
    ).encode("ascii")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for path, data in (
            (f"{dist_info}/METADATA", metadata),
            (f"{dist_info}/WHEEL", wheel),
        ):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_STORED
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return output.getvalue()


def _metadata(
    name: str,
    version: str,
    requirements: list[str],
    *,
    evidence_scope: str,
    requires_python: str | None,
) -> dict[str, JsonValue]:
    data = _metadata_bytes(
        name,
        version,
        requirements,
        requires_python=requires_python,
    )
    return {
        "bytes_base64": encode_bytes(data),
        "evidence_scope": evidence_scope,
        "sha256": digest_bytes(data),
    }


def _package(
    *,
    candidate_kind: str,
    candidate_name: str,
    target_environment: dict[str, JsonValue],
    top_level_requirements: list[str],
    distributions: list[JsonValue],
    worker_api_evidence: list[JsonValue],
) -> dict[str, JsonValue]:
    worker_api_evidence_anchor_id = canonical_identity(worker_api_evidence)
    package: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_qualification_package",
        "schema_version": SCHEMA_VERSION,
        "qualification_spec_id": qualification_spec()["spec_id"],
        "candidate_kind": candidate_kind,
        "candidate_name": candidate_name,
        "target_environment": target_environment,
        "extras_policy": {"mode": "forbid_all_extras", "requested": []},
        "top_level_requirements": cast("list[JsonValue]", top_level_requirements),
        "distributions": distributions,
        "worker_api_evidence": worker_api_evidence,
        "worker_api_evidence_anchor_id": worker_api_evidence_anchor_id,
        "worker_api_evidence_spec_id": worker_api_evidence_spec()["spec_id"],
        "frozen_schema_1_0_negative": _frozen_negative_relationship(),
        "claims": dict(_CLAIMS),
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }
    package["package_id"] = canonical_identity(package)
    return verify_qualification_package(package)


def historical_incompatible_qualification_package() -> dict[str, JsonValue]:
    """Return the exact historical pair as a deliberately incomplete negative projection."""
    mlx_source = _source(
        candidate_kind="historical_negative_projection",
        repository="https://github.com/ml-explore/mlx",
        revision="0e3ff3643b1c3719f78814b98e0d222afbad867c",
        tag="v0.29.3",
    )
    mlx_lm_source = _source(
        candidate_kind="historical_negative_projection",
        repository="https://github.com/ml-explore/mlx-lm",
        revision="5cfec4cb39deba54210b3ff4d86f2337c7bc10b5",
        tag="v0.30.6",
    )
    distributions: list[JsonValue] = [
        {
            "name": "mlx",
            "version": "0.29.3",
            "role": "top_level",
            "source": mlx_source,
            "wheel": {
                "abi_tag": "cp313",
                "bytes_base64": None,
                "filename": "mlx-0.29.3-cp313-cp313-macosx_15_0_arm64.whl",
                "platform_tag": "macosx_15_0_arm64",
                "provenance": "reviewed_pypi_artifact",
                "python_tag": "cp313",
                "sha256": (
                    "sha256:ec0aef311fab10cb5f2c274afa6edf6c482636096a5f7886aba43676454aa462"
                ),
                "size_bytes": 549_586,
                "url": (
                    "https://files.pythonhosted.org/packages/ad/76/"
                    "196c248c2b2a471f795356564ad1d7dc40284160c8b66370ffadfd991fa1/"
                    "mlx-0.29.3-cp313-cp313-macosx_15_0_arm64.whl"
                ),
            },
            "metadata": _metadata(
                "mlx",
                "0.29.3",
                [],
                evidence_scope="historical_requirement_projection",
                requires_python=None,
            ),
        },
        {
            "name": "mlx-lm",
            "version": "0.30.6",
            "role": "top_level",
            "source": mlx_lm_source,
            "wheel": {
                "abi_tag": "none",
                "bytes_base64": None,
                "filename": "mlx_lm-0.30.6-py3-none-any.whl",
                "platform_tag": "any",
                "provenance": "reviewed_pypi_artifact",
                "python_tag": "py3",
                "sha256": (
                    "sha256:a7405bd581eacc4bf8209d7a6b7f23629585a0d7c6740c2a97e51fee35b3b0e1"
                ),
                "size_bytes": 379_451,
                "url": (
                    "https://files.pythonhosted.org/packages/20/5f/"
                    "01d281f1fa8a1521d5936659beb4f5ab1f32b463d059263cf9d4cef969d9/"
                    "mlx_lm-0.30.6-py3-none-any.whl"
                ),
            },
            "metadata": _metadata(
                "mlx-lm",
                "0.30.6",
                ['mlx>=0.30.4; platform_system == "Darwin"'],
                evidence_scope="historical_requirement_projection",
                requires_python=None,
            ),
        },
    ]
    return _package(
        candidate_kind="historical_negative_projection",
        candidate_name="frozen-schema-1-0-incompatible-pair",
        target_environment={
            "implementation_name": "cpython",
            "macos_version": "15.0",
            "os_name": "posix",
            "platform_machine": "arm64",
            "platform_system": "Darwin",
            "python_abi": "cp313",
            "python_full_version": "3.13.0",
            "python_version": "3.13",
            "sys_platform": "darwin",
        },
        top_level_requirements=["mlx==0.29.3", "mlx-lm==0.30.6"],
        distributions=distributions,
        worker_api_evidence=[],
    )


def _api_evidence(
    *,
    probe: str,
    distribution: str,
    symbol: str,
    revision: str,
    source_path: str,
    source_text: str,
    match_text: str,
) -> dict[str, JsonValue]:
    data = source_text.encode("utf-8")
    return {
        "distribution": distribution,
        "probe": probe,
        "source_bytes_base64": encode_bytes(data),
        "source_path": source_path,
        "source_revision": revision,
        "source_sha256": digest_bytes(data),
        "symbol": symbol,
        "symbol_token": match_text,
    }


def synthetic_eligible_qualification_package() -> dict[str, JsonValue]:
    """Return a coherent synthetic closure that proves only the static contract."""
    kind = "synthetic_fixture"
    root = f"https://{_SYNTHETIC_DOMAIN}"
    revisions = {
        "mlx": "1111111111111111111111111111111111111111",
        "mlx-lm": "2222222222222222222222222222222222222222",
        "mlx-metal": "3333333333333333333333333333333333333333",
        "typing-extensions": "4444444444444444444444444444444444444444",
    }
    distributions: list[JsonValue] = [
        {
            "name": "mlx",
            "version": "1.0.0",
            "role": "top_level",
            "source": _source(
                candidate_kind=kind,
                repository=f"{root}/mlx",
                revision=revisions["mlx"],
                tag="v1.0.0-synthetic",
            ),
            "wheel": _wheel(
                candidate_kind=kind,
                name="mlx",
                version="1.0.0",
                python_tag="cp312",
                abi_tag="cp312",
                platform_tag="macosx_14_0_arm64",
                requirements=["mlx-metal==1.0.0"],
                requires_python=">=3.11",
                url_prefix=f"{root}/wheels",
            ),
            "metadata": _metadata(
                "mlx",
                "1.0.0",
                ["mlx-metal==1.0.0"],
                evidence_scope="complete_synthetic_metadata",
                requires_python=">=3.11",
            ),
        },
        {
            "name": "mlx-lm",
            "version": "1.0.0",
            "role": "top_level",
            "source": _source(
                candidate_kind=kind,
                repository=f"{root}/mlx-lm",
                revision=revisions["mlx-lm"],
                tag="v1.0.0-synthetic",
            ),
            "wheel": _wheel(
                candidate_kind=kind,
                name="mlx-lm",
                version="1.0.0",
                python_tag="py3",
                abi_tag="none",
                platform_tag="any",
                requirements=[
                    'mlx>=1.0.0; platform_system == "Darwin" and platform_machine == "arm64"',
                    'typing-extensions>=4.0; python_version < "3.13"',
                ],
                requires_python=">=3.11",
                url_prefix=f"{root}/wheels",
            ),
            "metadata": _metadata(
                "mlx-lm",
                "1.0.0",
                [
                    'mlx>=1.0.0; platform_system == "Darwin" and platform_machine == "arm64"',
                    'typing-extensions>=4.0; python_version < "3.13"',
                ],
                evidence_scope="complete_synthetic_metadata",
                requires_python=">=3.11",
            ),
        },
        {
            "name": "mlx-metal",
            "version": "1.0.0",
            "role": "transitive",
            "source": _source(
                candidate_kind=kind,
                repository=f"{root}/mlx-metal",
                revision=revisions["mlx-metal"],
                tag="v1.0.0-synthetic",
            ),
            "wheel": _wheel(
                candidate_kind=kind,
                name="mlx-metal",
                version="1.0.0",
                python_tag="py3",
                abi_tag="none",
                platform_tag="macosx_14_0_arm64",
                requirements=[],
                requires_python=">=3.11",
                url_prefix=f"{root}/wheels",
            ),
            "metadata": _metadata(
                "mlx-metal",
                "1.0.0",
                [],
                evidence_scope="complete_synthetic_metadata",
                requires_python=">=3.11",
            ),
        },
        {
            "name": "typing-extensions",
            "version": "4.12.0",
            "role": "transitive",
            "source": _source(
                candidate_kind=kind,
                repository=f"{root}/typing-extensions",
                revision=revisions["typing-extensions"],
                tag="v4.12.0-synthetic",
            ),
            "wheel": _wheel(
                candidate_kind=kind,
                name="typing-extensions",
                version="4.12.0",
                python_tag="py3",
                abi_tag="none",
                platform_tag="any",
                requirements=[],
                requires_python=">=3.9",
                url_prefix=f"{root}/wheels",
            ),
            "metadata": _metadata(
                "typing-extensions",
                "4.12.0",
                [],
                evidence_scope="complete_synthetic_metadata",
                requires_python=">=3.9",
            ),
        },
    ]
    api_evidence: list[JsonValue] = [
        _api_evidence(
            probe="default_device",
            distribution="mlx",
            symbol="mlx.core.default_device",
            revision=revisions["mlx"],
            source_path="python/src/core/default_device.cc",
            source_text="binding: mlx.core.default_device\n",
            match_text="mlx.core.default_device",
        ),
        _api_evidence(
            probe="default_stream",
            distribution="mlx",
            symbol="mlx.core.default_stream",
            revision=revisions["mlx"],
            source_path="python/src/core/default_stream.cc",
            source_text="binding: mlx.core.default_stream\n",
            match_text="mlx.core.default_stream",
        ),
        _api_evidence(
            probe="distribution_versions",
            distribution="mlx-lm",
            symbol="METADATA.Version",
            revision=revisions["mlx-lm"],
            source_path="dist-info/METADATA",
            source_text="field: METADATA.Version\n",
            match_text="METADATA.Version",
        ),
        _api_evidence(
            probe="import_mlx",
            distribution="mlx",
            symbol="mlx.core",
            revision=revisions["mlx"],
            source_path="python/mlx/core/__init__.py",
            source_text="module: mlx.core\n",
            match_text="mlx.core",
        ),
        _api_evidence(
            probe="import_mlx_lm",
            distribution="mlx-lm",
            symbol="mlx_lm",
            revision=revisions["mlx-lm"],
            source_path="mlx_lm/__init__.py",
            source_text="module: mlx_lm\n",
            match_text="mlx_lm",
        ),
        _api_evidence(
            probe="metal_is_available",
            distribution="mlx",
            symbol="mlx.core.metal.is_available",
            revision=revisions["mlx"],
            source_path="python/src/core/metal.cc",
            source_text="binding: mlx.core.metal.is_available\n",
            match_text="mlx.core.metal.is_available",
        ),
        _api_evidence(
            probe="synchronize",
            distribution="mlx",
            symbol="mlx.core.synchronize",
            revision=revisions["mlx"],
            source_path="python/src/core/synchronize.cc",
            source_text="binding: mlx.core.synchronize\n",
            match_text="mlx.core.synchronize",
        ),
    ]
    return _package(
        candidate_kind=kind,
        candidate_name="coherent-synthetic-schema-1-1-static-candidate",
        target_environment={
            "implementation_name": "cpython",
            "macos_version": "14.0",
            "os_name": "posix",
            "platform_machine": "arm64",
            "platform_system": "Darwin",
            "python_abi": "cp312",
            "python_full_version": "3.12.0",
            "python_version": "3.12",
            "sys_platform": "darwin",
        },
        top_level_requirements=["mlx==1.0.0", "mlx-lm==1.0.0"],
        distributions=distributions,
        worker_api_evidence=api_evidence,
    )


def _fixture_source() -> dict[str, JsonValue]:
    return {
        "record_type": "mlx_runtime_qualification_fixture_source",
        "schema_version": SCHEMA_VERSION,
        "evidence_status": "synthetic_static_contract_evidence_and_historical_projection",
        "historical_raw_evidence_committed": False,
        "historical_raw_evidence_path_disclosed": False,
        "physical_runtime_attempts": 0,
        "schema_1_0_retry_count": 0,
        "static_action_counters": dict(_ZERO_ACTION_COUNTERS),
    }


def compile_qualification_fixture(
    output_root: Path,
) -> tuple[Path, QualificationReplayResult]:
    """Publish deterministic eligible/ineligible static fixture evidence."""
    spec = qualification_spec()
    historical_package = historical_incompatible_qualification_package()
    eligible_package = synthetic_eligible_qualification_package()
    historical_record = build_qualification_record(historical_package)
    eligible_record = build_qualification_record(eligible_package)
    destination = publish_bundle(
        {
            "source/fixture.json": canonical_json(_fixture_source()),
            "source/qualification-spec.json": canonical_json(spec),
            "candidates/historical-incompatible-package.json": canonical_json(historical_package),
            "candidates/synthetic-eligible-package.json": canonical_json(eligible_package),
            "records/historical-incompatible-record.json": canonical_json(historical_record),
            "records/synthetic-eligible-record.json": canonical_json(eligible_record),
        },
        output_root,
        name_prefix="localinferencelab-mlx-runtime-qualification-synthetic-v1",
    )
    return destination, replay_qualification_fixture(destination)


def _canonical_value(data: bytes, label: str) -> JsonValue:
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError(f"{label} must use canonical JSON bytes")
    return value


def replay_qualification_fixture(bundle: Path) -> QualificationReplayResult:
    """Reconstruct both decisions from one closed bundle without runtime action."""
    content_root, files = read_closed_bundle(bundle)
    expected = {
        "source/fixture.json",
        "source/qualification-spec.json",
        "candidates/historical-incompatible-package.json",
        "candidates/synthetic-eligible-package.json",
        "records/historical-incompatible-record.json",
        "records/synthetic-eligible-record.json",
        "index.json",
        "receipt.json",
    }
    if set(files) != expected:
        raise ContractError("MLX runtime qualification fixture has an invalid content set")
    source = _canonical_value(
        files["source/fixture.json"],
        "qualification fixture source",
    )
    if canonical_json(source) != canonical_json(_fixture_source()):
        raise ContractError("qualification fixture source or zero-action claims drift")
    spec = _verify_spec(
        _canonical_value(
            files["source/qualification-spec.json"],
            "qualification specification",
        )
    )
    historical_package = verify_qualification_package(
        _canonical_value(
            files["candidates/historical-incompatible-package.json"],
            "historical qualification package",
        )
    )
    eligible_package = verify_qualification_package(
        _canonical_value(
            files["candidates/synthetic-eligible-package.json"],
            "synthetic qualification package",
        )
    )
    historical_record = verify_qualification_record(
        _canonical_value(
            files["records/historical-incompatible-record.json"],
            "historical qualification record",
        )
    )
    eligible_record = verify_qualification_record(
        _canonical_value(
            files["records/synthetic-eligible-record.json"],
            "synthetic qualification record",
        )
    )
    expected_historical_package = historical_incompatible_qualification_package()
    expected_eligible_package = synthetic_eligible_qualification_package()
    expected_historical_record = build_qualification_record(expected_historical_package)
    expected_eligible_record = build_qualification_record(expected_eligible_package)
    if (
        canonical_json(spec) != canonical_json(qualification_spec())
        or canonical_json(historical_package) != canonical_json(expected_historical_package)
        or canonical_json(eligible_package) != canonical_json(expected_eligible_package)
        or canonical_json(historical_record) != canonical_json(expected_historical_record)
        or canonical_json(eligible_record) != canonical_json(expected_eligible_record)
    ):
        raise ContractError("qualification fixture semantic reconstruction mismatch")
    if historical_record["decision"] != INELIGIBLE or eligible_record["decision"] != ELIGIBLE:
        raise ContractError("qualification fixture decisions drift")
    return QualificationReplayResult(
        bundle_root=content_root,
        eligible_record_id=cast("str", eligible_record["record_id"]),
        ineligible_record_id=cast("str", historical_record["record_id"]),
        eligible_decision=cast("str", eligible_record["decision"]),
        ineligible_decision=cast("str", historical_record["decision"]),
        package_installations=0,
        process_starts=0,
        runtime_imports=0,
        authorization_creations=0,
    )
