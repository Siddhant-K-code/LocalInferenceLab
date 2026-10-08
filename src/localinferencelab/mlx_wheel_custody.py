"""Offline custody for caller-supplied exact MLX dependency wheel packs."""

from __future__ import annotations

import hashlib
import io
import itertools
import os
import re
import stat
import struct
import zipfile
from dataclasses import dataclass
from email import errors, policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import BinaryIO, NamedTuple, cast
from urllib.parse import urlsplit

from localinferencelab.canonical import (
    ContractError,
    JsonValue,
    canonical_identity,
    canonical_json,
    decode_bytes,
    digest_bytes,
    load_canonical_json_file,
    load_json_bytes,
)
from localinferencelab.mlx_review_registry import committed_pack_review_approval

SCHEMA_VERSION = "1.0"
_DIGEST_LENGTH = 71
_CONTROL_LIMIT = 32
_MAX_DISTRIBUTIONS = 128
_MAX_WHEEL_BYTES = 128 * 1024 * 1024
_MAX_PACK_BYTES = 512 * 1024 * 1024
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_MAX_WHEEL_ENTRIES = 40_000
_MAX_WHEEL_UNCOMPRESSED_BYTES = 2 * 1024 * 1024 * 1024
_MAX_METADATA_BYTES = 512 * 1024
_MAX_REQUIREMENTS = 1024
_MAX_METADATA_HEADERS = 8192
_MAX_MARKER_TOKENS = 128
_MAX_EXPANDED_TAGS = 64
_LEGACY_MANIFEST_ANCHOR_SPEC_ID = (
    "sha256:099dbdf8190330224262ccd352066d49341c30b9a18d1dc0936a7f44c2161386"
)
_LEGACY_SUPPLIED_PACK_RECORD_FIELDS = {
    "assessment",
    "blockers",
    "candidate_anchor",
    "committed_record_alone_proves_supplied_bytes_present",
    "decision",
    "pack_verification",
    "qualification_spec_id",
    "record_id",
    "record_type",
    "record_verification_requires_supplied_pack",
    "schema_1_0_remains_permanently_disabled",
    "schema_version",
    "static_action_counters",
    "wheel_evidence_manifest_anchor_spec_id",
    "wheel_evidence_manifest_id",
    "wheel_evidence_pack_spec_id",
}
_CURRENT_SUPPLIED_PACK_RECORD_FIELDS = _LEGACY_SUPPLIED_PACK_RECORD_FIELDS | {
    "review_approval_id",
    "review_registry_id",
}
_MIN_COMPATIBLE_RELEASE_COMPONENTS = 2
_TARGET_VERSION_COMPONENTS = 2
_READ_BLOCK_BYTES = 1024 * 1024
_ZIP_LOCAL_HEADER_BYTES = 30
_ZIP_LOCAL_HEADER_SIGNATURE = 0x04034B50
_PACKAGE_DOMAINS = {"files.pythonhosted.org"}
_INDEX_DOMAINS = {"pypi.org"}
_SOURCE_DOMAINS = {"github.com"}
_NAME_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_RELEASE_PATTERN = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}$")
_SPECIFIER_PATTERN = re.compile(
    r"^(?P<operator>===|==|!=|~=|<=|>=|<|>)\s*"
    r"(?P<version>(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3}"
    r"(?:\.\*|(?:a|b|rc)[0-9]+)?)$"
)
_REQUIREMENT_PATTERN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\s*,\s*[A-Za-z0-9][A-Za-z0-9._-]*)*)\])?"
    r"(?P<specifiers>.*)$"
)
_WHEEL_TAG_PATTERN = re.compile(
    r"^(?P<python>[A-Za-z0-9.]+)-(?P<abi>[A-Za-z0-9.]+)-"
    r"(?P<platform>[A-Za-z0-9_.]+)$"
)
_CPYTHON_TAG_PATTERN = re.compile(r"^cp(?P<major>[1-9])(?P<minor>[0-9]{1,2})$")
_MACOS_PLATFORM_PATTERN = re.compile(
    r"^macosx_(?P<major>[0-9]+)_(?P<minor>[0-9]+)_"
    r"(?P<arch>arm64|x86_64|universal2)$"
)
_REVISION_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_TAG_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$")
_TIMESTAMP_PATTERN = re.compile(
    r"^(?:[0-9]{4})-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_SUPPORTED_METADATA_VERSIONS = {"2.1", "2.2", "2.3", "2.4", "2.5"}
_METADATA_POLICY = policy.default.clone(
    utf8=True,
    refold_source="none",
    raise_on_defect=False,
)
_WHEEL_POLICY = policy.default.clone(
    utf8=False,
    refold_source="none",
    raise_on_defect=True,
)
_REVIEWED_WHEEL_EVIDENCE_MANIFEST_ANCHORS: tuple[str, ...] = ()
_MARKER_VARIABLES = {
    "extra",
    "implementation_name",
    "os_name",
    "platform_machine",
    "platform_python_implementation",
    "platform_system",
    "python_full_version",
    "python_version",
    "sys_platform",
}
_DISTRIBUTION_BLOCKER_PREFIXES = (
    "dependency_",
    "distribution_role_",
    "incomplete_metadata_",
    "missing_required_distribution:",
    "requires_python_",
    "unreachable_supplied_distribution:",
    "wheel_",
)


class PackRequirement(NamedTuple):
    """One bounded PEP 508 requirement used by the supplied-pack contract."""

    raw: str
    name: str
    extras: tuple[str, ...]
    specifiers: tuple[tuple[str, str], ...]
    marker: str | None
    marker_identity: tuple[object, ...] | None


class _ParsedDistribution(NamedTuple):
    name: str
    version: str
    role: str
    requirements: tuple[PackRequirement, ...]
    requires_python: str
    requires_python_specifiers: tuple[tuple[str, str], ...]
    wheel_compatible: bool
    size_bytes: int


@dataclass(frozen=True, slots=True)
class VerifiedWheelEvidence:
    """In-memory result of verifying one supplied exact wheel."""

    name: str
    version: str
    filename: str
    size_bytes: int
    sha256: str
    metadata_sha256: str
    wheel_metadata_sha256: str
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifiedWheelEvidencePack:
    """In-memory proof that one caller-supplied pack matched a trusted manifest."""

    manifest_id: str
    pack_spec_id: str
    artifacts: tuple[VerifiedWheelEvidence, ...]
    total_size_bytes: int
    receipt_bytes: bytes

    def receipt(self) -> dict[str, JsonValue]:
        receipt = load_json_bytes(self.receipt_bytes)
        if not isinstance(receipt, dict):
            raise ContractError("verified wheel pack receipt must be an object")
        return receipt


def _mapping(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _array(value: JsonValue, label: str, *, maximum: int) -> list[JsonValue]:
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


def _normalized_name(value: JsonValue, label: str) -> str:
    original = _text(value, label, maximum=128)
    name = re.sub(r"[-_.]+", "-", original).lower()
    if _NAME_PATTERN.fullmatch(name) is None:
        raise ContractError(f"{label} is not a supported distribution name")
    return name


def _canonical_name(value: JsonValue, label: str) -> str:
    original = _text(value, label, maximum=128)
    name = _normalized_name(original, label)
    if original != name:
        raise ContractError(f"{label} must already be normalized")
    return name


def _release(value: JsonValue, label: str) -> str:
    version = _text(value, label, maximum=64)
    if _RELEASE_PATTERN.fullmatch(version) is None:
        raise ContractError(f"{label} must be a stable canonical release")
    return version


def _url(
    value: JsonValue,
    label: str,
    *,
    domains: set[str],
    expected_filename: str | None = None,
) -> str:
    url = _text(value, label, maximum=2048)
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in domains
        or parsed.port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
    ):
        raise ContractError(f"{label} is not an allowed credential-free HTTPS URL")
    if expected_filename is not None and not parsed.path.endswith(f"/{expected_filename}"):
        raise ContractError(f"{label} does not end with the exact wheel filename")
    return url


def _basename(value: JsonValue, label: str) -> str:
    name = _text(value, label, maximum=255)
    if (
        name in {".", ".."}
        or "/" in name
        or "\\" in name
        or "\x00" in name
        or Path(name).name != name
        or not name.isascii()
    ):
        raise ContractError(f"{label} must be a safe ASCII basename")
    return name


def _encoded_bytes(
    value: JsonValue,
    label: str,
    *,
    maximum: int = _MAX_METADATA_BYTES,
) -> bytes:
    encoded = _text(value, label, maximum=(maximum * 4 // 3) + 16)
    try:
        data = decode_bytes(encoded)
    except ContractError as error:
        raise ContractError(f"{label} is not canonical base64") from error
    if not data or len(data) > maximum:
        raise ContractError(f"{label} has invalid decoded length")
    return data


def _version_key(value: str) -> tuple[tuple[int, ...], int, int]:
    match = re.fullmatch(
        r"(?P<release>(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,3})"
        r"(?:(?P<stage>a|b|rc)(?P<number>[0-9]+))?",
        value,
    )
    if match is None:
        raise ContractError(f"unsupported version in specifier: {value}")
    release = tuple(int(component) for component in match.group("release").split("."))
    release += (0,) * (4 - len(release))
    stage = match.group("stage")
    stage_rank = {"a": -3, "b": -2, "rc": -1, None: 0}[stage]
    stage_number = int(match.group("number") or 0)
    return release, stage_rank, stage_number


def _parse_specifiers(value: str, label: str) -> tuple[tuple[str, str], ...]:
    value = value.strip()
    if not value:
        return ()
    if value.startswith("(") or value.endswith(")"):
        if not (value.startswith("(") and value.endswith(")")):
            raise ContractError(f"{label} has unbalanced specifier parentheses")
        value = value[1:-1].strip()
    parsed: list[tuple[str, str]] = []
    for piece in value.split(","):
        match = _SPECIFIER_PATTERN.fullmatch(piece.strip())
        if match is None:
            raise ContractError(f"{label} uses unsupported version specifier grammar")
        item = (match.group("operator"), match.group("version"))
        if item in parsed:
            raise ContractError(f"{label} contains duplicate version specifiers")
        parsed.append(item)
    return tuple(parsed)


def _satisfies(  # noqa: PLR0911
    version: str,
    specifiers: tuple[tuple[str, str], ...],
) -> bool:
    selected = _version_key(version)
    for operator, required_version in specifiers:
        if required_version.endswith(".*"):
            prefix = tuple(int(part) for part in required_version[:-2].split("."))
            matched = selected[0][: len(prefix)] == prefix
            if operator == "==" and not matched:
                return False
            if operator == "!=" and matched:
                return False
            if operator not in {"==", "!="}:
                raise ContractError("wildcard release supports only == and !=")
            continue
        required = _version_key(required_version)
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
            release = required[0]
            raw_components = required_version.split(".")
            if len(raw_components) < _MIN_COMPATIBLE_RELEASE_COMPONENTS:
                raise ContractError("compatible-release specifier requires at least two components")
            prefix_length = len(raw_components) - 1
            upper = list(release)
            upper[prefix_length - 1] += 1
            for index in range(prefix_length, len(upper)):
                upper[index] = 0
            if selected < required or selected >= (tuple(upper), 0, 0):
                return False
    return True


def _marker_tokens(value: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    index = 0
    while index < len(value):
        if value[index].isspace():
            index += 1
            continue
        if value[index] in "()":
            tokens.append((value[index], value[index]))
            index += 1
            continue
        if value[index] in {'"', "'"}:
            quote = value[index]
            end = value.find(quote, index + 1)
            if end == -1 or "\\" in value[index + 1 : end]:
                raise ContractError("environment marker has an invalid quoted value")
            tokens.append(("string", value[index + 1 : end]))
            index = end + 1
            continue
        operator = next(
            (
                candidate
                for candidate in ("not in", "==", "!=", "<=", ">=", "<", ">", "in")
                if value.startswith(candidate, index)
                and (
                    candidate not in {"in", "not in"}
                    or index + len(candidate) == len(value)
                    or value[index + len(candidate)].isspace()
                )
            ),
            None,
        )
        if operator is not None:
            tokens.append(("operator", operator))
            index += len(operator)
            continue
        identifier = re.match(r"[A-Za-z_][A-Za-z0-9_]*", value[index:])
        if identifier is None:
            raise ContractError("environment marker contains an unsupported token")
        word = identifier.group(0)
        tokens.append(("word", word))
        index += len(word)
    if len(tokens) > _MAX_MARKER_TOKENS:
        raise ContractError("environment marker exceeds the token bound")
    return tokens


class _MarkerParser:
    def __init__(self, value: str) -> None:
        self._tokens = _marker_tokens(value)
        self._index = 0

    def parse(self) -> tuple[object, ...]:
        if not self._tokens:
            raise ContractError("environment marker is empty")
        expression = self._parse_or()
        if self._index != len(self._tokens):
            raise ContractError("environment marker has trailing tokens")
        return expression

    def _peek(self, kind: str, value: str | None = None) -> bool:
        if self._index >= len(self._tokens):
            return False
        token_kind, token_value = self._tokens[self._index]
        return token_kind == kind and (value is None or token_value == value)

    def _take(self, kind: str, value: str | None = None) -> str:
        if not self._peek(kind, value):
            raise ContractError("environment marker has invalid expression structure")
        token = self._tokens[self._index][1]
        self._index += 1
        return token

    def _parse_or(self) -> tuple[object, ...]:
        items = [self._parse_and()]
        while self._peek("word", "or"):
            self._take("word", "or")
            items.append(self._parse_and())
        return items[0] if len(items) == 1 else ("or", *items)

    def _parse_and(self) -> tuple[object, ...]:
        items = [self._parse_atom()]
        while self._peek("word", "and"):
            self._take("word", "and")
            items.append(self._parse_atom())
        return items[0] if len(items) == 1 else ("and", *items)

    def _parse_atom(self) -> tuple[object, ...]:
        if self._peek("("):
            self._take("(")
            nested = self._parse_or()
            self._take(")")
            return nested
        variable = self._take("word")
        if variable not in _MARKER_VARIABLES:
            raise ContractError(f"environment marker variable is unsupported: {variable}")
        operator = self._take("operator")
        literal = self._take("string")
        return ("compare", variable, operator, literal)


def _compare_marker(  # noqa: PLR0911
    variable: str,
    left: str,
    operator: str,
    right: str,
) -> bool:
    if variable in {"python_version", "python_full_version"}:
        left_version = _version_key(left)
        right_version = _version_key(right)
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
        raise ContractError("version markers do not support membership operators")
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
    raise ContractError("environment marker operator is unsupported")


def _evaluate_marker_node(node: tuple[object, ...], environment: dict[str, str]) -> bool:
    operation = cast("str", node[0])
    if operation == "compare":
        variable = cast("str", node[1])
        return _compare_marker(
            variable,
            environment[variable],
            cast("str", node[2]),
            cast("str", node[3]),
        )
    children = cast("tuple[tuple[object, ...], ...]", node[1:])
    if operation == "and":
        return all(_evaluate_marker_node(child, environment) for child in children)
    if operation == "or":
        return any(_evaluate_marker_node(child, environment) for child in children)
    raise ContractError("environment marker AST is unsupported")


def _parse_requirement(value: str, label: str) -> PackRequirement:
    raw = _text(value, label, maximum=1024)
    if raw.count(";") > 1:
        raise ContractError(f"{label} has ambiguous marker separators")
    if ";" in raw:
        head, marker_text = raw.split(";", 1)
        marker = marker_text.strip()
        if not marker:
            raise ContractError(f"{label} has an empty environment marker")
        marker_identity = _MarkerParser(marker).parse()
    else:
        head = raw
        marker = None
        marker_identity = None
    match = _REQUIREMENT_PATTERN.fullmatch(head.strip())
    if match is None:
        raise ContractError(f"{label} uses unsupported requirement grammar")
    name = _normalized_name(match.group("name"), f"{label}.name")
    extras_text = match.group("extras")
    extras = (
        ()
        if extras_text is None
        else tuple(
            sorted(
                _normalized_name(item.strip(), f"{label}.extra") for item in extras_text.split(",")
            )
        )
    )
    if len(extras) != len(set(extras)):
        raise ContractError(f"{label} extras must be unique")
    specifiers = _parse_specifiers(match.group("specifiers"), f"{label}.specifiers")
    return PackRequirement(raw, name, extras, specifiers, marker, marker_identity)


def _metadata_header_values(message: Message, name: str) -> list[str]:
    return [str(value) for value in message.get_all(name, [])]


def _single_metadata_header(message: Message, name: str, label: str) -> str:
    values = _metadata_header_values(message, name)
    if len(values) != 1:
        raise ContractError(f"{label} must contain exactly one {name} header")
    return _text(values[0], f"{label}.{name}", maximum=512)


def _parse_metadata(
    data: bytes,
    *,
    expected_name: str,
    expected_version: str,
    label: str,
) -> tuple[tuple[PackRequirement, ...], str, tuple[tuple[str, str], ...]]:
    if b"\x00" in data:
        raise ContractError(f"{label} contains a NUL byte")
    try:
        data.decode("utf-8", errors="strict")
        message = BytesParser(policy=_METADATA_POLICY).parsebytes(data)
    except (UnicodeDecodeError, ValueError, errors.MessageDefect) as error:
        raise ContractError(f"{label} is not valid UTF-8 Core Metadata") from error
    if message.defects:
        names = ",".join(sorted(type(defect).__name__ for defect in message.defects))
        raise ContractError(f"{label} contains Core Metadata defects: {names}")
    raw_headers = list(message.raw_items())
    if not raw_headers or len(raw_headers) > _MAX_METADATA_HEADERS:
        raise ContractError(f"{label} has an invalid header count")
    critical = {"metadata-version", "name", "version", "requires-dist", "requires-python"}
    for header_name, raw_value in raw_headers:
        if header_name.lower() in critical and ("\n" in raw_value or "\r" in raw_value):
            raise ContractError(f"{label} may not fold {header_name} values")
    metadata_version = _single_metadata_header(message, "Metadata-Version", label)
    if metadata_version not in _SUPPORTED_METADATA_VERSIONS:
        raise ContractError(f"{label} has unsupported Metadata-Version {metadata_version}")
    name = _normalized_name(_single_metadata_header(message, "Name", label), f"{label}.Name")
    version = _release(_single_metadata_header(message, "Version", label), f"{label}.Version")
    if name != expected_name or version != expected_version:
        raise ContractError(f"{label} name or version differs from the distribution")
    requires_python_values = _metadata_header_values(message, "Requires-Python")
    if len(requires_python_values) != 1:
        raise ContractError(f"{label} must contain exactly one Requires-Python header")
    requires_python = _text(
        requires_python_values[0],
        f"{label}.Requires-Python",
        maximum=512,
    )
    requires_python_specifiers = _parse_specifiers(
        requires_python,
        f"{label}.Requires-Python",
    )
    requirements = tuple(
        _parse_requirement(item, f"{label}.Requires-Dist[{index}]")
        for index, item in enumerate(_metadata_header_values(message, "Requires-Dist"))
    )
    if len(requirements) > _MAX_REQUIREMENTS:
        raise ContractError(f"{label} exceeds the requirement count bound")
    return requirements, requires_python, requires_python_specifiers


def _parse_wheel_metadata(data: bytes, label: str) -> tuple[str, ...]:
    if b"\x00" in data:
        raise ContractError(f"{label} contains a NUL byte")
    if b"\r" in data.replace(b"\r\n", b""):
        raise ContractError(f"{label} contains a bare carriage return")
    try:
        data.decode("ascii", errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} must be ASCII") from error
    normalized = data.replace(b"\r\n", b"\n")
    header_bytes, separator, body = normalized.partition(b"\n\n")
    if separator and body:
        raise ContractError(f"{label} must not contain a body")
    if not header_bytes or not normalized.endswith(b"\n"):
        raise ContractError(f"{label} must have a complete header record")
    if any(line.startswith((b" ", b"\t")) for line in header_bytes.split(b"\n")):
        raise ContractError(f"{label} may not contain folded headers")
    try:
        message = BytesParser(policy=_WHEEL_POLICY).parsebytes(data if separator else data + b"\n")
    except (UnicodeDecodeError, ValueError, errors.MessageDefect) as error:
        raise ContractError(f"{label} is malformed wheel metadata") from error
    if message.defects:
        names = ",".join(sorted(type(defect).__name__ for defect in message.defects))
        raise ContractError(f"{label} contains wheel metadata defects: {names}")
    raw_headers = list(message.raw_items())
    if not raw_headers or len(raw_headers) > _MAX_METADATA_HEADERS:
        raise ContractError(f"{label} has an invalid header count")
    if message.is_multipart() or message.get_payload() not in {"", None}:
        raise ContractError(f"{label} must not contain a body")
    wheel_version = _single_metadata_header(message, "Wheel-Version", label)
    if wheel_version != "1.0":
        raise ContractError(f"{label} has unsupported Wheel-Version")
    root_is_purelib = _single_metadata_header(message, "Root-Is-Purelib", label)
    if root_is_purelib not in {"true", "false"}:
        raise ContractError(f"{label} has invalid Root-Is-Purelib")
    tags = [
        _text(item, f"{label}.Tag[{index}]", maximum=256)
        for index, item in enumerate(_metadata_header_values(message, "Tag"))
    ]
    if not tags or len(tags) > _MAX_EXPANDED_TAGS:
        raise ContractError(f"{label} has an invalid Tag header count")
    if len(tags) != len(set(tags)):
        raise ContractError(f"{label} contains duplicate Tag headers")
    if any(_WHEEL_TAG_PATTERN.fullmatch(tag) is None for tag in tags):
        raise ContractError(f"{label} contains a malformed Tag header")
    return tuple(sorted(tags))


def _parse_wheel_filename(filename: str) -> tuple[str, str, str, str, str]:
    if not filename.endswith(".whl"):
        raise ContractError("wheel filename must end in .whl")
    try:
        name_version, python_tag, abi_tag, platform_tag = filename[:-4].rsplit("-", 3)
        name_part, version = name_version.rsplit("-", 1)
    except ValueError as error:
        raise ContractError("wheel filename does not have the supported five-part form") from error
    name = _normalized_name(name_part, "wheel filename distribution")
    parsed_version = _release(version, "wheel filename version")
    tag = f"{python_tag}-{abi_tag}-{platform_tag}"
    if _WHEEL_TAG_PATTERN.fullmatch(tag) is None:
        raise ContractError("wheel filename contains unsupported tags")
    return name, parsed_version, python_tag, abi_tag, platform_tag


def _expanded_filename_tags(python_tag: str, abi_tag: str, platform_tag: str) -> tuple[str, ...]:
    tags = tuple(
        sorted(
            f"{python}-{abi}-{platform}"
            for python in python_tag.split(".")
            for abi in abi_tag.split(".")
            for platform in platform_tag.split(".")
        )
    )
    if len(tags) > _MAX_EXPANDED_TAGS or len(tags) != len(set(tags)):
        raise ContractError("wheel filename compressed tags are ambiguous")
    return tags


def _tag_compatible(tag: str, target: dict[str, JsonValue]) -> bool:
    match = _WHEEL_TAG_PATTERN.fullmatch(tag)
    if match is None:
        return False
    python_tag = match.group("python")
    abi_tag = match.group("abi")
    platform_tag = match.group("platform")
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
        platform = _MACOS_PLATFORM_PATTERN.fullmatch(platform_tag)
        if platform is None:
            platform_compatible = False
        else:
            target_version = tuple(
                int(component) for component in cast("str", target["macos_version"]).split(".")
            )
            minimum = (int(platform.group("major")), int(platform.group("minor")))
            platform_compatible = minimum <= target_version and platform.group("arch") in {
                cast("str", target["platform_machine"]),
                "universal2",
            }
    return python_compatible and platform_compatible


def _verify_target(value: JsonValue) -> dict[str, JsonValue]:
    target = _mapping(value, "wheel_evidence_manifest.target_environment")
    fields = {
        "implementation_name",
        "macos_version",
        "os_name",
        "platform_machine",
        "platform_python_implementation",
        "platform_system",
        "python_abi",
        "python_full_version",
        "python_version",
        "runtime_target_anchor_id",
        "sys_platform",
    }
    _keys(target, fields, "wheel_evidence_manifest.target_environment")
    values = {
        name: _text(
            target[name],
            f"target_environment.{name}",
            maximum=80 if name == "runtime_target_anchor_id" else 64,
        )
        for name in fields
    }
    if (
        values["implementation_name"] != "cpython"
        or values["os_name"] != "posix"
        or values["platform_machine"] != "arm64"
        or values["platform_python_implementation"] != "CPython"
        or values["platform_system"] != "Darwin"
        or values["sys_platform"] != "darwin"
    ):
        raise ContractError("wheel evidence target must be explicit CPython macOS arm64")
    python_version = _release(values["python_version"], "target_environment.python_version")
    full_version = _release(
        values["python_full_version"],
        "target_environment.python_full_version",
    )
    if len(python_version.split(".")) != _TARGET_VERSION_COMPONENTS or not full_version.startswith(
        f"{python_version}."
    ):
        raise ContractError("wheel evidence target Python versions disagree")
    if values["python_abi"] != f"cp{python_version.replace('.', '')}":
        raise ContractError("wheel evidence target ABI differs from Python version")
    _sha256(
        values["runtime_target_anchor_id"],
        "target_environment.runtime_target_anchor_id",
    )
    macos_version = _release(
        values["macos_version"],
        "target_environment.macos_version",
    )
    if len(macos_version.split(".")) not in {
        _TARGET_VERSION_COMPONENTS,
        _TARGET_VERSION_COMPONENTS + 1,
    }:
        raise ContractError("wheel evidence target macOS version has invalid components")
    return dict(target)


def wheel_evidence_pack_spec() -> dict[str, JsonValue]:
    """Return the frozen offline supplied-wheel custody specification."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_wheel_evidence_pack_spec",
        "schema_version": SCHEMA_VERSION,
        "artifact_domain_allowlist": cast("list[JsonValue]", sorted(_PACKAGE_DOMAINS)),
        "index_domain_allowlist": cast("list[JsonValue]", sorted(_INDEX_DOMAINS)),
        "source_domain_allowlist": cast("list[JsonValue]", sorted(_SOURCE_DOMAINS)),
        "bounds": {
            "maximum_distribution_count": _MAX_DISTRIBUTIONS,
            "maximum_manifest_bytes": _MAX_MANIFEST_BYTES,
            "maximum_pack_bytes": _MAX_PACK_BYTES,
            "maximum_wheel_bytes": _MAX_WHEEL_BYTES,
            "maximum_wheel_entries": _MAX_WHEEL_ENTRIES,
            "maximum_wheel_uncompressed_bytes": _MAX_WHEEL_UNCOMPRESSED_BYTES,
        },
        "manifest_identity_rule": ("caller_supplied_content_address_for_generic_verification_only"),
        "pack_member_policy": ("exact_manifest_basenames_only_no_follow_regular_single_link_files"),
        "verification_network_policy": "forbidden",
        "wheel_archive_policy": (
            "bounded_non_overlapping_ascii_paths_no_duplicates_no_links_exact_dist_info"
        ),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def wheel_evidence_manifest_anchor_spec() -> dict[str, JsonValue]:
    """Return the independently mutable reviewed-manifest allowlist."""
    content: dict[str, JsonValue] = {
        "record_type": "mlx_wheel_evidence_manifest_anchor_spec",
        "schema_version": SCHEMA_VERSION,
        "qualification_rule": ("manifest_id_must_be_independently_committed_after_manifest_review"),
        "reviewed_manifest_ids": cast(
            "list[JsonValue]",
            list(_REVIEWED_WHEEL_EVIDENCE_MANIFEST_ANCHORS),
        ),
    }
    content["spec_id"] = canonical_identity(content)
    return content


def _fixed_acquisition_policy() -> dict[str, JsonValue]:
    return {
        "artifact_domains": cast("list[JsonValue]", sorted(_PACKAGE_DOMAINS)),
        "credentialed_requests": False,
        "index_domains": cast("list[JsonValue]", sorted(_INDEX_DOMAINS)),
        "network_during_pack_verification": False,
        "source_domains": cast("list[JsonValue]", sorted(_SOURCE_DOMAINS)),
    }


def _fixed_selection_policy(acquired_at_utc: str) -> dict[str, JsonValue]:
    return {
        "acquired_at_utc": acquired_at_utc,
        "offline_verifier_attests_index_completeness": False,
        "release_rule": ("externally_acquired_exact_manifest_version_no_index_optimality_claim"),
        "root_rule": "root_versions_remain_exactly_pinned",
        "wheel_rule": (
            "externally_acquired_exact_manifest_artifact_target_compatibility_verified_only"
        ),
    }


def _fixed_claims() -> dict[str, JsonValue]:
    return {
        "committed_manifest_alone_proves_supplied_bytes_present": False,
        "manifest_contains_third_party_wheel_bytes": False,
        "pack_verification_executes_wheel_contents": False,
        "pack_verification_imports_candidate_packages": False,
        "pack_verification_installs_packages": False,
        "supplied_pack_required_for_byte_presence_claim": True,
        "third_party_wheels_redistributed": False,
    }


def _verify_source(value: JsonValue, label: str) -> dict[str, JsonValue]:
    source = _mapping(value, label)
    _keys(source, {"availability", "repository_url", "revision", "tag"}, label)
    availability = _text(source["availability"], f"{label}.availability", maximum=32)
    if availability not in {"bound_revision_and_tag", "repository_only", "unavailable"}:
        raise ContractError(f"{label}.availability is unsupported")
    repository = source["repository_url"]
    revision = source["revision"]
    tag = source["tag"]
    if availability == "unavailable":
        if repository is not None or revision is not None or tag is not None:
            raise ContractError(f"{label} unavailable source must use null bindings")
    else:
        _url(repository, f"{label}.repository_url", domains=_SOURCE_DOMAINS)
        if availability == "repository_only":
            if revision is not None or tag is not None:
                raise ContractError(f"{label} repository-only source must use null revision/tag")
        else:
            revision_text = _text(revision, f"{label}.revision", maximum=40)
            if _REVISION_PATTERN.fullmatch(revision_text) is None:
                raise ContractError(f"{label}.revision must be exact lowercase 40-hex")
            tag_text = _text(tag, f"{label}.tag", maximum=128)
            if _TAG_PATTERN.fullmatch(tag_text) is None:
                raise ContractError(f"{label}.tag is invalid")
    return dict(source)


def _verify_bound_bytes(
    value: JsonValue,
    label: str,
    *,
    extra_fields: set[str] | None = None,
) -> tuple[dict[str, JsonValue], bytes]:
    binding = _mapping(value, label)
    _keys(
        binding,
        {"bytes_base64", "sha256", "size_bytes"} | (extra_fields or set()),
        label,
    )
    data = _encoded_bytes(binding["bytes_base64"], f"{label}.bytes_base64")
    size = _integer(
        binding["size_bytes"],
        f"{label}.size_bytes",
        minimum=1,
        maximum=_MAX_METADATA_BYTES,
    )
    digest = _sha256(binding["sha256"], f"{label}.sha256")
    if len(data) != size or digest_bytes(data) != digest:
        raise ContractError(f"{label} byte size or digest mismatch")
    return dict(binding), data


def _verify_distribution(
    value: JsonValue,
    *,
    target: dict[str, JsonValue],
    index: int,
) -> tuple[dict[str, JsonValue], _ParsedDistribution]:
    label = f"wheel_evidence_manifest.distributions[{index}]"
    distribution = _mapping(value, label)
    _keys(
        distribution,
        {
            "artifact",
            "dist_info",
            "metadata",
            "name",
            "pypi_release_json_url",
            "role",
            "selected_by",
            "source",
            "version",
            "wheel_metadata",
        },
        label,
    )
    name = _canonical_name(distribution["name"], f"{label}.name")
    version = _release(distribution["version"], f"{label}.version")
    role = _text(distribution["role"], f"{label}.role", maximum=32)
    if role not in {"root", "transitive"}:
        raise ContractError(f"{label}.role is unsupported")
    _url(
        distribution["pypi_release_json_url"],
        f"{label}.pypi_release_json_url",
        domains=_INDEX_DOMAINS,
    )
    artifact = _mapping(distribution["artifact"], f"{label}.artifact")
    _keys(
        artifact,
        {
            "abi_tag",
            "filename",
            "platform_tag",
            "python_tag",
            "sha256",
            "size_bytes",
            "url",
        },
        f"{label}.artifact",
    )
    filename = _basename(artifact["filename"], f"{label}.artifact.filename")
    parsed_name, parsed_version, python_tag, abi_tag, platform_tag = _parse_wheel_filename(filename)
    if parsed_name != name or parsed_version != version:
        raise ContractError(f"{label}.artifact filename identity drift")
    for field, expected in (
        ("python_tag", python_tag),
        ("abi_tag", abi_tag),
        ("platform_tag", platform_tag),
    ):
        if _text(artifact[field], f"{label}.artifact.{field}", maximum=128) != expected:
            raise ContractError(f"{label}.artifact.{field} differs from filename")
    _url(
        artifact["url"],
        f"{label}.artifact.url",
        domains=_PACKAGE_DOMAINS,
        expected_filename=filename,
    )
    size_bytes = _integer(
        artifact["size_bytes"],
        f"{label}.artifact.size_bytes",
        minimum=1,
        maximum=_MAX_WHEEL_BYTES,
    )
    _sha256(artifact["sha256"], f"{label}.artifact.sha256")
    dist_info = _mapping(distribution["dist_info"], f"{label}.dist_info")
    _keys(
        dist_info,
        {"directory", "metadata_path", "wheel_path"},
        f"{label}.dist_info",
    )
    directory = _text(dist_info["directory"], f"{label}.dist_info.directory", maximum=255)
    metadata_path = _text(
        dist_info["metadata_path"],
        f"{label}.dist_info.metadata_path",
        maximum=512,
    )
    wheel_path = _text(
        dist_info["wheel_path"],
        f"{label}.dist_info.wheel_path",
        maximum=512,
    )
    if (
        not directory.endswith(".dist-info")
        or metadata_path != f"{directory}/METADATA"
        or wheel_path != f"{directory}/WHEEL"
    ):
        raise ContractError(f"{label}.dist_info paths are inconsistent")
    dist_identity = directory.removesuffix(".dist-info")
    try:
        dist_name, dist_version = dist_identity.rsplit("-", 1)
    except ValueError as error:
        raise ContractError(f"{label}.dist_info directory is malformed") from error
    if (
        _normalized_name(dist_name, f"{label}.dist_info.name") != name
        or _release(
            dist_version,
            f"{label}.dist_info.version",
        )
        != version
    ):
        raise ContractError(f"{label}.dist_info identity drift")
    _metadata_binding, metadata_bytes = _verify_bound_bytes(
        distribution["metadata"],
        f"{label}.metadata",
    )
    requirements, requires_python, requires_python_specifiers = _parse_metadata(
        metadata_bytes,
        expected_name=name,
        expected_version=version,
        label=f"{label}.metadata",
    )
    wheel_binding, wheel_bytes = _verify_bound_bytes(
        distribution["wheel_metadata"],
        f"{label}.wheel_metadata",
        extra_fields={"tags"},
    )
    wheel_binding_mapping = _mapping(wheel_binding, f"{label}.wheel_metadata")
    parsed_tags = _parse_wheel_metadata(wheel_bytes, f"{label}.wheel_metadata")
    declared_tags = [
        _text(item, f"{label}.wheel_metadata.tags[{tag_index}]", maximum=256)
        for tag_index, item in enumerate(
            _array(
                wheel_binding_mapping["tags"],
                f"{label}.wheel_metadata.tags",
                maximum=64,
            )
        )
    ]
    if (
        declared_tags != sorted(set(declared_tags))
        or parsed_tags != tuple(declared_tags)
        or tuple(declared_tags) != _expanded_filename_tags(python_tag, abi_tag, platform_tag)
    ):
        raise ContractError(f"{label}.wheel_metadata tags do not exactly bind the filename")
    _verify_source(distribution["source"], f"{label}.source")
    selected_by = [
        _text(item, f"{label}.selected_by[{selector_index}]", maximum=2048)
        for selector_index, item in enumerate(
            _array(distribution["selected_by"], f"{label}.selected_by", maximum=128)
        )
    ]
    if selected_by != sorted(set(selected_by)) or not selected_by:
        raise ContractError(f"{label}.selected_by must be non-empty, unique, and sorted")
    return dict(distribution), _ParsedDistribution(
        name,
        version,
        role,
        requirements,
        requires_python,
        requires_python_specifiers,
        any(_tag_compatible(tag, target) for tag in declared_tags),
        size_bytes,
    )


def _marker_environment(target: dict[str, JsonValue]) -> dict[str, str]:
    return {
        key: cast("str", target[key])
        for key in (
            "extra",
            "implementation_name",
            "os_name",
            "platform_machine",
            "platform_python_implementation",
            "platform_system",
            "python_full_version",
            "python_version",
            "sys_platform",
        )
        if key in target
    } | {"extra": ""}


def _derive_selection_and_closure(
    distributions: dict[str, _ParsedDistribution],
    target: dict[str, JsonValue],
    roots: list[str],
) -> tuple[dict[str, list[str]], dict[str, JsonValue]]:
    environment = _marker_environment(target)
    root_requirements = [
        _parse_requirement(requirement, f"wheel_evidence_manifest.roots[{index}]")
        for index, requirement in enumerate(roots)
    ]
    selectors: dict[str, list[str]] = {name: [] for name in distributions}
    blockers: list[str] = []
    edges: dict[str, list[str]] = {name: [] for name in distributions}
    for requirement in root_requirements:
        if requirement.extras or requirement.marker is not None:
            raise ContractError("wheel evidence roots must be exact unmarked requirements")
        selected = distributions.get(requirement.name)
        if selected is None:
            blockers.append(f"missing_required_distribution:{requirement.name}")
            continue
        selectors[requirement.name].append(f"root:{requirement.raw}")
        if requirement.specifiers != (("==", selected.version),):
            blockers.append(
                f"root_pin_mismatch:{requirement.raw}:selected={requirement.name}=="
                f"{selected.version}"
            )
    target_python = cast("str", target["python_full_version"])
    for name, distribution in distributions.items():
        if not _satisfies(target_python, distribution.requires_python_specifiers):
            blockers.append(
                f"requires_python_unsatisfied:{name}:{distribution.requires_python}:"
                f"selected={target_python}"
            )
        if not distribution.wheel_compatible:
            blockers.append(f"wheel_tag_incompatible:{name}")
        for requirement in distribution.requirements:
            applicable = (
                True
                if requirement.marker_identity is None
                else _evaluate_marker_node(requirement.marker_identity, environment)
            )
            if not applicable:
                continue
            if requirement.extras:
                blockers.append(f"dependency_extras_forbidden:{name}:{requirement.raw}")
                continue
            edges[name].append(requirement.name)
            selected = distributions.get(requirement.name)
            if selected is None:
                blockers.append(f"dependency_missing:{name}:{requirement.raw}")
                continue
            selectors[requirement.name].append(f"{name}:{requirement.raw}")
            if not _satisfies(selected.version, requirement.specifiers):
                blockers.append(
                    f"dependency_unsatisfied:{name}:{requirement.raw}:"
                    f"selected={requirement.name}=={selected.version}"
                )
    root_names = [requirement.name for requirement in root_requirements]
    reachable: set[str] = set()
    pending = list(root_names)
    while pending:
        name = pending.pop()
        if name in reachable or name not in distributions:
            continue
        reachable.add(name)
        pending.extend(edges[name])
    unreachable = sorted(set(distributions) - reachable)
    blockers.extend(f"unreachable_supplied_distribution:{name}" for name in unreachable)
    for name, distribution in distributions.items():
        expected_role = "root" if name in root_names else "transitive"
        if distribution.role != expected_role:
            blockers.append(f"distribution_role_mismatch:{name}:expected={expected_role}")
    normalized_selectors = {name: sorted(set(values)) for name, values in selectors.items()}
    for name, values in normalized_selectors.items():
        if not values:
            blockers.append(f"unselected_supplied_distribution:{name}")
    sorted_blockers = sorted(set(blockers))
    closure: dict[str, JsonValue] = {
        "applicable_dependency_graph": [
            {
                "dependencies": cast("list[JsonValue]", sorted(set(edges[name]))),
                "distribution": name,
            }
            for name in sorted(edges)
        ],
        "blockers": cast("list[JsonValue]", sorted_blockers),
        "complete": not sorted_blockers,
        "distribution_count": len(distributions),
        "reachable_distributions": cast("list[JsonValue]", sorted(reachable)),
        "roots": cast("list[JsonValue]", roots),
        "selected_distributions": cast(
            "list[JsonValue]",
            [f"{name}=={distributions[name].version}" for name in sorted(distributions)],
        ),
        "unreachable_distributions": cast("list[JsonValue]", unreachable),
        "wheel_bytes_total": sum(item.size_bytes for item in distributions.values()),
    }
    return normalized_selectors, closure


def build_wheel_evidence_manifest(
    *,
    candidate_anchor: dict[str, JsonValue],
    target_environment: dict[str, JsonValue],
    roots: list[str],
    distributions: list[dict[str, JsonValue]],
    acquired_at_utc: str,
) -> dict[str, JsonValue]:
    """Build a canonical manifest from already acquired inert wheel evidence."""
    if _TIMESTAMP_PATTERN.fullmatch(acquired_at_utc) is None:
        raise ContractError("acquired_at_utc must be a whole-second UTC timestamp")
    content: dict[str, JsonValue] = {
        "record_type": "mlx_wheel_evidence_pack_manifest",
        "schema_version": SCHEMA_VERSION,
        "pack_spec_id": wheel_evidence_pack_spec()["spec_id"],
        "candidate_anchor": candidate_anchor,
        "target_environment": target_environment,
        "roots": cast("list[JsonValue]", roots),
        "acquisition_policy": _fixed_acquisition_policy(),
        "selection_policy": _fixed_selection_policy(acquired_at_utc),
        "claims": _fixed_claims(),
        "distributions": cast("list[JsonValue]", distributions),
        "closure": {},
    }
    target = _verify_target(content["target_environment"])
    parsed: dict[str, _ParsedDistribution] = {}
    for index, value in enumerate(cast("list[JsonValue]", content["distributions"])):
        distribution, parsed_distribution = _verify_distribution(
            value,
            target=target,
            index=index,
        )
        name = cast("str", distribution["name"])
        if name in parsed:
            raise ContractError("wheel evidence distributions contain a canonical-name collision")
        parsed[name] = parsed_distribution
    selectors, closure = _derive_selection_and_closure(parsed, target, roots)
    for item in cast("list[JsonValue]", content["distributions"]):
        distribution = _mapping(item, "wheel evidence distribution")
        distribution["selected_by"] = cast(
            "list[JsonValue]",
            selectors[cast("str", distribution["name"])],
        )
    content["distributions"] = cast(
        "list[JsonValue]",
        sorted(
            cast("list[JsonValue]", content["distributions"]),
            key=lambda item: cast("str", _mapping(item, "distribution")["name"]),
        ),
    )
    content["closure"] = closure
    content["manifest_id"] = canonical_identity(content)
    return verify_wheel_evidence_manifest(content, cast("str", content["manifest_id"]))


def verify_wheel_evidence_manifest(
    value: JsonValue,
    expected_manifest_id: str,
) -> dict[str, JsonValue]:
    """Verify a manifest against a caller-supplied content address."""
    manifest = _mapping(value, "mlx_wheel_evidence_pack_manifest")
    fields = {
        "acquisition_policy",
        "candidate_anchor",
        "claims",
        "closure",
        "distributions",
        "manifest_id",
        "pack_spec_id",
        "record_type",
        "roots",
        "schema_version",
        "selection_policy",
        "target_environment",
    }
    _keys(manifest, fields, "mlx_wheel_evidence_pack_manifest")
    if (
        manifest["record_type"] != "mlx_wheel_evidence_pack_manifest"
        or manifest["schema_version"] != SCHEMA_VERSION
        or manifest["pack_spec_id"] != wheel_evidence_pack_spec()["spec_id"]
    ):
        raise ContractError("unsupported MLX wheel evidence manifest")
    trusted_identity = _sha256(expected_manifest_id, "expected_manifest_id")
    manifest_identity = _sha256(manifest["manifest_id"], "manifest.manifest_id")
    if manifest_identity != trusted_identity:
        raise ContractError("wheel evidence manifest differs from expected content address")
    content = dict(manifest)
    del content["manifest_id"]
    if canonical_identity(content) != manifest_identity:
        raise ContractError("wheel evidence manifest identity mismatch")
    candidate = _mapping(manifest["candidate_anchor"], "manifest.candidate_anchor")
    _keys(
        candidate,
        {"candidate_name", "package_id", "qualification_spec_id", "review_anchor_id"},
        "manifest.candidate_anchor",
    )
    _text(candidate["candidate_name"], "manifest.candidate_anchor.candidate_name", maximum=128)
    _sha256(candidate["package_id"], "manifest.candidate_anchor.package_id")
    _sha256(
        candidate["qualification_spec_id"],
        "manifest.candidate_anchor.qualification_spec_id",
    )
    _sha256(candidate["review_anchor_id"], "manifest.candidate_anchor.review_anchor_id")
    target = _verify_target(manifest["target_environment"])
    if canonical_json(manifest["acquisition_policy"]) != canonical_json(
        _fixed_acquisition_policy()
    ):
        raise ContractError("wheel evidence acquisition policy drift")
    selection = _mapping(manifest["selection_policy"], "manifest.selection_policy")
    _keys(
        selection,
        {
            "acquired_at_utc",
            "offline_verifier_attests_index_completeness",
            "release_rule",
            "root_rule",
            "wheel_rule",
        },
        "manifest.selection_policy",
    )
    acquired = _text(
        selection["acquired_at_utc"],
        "manifest.selection_policy.acquired_at_utc",
        maximum=20,
    )
    if _TIMESTAMP_PATTERN.fullmatch(acquired) is None or canonical_json(
        selection
    ) != canonical_json(_fixed_selection_policy(acquired)):
        raise ContractError("wheel evidence selection policy drift")
    if canonical_json(manifest["claims"]) != canonical_json(_fixed_claims()):
        raise ContractError("wheel evidence claims drift")
    roots = [
        _text(item, f"manifest.roots[{index}]", maximum=256)
        for index, item in enumerate(_array(manifest["roots"], "manifest.roots", maximum=16))
    ]
    if roots != sorted(set(roots)) or not roots:
        raise ContractError("wheel evidence roots must be non-empty, unique, and sorted")
    parsed: dict[str, _ParsedDistribution] = {}
    verified_distributions: list[dict[str, JsonValue]] = []
    for index, item in enumerate(
        _array(
            manifest["distributions"],
            "manifest.distributions",
            maximum=_MAX_DISTRIBUTIONS,
        )
    ):
        distribution, parsed_distribution = _verify_distribution(
            item,
            target=target,
            index=index,
        )
        name = cast("str", distribution["name"])
        if name in parsed:
            raise ContractError("wheel evidence distributions contain a canonical-name collision")
        parsed[name] = parsed_distribution
        verified_distributions.append(distribution)
    if [cast("str", item["name"]) for item in verified_distributions] != sorted(parsed):
        raise ContractError("wheel evidence distributions must be sorted by canonical name")
    selectors, closure = _derive_selection_and_closure(parsed, target, roots)
    for distribution in verified_distributions:
        if distribution["selected_by"] != selectors[cast("str", distribution["name"])]:
            raise ContractError("wheel evidence selection provenance drift")
    if canonical_json(manifest["closure"]) != canonical_json(closure):
        raise ContractError("wheel evidence closure semantic reconstruction mismatch")
    return dict(manifest)


def load_wheel_evidence_manifest(
    path: Path,
    expected_manifest_id: str,
) -> dict[str, JsonValue]:
    """Load one bounded, stable, no-follow canonical wheel evidence manifest."""
    try:
        descriptor = os.open(path, _file_flags())
    except OSError as error:
        raise ContractError("cannot open MLX wheel evidence manifest without following") from error
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 1
            or before.st_size > _MAX_MANIFEST_BYTES
        ):
            raise ContractError("MLX wheel evidence manifest has unsafe file metadata or size")
        captured = bytearray()
        while block := os.read(descriptor, _READ_BLOCK_BYTES):
            captured.extend(block)
            if len(captured) > before.st_size or len(captured) > _MAX_MANIFEST_BYTES:
                raise ContractError("MLX wheel evidence manifest grew during bounded read")
        after = os.fstat(descriptor)
        try:
            path_after = path.stat(follow_symlinks=False)
        except OSError as error:
            raise ContractError("MLX wheel evidence manifest path changed during read") from error
        if (
            len(captured) != before.st_size
            or _stable_file_tuple(after) != _stable_file_tuple(before)
            or (path_after.st_dev, path_after.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ContractError("MLX wheel evidence manifest changed during bounded read")
    finally:
        os.close(descriptor)
    data = bytes(captured)
    value = load_json_bytes(data)
    if canonical_json(value) != data:
        raise ContractError("MLX wheel evidence manifest must use canonical JSON")
    return verify_wheel_evidence_manifest(value, expected_manifest_id)


def _file_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _directory_flags() -> int:
    flags = _file_flags()
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    return flags


def _stable_file_tuple(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_zip_path(name: str, label: str) -> tuple[str, bool]:
    directory_marker = name.endswith("/")
    unmarked = name[:-1] if directory_marker else name
    path = PurePosixPath(unmarked)
    if (
        not name
        or not unmarked
        or not name.isascii()
        or "\\" in name
        or "\x00" in name
        or unmarked.endswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.as_posix() != unmarked
    ):
        raise ContractError(f"{label} contains an unsafe or ambiguous path")
    return path.as_posix(), directory_marker


def _local_zip_entry_range(
    handle: BinaryIO,
    entry: zipfile.ZipInfo,
    label: str,
) -> tuple[int, int]:
    handle.seek(entry.header_offset)
    header = handle.read(_ZIP_LOCAL_HEADER_BYTES)
    if len(header) != _ZIP_LOCAL_HEADER_BYTES:
        raise ContractError(f"{label} has a truncated local ZIP header")
    signature, *_fields, filename_length, extra_length = struct.unpack("<IHHHHHIIIHH", header)
    if signature != _ZIP_LOCAL_HEADER_SIGNATURE:
        raise ContractError(f"{label} local ZIP header signature mismatch")
    encoded_name = handle.read(filename_length)
    if len(encoded_name) != filename_length:
        raise ContractError(f"{label} has a truncated local ZIP filename")
    encoding = "utf-8" if entry.flag_bits & 0x800 else "cp437"
    try:
        local_name = encoded_name.decode(encoding, errors="strict")
    except UnicodeDecodeError as error:
        raise ContractError(f"{label} local ZIP filename is malformed") from error
    if local_name != entry.filename:
        raise ContractError(f"{label} local and central ZIP filenames differ")
    data_start = entry.header_offset + _ZIP_LOCAL_HEADER_BYTES + filename_length + extra_length
    return entry.header_offset, data_start + entry.compress_size


def _inspect_supplied_wheel(
    descriptor: int,
    *,
    distribution: dict[str, JsonValue],
    parsed: _ParsedDistribution,
    label: str,
) -> VerifiedWheelEvidence:
    artifact = _mapping(distribution["artifact"], f"{label}.artifact")
    expected_size = cast("int", artifact["size_bytes"])
    expected_digest = cast("str", artifact["sha256"])
    hasher = hashlib.sha256()
    total = 0
    snapshot = io.BytesIO()
    while block := os.read(descriptor, _READ_BLOCK_BYTES):
        total += len(block)
        if total > expected_size:
            raise ContractError(f"{label} exceeds its declared size")
        hasher.update(block)
        snapshot.write(block)
    actual_digest = f"sha256:{hasher.hexdigest()}"
    if total != expected_size or actual_digest != expected_digest:
        raise ContractError(f"{label} byte size or digest mismatch")
    snapshot.seek(0)
    try:
        with snapshot, zipfile.ZipFile(snapshot) as archive:
            raw = snapshot
            entries = archive.infolist()
            if not entries or len(entries) > _MAX_WHEEL_ENTRIES:
                raise ContractError(f"{label} has an invalid ZIP entry count")
            names = [entry.filename for entry in entries]
            if len(names) != len(set(names)) or len(names) != len(set(map(str.casefold, names))):
                raise ContractError(f"{label} contains duplicate or colliding ZIP paths")
            total_uncompressed = 0
            ranges: list[tuple[int, int]] = []
            offsets: set[int] = set()
            canonical_paths: set[str] = set()
            folded_canonical_paths: set[str] = set()
            for entry in entries:
                canonical_path, directory_marker = _safe_zip_path(entry.filename, label)
                folded_path = canonical_path.casefold()
                if canonical_path in canonical_paths or folded_path in folded_canonical_paths:
                    raise ContractError(f"{label} contains colliding canonical ZIP paths")
                canonical_paths.add(canonical_path)
                folded_canonical_paths.add(folded_path)
                if entry.flag_bits & 0x1:
                    raise ContractError(f"{label} contains an encrypted ZIP entry")
                mode = entry.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if (
                    file_type not in {0, stat.S_IFREG, stat.S_IFDIR}
                    or (directory_marker and file_type == stat.S_IFREG)
                    or (not directory_marker and file_type == stat.S_IFDIR)
                    or (directory_marker and (entry.file_size != 0 or entry.compress_size != 0))
                ):
                    raise ContractError(f"{label} contains a link or special ZIP entry")
                if entry.header_offset in offsets:
                    raise ContractError(f"{label} contains duplicate ZIP header offsets")
                offsets.add(entry.header_offset)
                total_uncompressed += entry.file_size
                if total_uncompressed > _MAX_WHEEL_UNCOMPRESSED_BYTES:
                    raise ContractError(f"{label} exceeds the ZIP expansion bound")
                ranges.append(_local_zip_entry_range(raw, entry, label))
            ordered_ranges = sorted(ranges)
            if any(
                current[0] < previous[1] for previous, current in itertools.pairwise(ordered_ranges)
            ):
                raise ContractError(f"{label} contains overlapping ZIP entries")
            dist_info = _mapping(distribution["dist_info"], f"{label}.dist_info")
            metadata_path = cast("str", dist_info["metadata_path"])
            wheel_path = cast("str", dist_info["wheel_path"])
            metadata_entries = [entry for entry in entries if entry.filename == metadata_path]
            wheel_entries = [entry for entry in entries if entry.filename == wheel_path]
            all_metadata = [
                entry for entry in entries if entry.filename.endswith(".dist-info/METADATA")
            ]
            all_wheel = [entry for entry in entries if entry.filename.endswith(".dist-info/WHEEL")]
            if (
                len(metadata_entries) != 1
                or len(wheel_entries) != 1
                or len(all_metadata) != 1
                or len(all_wheel) != 1
            ):
                raise ContractError(f"{label} must contain exactly one bound METADATA and WHEEL")
            if (
                metadata_entries[0].file_size > _MAX_METADATA_BYTES
                or wheel_entries[0].file_size > _MAX_METADATA_BYTES
            ):
                raise ContractError(f"{label} metadata entries exceed bounds")
            metadata_bytes = archive.read(metadata_entries[0])
            wheel_bytes = archive.read(wheel_entries[0])
    except (OSError, RuntimeError, zipfile.BadZipFile) as error:
        raise ContractError(f"{label} is not an unambiguous readable ZIP wheel") from error
    expected_metadata = _encoded_bytes(
        _mapping(distribution["metadata"], f"{label}.metadata")["bytes_base64"],
        f"{label}.metadata.bytes_base64",
    )
    expected_wheel = _encoded_bytes(
        _mapping(distribution["wheel_metadata"], f"{label}.wheel_metadata")["bytes_base64"],
        f"{label}.wheel_metadata.bytes_base64",
    )
    if metadata_bytes != expected_metadata:
        raise ContractError(f"{label} embedded METADATA differs from the manifest")
    if wheel_bytes != expected_wheel:
        raise ContractError(f"{label} embedded WHEEL differs from the manifest")
    _parse_metadata(
        metadata_bytes,
        expected_name=parsed.name,
        expected_version=parsed.version,
        label=f"{label}.embedded_metadata",
    )
    wheel_binding = _mapping(distribution["wheel_metadata"], f"{label}.wheel_metadata")
    tags = tuple(cast("list[str]", wheel_binding["tags"]))
    return VerifiedWheelEvidence(
        parsed.name,
        parsed.version,
        cast("str", artifact["filename"]),
        expected_size,
        expected_digest,
        cast("str", _mapping(distribution["metadata"], f"{label}.metadata")["sha256"]),
        cast("str", wheel_binding["sha256"]),
        tags,
    )


def verify_supplied_wheel_pack(
    manifest_value: JsonValue,
    pack_root: Path,
    expected_manifest_id: str,
) -> VerifiedWheelEvidencePack:
    """Verify one exact caller-supplied wheel directory without following links."""
    manifest = verify_wheel_evidence_manifest(manifest_value, expected_manifest_id)
    target = _verify_target(manifest["target_environment"])
    distributions = [
        _mapping(item, "wheel evidence distribution")
        for item in cast("list[JsonValue]", manifest["distributions"])
    ]
    parsed_by_name: dict[str, _ParsedDistribution] = {}
    for index, distribution in enumerate(distributions):
        _verified, parsed = _verify_distribution(distribution, target=target, index=index)
        parsed_by_name[parsed.name] = parsed
    expected_files = {
        cast("str", _mapping(item["artifact"], "wheel artifact")["filename"]): item
        for item in distributions
    }
    try:
        root_descriptor = os.open(pack_root, _directory_flags())
    except OSError as error:
        raise ContractError("supplied wheel pack root must be a no-follow directory") from error
    try:
        root_metadata = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_metadata.st_mode):
            raise ContractError("supplied wheel pack root must be a directory")
        try:
            member_names = os.listdir(root_descriptor)  # noqa: PTH208
        except OSError as error:
            raise ContractError("supplied wheel pack root cannot be enumerated") from error
        if len(member_names) != len(set(member_names)):
            raise ContractError("supplied wheel pack contains duplicate directory entries")
        if set(member_names) != set(expected_files):
            missing = sorted(set(expected_files) - set(member_names))
            extra = sorted(set(member_names) - set(expected_files))
            raise ContractError(
                f"supplied wheel pack member set mismatch: missing={missing!r} unexpected={extra!r}"
            )
        artifacts: list[VerifiedWheelEvidence] = []
        total_size = 0
        for filename in sorted(member_names):
            _basename(filename, "supplied wheel pack member")
            try:
                before = os.stat(filename, dir_fd=root_descriptor, follow_symlinks=False)
            except OSError as error:
                raise ContractError(f"cannot inspect supplied wheel {filename}") from error
            if not stat.S_ISREG(before.st_mode):
                raise ContractError(f"supplied wheel {filename} must be a regular file")
            if before.st_nlink != 1:
                raise ContractError(f"supplied wheel {filename} must have exactly one hard link")
            try:
                descriptor = os.open(filename, _file_flags(), dir_fd=root_descriptor)
            except OSError as error:
                raise ContractError(
                    f"cannot open supplied wheel {filename} without following"
                ) from error
            try:
                after = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(after.st_mode)
                    or after.st_nlink != 1
                    or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                ):
                    raise ContractError(f"supplied wheel {filename} changed during open")
                total_size += after.st_size
                if total_size > _MAX_PACK_BYTES:
                    raise ContractError("supplied wheel pack exceeds the total byte bound")
                distribution = expected_files[filename]
                parsed = parsed_by_name[cast("str", distribution["name"])]
                artifacts.append(
                    _inspect_supplied_wheel(
                        descriptor,
                        distribution=distribution,
                        parsed=parsed,
                        label=f"supplied wheel {filename}",
                    )
                )
            finally:
                os.close(descriptor)
    finally:
        os.close(root_descriptor)
    expected_total = cast(
        "int",
        _mapping(manifest["closure"], "manifest.closure")["wheel_bytes_total"],
    )
    if total_size != expected_total:
        raise ContractError("supplied wheel pack total byte size mismatch")
    receipt: dict[str, JsonValue] = {
        "record_type": "mlx_wheel_evidence_pack_verification_receipt",
        "schema_version": SCHEMA_VERSION,
        "manifest_id": manifest["manifest_id"],
        "pack_spec_id": manifest["pack_spec_id"],
        "artifact_count": len(artifacts),
        "total_size_bytes": total_size,
        "supplied_pack_verified": True,
        "committed_manifest_alone_proves_supplied_bytes_present": False,
        "network_actions": 0,
        "package_installations": 0,
        "runtime_imports": 0,
        "process_starts": 0,
    }
    receipt["receipt_id"] = canonical_identity(receipt)
    return VerifiedWheelEvidencePack(
        cast("str", manifest["manifest_id"]),
        cast("str", manifest["pack_spec_id"]),
        tuple(artifacts),
        total_size,
        canonical_json(receipt),
    )


def verify_supplied_wheel_pack_files(
    manifest_path: Path,
    pack_root: Path,
    expected_manifest_id: str,
) -> VerifiedWheelEvidencePack:
    """Load a canonical manifest and verify its exact supplied pack."""
    manifest = load_wheel_evidence_manifest(manifest_path, expected_manifest_id)
    return verify_supplied_wheel_pack(manifest, pack_root, expected_manifest_id)


def _pack_record_blockers(
    candidate: dict[str, JsonValue],
    candidate_record: dict[str, JsonValue],
    manifest: dict[str, JsonValue],
    receipt: dict[str, JsonValue],
) -> tuple[list[str], str, str | None]:
    original = [
        cast("str", item)
        for item in cast("list[JsonValue]", candidate_record["blockers"])
        if not cast("str", item).startswith(_DISTRIBUTION_BLOCKER_PREFIXES)
    ]
    closure = _mapping(manifest["closure"], "wheel evidence closure")
    assessment = _mapping(candidate_record["assessment"], "candidate assessment")
    manifest_id = cast("str", manifest["manifest_id"])
    target = _mapping(candidate["target_environment"], "candidate target")
    registry, approval = committed_pack_review_approval(
        candidate_package_id=cast("str", candidate["package_id"]),
        candidate_review_anchor_id=cast("str", assessment["review_anchor_id"]),
        predecessor_manifest_anchor_spec_id=cast(
            "str",
            wheel_evidence_manifest_anchor_spec()["spec_id"],
        ),
        qualification_spec_id=cast("str", candidate["qualification_spec_id"]),
        runtime_target_anchor_id=cast("str", target["runtime_target_anchor_id"]),
        wheel_evidence_manifest_id=manifest_id,
        wheel_evidence_pack_receipt_id=cast("str", receipt["receipt_id"]),
        wheel_evidence_pack_spec_id=cast("str", manifest["pack_spec_id"]),
        worker_api_evidence_anchor_id=cast(
            "str",
            candidate["worker_api_evidence_anchor_id"],
        ),
    )
    if candidate["candidate_kind"] != "reviewed_candidate":
        approval = None
        original.append(f"candidate_kind_not_reviewable_by_registry:{candidate['candidate_kind']}")
    if approval is None:
        original.append(f"wheel_evidence_manifest_anchor_not_independently_reviewed:{manifest_id}")
    blockers = sorted(set(original + cast("list[str]", closure["blockers"])))
    return (
        blockers,
        cast("str", registry["registry_id"]),
        None if approval is None else cast("str", approval["approval_id"]),
    )


def _legacy_pack_record_blockers(
    candidate_record: dict[str, JsonValue],
    manifest: dict[str, JsonValue],
) -> list[str]:
    original = [
        cast("str", item)
        for item in cast("list[JsonValue]", candidate_record["blockers"])
        if not cast("str", item).startswith(_DISTRIBUTION_BLOCKER_PREFIXES)
    ]
    closure = _mapping(manifest["closure"], "wheel evidence closure")
    manifest_id = cast("str", manifest["manifest_id"])
    original.append(f"wheel_evidence_manifest_anchor_not_independently_reviewed:{manifest_id}")
    return sorted(set(original + cast("list[str]", closure["blockers"])))


def _verify_candidate_manifest_binding(
    candidate: dict[str, JsonValue],
    manifest: dict[str, JsonValue],
) -> None:
    candidate_target = _mapping(candidate["target_environment"], "candidate target")
    manifest_target = _mapping(manifest["target_environment"], "manifest target")
    for name in (
        "implementation_name",
        "macos_version",
        "os_name",
        "platform_machine",
        "platform_system",
        "python_abi",
        "python_full_version",
        "python_version",
        "runtime_target_anchor_id",
        "sys_platform",
    ):
        if candidate_target[name] != manifest_target[name]:
            raise ContractError(f"wheel evidence manifest target drift: {name}")
    candidate_roots = cast("list[str]", candidate["top_level_requirements"])
    manifest_roots = cast("list[str]", manifest["roots"])
    if sorted(candidate_roots) != sorted(manifest_roots):
        raise ContractError("wheel evidence manifest root requirements drift")
    candidate_distributions = {
        cast("str", item["name"]): item
        for item in (
            _mapping(value, "candidate distribution")
            for value in cast("list[JsonValue]", candidate["distributions"])
        )
    }
    manifest_distributions = {
        cast("str", item["name"]): item
        for item in (
            _mapping(value, "manifest distribution")
            for value in cast("list[JsonValue]", manifest["distributions"])
        )
    }
    for root in (_parse_requirement(item, "candidate root") for item in candidate_roots):
        candidate_distribution = candidate_distributions.get(root.name)
        manifest_distribution = manifest_distributions.get(root.name)
        if candidate_distribution is None or manifest_distribution is None:
            raise ContractError(f"wheel evidence manifest omits candidate root {root.name}")
        candidate_wheel = _mapping(candidate_distribution["wheel"], "candidate root wheel")
        manifest_artifact = _mapping(
            manifest_distribution["artifact"],
            "manifest root artifact",
        )
        for name in (
            "abi_tag",
            "filename",
            "platform_tag",
            "python_tag",
            "sha256",
            "size_bytes",
            "url",
        ):
            if candidate_wheel[name] != manifest_artifact[name]:
                raise ContractError(f"wheel evidence manifest root artifact drift: {root.name}")
        candidate_metadata = _mapping(
            candidate_distribution["metadata"],
            "candidate root metadata",
        )
        manifest_metadata = _mapping(
            manifest_distribution["metadata"],
            "manifest root metadata",
        )
        if (
            candidate_metadata["bytes_base64"] != manifest_metadata["bytes_base64"]
            or candidate_metadata["sha256"] != manifest_metadata["sha256"]
        ):
            raise ContractError(f"wheel evidence manifest root metadata drift: {root.name}")
        candidate_source = _mapping(candidate_distribution["source"], "candidate root source")
        manifest_source = _mapping(manifest_distribution["source"], "manifest root source")
        if manifest_source != {
            "availability": "bound_revision_and_tag",
            "repository_url": candidate_source["repository_url"],
            "revision": candidate_source["revision"],
            "tag": candidate_source["tag"],
        }:
            raise ContractError(f"wheel evidence manifest root source drift: {root.name}")


def build_supplied_pack_qualification_record(
    candidate_anchor_value: JsonValue,
    manifest_value: JsonValue,
    pack_root: Path,
    expected_manifest_id: str,
) -> dict[str, JsonValue]:
    """Build a small qualification record only after verifying supplied wheel bytes."""
    from localinferencelab.mlx_qualification import (  # noqa: PLC0415
        ELIGIBLE,
        INELIGIBLE,
        build_qualification_record,
        qualification_spec,
        verify_qualification_package,
    )

    candidate = verify_qualification_package(candidate_anchor_value)
    manifest = verify_wheel_evidence_manifest(manifest_value, expected_manifest_id)
    candidate_binding = _mapping(manifest["candidate_anchor"], "manifest.candidate_anchor")
    if (
        candidate["package_id"] != candidate_binding["package_id"]
        or candidate["candidate_name"] != candidate_binding["candidate_name"]
        or candidate["qualification_spec_id"] != candidate_binding["qualification_spec_id"]
        or candidate["qualification_spec_id"] != qualification_spec()["spec_id"]
    ):
        raise ContractError("wheel evidence manifest candidate anchor mismatch")
    _verify_candidate_manifest_binding(candidate, manifest)
    candidate_record = build_qualification_record(candidate)
    candidate_assessment = _mapping(candidate_record["assessment"], "candidate assessment")
    if candidate_assessment["review_anchor_id"] != candidate_binding["review_anchor_id"]:
        raise ContractError("wheel evidence manifest review anchor mismatch")
    verified_pack = verify_supplied_wheel_pack(manifest, pack_root, expected_manifest_id)
    receipt = verified_pack.receipt()
    blockers, review_registry_id, review_approval_id = _pack_record_blockers(
        candidate,
        candidate_record,
        manifest,
        receipt,
    )
    decision = ELIGIBLE if not blockers else INELIGIBLE
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_supplied_pack_qualification_record",
        "schema_version": SCHEMA_VERSION,
        "qualification_spec_id": candidate["qualification_spec_id"],
        "candidate_anchor": dict(candidate_binding),
        "wheel_evidence_manifest_id": manifest["manifest_id"],
        "wheel_evidence_manifest_anchor_spec_id": _LEGACY_MANIFEST_ANCHOR_SPEC_ID,
        "wheel_evidence_pack_spec_id": manifest["pack_spec_id"],
        "pack_verification": receipt,
        "review_registry_id": review_registry_id,
        "review_approval_id": review_approval_id,
        "assessment": {
            "closure": manifest["closure"],
            "decision": decision,
            "blockers": cast("list[JsonValue]", blockers),
            "review_anchor_id": candidate_assessment["review_anchor_id"],
            "review_registry_id": review_registry_id,
            "review_approval_id": review_approval_id,
            "eligibility_scope": (
                "human_review_for_new_schema_1_1_observed_authorization_only"
                if decision == ELIGIBLE
                else "not_eligible_for_new_observed_authorization"
            ),
        },
        "decision": decision,
        "blockers": cast("list[JsonValue]", blockers),
        "committed_record_alone_proves_supplied_bytes_present": False,
        "record_verification_requires_supplied_pack": True,
        "schema_1_0_remains_permanently_disabled": True,
        "static_action_counters": {
            "package_installations": 0,
            "package_network_requests": 0,
            "process_starts": 0,
            "runtime_imports": 0,
        },
    }
    record["record_id"] = canonical_identity(record)
    return record


def _build_legacy_supplied_pack_qualification_record(
    candidate_anchor_value: JsonValue,
    manifest_value: JsonValue,
    pack_root: Path,
    expected_manifest_id: str,
) -> dict[str, JsonValue]:
    from localinferencelab.mlx_qualification import (  # noqa: PLC0415
        ELIGIBLE,
        INELIGIBLE,
        _build_legacy_qualification_record,
        qualification_spec,
        verify_qualification_package,
    )

    candidate = verify_qualification_package(candidate_anchor_value)
    manifest = verify_wheel_evidence_manifest(manifest_value, expected_manifest_id)
    candidate_binding = _mapping(manifest["candidate_anchor"], "manifest.candidate_anchor")
    if (
        candidate["package_id"] != candidate_binding["package_id"]
        or candidate["candidate_name"] != candidate_binding["candidate_name"]
        or candidate["qualification_spec_id"] != candidate_binding["qualification_spec_id"]
        or candidate["qualification_spec_id"] != qualification_spec()["spec_id"]
    ):
        raise ContractError("wheel evidence manifest candidate anchor mismatch")
    _verify_candidate_manifest_binding(candidate, manifest)
    candidate_record = _build_legacy_qualification_record(candidate)
    candidate_assessment = _mapping(candidate_record["assessment"], "candidate assessment")
    if candidate_assessment["review_anchor_id"] != candidate_binding["review_anchor_id"]:
        raise ContractError("wheel evidence manifest review anchor mismatch")
    verified_pack = verify_supplied_wheel_pack(manifest, pack_root, expected_manifest_id)
    blockers = _legacy_pack_record_blockers(candidate_record, manifest)
    decision = ELIGIBLE if not blockers else INELIGIBLE
    record: dict[str, JsonValue] = {
        "record_type": "mlx_runtime_supplied_pack_qualification_record",
        "schema_version": SCHEMA_VERSION,
        "qualification_spec_id": candidate["qualification_spec_id"],
        "candidate_anchor": dict(candidate_binding),
        "wheel_evidence_manifest_id": manifest["manifest_id"],
        "wheel_evidence_manifest_anchor_spec_id": wheel_evidence_manifest_anchor_spec()["spec_id"],
        "wheel_evidence_pack_spec_id": manifest["pack_spec_id"],
        "pack_verification": verified_pack.receipt(),
        "assessment": {
            "closure": manifest["closure"],
            "decision": decision,
            "blockers": cast("list[JsonValue]", blockers),
            "review_anchor_id": candidate_assessment["review_anchor_id"],
            "eligibility_scope": (
                "human_review_for_new_schema_1_1_observed_authorization_only"
                if decision == ELIGIBLE
                else "not_eligible_for_new_observed_authorization"
            ),
        },
        "decision": decision,
        "blockers": cast("list[JsonValue]", blockers),
        "committed_record_alone_proves_supplied_bytes_present": False,
        "record_verification_requires_supplied_pack": True,
        "schema_1_0_remains_permanently_disabled": True,
        "static_action_counters": {
            "package_installations": 0,
            "package_network_requests": 0,
            "process_starts": 0,
            "runtime_imports": 0,
        },
    }
    record["record_id"] = canonical_identity(record)
    return record


def verify_supplied_pack_qualification_record(
    value: JsonValue,
    candidate_anchor_value: JsonValue,
    manifest_value: JsonValue,
    pack_root: Path,
    expected_manifest_id: str,
) -> dict[str, JsonValue]:
    """Reconstruct a supplied-pack qualification record with the pack present."""
    record = _mapping(value, "mlx_runtime_supplied_pack_qualification_record")
    record_fields = set(record)
    if record_fields == _CURRENT_SUPPLIED_PACK_RECORD_FIELDS:
        legacy_replay = False
    elif record_fields == _LEGACY_SUPPLIED_PACK_RECORD_FIELDS:
        legacy_replay = True
    else:
        expected = (
            _CURRENT_SUPPLIED_PACK_RECORD_FIELDS
            if {"review_approval_id", "review_registry_id"} & record_fields
            else _LEGACY_SUPPLIED_PACK_RECORD_FIELDS
        )
        _keys(record, expected, "mlx_runtime_supplied_pack_qualification_record")
        raise ContractError("unsupported supplied-pack qualification record shape")
    if (
        record["record_type"] != "mlx_runtime_supplied_pack_qualification_record"
        or record["schema_version"] != SCHEMA_VERSION
        or record["committed_record_alone_proves_supplied_bytes_present"] is not False
        or record["record_verification_requires_supplied_pack"] is not True
        or record["schema_1_0_remains_permanently_disabled"] is not True
    ):
        raise ContractError("unsupported supplied-pack qualification record")
    identity = _sha256(record["record_id"], "supplied_pack_record.record_id")
    if not legacy_replay:
        _sha256(record["review_registry_id"], "supplied_pack_record.review_registry_id")
        if record["review_approval_id"] is not None:
            _sha256(record["review_approval_id"], "supplied_pack_record.review_approval_id")
    content = dict(record)
    del content["record_id"]
    if canonical_identity(content) != identity:
        raise ContractError("supplied-pack qualification record identity mismatch")
    rebuild = (
        _build_legacy_supplied_pack_qualification_record
        if legacy_replay
        else build_supplied_pack_qualification_record
    )
    rebuilt = rebuild(candidate_anchor_value, manifest_value, pack_root, expected_manifest_id)
    if canonical_json(record) != canonical_json(rebuilt):
        raise ContractError("supplied-pack qualification semantic reconstruction mismatch")
    return dict(record)


def write_supplied_pack_qualification_record(
    path: Path,
    value: JsonValue,
    candidate_anchor_value: JsonValue,
    manifest_value: JsonValue,
    pack_root: Path,
    expected_manifest_id: str,
) -> None:
    """Write one reconstructed supplied-pack record without replacement."""
    record = verify_supplied_pack_qualification_record(
        value,
        candidate_anchor_value,
        manifest_value,
        pack_root,
        expected_manifest_id,
    )
    with path.open("xb") as output:
        output.write(canonical_json(record))
        output.flush()
        os.fsync(output.fileno())


def load_supplied_pack_qualification_record(
    path: Path,
    candidate_anchor_value: JsonValue,
    manifest_value: JsonValue,
    pack_root: Path,
    expected_manifest_id: str,
) -> dict[str, JsonValue]:
    """Load and reconstruct one supplied-pack qualification record."""
    return verify_supplied_pack_qualification_record(
        load_canonical_json_file(path, "MLX supplied-pack qualification record"),
        candidate_anchor_value,
        manifest_value,
        pack_root,
        expected_manifest_id,
    )


def supplied_pack_qualification_inspection(value: JsonValue) -> dict[str, JsonValue]:
    """Return a bounded non-verifying projection of an already verified record."""
    record = _mapping(value, "mlx_runtime_supplied_pack_qualification_record")
    record_fields = set(record)
    if record_fields == _LEGACY_SUPPLIED_PACK_RECORD_FIELDS:
        legacy_replay = True
    elif record_fields == _CURRENT_SUPPLIED_PACK_RECORD_FIELDS:
        legacy_replay = False
    else:
        raise ContractError("unsupported supplied-pack qualification record shape")
    return {
        "record_id": record["record_id"],
        "candidate_package_id": _mapping(
            record["candidate_anchor"],
            "supplied pack candidate anchor",
        )["package_id"],
        "manifest_id": record["wheel_evidence_manifest_id"],
        "review_registry_id": record.get("review_registry_id"),
        "review_approval_id": record.get("review_approval_id"),
        "decision": record["decision"],
        "blockers": record["blockers"],
        "verification_scope": (
            "verified_historical_replay_non_promotable"
            if legacy_replay
            else "current_registry_policy"
        ),
        "current_registry_policy_bound": not legacy_replay,
        "record_verification_requires_supplied_pack": True,
        "committed_record_alone_proves_supplied_bytes_present": False,
    }
