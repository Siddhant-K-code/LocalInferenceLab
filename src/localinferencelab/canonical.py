"""Canonical JSON and content identities."""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import NoReturn, TypeAlias

JsonScalar: TypeAlias = None | bool | int | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
SHA256_ID_LENGTH = 71
_SURROGATE_START = 0xD800
_SURROGATE_END = 0xDFFF


class ContractError(ValueError):
    """Raised when a record violates the canonical contract."""


def _reject_float(_value: str) -> NoReturn:
    raise ContractError("floating-point JSON numbers are forbidden; use integer units")


def _reject_constant(value: str) -> NoReturn:
    raise ContractError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    result: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_json_value(value: object, path: str = "$") -> JsonValue:
    """Return a type-narrowed canonical value or reject unsupported types."""
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        if any(_SURROGATE_START <= ord(character) <= _SURROGATE_END for character in value):
            raise ContractError(f"{path}: Unicode surrogate code points are forbidden")
        return value
    if isinstance(value, float):
        raise ContractError(f"{path}: floating-point values are forbidden")
    if isinstance(value, Mapping):
        output: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError(f"{path}: object keys must be strings")
            checked_key = validate_json_value(key, f"{path}.<key>")
            if not isinstance(checked_key, str):
                raise ContractError(f"{path}: object keys must be strings")
            output[checked_key] = validate_json_value(item, f"{path}.{checked_key}")
        return output
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [validate_json_value(item, f"{path}[{index}]") for index, item in enumerate(value)]
    raise ContractError(f"{path}: unsupported canonical value type {type(value).__name__}")


def canonical_json(value: object) -> bytes:
    """Encode a value as the project's deterministic JSON representation."""
    checked = validate_json_value(value)
    return json.dumps(
        checked,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_identity(value: object) -> str:
    """Return a prefixed SHA-256 identity for a canonical value."""
    return digest_bytes(canonical_json(value))


def digest_bytes(data: bytes) -> str:
    """Return a prefixed SHA-256 digest."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def load_json_bytes(data: bytes) -> JsonValue:
    """Parse strict UTF-8 JSON with duplicate keys and floats rejected."""
    try:
        text = data.decode("utf-8", errors="strict")
        parsed: object = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as error:
        raise ContractError("JSON must be valid UTF-8") from error
    except json.JSONDecodeError as error:
        raise ContractError(f"malformed JSON: {error.msg}") from error
    return validate_json_value(parsed)


def encode_bytes(data: bytes) -> str:
    """Encode bytes without padding using URL-safe base64."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode_bytes(value: str) -> bytes:
    """Decode the project's canonical URL-safe base64 representation."""
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ContractError("invalid URL-safe base64") from error
    if encode_bytes(decoded) != value:
        raise ContractError("base64 value is not canonical")
    return decoded
