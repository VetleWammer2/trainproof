"""A deliberately small canonical-JSON profile.

Protocol objects may contain only dictionaries with string keys, lists, NFC
strings, bounded integers, booleans, and null. Floats and binary values are
forbidden; binary values must be represented as lowercase hexadecimal text.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unicodedata
from pathlib import Path
from typing import Any

from .constants import PROTOCOL_VERSION

_PREFIX = (PROTOCOL_VERSION + "\0").encode("ascii")
_MAX_INTEGER_BITS = 256


class CanonicalEncodingError(ValueError):
    """Raised when a value is outside the canonical protocol profile."""


def _validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value.bit_length() > _MAX_INTEGER_BITS:
            raise CanonicalEncodingError(f"{path}: integer exceeds 256 bits")
        return
    if isinstance(value, float):
        raise CanonicalEncodingError(f"{path}: floating-point values are forbidden")
    if isinstance(value, str):
        if unicodedata.normalize("NFC", value) != value:
            raise CanonicalEncodingError(f"{path}: string is not NFC-normalized")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalEncodingError(f"{path}: dictionary keys must be strings")
            _validate(key, f"{path}.<key>")
            _validate(item, f"{path}.{key}")
        return
    raise CanonicalEncodingError(
        f"{path}: unsupported value type {type(value).__name__}"
    )


def canonical_bytes(value: Any) -> bytes:
    """Encode a protocol value deterministically as UTF-8 JSON."""

    _validate(value)
    text = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return text.encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalEncodingError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json(data: bytes | str) -> Any:
    """Parse JSON while rejecting duplicate keys and non-profile values."""

    try:
        value = json.loads(
            data,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda token: (_ for _ in ()).throw(
                CanonicalEncodingError(f"invalid numeric constant: {token}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalEncodingError(str(exc)) from exc
    _validate(value)
    return value


def read_json(path: str | Path) -> Any:
    return parse_json(Path(path).read_bytes())


def write_json(path: str | Path, value: Any) -> None:
    """Atomically write canonical JSON followed by one non-hashed newline."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_bytes(value) + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, destination)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def hash_bytes(domain: str, payload: bytes) -> bytes:
    """SHA-256 with versioned, length-prefixed domain separation."""

    if not domain or not domain.isascii():
        raise ValueError("hash domain must be non-empty ASCII")
    encoded_domain = domain.encode("ascii")
    if len(encoded_domain) > 65535:
        raise ValueError("hash domain is too long")
    digest = hashlib.sha256()
    digest.update(_PREFIX)
    digest.update(len(encoded_domain).to_bytes(2, "big"))
    digest.update(encoded_domain)
    digest.update(len(payload).to_bytes(8, "big"))
    digest.update(payload)
    return digest.digest()


def hash_object(domain: str, value: Any) -> bytes:
    return hash_bytes(domain, canonical_bytes(value))


def hash_hex(domain: str, value: Any) -> str:
    return hash_object(domain, value).hex()


def file_hash(path: str | Path, domain: str = "artifact-file/v1") -> str:
    return hash_bytes(domain, Path(path).read_bytes()).hex()
