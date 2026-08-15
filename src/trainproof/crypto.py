"""Ed25519 identities and signed protocol objects."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .canonical import hash_bytes, hash_object, read_json, write_json
from .constants import PROTOCOL_VERSION, SIGNATURE_ALGORITHM


class SignatureError(ValueError):
    """Raised for malformed or invalid signatures."""


_PUBLIC_KEY_FIELDS = {"protocol", "scheme", "role", "key_id", "public_key"}
_SIGNATURE_FIELDS = {
    "scheme",
    "key_id",
    "signed_domain",
    "signed_digest",
    "signature",
}


def key_id(public_key: bytes) -> str:
    return hash_bytes("signing-key-id/v1", public_key).hex()


def public_key_document(public_key: bytes, role: str) -> dict[str, Any]:
    if len(public_key) != 32:
        raise SignatureError("Ed25519 public keys must be 32 bytes")
    if not isinstance(role, str) or not role or not role.isascii():
        raise SignatureError("key role must be a non-empty ASCII string")
    return {
        "protocol": PROTOCOL_VERSION,
        "scheme": SIGNATURE_ALGORITHM,
        "role": role,
        "key_id": key_id(public_key),
        "public_key": public_key.hex(),
    }


def validate_public_key_document(
    document: Any,
    expected_role: str | None = None,
) -> bytes:
    """Validate a complete public-key document and optionally pin its role."""

    if not isinstance(document, dict) or set(document) != _PUBLIC_KEY_FIELDS:
        raise SignatureError("malformed public-key document")
    if document.get("protocol") != PROTOCOL_VERSION:
        raise SignatureError("unsupported public-key protocol")
    if document.get("scheme") != SIGNATURE_ALGORITHM:
        raise SignatureError("unsupported public-key scheme")
    role = document.get("role")
    if not isinstance(role, str) or not role or not role.isascii():
        raise SignatureError("invalid public-key role")
    if expected_role is not None and role != expected_role:
        raise SignatureError(
            f"public-key role mismatch: expected {expected_role}, got {role}"
        )
    public_hex = document.get("public_key")
    key_id_hex = document.get("key_id")
    if not isinstance(public_hex, str) or not isinstance(key_id_hex, str):
        raise SignatureError("malformed public key or key id")
    try:
        public_bytes = bytes.fromhex(public_hex)
    except ValueError as exc:
        raise SignatureError("malformed public key") from exc
    if len(public_bytes) != 32 or public_bytes.hex() != public_hex:
        raise SignatureError("public key must be canonical lowercase Ed25519 bytes")
    if key_id(public_bytes) != key_id_hex:
        raise SignatureError("public-key id is invalid")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes)
    except ValueError as exc:
        raise SignatureError("invalid Ed25519 public key") from exc
    return public_bytes


def generate_keypair(
    private_path: str | Path, public_path: str | Path, role: str
) -> dict[str, Any]:
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_document = public_key_document(public_bytes, role)
    private_document = {
        **public_document,
        "private_key": private_bytes.hex(),
        "warning": "demo key material; protect with an HSM or OS keystore in production",
    }
    write_json(private_path, private_document)
    try:
        os.chmod(private_path, 0o600)
    except OSError:
        pass
    write_json(public_path, public_document)
    return public_document


def load_private_key(path: str | Path) -> tuple[Ed25519PrivateKey, dict[str, Any]]:
    document = read_json(path)
    if not isinstance(document, dict):
        raise SignatureError("malformed private-key document")
    validate_public_key_document(
        {field: document.get(field) for field in _PUBLIC_KEY_FIELDS}
    )
    try:
        raw_private = bytes.fromhex(document["private_key"])
        raw_public = bytes.fromhex(document["public_key"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SignatureError("malformed private-key document") from exc
    if len(raw_private) != 32 or raw_private.hex() != document["private_key"]:
        raise SignatureError("private key must be canonical lowercase Ed25519 bytes")
    private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
    derived_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if derived_public != raw_public or key_id(raw_public) != document.get("key_id"):
        raise SignatureError("private-key document is internally inconsistent")
    return private_key, document


def sign_object(
    private_key_path: str | Path, domain: str, value: Any
) -> dict[str, Any]:
    private_key, key_document = load_private_key(private_key_path)
    digest = hash_object(domain, value)
    signature = private_key.sign(digest)
    return {
        "scheme": SIGNATURE_ALGORITHM,
        "key_id": key_document["key_id"],
        "signed_domain": domain,
        "signed_digest": digest.hex(),
        "signature": signature.hex(),
    }


def verify_signature(
    public_key_document_value: dict[str, Any],
    domain: str,
    value: Any,
    signature_document: dict[str, Any],
    *,
    expected_role: str | None = None,
) -> None:
    public_bytes = validate_public_key_document(
        public_key_document_value,
        expected_role=expected_role,
    )
    if (
        not isinstance(signature_document, dict)
        or set(signature_document) != _SIGNATURE_FIELDS
    ):
        raise SignatureError("malformed signature document")
    if signature_document.get("scheme") != SIGNATURE_ALGORITHM:
        raise SignatureError("unsupported signature scheme")
    if signature_document.get("key_id") != public_key_document_value.get("key_id"):
        raise SignatureError("signature key id does not match public key")
    if signature_document.get("signed_domain") != domain:
        raise SignatureError("signature domain mismatch")
    signature_hex = signature_document.get("signature")
    signed_digest = signature_document.get("signed_digest")
    if not isinstance(signature_hex, str) or not isinstance(signed_digest, str):
        raise SignatureError("malformed signature")
    try:
        signature_bytes = bytes.fromhex(signature_hex)
        signed_digest_bytes = bytes.fromhex(signed_digest)
    except ValueError as exc:
        raise SignatureError("malformed signature") from exc
    if len(signature_bytes) != 64 or signature_bytes.hex() != signature_hex:
        raise SignatureError("signature must be canonical lowercase Ed25519 bytes")
    if len(signed_digest_bytes) != 32 or signed_digest_bytes.hex() != signed_digest:
        raise SignatureError("signed digest must be canonical lowercase SHA-256 bytes")
    digest = hash_object(domain, value)
    if signature_document.get("signed_digest") != digest.hex():
        raise SignatureError("signed digest does not match object")
    try:
        Ed25519PublicKey.from_public_bytes(public_bytes).verify(signature_bytes, digest)
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("invalid Ed25519 signature") from exc
