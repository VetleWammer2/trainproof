"""Verifier-supplied run and participant trust policies.

Signatures authenticate only relative to a public key.  This module lets the
caller pin both the expected key IDs and the exact run claims outside the
bundle, so self-issued identities and producer-selected inputs cannot silently
become trusted assertions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .canonical import read_json
from .constants import PROTOCOL_VERSION

TRUST_PROFILE = "pinned-run-and-participant-claims/v2"


class TrustPolicyError(ValueError):
    """Raised when a verifier-supplied trust policy does not match a run."""


def _is_key_id(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def verify_trust_policy(
    path: str | Path,
    actual_participants: dict[str, str | list[str]],
    actual_claims: dict[str, Any],
) -> dict[str, Any]:
    policy = read_json(path)
    if not isinstance(policy, dict) or set(policy) != {
        "protocol",
        "profile",
        "participants",
        "claims",
    }:
        raise TrustPolicyError("trust policy has unexpected or missing fields")
    if policy["protocol"] != PROTOCOL_VERSION or policy["profile"] != TRUST_PROFILE:
        raise TrustPolicyError("unsupported trust-policy profile")
    expected = policy["participants"]
    if not isinstance(expected, dict) or set(expected) != set(actual_participants):
        raise TrustPolicyError(
            "trust-policy participant roles do not match this verifier profile"
        )
    for role, actual in actual_participants.items():
        pinned = expected[role]
        if isinstance(actual, list):
            if (
                not isinstance(pinned, list)
                or any(not _is_key_id(value) for value in pinned)
                or pinned != actual
            ):
                raise TrustPolicyError(f"trust-policy key IDs do not match role {role}")
        elif not _is_key_id(pinned) or pinned != actual:
            raise TrustPolicyError(f"trust-policy key ID does not match role {role}")
    if not isinstance(policy["claims"], dict) or policy["claims"] != actual_claims:
        raise TrustPolicyError(
            "trust-policy run, dataset, code, trajectory, or checkpoint claims do not match"
        )
    return policy


def policy_document(
    actual_participants: dict[str, str | list[str]],
    actual_claims: dict[str, Any],
) -> dict[str, Any]:
    """Return a template that must be moved and trusted out of band."""

    return {
        "protocol": PROTOCOL_VERSION,
        "profile": TRUST_PROFILE,
        "participants": actual_participants,
        "claims": actual_claims,
    }
