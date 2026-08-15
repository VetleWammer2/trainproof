from __future__ import annotations

from copy import deepcopy

import pytest

from trainproof.crypto import (
    SignatureError,
    generate_keypair,
    validate_public_key_document,
)


def test_public_key_document_binds_protocol_and_role(tmp_path) -> None:
    document = generate_keypair(
        tmp_path / "private.json",
        tmp_path / "public.json",
        "training-coordinator",
    )
    validate_public_key_document(document, "training-coordinator")

    wrong_role = deepcopy(document)
    wrong_role["role"] = "dataset-custodian"
    with pytest.raises(SignatureError, match="role mismatch"):
        validate_public_key_document(wrong_role, "training-coordinator")

    wrong_protocol = deepcopy(document)
    wrong_protocol["protocol"] = "trainproof/future"
    with pytest.raises(SignatureError, match="protocol"):
        validate_public_key_document(wrong_protocol, "training-coordinator")
