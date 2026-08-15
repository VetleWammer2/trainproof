from __future__ import annotations

import pytest

from trainproof.canonical import CanonicalEncodingError, canonical_bytes, parse_json


def test_canonical_key_order_is_stable() -> None:
    assert canonical_bytes({"z": 1, "a": [2, 3]}) == b'{"a":[2,3],"z":1}'


def test_float_and_duplicate_keys_are_rejected() -> None:
    with pytest.raises(CanonicalEncodingError):
        canonical_bytes({"value": 1.5})
    with pytest.raises(CanonicalEncodingError):
        parse_json('{"same":1,"same":2}')
