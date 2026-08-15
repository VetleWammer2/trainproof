"""Protocol constants shared by producers and verifiers."""

PROTOCOL_VERSION = "trainproof/v1"
HASH_ALGORITHM = "sha256"
SIGNATURE_ALGORITHM = "ed25519"
ZERO_HASH = "00" * 32

# BN254 scalar-field modulus used by Circom/snarkjs.
BN254_PRIME = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
