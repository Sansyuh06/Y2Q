"""Toy group arithmetic and toy key exchange over additive Z_32.

Implements arithmetic over the additive cyclic group of integers modulo 32
with generator G = 5. Provides key generation, shared element derivation,
HKDF-SHA256 key derivation, and AES-256-GCM encryption/decryption.

Framing: This is a Shor-style discrete-log circuit over a cyclic group of
order 32, encoded as integers, not an elliptic-curve implementation.
"""

from __future__ import annotations

import math
import os
from typing import NamedTuple, Tuple

GROUP_ORDER: int = 32
GENERATOR: int = 5
FIXED_AAD: bytes = b"Y2Q-HNDL-AAD-v1"


def scalar_mult(k: int, p: int = GENERATOR) -> int:
    """Compute (k * p) mod 32 in the additive group Z_32."""
    return (k * p) % GROUP_ORDER


def mod_inverse(a: int, m: int = GROUP_ORDER) -> int:
    """Compute the modular inverse of a modulo m.

    Raises ValueError if a and m are not coprime.
    """
    a_norm = a % m
    if math.gcd(a_norm, m) != 1:
        raise ValueError(f"Element {a} is not coprime to modulus {m}; inverse does not exist")
    return pow(a_norm, -1, m)


class KeyPair(NamedTuple):
    private_scalar: int
    public_element: int


def generate_keypair(private_scalar: int | None = None) -> KeyPair:
    """Generate or construct a key pair in Z_32.

    If private_scalar is not provided, selects a random coprime scalar in [1, 31].
    """
    if private_scalar is None:
        coprimes = [x for x in range(1, GROUP_ORDER) if math.gcd(x, GROUP_ORDER) == 1]
        rnd_idx = int.from_bytes(os.urandom(2), "big") % len(coprimes)
        private_scalar = coprimes[rnd_idx]

    pub = scalar_mult(private_scalar, GENERATOR)
    return KeyPair(private_scalar=private_scalar, public_element=pub)


def derive_shared_element(private_scalar: int, peer_public_element: int) -> int:
    """Derive shared element in Z_32: (private_scalar * peer_public_element) mod 32."""
    return scalar_mult(private_scalar, peer_public_element)


def derive_symmetric_key(shared_element: int, salt: bytes) -> bytes:
    """Derive a 32-byte symmetric key using HKDF-SHA256 from the shared element and salt."""
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for HNDL key derivation. "
            "Install with: pip install .[hndl]"
        ) from exc

    ikm = shared_element.to_bytes(4, "big")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"Y2Q-HNDL-Z32-AES256GCM",
    )
    return hkdf.derive(ikm)


def encrypt_payload(
    key: bytes,
    plaintext: bytes,
    nonce: bytes | None = None,
    aad: bytes = FIXED_AAD,
) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM.

    Returns (nonce, ciphertext_with_tag).
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for HNDL AES-GCM. "
            "Install with: pip install .[hndl]"
        ) from exc

    if nonce is None:
        nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt_payload(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes = FIXED_AAD,
) -> bytes:
    """Decrypt ciphertext using AES-256-GCM.

    Raises InvalidTag on tampering / authentication failure.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ImportError(
            "cryptography is required for HNDL AES-GCM. "
            "Install with: pip install .[hndl]"
        ) from exc

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad)
