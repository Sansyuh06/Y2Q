"""Verification and decryption for HNDL attack candidate.

Enforces strict verification against the public relation before decryption:
- A candidate that fails the public relation is recorded as REJECTED_BY_PUBLIC_RELATION
  and must not proceed to decryption.
- k = 0, k = 32, and k = 33 are strictly rejected, not silently reduced.
- Plaintext SHA-256 match is evaluated and reported separately from AES-GCM tag verification.

Framing: This is a Shor-style discrete-log circuit over a cyclic group of
order 32, encoded as integers, not an elliptic-curve implementation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

from y2q.hndl.toygroup import (
    FIXED_AAD,
    GENERATOR,
    GROUP_ORDER,
    decrypt_payload,
    derive_shared_element,
    derive_symmetric_key,
)


@dataclass(frozen=True)
class VerificationResult:
    public_relation_status: str  # "VERIFIED" | "REJECTED_BY_PUBLIC_RELATION"
    candidate_k: Optional[int]
    decrypted: bool
    sha256_match: bool
    recovered_plaintext_sha256: Optional[str]
    error_message: Optional[str] = None


def verify_public_relation(
    candidate_k: Optional[int],
    target_public_element: int,
    generator: int = GENERATOR,
    group_order: int = GROUP_ORDER,
) -> bool:
    """Check if candidate_k * generator == target_public_element in Z_order.

    k <= 0 or k >= group_order (such as k=0, k=32, k=33) are rejected,
    never silently reduced mod group_order.
    """
    if candidate_k is None or not isinstance(candidate_k, int):
        return False
    if candidate_k <= 0 or candidate_k >= group_order:
        return False
    return (candidate_k * generator) % group_order == (target_public_element % group_order)


def verify_and_decrypt(
    candidate_k: Optional[int],
    target_public_element: int,
    peer_public_element: int,
    salt: bytes,
    nonce: bytes,
    ciphertext: bytes,
    expected_plaintext_sha256: str,
    generator: int = GENERATOR,
    group_order: int = GROUP_ORDER,
    aad: bytes = FIXED_AAD,
) -> VerificationResult:
    """Verify candidate against public relation and attempt AES-256-GCM decryption."""
    # Step 1: Check public relation
    if not verify_public_relation(candidate_k, target_public_element, generator, group_order):
        return VerificationResult(
            public_relation_status="REJECTED_BY_PUBLIC_RELATION",
            candidate_k=candidate_k,
            decrypted=False,
            sha256_match=False,
            recovered_plaintext_sha256=None,
            error_message="Candidate scalar fails public relation check k*G == Q",
        )

    # Step 2: Derive shared element and key (assert candidate_k is not None for mypy)
    assert candidate_k is not None
    shared_element = derive_shared_element(candidate_k, peer_public_element)
    key = derive_symmetric_key(shared_element, salt)

    # Step 3: Attempt AES-GCM authenticated decryption
    try:
        decrypted_bytes = decrypt_payload(key, nonce, ciphertext, aad=aad)
    except Exception as exc:
        return VerificationResult(
            public_relation_status="VERIFIED",
            candidate_k=candidate_k,
            decrypted=False,
            sha256_match=False,
            recovered_plaintext_sha256=None,
            error_message=f"AES-GCM authentication failure: {exc}",
        )

    # Step 4: Validate plaintext SHA-256 match
    actual_sha256 = hashlib.sha256(decrypted_bytes).hexdigest()
    match = actual_sha256.lower() == expected_plaintext_sha256.lower()

    return VerificationResult(
        public_relation_status="VERIFIED",
        candidate_k=candidate_k,
        decrypted=True,
        sha256_match=match,
        recovered_plaintext_sha256=actual_sha256,
        error_message=None if match else "Plaintext SHA-256 mismatch",
    )
