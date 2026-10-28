"""Case generator for the controlled HNDL experiment.

Generates a toy key exchange over the additive group Z_32 with generator G = 5,
derives an AES-256-GCM key, encrypts a synthetic payload, and writes:
- challenge.json: strictly public parameters and ciphertext for the attack.
- truth.json: ground-truth private scalars, shared element, and plaintext.
  Written to a separate path that attack never opens and never prints.

Framing: This is a Shor-style discrete-log circuit over a cyclic group of
order 32, encoded as integers, not an elliptic-curve implementation.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Optional, Tuple

from y2q.hndl.toygroup import (
    FIXED_AAD,
    GENERATOR,
    GROUP_ORDER,
    derive_shared_element,
    derive_symmetric_key,
    encrypt_payload,
    generate_keypair,
)

DEFAULT_SYNTHETIC_MESSAGE: bytes = b"Y2Q-HNDL-SYNTHETIC-PLAINTEXT-SECRET-DATA"


def generate_case(
    output_dir: str | Path,
    case_id: Optional[str] = None,
    private_scalar_a: Optional[int] = None,
    private_scalar_b: Optional[int] = None,
    message: bytes = DEFAULT_SYNTHETIC_MESSAGE,
) -> Tuple[Path, Path]:
    """Generate challenge.json and truth.json in output_dir.

    Returns (challenge_path, truth_path).
    """
    case_path = Path(output_dir)
    case_path.mkdir(parents=True, exist_ok=True)

    if case_id is None:
        case_id = f"case_{uuid.uuid4().hex[:8]}"

    # Generate key pairs for Alice and Bob
    kp_alice = generate_keypair(private_scalar_a)
    kp_bob = generate_keypair(private_scalar_b)

    # Derive shared element
    shared_element = derive_shared_element(kp_alice.private_scalar, kp_bob.public_element)

    # Derive symmetric key via HKDF-SHA256
    salt = os.urandom(16)
    key = derive_symmetric_key(shared_element, salt)

    # Encrypt payload with AES-256-GCM
    nonce, ciphertext = encrypt_payload(key, message, aad=FIXED_AAD)
    expected_sha256 = hashlib.sha256(message).hexdigest()

    challenge_data = {
        "case_id": case_id,
        "group_order": GROUP_ORDER,
        "generator": GENERATOR,
        "alice_public": kp_alice.public_element,
        "bob_public": kp_bob.public_element,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "aad": FIXED_AAD.hex(),
        "expected_plaintext_sha256": expected_sha256,
        "framing": (
            "A Shor-style discrete-log circuit over a cyclic group of order 32, "
            "encoded as integers, not an elliptic-curve implementation."
        ),
    }

    truth_data = {
        "case_id": case_id,
        "alice_private": kp_alice.private_scalar,
        "bob_private": kp_bob.private_scalar,
        "shared_element": shared_element,
        "plaintext_hex": message.hex(),
        "plaintext_utf8": message.decode("utf-8", errors="replace"),
    }

    challenge_file = case_path / "challenge.json"
    truth_file = case_path / "truth.json"

    with open(challenge_file, "w", encoding="utf-8") as f:
        json.dump(challenge_data, f, indent=2)

    with open(truth_file, "w", encoding="utf-8") as f:
        json.dump(truth_data, f, indent=2)

    return challenge_file, truth_file
