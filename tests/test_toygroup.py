import pytest
from y2q.hndl.toygroup import (
    FIXED_AAD,
    GENERATOR,
    GROUP_ORDER,
    decrypt_payload,
    derive_shared_element,
    derive_symmetric_key,
    encrypt_payload,
    generate_keypair,
    mod_inverse,
    scalar_mult,
)


def test_generator_order():
    """Generator 5 must generate all 32 elements of cyclic group Z_32."""
    generated = {scalar_mult(k, GENERATOR) for k in range(GROUP_ORDER)}
    assert len(generated) == 32
    assert generated == set(range(32))


def test_shared_element_commutativity():
    """k_A * Q_B == k_B * Q_A mod 32."""
    for k_a in [1, 3, 5, 7, 11, 13, 17, 19]:
        for k_b in [1, 3, 5, 7, 11, 13, 17, 19]:
            q_a = scalar_mult(k_a, GENERATOR)
            q_b = scalar_mult(k_b, GENERATOR)
            s_a = derive_shared_element(k_a, q_b)
            s_b = derive_shared_element(k_b, q_a)
            assert s_a == s_b
            assert s_a == (k_a * k_b * GENERATOR) % GROUP_ORDER


def test_modular_inverse_rejection_for_non_coprime():
    """Non-coprime inputs (even numbers mod 32) must raise ValueError."""
    # Coprimes succeed
    for odd in [1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31]:
        inv = mod_inverse(odd, GROUP_ORDER)
        assert (odd * inv) % GROUP_ORDER == 1

    # Non-coprimes fail
    for even in [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32]:
        with pytest.raises(ValueError):
            mod_inverse(even, GROUP_ORDER)


def test_roundtrip_encrypt_decrypt():
    """AES-256-GCM encrypt and decrypt round trip."""
    key = b"\x01" * 32
    plaintext = b"attack_at_dawn_quantum_post_compromise"
    nonce, ciphertext = encrypt_payload(key, plaintext, aad=FIXED_AAD)
    recovered = decrypt_payload(key, nonce, ciphertext, aad=FIXED_AAD)
    assert recovered == plaintext


def test_tampered_ciphertext_fails_authentication():
    """Tampered ciphertext must raise InvalidTag / authentication failure, never wrong plaintext."""
    from cryptography.exceptions import InvalidTag

    key = b"\x02" * 32
    plaintext = b"confidential_payload"
    nonce, ciphertext = encrypt_payload(key, plaintext, aad=FIXED_AAD)

    # Flip a single bit in the ciphertext
    tampered_bytes = bytearray(ciphertext)
    tampered_bytes[0] ^= 0x01
    tampered = bytes(tampered_bytes)

    with pytest.raises(InvalidTag):
        decrypt_payload(key, nonce, tampered, aad=FIXED_AAD)
