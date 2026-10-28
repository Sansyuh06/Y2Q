import pytest
from y2q.hndl.toygroup import GENERATOR, GROUP_ORDER, scalar_mult
from y2q.hndl.verify import verify_and_decrypt, verify_public_relation


def test_public_relation_wrong_candidate_rejected():
    """A wrong candidate scalar must be rejected by verify_public_relation."""
    true_k = 7
    target_q = scalar_mult(true_k, GENERATOR)

    # Wrong candidates
    for wrong_k in [1, 2, 3, 4, 5, 6, 8, 9, 15, 23, 31]:
        assert not verify_public_relation(wrong_k, target_q, GENERATOR, GROUP_ORDER)

    # True candidate accepted
    assert verify_public_relation(true_k, target_q, GENERATOR, GROUP_ORDER)


def test_boundary_candidates_rejected_without_silent_reduction():
    """k = 0, k = 32, and k = 33 must be rejected rather than silently reduced mod 32."""
    g = 5
    q_1 = scalar_mult(1, g)  # (1 * 5) % 32 = 5
    q_0 = 0

    # k = 0 should be rejected
    assert not verify_public_relation(0, q_0, g, 32)
    assert not verify_public_relation(0, q_1, g, 32)

    # k = 32 should be rejected
    assert not verify_public_relation(32, q_0, g, 32)

    # k = 33 (which is 1 mod 32) must NOT be silently reduced to 1
    assert not verify_public_relation(33, q_1, g, 32)

    # Negative numbers must also be rejected
    assert not verify_public_relation(-1, q_1, g, 32)


def test_verify_and_decrypt_stops_when_public_relation_fails():
    """verify_and_decrypt must set REJECTED_BY_PUBLIC_RELATION and not decrypt."""
    true_k = 11
    target_q = scalar_mult(true_k, GENERATOR)
    peer_q = scalar_mult(3, GENERATOR)

    res = verify_and_decrypt(
        candidate_k=99,  # invalid candidate
        target_public_element=target_q,
        peer_public_element=peer_q,
        salt=b"\x00" * 16,
        nonce=b"\x00" * 12,
        ciphertext=b"\x00" * 32,
        expected_plaintext_sha256="abc",
    )
    assert res.public_relation_status == "REJECTED_BY_PUBLIC_RELATION"
    assert res.decrypted is False
    assert res.sha256_match is False
