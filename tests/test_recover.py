import pytest
from y2q.hndl.recover import recover_candidate_scalar


def test_recover_candidate_from_known_peak_structure():
    """Correct k extracted from synthetic counts generated with known peak structure."""
    true_k = 19
    modulus = 32
    counts = {}

    # Generate synthetic peaks satisfying b = (true_k * a) % 32 for all 32 values of a
    for val_a in range(32):
        val_b = (true_k * val_a) % modulus
        # format 'cb ca' (5 bits each)
        bitstr = f"{val_b:05b} {val_a:05b}"
        counts[bitstr] = 128  # 32 * 128 = 4096 shots

    res = recover_candidate_scalar(counts, modulus=modulus)
    assert res.status == "RECOVERED"
    assert res.candidate_k == true_k
    # All 16 odd (coprime) values of a yield true_k: 16 * 128 = 2048 shots (50% of total)
    assert res.top_candidate_shots == 2048
    assert res.fraction == 0.50


def test_recover_candidate_returns_not_recovered_for_flat_distribution():
    """NOT_RECOVERED returned for flat/uniform distribution over all 1024 bitstrings."""
    modulus = 32
    flat_counts = {}

    # Uniform distribution across all 1024 possible 10-bit states (b, a)
    for b in range(32):
        for a in range(32):
            bitstr = f"{b:05b} {a:05b}"
            flat_counts[bitstr] = 4  # 1024 * 4 = 4096 shots

    # In a uniform distribution, the coprime samples are evenly spread across all 32 candidate scalars
    # (each scalar gets 1/32 of coprime shots, i.e., 2048 / 32 = 64 shots, or fraction 64/4096 = 0.0156)
    # This is well below the threshold fraction of 0.10.
    res = recover_candidate_scalar(flat_counts, modulus=modulus)
    assert res.status == "NOT_RECOVERED"
    assert res.candidate_k is None
    assert "below threshold" in (res.reason or "")
