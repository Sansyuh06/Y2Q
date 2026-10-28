"""Post-processing and recovery of discrete logarithm from quantum measurement counts.

Framing: This is a Shor-style discrete-log circuit over a cyclic group of
order 32, encoded as integers, not an elliptic-curve implementation.

Post-processing algorithm:
1. Parse measurement counts into pairs (a, b).
2. Filter for pairs with gcd(a, 32) == 1 (invertible in Z_32).
3. Compute candidate scalar k = (b * a^-1) mod 32.
4. Aggregate counts per candidate k and rank by frequency.
5. If top candidate meets the constant PEAK_THRESHOLD_FRACTION, return it.
   Otherwise return NOT_RECOVERED.

Strict rules:
- No classical search/enumeration fallback over candidate scalars.
- Constant peak-fraction threshold, not tuned per run.
- Operates on measurement counts only.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Dict, NamedTuple, Optional, Tuple

GROUP_ORDER: int = 32

# Minimum fraction of total measurement shots that the top candidate scalar k
# must account for to be declared recovered.
# In an ideal Shor circuit on Z_32, coprime pairs account for ~50% of total shots
# and 100% of coprime pairs concentrate on the true k.
# In a flat or randomized distribution, candidates are uniformly distributed
# (~1/32 = 0.03125 of coprime shots).
# 0.10 (10% of total shots) cleanly distinguishes genuine quantum interference
# from flat noise without post-hoc tuning.
PEAK_THRESHOLD_FRACTION: float = 0.10


class RecoveryResult(NamedTuple):
    status: str  # "RECOVERED" | "NOT_RECOVERED"
    candidate_k: Optional[int]
    top_candidate_shots: int
    total_shots: int
    fraction: float
    candidate_distribution: Dict[int, int]
    reason: Optional[str] = None


def parse_bitstring_pair(bitstring: str) -> Tuple[int, int]:
    """Parse a measurement bitstring into (a, b) integer values.

    Handles space-separated 'cb ca' (from Qiskit multi-register measurement)
    or continuous bitstrings.
    In Qiskit register order:
      qr_a -> cr_a (least-recent register, printed on right)
      qr_b -> cr_b (most-recent register, printed on left)
    """
    parts = bitstring.strip().split()
    if len(parts) == 2:
        # 'cb ca'
        b_bits, a_bits = parts[0], parts[1]
    elif len(parts) == 1:
        # 10 bits: top 5 bits cb, bottom 5 bits ca
        s = parts[0]
        if len(s) >= 10:
            b_bits = s[:5]
            a_bits = s[5:10]
        else:
            raise ValueError(f"Bitstring '{bitstring}' is too short to parse into (a, b)")
    else:
        raise ValueError(f"Unexpected bitstring format: '{bitstring}'")

    val_a = int(a_bits, 2)
    val_b = int(b_bits, 2)
    return val_a, val_b


def recover_candidate_scalar(
    counts: Dict[str, int],
    modulus: int = GROUP_ORDER,
    threshold_fraction: float = PEAK_THRESHOLD_FRACTION,
) -> RecoveryResult:
    """Recover secret scalar candidate from measurement counts.

    Strictly no classical search over candidate scalars.
    """
    total_shots = sum(counts.values())
    if total_shots == 0:
        return RecoveryResult(
            status="NOT_RECOVERED",
            candidate_k=None,
            top_candidate_shots=0,
            total_shots=0,
            fraction=0.0,
            candidate_distribution={},
            reason="Empty measurement counts",
        )

    candidate_counts: Counter[int] = Counter()

    for bitstring, count in counts.items():
        try:
            val_a, val_b = parse_bitstring_pair(bitstring)
        except ValueError:
            continue

        a_norm = val_a % modulus
        # Requirement: keep peaks with gcd(a, 32) == 1
        if math.gcd(a_norm, modulus) == 1:
            try:
                a_inv = pow(a_norm, -1, modulus)
                cand_k = (val_b * a_inv) % modulus
                candidate_counts[cand_k] += count
            except ValueError:
                continue

    if not candidate_counts:
        return RecoveryResult(
            status="NOT_RECOVERED",
            candidate_k=None,
            top_candidate_shots=0,
            total_shots=total_shots,
            fraction=0.0,
            candidate_distribution={},
            reason="No coprime peaks with gcd(a, 32) == 1 found in counts",
        )

    # Rank by frequency, take the top candidate
    top_candidate, top_shots = candidate_counts.most_common(1)[0]
    fraction = top_shots / total_shots

    if fraction >= threshold_fraction:
        return RecoveryResult(
            status="RECOVERED",
            candidate_k=top_candidate,
            top_candidate_shots=top_shots,
            total_shots=total_shots,
            fraction=fraction,
            candidate_distribution=dict(candidate_counts),
            reason=None,
        )

    return RecoveryResult(
        status="NOT_RECOVERED",
        candidate_k=None,
        top_candidate_shots=top_shots,
        total_shots=total_shots,
        fraction=fraction,
        candidate_distribution=dict(candidate_counts),
        reason=f"Top candidate fraction {fraction:.4f} below threshold {threshold_fraction:.4f}",
    )
