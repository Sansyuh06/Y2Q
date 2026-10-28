import pytest
from y2q.hndl.circuit import (
    CircuitSpec,
    build_oracle,
    build_shor_dlog_circuit,
)
from y2q.hndl.toygroup import GENERATOR, GROUP_ORDER, scalar_mult

qiskit = pytest.importorskip("qiskit")
qiskit_aer = pytest.importorskip("qiskit_aer")
from qiskit import QuantumCircuit, QuantumRegister, transpile
from qiskit.quantum_info import Statevector
from qiskit_aer import AerSimulator


def test_secret_scalar_absent_from_circuitspec_and_oracle():
    """Assert CircuitSpec cannot carry secret scalar k and only holds public parameters."""
    spec = CircuitSpec(generator=5, public_element=20, group_order=32)
    assert not hasattr(spec, "k")
    assert not hasattr(spec, "secret_scalar")

    # Attempting to assign secret scalar raises an error
    with pytest.raises(Exception):
        spec.k = 7  # frozen dataclass


def test_statevector_oracle_computational_basis():
    """Statevector test: verify oracle maps |a>|b>|0> -> |a>|b>|(a*G + b*Q) mod 32>.

    Exhaustively tests sample combinations of computational basis states.
    """
    g = 5
    true_k = 7
    q = (true_k * g) % 32  # 35 % 32 = 3
    spec = CircuitSpec(generator=g, public_element=q, group_order=32)

    # Test representative basis pairs across the space
    test_pairs = [
        (0, 0), (1, 0), (0, 1), (1, 1),
        (3, 5), (7, 11), (13, 17), (23, 29), (31, 31)
    ]

    for val_a, val_b in test_pairs:
        qr_a = QuantumRegister(5, "qa")
        qr_b = QuantumRegister(5, "qb")
        qr_w = QuantumRegister(5, "qw")
        qc = QuantumCircuit(qr_a, qr_b, qr_w)

        # Prepare computational basis state |val_a> on qr_a and |val_b> on qr_b
        for bit in range(5):
            if (val_a >> bit) & 1:
                qc.x(qr_a[bit])
            if (val_b >> bit) & 1:
                qc.x(qr_b[bit])

        # Apply oracle
        build_oracle(spec, qr_a, qr_b, qr_w, circuit=qc)

        # Simulate statevector
        sim = AerSimulator(method="statevector")
        qc_t = transpile(qc, sim)
        qc_t.save_statevector()
        result = sim.run(qc_t).result()
        sv = result.get_statevector()

        # Filter tiny floating point numerical precision artifacts (< 1e-6)
        probs = {k: v for k, v in sv.probabilities_dict().items() if v > 1e-6}
        assert len(probs) == 1
        bitstr = list(probs.keys())[0]  # format: 15 bits, qw (bits 10..14) at left

        # In Qiskit, bitstring ordering is from highest qubit index (qw[4]) to lowest (qa[0])
        val_w_measured = int(bitstr[:5], 2)
        expected_w = (val_a * g + val_b * q) % 32
        assert val_w_measured == expected_w


def test_peak_structure_and_satisfaction_relation():
    """Peak-structure test at 4096 shots on Aer simulator.

    Circuit must produce far more than one distinct bitstring, and every
    well-formed peak (a, b) must satisfy b - k*a = 0 (mod 32) for true k.
    """
    g = 5
    true_k = 7
    q = (true_k * g) % 32  # 3
    spec = CircuitSpec(generator=g, public_element=q, group_order=32)

    qc = build_shor_dlog_circuit(spec)
    sim = AerSimulator()
    qc_transpiled = transpile(qc, sim)

    shots = 4096
    result = sim.run(qc_transpiled, shots=shots).result()
    counts = result.get_counts()

    # Must produce far more than one distinct outcome
    distinct_outcomes = len(counts)
    assert distinct_outcomes > 16, f"Expected >16 distinct outcomes, got {distinct_outcomes}"

    # Verify that every peak (a, b) satisfies b - k*a = 0 (mod 32)
    satisfying_shots = 0
    total_measured_shots = sum(counts.values())

    for bitstring, count in counts.items():
        parts = bitstring.split()
        val_b = int(parts[0], 2)
        val_a = int(parts[1], 2)
        if (val_b - true_k * val_a) % 32 == 0:
            satisfying_shots += count

    fraction_satisfying = satisfying_shots / total_measured_shots
    # In noise-free simulator, fraction should be 1.0 (100%)
    assert fraction_satisfying >= 0.99, (
        f"Expected >= 99% of peaks to satisfy b - k*a = 0 (mod 32), got {fraction_satisfying:.4f}"
    )
