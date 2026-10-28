"""Quantum circuit construction for Shor-style discrete-log over Z_32.

Implements the quantum circuit from Tippeconnic (arXiv:2507.10592), CC BY 4.0:
"A Shor-style discrete-log circuit over a cyclic group of order 32,
encoded as integers, not an elliptic-curve implementation."

Registers:
- qr_a: 5-qubit exponent register for generator G
- qr_b: 5-qubit exponent register for public target Q
- qr_w: 5-qubit work register for Draper QFT adder (a*G + b*Q mod 32)
Total qubits: 15.

The secret scalar k is never passed to or stored within the circuit or CircuitSpec.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Tuple

try:
    from qiskit import ClassicalRegister, QuantumCircuit, QuantumRegister
    from qiskit.circuit.library import QFTGate
except ImportError:
    # Allow importing module for docstrings / inspection without qiskit installed
    ClassicalRegister = None
    QuantumCircuit = None
    QuantumRegister = None
    QFTGate = None


@dataclass(frozen=True)
class CircuitSpec:
    """Public specification for the discrete-log quantum circuit.

    Only public group parameters are permitted. Secret scalar k is strictly absent.
    """
    generator: int = 5
    public_element: int = 0
    group_order: int = 32
    num_qubits_exponent: int = 5
    num_qubits_work: int = 5

    def __post_init__(self):
        if hasattr(self, "k") or hasattr(self, "secret_scalar"):
            raise ValueError("Secret scalar must not be part of CircuitSpec")


def _require_qiskit():
    if QuantumCircuit is None:
        raise ImportError(
            "qiskit is required to build HNDL quantum circuits. "
            "Install with: pip install .[hndl]"
        )


def _draper_add_constant(
    qc: QuantumCircuit,
    qr_ctrl: QuantumRegister,
    ctrl_bit: int,
    qr_w: QuantumRegister,
    constant: int,
    modulus: int = 32,
) -> None:
    """Controlled constant addition into Fourier-transformed register qr_w."""
    c = constant % modulus
    num_qubits = len(qr_w)
    for m in range(num_qubits):
        angle = (2.0 * math.pi * c * (2**m)) / modulus
        qc.cp(angle, qr_ctrl[ctrl_bit], qr_w[m])


def build_oracle(
    spec: CircuitSpec,
    qr_a: QuantumRegister,
    qr_b: QuantumRegister,
    qr_w: QuantumRegister,
    circuit: QuantumCircuit | None = None,
) -> QuantumCircuit:
    """Build the oracle mapping |a>|b>|0> -> |a>|b>|(a*G + b*Q) mod 32>.

    Uses a controlled Draper QFT adder. Does not synthesize generic permutation matrices.
    """
    _require_qiskit()
    n = spec.num_qubits_exponent
    modulus = spec.group_order
    g = spec.generator
    q = spec.public_element

    if circuit is None:
        circuit = QuantumCircuit(qr_a, qr_b, qr_w, name="oracle")

    # Transform work register into Fourier basis
    circuit.append(QFTGate(n), qr_w)

    # Controlled addition of a * G: for each bit i of qr_a, add (2^i * G) mod 32
    for i in range(n):
        term = ((2**i) * g) % modulus
        _draper_add_constant(circuit, qr_a, i, qr_w, term, modulus)

    # Controlled addition of b * Q: for each bit j of qr_b, add (2^j * Q) mod 32
    for j in range(n):
        term = ((2**j) * q) % modulus
        _draper_add_constant(circuit, qr_b, j, qr_w, term, modulus)

    # Inverse QFT on work register to return to computational basis
    circuit.append(QFTGate(n).inverse(), qr_w)

    return circuit


def build_shor_dlog_circuit(spec: CircuitSpec) -> QuantumCircuit:
    """Construct the full Shor discrete-log circuit for public element Q.

    Architecture:
    1. qr_a (5 qubits), qr_b (5 qubits), qr_w (5 qubits)
    2. Hadamard on qr_a and qr_b
    3. Oracle: |a>|b>|0> -> |a>|b>|(a*G + b*Q) mod 32>
    4. Inverse QFT on qr_a and qr_b
    5. Measure qr_a and qr_b
    """
    _require_qiskit()
    n = spec.num_qubits_exponent
    qr_a = QuantumRegister(n, name="qa")
    qr_b = QuantumRegister(n, name="qb")
    qr_w = QuantumRegister(n, name="qw")
    cr_a = ClassicalRegister(n, name="ca")
    cr_b = ClassicalRegister(n, name="cb")

    qc = QuantumCircuit(qr_a, qr_b, qr_w, cr_a, cr_b, name=f"shor_dlog_z{spec.group_order}")

    # Step 1: Create uniform superposition on exponent registers
    qc.h(qr_a)
    qc.h(qr_b)

    # Step 2: Apply Draper QFT addition oracle
    build_oracle(spec, qr_a, qr_b, qr_w, circuit=qc)

    # Step 3: Inverse QFT on exponent registers
    qc.append(QFTGate(n).inverse(), qr_a)
    qc.append(QFTGate(n).inverse(), qr_b)

    # Step 4: Measurement
    qc.measure(qr_a, cr_a)
    qc.measure(qr_b, cr_b)

    return qc
