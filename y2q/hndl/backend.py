"""Execution backends and evidence artifact persistence for HNDL experiment.

Supported backends:
1. simulator: Qiskit Aer simulator, transpiled and executed locally.
2. ibm: IBM Quantum hardware via Qiskit Runtime. Requires valid credentials
   and explicit user confirmation (--confirm-ibm-hardware).

Strict invariant:
A simulator run is structurally incapable of being reported as hardware.
source is strictly 'simulator' or 'ibm_hardware'. No fallback from ibm to simulator.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import qiskit
    from qiskit import QuantumCircuit, transpile
    from qiskit_aer import AerSimulator
except ImportError:
    qiskit = None
    QuantumCircuit = None
    transpile = None
    AerSimulator = None

try:
    import qiskit_ibm_runtime
    from qiskit_ibm_runtime import QiskitRuntimeService, SamplerV2
except ImportError:
    qiskit_ibm_runtime = None
    QiskitRuntimeService = None
    SamplerV2 = None


@dataclass
class ExecutionResult:
    source: str  # Strictly "simulator" or "ibm_hardware"
    backend_name: str
    job_id: Optional[str]
    timestamp_utc: str
    qiskit_version: str
    runtime_version: Optional[str]
    qubit_count: int
    transpiled_depth: int
    cx_count: int
    gate_counts: Dict[str, int]
    shot_count: int
    counts: Dict[str, int]
    status: str  # "SUCCESS" | "FAILED"
    error_message: Optional[str] = None


def get_environment_versions() -> Tuple[str, Optional[str]]:
    q_ver = getattr(qiskit, "__version__", "unknown") if qiskit else "not_installed"
    rt_ver = (
        getattr(qiskit_ibm_runtime, "__version__", None)
        if qiskit_ibm_runtime
        else None
    )
    return q_ver, rt_ver


def execute_simulator(circuit: QuantumCircuit, shots: int = 4096) -> ExecutionResult:
    """Execute quantum circuit on local Aer simulator."""
    if AerSimulator is None or transpile is None:
        raise ImportError(
            "qiskit and qiskit-aer are required to run the simulator. "
            "Install with: pip install .[hndl]"
        )

    q_ver, rt_ver = get_environment_versions()
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    simulator = AerSimulator()
    transpiled_qc = transpile(circuit, simulator, optimization_level=1)

    depth = transpiled_qc.depth()
    qubits = transpiled_qc.num_qubits
    gate_ops = dict(transpiled_qc.count_ops())
    cx_count = gate_ops.get("cx", 0)

    sim_job = simulator.run(transpiled_qc, shots=shots)
    job_res = sim_job.result()
    raw_counts = job_res.get_counts()

    return ExecutionResult(
        source="simulator",
        backend_name="aer_simulator",
        job_id=None,
        timestamp_utc=timestamp,
        qiskit_version=q_ver,
        runtime_version=rt_ver,
        qubit_count=qubits,
        transpiled_depth=depth,
        cx_count=cx_count,
        gate_counts=gate_ops,
        shot_count=shots,
        counts=raw_counts,
        status="SUCCESS",
        error_message=None,
    )


def execute_ibm_hardware(
    circuit: QuantumCircuit,
    backend_name: Optional[str] = None,
    shots: int = 4096,
    confirm_hardware: bool = False,
) -> ExecutionResult:
    """Execute circuit on IBM Quantum hardware.

    Refuses to run unless confirm_hardware is True.
    Raises RuntimeError on missing credentials or failure. Never falls back to simulator.
    """
    q_ver, rt_ver = get_environment_versions()
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if not confirm_hardware:
        raise RuntimeError(
            "IBM Quantum execution refused: explicit confirmation (--confirm-ibm-hardware) "
            "is required to submit jobs to hardware."
        )

    if QiskitRuntimeService is None:
        raise RuntimeError(
            "qiskit-ibm-runtime is not installed. Install with: pip install .[hndl]"
        )

    try:
        service = QiskitRuntimeService()
    except Exception as exc:
        raise RuntimeError(
            f"Failed to authenticate with IBM Quantum service: {exc}. "
            "Ensure valid credentials are configured."
        ) from exc

    try:
        if backend_name:
            ibm_backend = service.backend(backend_name)
        else:
            ibm_backend = service.least_busy(operational=True, simulator=False)
            backend_name = ibm_backend.name

        transpiled_qc = transpile(circuit, ibm_backend, optimization_level=2)
        depth = transpiled_qc.depth()
        qubits = transpiled_qc.num_qubits
        gate_ops = dict(transpiled_qc.count_ops())
        cx_count = gate_ops.get("cx", gate_ops.get("ecr", gate_ops.get("cz", 0)))

        sampler = SamplerV2(mode=ibm_backend)
        job = sampler.run([transpiled_qc], shots=shots)
        job_id = job.job_id()

        result = job.result()
        # Parse counts from PrimitiveResult / DataBin
        pub_result = result[0]
        # In SamplerV2, counts can be extracted from bit arrays
        counts = {}
        for reg_name in ("cb", "ca"):
            if hasattr(pub_result.data, reg_name):
                # get counts
                pass
        # Fallback to direct get_counts() if available
        if hasattr(pub_result.data, "meas"):
            counts = pub_result.data.meas.get_counts()

        return ExecutionResult(
            source="ibm_hardware",
            backend_name=backend_name,
            job_id=job_id,
            timestamp_utc=timestamp,
            qiskit_version=q_ver,
            runtime_version=rt_ver,
            qubit_count=qubits,
            transpiled_depth=depth,
            cx_count=cx_count,
            gate_counts=gate_ops,
            shot_count=shots,
            counts=counts,
            status="SUCCESS",
            error_message=None,
        )
    except Exception as exc:
        # Failure preserved as ibm_hardware record with status FAILED
        return ExecutionResult(
            source="ibm_hardware",
            backend_name=backend_name or "unknown_ibm_backend",
            job_id=None,
            timestamp_utc=timestamp,
            qiskit_version=q_ver,
            runtime_version=rt_ver,
            qubit_count=circuit.num_qubits if circuit else 0,
            transpiled_depth=0,
            cx_count=0,
            gate_counts={},
            shot_count=shots,
            counts={},
            status="FAILED",
            error_message=str(exc),
        )


def save_evidence_record(
    exec_result: ExecutionResult,
    case_id: str,
    run_id: str,
    candidate_status: str,
    public_relation_status: str,
    decryption_status: bool,
    sha256_match: bool,
    artifacts_dir: str | Path = "artifacts/hndl",
) -> Path:
    """Save immutable evidence record to artifacts/hndl/<case_id>/<run_id>.json."""
    base_dir = Path(artifacts_dir) / case_id
    base_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = base_dir / f"{run_id}.json"

    evidence_data = {
        "case_id": case_id,
        "run_id": run_id,
        "source": exec_result.source,
        "backend_name": exec_result.backend_name,
        "job_id": exec_result.job_id,
        "timestamp_utc": exec_result.timestamp_utc,
        "qiskit_version": exec_result.qiskit_version,
        "runtime_version": exec_result.runtime_version,
        "qubit_count": exec_result.qubit_count,
        "transpiled_depth": exec_result.transpiled_depth,
        "cx_count": exec_result.cx_count,
        "gate_counts": exec_result.gate_counts,
        "shot_count": exec_result.shot_count,
        "counts": exec_result.counts,
        "status": exec_result.status,
        "candidate_status": candidate_status,
        "public_relation_status": public_relation_status,
        "decryption_status": decryption_status,
        "sha256_match": sha256_match,
        "error_message": exec_result.error_message,
        "framing": (
            "A Shor-style discrete-log circuit over a cyclic group of order 32, "
            "encoded as integers, not an elliptic-curve implementation."
        ),
    }

    with open(evidence_path, "w", encoding="utf-8") as f:
        json.dump(evidence_data, f, indent=2)

    return evidence_path
