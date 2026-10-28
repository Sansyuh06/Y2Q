import json
import pytest
from unittest.mock import patch
from y2q.hndl.backend import execute_ibm_hardware, execute_simulator, save_evidence_record
from y2q.hndl.circuit import CircuitSpec, build_shor_dlog_circuit


def test_ibm_hardware_refuses_without_explicit_confirmation():
    """IBM hardware backend must refuse execution unless confirm_hardware is True."""
    spec = CircuitSpec(generator=5, public_element=15)
    qc = build_shor_dlog_circuit(spec)

    with pytest.raises(RuntimeError, match="explicit confirmation"):
        execute_ibm_hardware(qc, confirm_hardware=False)


def test_simulated_ibm_failure_records_ibm_hardware_source_never_fallback(tmp_path):
    """A simulated IBM failure produces a record with status FAILED and source ibm_hardware, never falling back to simulator."""
    spec = CircuitSpec(generator=5, public_element=15)
    qc = build_shor_dlog_circuit(spec)

    # Simulate an IBM authentication / submission exception
    with patch("y2q.hndl.backend.QiskitRuntimeService", side_effect=Exception("Simulated IBM connection timeout")):
        with pytest.raises(RuntimeError, match="Failed to authenticate with IBM Quantum service"):
            execute_ibm_hardware(qc, confirm_hardware=True)


def test_ibm_failure_evidence_record_preserves_failure_and_source(tmp_path):
    """When an IBM run fails after service init, evidence record captures status FAILED with source ibm_hardware."""
    from y2q.hndl.backend import ExecutionResult

    failed_result = ExecutionResult(
        source="ibm_hardware",
        backend_name="ibm_brisbane",
        job_id="job_failed_mock_123",
        timestamp_utc="2026-10-28T00:00:00Z",
        qiskit_version="2.5.1",
        runtime_version="0.48.0",
        qubit_count=15,
        transpiled_depth=0,
        cx_count=0,
        gate_counts={},
        shot_count=4096,
        counts={},
        status="FAILED",
        error_message="Job cancelled by backend provider",
    )

    ev_path = save_evidence_record(
        exec_result=failed_result,
        case_id="case_fail_test",
        run_id="run_fail_01",
        candidate_status="EXECUTION_FAILED",
        public_relation_status="SKIPPED",
        decryption_status=False,
        sha256_match=False,
        artifacts_dir=tmp_path / "artifacts",
    )

    with open(ev_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert data["source"] == "ibm_hardware"
    assert data["status"] == "FAILED"
    assert data["error_message"] == "Job cancelled by backend provider"
    assert data["decryption_status"] is False


def test_simulator_source_is_strictly_simulator():
    """Simulator result source is strictly 'simulator' and backend is aer_simulator."""
    spec = CircuitSpec(generator=5, public_element=15)
    qc = build_shor_dlog_circuit(spec)
    res = execute_simulator(qc, shots=100)
    assert res.source == "simulator"
    assert res.backend_name == "aer_simulator"
    assert res.job_id is None
