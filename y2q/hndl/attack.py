"""Attack orchestration for HNDL experiment.

Reads challenge.json ONLY. Never accesses, opens, or prints truth.json.
Builds the discrete-log quantum circuit from public parameters,
executes on the requested backend, recovers candidate scalar, verifies
against public relation, attempts AES-GCM decryption, and writes evidence.

Framing: This is a Shor-style discrete-log circuit over a cyclic group of
order 32, encoded as integers, not an elliptic-curve implementation.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

from y2q.hndl.backend import (
    ExecutionResult,
    execute_ibm_hardware,
    execute_simulator,
    save_evidence_record,
)
from y2q.hndl.circuit import CircuitSpec, build_shor_dlog_circuit
from y2q.hndl.recover import recover_candidate_scalar
from y2q.hndl.verify import verify_and_decrypt


def run_hndl_attack(
    challenge_path: str | Path,
    backend: str = "simulator",
    backend_name: Optional[str] = None,
    shots: int = 4096,
    confirm_ibm_hardware: bool = False,
    artifacts_dir: str | Path = "artifacts/hndl",
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute HNDL discrete-log attack using challenge.json only.

    Strict invariant: Never opens or reads truth.json.
    """
    challenge_file = Path(challenge_path)
    if not challenge_file.is_file():
        raise FileNotFoundError(f"Challenge file not found: {challenge_file}")

    with open(challenge_file, "r", encoding="utf-8") as f:
        challenge = json.load(f)

    case_id = challenge.get("case_id", "unknown_case")
    if run_id is None:
        run_id = f"run_{uuid.uuid4().hex[:8]}"

    # Extract public parameters
    generator = challenge["generator"]
    target_public = challenge["alice_public"]
    peer_public = challenge["bob_public"]
    group_order = challenge.get("group_order", 32)
    salt = bytes.fromhex(challenge["salt"])
    nonce = bytes.fromhex(challenge["nonce"])
    ciphertext = bytes.fromhex(challenge["ciphertext"])
    expected_sha256 = challenge["expected_plaintext_sha256"]
    aad = bytes.fromhex(challenge.get("aad", "")) if challenge.get("aad") else b"Y2Q-HNDL-AAD-v1"

    # 1. Build circuit from public parameters ONLY
    spec = CircuitSpec(
        generator=generator,
        public_element=target_public,
        group_order=group_order,
    )
    circuit = build_shor_dlog_circuit(spec)

    # 2. Execute on specified backend
    if backend == "simulator":
        exec_result = execute_simulator(circuit, shots=shots)
    elif backend == "ibm":
        exec_result = execute_ibm_hardware(
            circuit,
            backend_name=backend_name,
            shots=shots,
            confirm_hardware=confirm_ibm_hardware,
        )
    else:
        raise ValueError(f"Unknown backend '{backend}'; choose 'simulator' or 'ibm'")

    # 3. Post-processing and recovery
    if exec_result.status == "SUCCESS":
        recovery = recover_candidate_scalar(exec_result.counts, modulus=group_order)
        candidate_status = recovery.status
        candidate_k = recovery.candidate_k
    else:
        candidate_status = "EXECUTION_FAILED"
        candidate_k = None

    # 4. Public relation verification & authenticated decryption
    if candidate_k is not None:
        verif = verify_and_decrypt(
            candidate_k=candidate_k,
            target_public_element=target_public,
            peer_public_element=peer_public,
            salt=salt,
            nonce=nonce,
            ciphertext=ciphertext,
            expected_plaintext_sha256=expected_sha256,
            generator=generator,
            group_order=group_order,
            aad=aad,
        )
        pr_status = verif.public_relation_status
        decrypted = verif.decrypted
        sha256_match = verif.sha256_match
    else:
        pr_status = "SKIPPED_NO_CANDIDATE"
        decrypted = False
        sha256_match = False

    # 5. Persist evidence artifact
    evidence_path = save_evidence_record(
        exec_result=exec_result,
        case_id=case_id,
        run_id=run_id,
        candidate_status=candidate_status,
        public_relation_status=pr_status,
        decryption_status=decrypted,
        sha256_match=sha256_match,
        artifacts_dir=artifacts_dir,
    )

    return {
        "case_id": case_id,
        "run_id": run_id,
        "evidence_file": str(evidence_path),
        "source": exec_result.source,
        "backend_name": exec_result.backend_name,
        "job_id": exec_result.job_id,
        "status": exec_result.status,
        "qubit_count": exec_result.qubit_count,
        "transpiled_depth": exec_result.transpiled_depth,
        "cx_count": exec_result.cx_count,
        "candidate_k": candidate_k,
        "candidate_status": candidate_status,
        "public_relation_status": pr_status,
        "decrypted": decrypted,
        "sha256_match": sha256_match,
        "error_message": exec_result.error_message,
        "framing": (
            "A Shor-style discrete-log circuit over a cyclic group of order 32, "
            "encoded as integers, not an elliptic-curve implementation."
        ),
    }
