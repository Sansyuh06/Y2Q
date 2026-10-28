"""Unified report generator combining TLS scanner data and HNDL experimental results.

Strictly separates live TLS measurements from controlled lab discrete-log results.
Maintains clear provenance and plain-language limitations.
"""

from __future__ import annotations

import csv
import datetime
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_scan_data(scan_path: str | Path) -> List[Dict[str, Any]]:
    """Load scanner results from JSON, JSONL, or CSV format."""
    p = Path(scan_path)
    if not p.is_file():
        raise FileNotFoundError(f"Scan artifact file not found: {scan_path}")

    content = p.read_text(encoding="utf-8-sig", errors="replace").strip()
    if not content:
        return []

    # Check for JSON array or JSON object
    if content.startswith("["):
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

    if content.startswith("{"):
        # Could be single JSON object or JSON Lines
        lines = [line.strip() for line in content.split("\n") if line.strip()]
        if len(lines) == 1:
            try:
                obj = json.loads(lines[0])
                return [obj]
            except json.JSONDecodeError:
                pass
        else:
            # Try parsing as JSONL
            try:
                return [json.loads(line) for line in lines]
            except json.JSONDecodeError:
                pass

    # Fallback to CSV
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


def load_hndl_data(hndl_path: str | Path) -> Dict[str, Any]:
    """Load HNDL result JSON artifact."""
    p = Path(hndl_path)
    if not p.is_file():
        raise FileNotFoundError(f"HNDL artifact file not found: {hndl_path}")
    return json.loads(p.read_text(encoding="utf-8", errors="replace"))


def generate_limitations(hndl_data: Dict[str, Any]) -> List[str]:
    """Generate explicit plain-language limitations."""
    limitations = [
        (
            "The toy discrete-log circuit operates strictly on an additive cyclic group of "
            "order 32 (integers modulo 32) and cannot decrypt real X25519 (Curve25519) "
            "sessions or elliptic-curve cryptography."
        ),
        (
            "Breaking the classical key-exchange half of X25519MLKEM768 does not reveal "
            "the ML-KEM-768 (lattice-based post-quantum) shared secret, preserving session "
            "confidentiality against classical discrete-log attacks."
        ),
    ]

    hndl_source = hndl_data.get("source")
    hardware_job_id = hndl_data.get("job_id")
    if hndl_source != "ibm_hardware" or not hardware_job_id:
        limitations.append(
            "No quantum hardware run exists. All discrete-log results were obtained "
            "exclusively via local Aer simulator."
        )

    return limitations


def build_unified_report(
    scan_path: str | Path,
    hndl_path: str | Path,
) -> Dict[str, Any]:
    """Build unified report combining scanner measurements and HNDL experimental results."""
    scan_data = load_scan_data(scan_path)
    hndl_data = load_hndl_data(hndl_path)

    timestamp_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    report = {
        "report_id": f"report_{timestamp_utc.replace(':', '').replace('-', '')}",
        "timestamp_utc": timestamp_utc,
        "provenance": {
            "scanner": {
                "source": "live_tls_measurements",
                "vantage_point": "Local scanner host",
                "description": "Live network TLS 1.3 key-exchange group measurements.",
            },
            "hndl": {
                "source": "controlled_lab_experiment",
                "framing": (
                    "A Shor-style discrete-log circuit over a cyclic group of order 32, "
                    "encoded as integers, not an elliptic-curve implementation."
                ),
                "description": "Controlled synthetic discrete-log experiment on Z_32.",
            },
        },
        "limitations": generate_limitations(hndl_data),
        "scanner_results": scan_data,
        "hndl_experiment": hndl_data,
    }
    return report


def format_terminal_summary(report: Dict[str, Any]) -> str:
    """Format human-readable terminal summary."""
    lines = []
    lines.append("=" * 68)
    lines.append("Y2Q UNIFIED EVIDENCE REPORT")
    lines.append("=" * 68)
    lines.append(f"Generated at : {report.get('timestamp_utc')}")
    lines.append("")

    lines.append("[1] TLS Scanner Live Measurements")
    scan_results = report.get("scanner_results", [])
    total_targets = len(scan_results)
    hybrid_count = sum(1 for r in scan_results if r.get("verdict") == "HYBRID_NEGOTIATED")
    classical_count = sum(1 for r in scan_results if r.get("verdict") == "CLASSICAL_ONLY")
    inconclusive_count = sum(1 for r in scan_results if r.get("verdict") == "INCONCLUSIVE")
    lines.append(f"    Total endpoints surveyed : {total_targets}")
    lines.append(f"    HYBRID_NEGOTIATED        : {hybrid_count}")
    lines.append(f"    CLASSICAL_ONLY           : {classical_count}")
    lines.append(f"    INCONCLUSIVE             : {inconclusive_count}")
    lines.append("")

    lines.append("[2] Controlled HNDL Experiment (Z_32)")
    hndl = report.get("hndl_experiment", {})
    lines.append(f"    Backend source           : {hndl.get('source')}")
    lines.append(f"    Backend name             : {hndl.get('backend_name')}")
    lines.append(f"    Hardware job ID          : {hndl.get('job_id') or 'none (simulator)'}")
    lines.append(f"    Qubit count              : {hndl.get('qubit_count')}")
    lines.append(f"    Transpiled depth         : {hndl.get('transpiled_depth')}")
    lines.append(f"    Candidate status         : {hndl.get('candidate_status')}")
    lines.append(f"    Public-relation status   : {hndl.get('public_relation_status')}")
    lines.append(f"    AES-GCM decrypted        : {hndl.get('decryption_status')}")
    lines.append(f"    Plaintext SHA-256 match  : {hndl.get('sha256_match')}")
    lines.append("")

    lines.append("[3] Limitations")
    for lim in report.get("limitations", []):
        lines.append(f"    - {lim}")
    lines.append("=" * 68)

    return "\n".join(lines)
