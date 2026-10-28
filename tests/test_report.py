import json
import pytest
from y2q.report import build_unified_report


def test_report_endpoint_verdicts_are_byte_identical_to_scanner_output(tmp_path):
    """Endpoint verdicts in the report must be byte-identical to scanner output, regardless of HNDL outcome."""
    # 1. Create a scanner JSON artifact with various verdicts
    scan_records = [
        {"target": "apple.com", "port": 443, "verdict": "HYBRID_NEGOTIATED"},
        {"target": "amazon.com", "port": 443, "verdict": "CLASSICAL_ONLY"},
        {"target": "hsbc.com", "port": 443, "verdict": "INCONCLUSIVE"},
    ]
    scan_file = tmp_path / "scan.json"
    scan_file.write_text(json.dumps(scan_records), encoding="utf-8")

    # 2. Create HNDL result artifact
    hndl_data = {
        "case_id": "case_test_01",
        "source": "simulator",
        "backend_name": "aer_simulator",
        "job_id": None,
        "candidate_status": "RECOVERED",
        "public_relation_status": "VERIFIED",
        "decryption_status": True,
        "sha256_match": True,
    }
    hndl_file = tmp_path / "hndl-result.json"
    hndl_file.write_text(json.dumps(hndl_data), encoding="utf-8")

    # 3. Build unified report
    report = build_unified_report(scan_file, hndl_file)

    # 4. Assert scanner results in report match original byte-for-byte / value-for-value
    reported_scans = report["scanner_results"]
    assert len(reported_scans) == len(scan_records)
    for orig, rep in zip(scan_records, reported_scans):
        assert orig["verdict"] == rep["verdict"]
        assert orig["target"] == rep["target"]


def test_missing_hardware_run_stated_explicitly_in_limitations(tmp_path):
    """When source is simulator, limitations explicitly state that no hardware run exists."""
    scan_file = tmp_path / "scan.json"
    scan_file.write_text("[]", encoding="utf-8")

    hndl_data = {
        "case_id": "case_sim",
        "source": "simulator",
        "backend_name": "aer_simulator",
        "job_id": None,
    }
    hndl_file = tmp_path / "hndl-sim.json"
    hndl_file.write_text(json.dumps(hndl_data), encoding="utf-8")

    report = build_unified_report(scan_file, hndl_file)
    limitations_text = " ".join(report["limitations"])
    assert "No quantum hardware run exists" in limitations_text
    assert "Aer simulator" in limitations_text


def test_separate_top_level_keys_in_unified_report(tmp_path):
    """Unified report must keep scanner results and HNDL experiment in separate top-level keys."""
    scan_file = tmp_path / "scan.json"
    scan_file.write_text("[]", encoding="utf-8")
    hndl_file = tmp_path / "hndl.json"
    hndl_file.write_text("{}", encoding="utf-8")

    report = build_unified_report(scan_file, hndl_file)
    assert "provenance" in report
    assert "limitations" in report
    assert "scanner_results" in report
    assert "hndl_experiment" in report
