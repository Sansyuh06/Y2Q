import io
import json
import random
import sys
from y2q.cli import (
    format_batch_csv,
    format_human_readable,
    main,
    make_invalid_target_record,
    sort_records,
)


def test_json_schema_shape():
    dummy = {
        "target": "example.com",
        "port": 443,
        "timestamp": "2026-10-27T14:22:01Z",
        "scanner": {"openssl_version": "OpenSSL 3.5.7"},
        "default": {
            "group": "X25519MLKEM768",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "outcome": "NEGOTIATED",
            "error_category": None,
            "reason": None,
            "evidence": None,
        },
        "forced_hybrid": {
            "group": "X25519MLKEM768",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "outcome": "NEGOTIATED",
            "error_category": None,
            "reason": None,
            "evidence": None,
        },
        "forced_classical": {
            "group": "X25519",
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "outcome": "NEGOTIATED",
            "error_category": None,
            "reason": None,
            "evidence": None,
        },
        "verdict": "HYBRID_NEGOTIATED",
    }
    # Verify exact schema keys
    assert set(dummy.keys()) == {
        "target",
        "port",
        "timestamp",
        "scanner",
        "default",
        "forced_hybrid",
        "forced_classical",
        "verdict",
    }
    for sub in ("default", "forced_hybrid", "forced_classical"):
        assert set(dummy[sub].keys()) == {
            "group",
            "tls_version",
            "cipher",
            "outcome",
            "error_category",
            "reason",
            "evidence",
        }


def test_csv_header_and_column_order():
    records = [
        {
            "target": "example.com",
            "port": 443,
            "timestamp": "2026-10-27T14:22:01Z",
            "scanner": {"openssl_version": "OpenSSL 3.5.7"},
            "default": {
                "group": "X25519MLKEM768",
                "tls_version": "TLSv1.3",
                "cipher": "TLS_AES_256_GCM_SHA384",
                "outcome": "NEGOTIATED",
                "error_category": None,
            },
            "forced_hybrid": {"group": "X25519MLKEM768", "outcome": "NEGOTIATED"},
            "forced_classical": {"group": "X25519", "outcome": "NEGOTIATED"},
            "verdict": "HYBRID_NEGOTIATED",
        }
    ]
    csv_text = format_batch_csv(records)
    lines = csv_text.strip().split("\n")
    expected_header = (
        "target,port,default_group,default_outcome,forced_hybrid_outcome,"
        "forced_classical_outcome,tls_version,cipher,verdict,error_category,timestamp"
    )
    assert lines[0] == expected_header
    assert lines[1].startswith("example.com,443,X25519MLKEM768,NEGOTIATED,NEGOTIATED,NEGOTIATED,TLSv1.3,TLS_AES_256_GCM_SHA384,HYBRID_NEGOTIATED,,2026-10-27T14:22:01Z")


def test_deterministic_sort_order():
    r1 = {"target": "b.example.com", "port": 443, "verdict": "HYBRID_NEGOTIATED"}
    r2 = {"target": "a.example.com", "port": 443, "verdict": "HYBRID_NEGOTIATED"}
    r3 = {"target": "z.example.com", "port": 443, "verdict": "CLASSICAL_ONLY"}
    r4 = {"target": "m.example.com", "port": 443, "verdict": "INCONCLUSIVE"}
    r5 = {"target": "a.example.com", "port": 8443, "verdict": "HYBRID_NEGOTIATED"}

    original = [r1, r2, r3, r4, r5]
    shuffled = list(original)
    random.seed(42)
    random.shuffle(shuffled)

    sorted_res = sort_records(shuffled)
    targets_ordered = [(r["target"], r["port"], r["verdict"]) for r in sorted_res]

    assert targets_ordered == [
        ("a.example.com", 443, "HYBRID_NEGOTIATED"),
        ("a.example.com", 8443, "HYBRID_NEGOTIATED"),
        ("b.example.com", 443, "HYBRID_NEGOTIATED"),
        ("z.example.com", 443, "CLASSICAL_ONLY"),
        ("m.example.com", 443, "INCONCLUSIVE"),
    ]


def test_batch_continues_after_failing_target(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "-invalid-flag-host\n"
        "broken..label\n",
        encoding="utf-8",
    )

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = stdout_buf, stderr_buf
        exit_code = main(["scan", "--file", str(target_file), "--json"])
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    # Both invalid targets should be reported as invalid_input, one JSON per line
    assert exit_code == 2
    out_lines = stdout_buf.getvalue().strip().split("\n")
    assert len(out_lines) == 2

    row1 = json.loads(out_lines[0])
    row2 = json.loads(out_lines[1])
    assert row1["verdict"] == "INCONCLUSIVE"
    assert row1["default"]["error_category"] == "invalid_input"
    assert row2["verdict"] == "INCONCLUSIVE"
    assert row2["default"]["error_category"] == "invalid_input"


def test_cli_single_invalid_target_rejection():
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = stdout_buf, stderr_buf
        exit_code = main(["scan", "-servername", "--json"])
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    assert exit_code == 2
    # Exactly one JSON object on stdout
    data = json.loads(stdout_buf.getvalue())
    assert data["target"] == "-servername"
    assert data["verdict"] == "INCONCLUSIVE"
    assert data["default"]["error_category"] == "invalid_input"
