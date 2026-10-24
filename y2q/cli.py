import argparse
import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from y2q.classify import (
    TargetVerdict,
    TestOutcome,
    TestResult,
    classify_test_result,
    derive_target_verdict,
)
from y2q.parse import parse_openssl_output
from y2q.probe import (
    check_native_mlkem_support,
    execute_probe,
    find_openssl_binary,
    get_openssl_version,
)
from y2q.validate import (
    Target,
    parse_target_lines,
    validate_target,
)


def get_current_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def scan_single_target(
    target: Target,
    openssl_bin: str,
    openssl_ver_str: str,
) -> Dict[str, Any]:
    timestamp = get_current_timestamp()

    # Progress diagnostics on stderr only
    sys.stderr.write(f"[*] Scanning {target.connect_target}...\n")
    sys.stderr.flush()

    # 1. Default test
    probe_default = execute_probe(openssl_bin, target, "default")
    parsed_default = parse_openssl_output(probe_default.stdout, probe_default.stderr)
    res_default = classify_test_result(
        parsed_default,
        "default",
        is_timeout=probe_default.is_timeout,
        timeout_reason=probe_default.timeout_reason,
    )

    # 2. Forced Classical test (control)
    probe_classical = execute_probe(openssl_bin, target, "forced_classical")
    parsed_classical = parse_openssl_output(probe_classical.stdout, probe_classical.stderr)
    res_classical = classify_test_result(
        parsed_classical,
        "forced_classical",
        is_timeout=probe_classical.is_timeout,
        timeout_reason=probe_classical.timeout_reason,
    )

    # 3. Forced Hybrid test (evaluated against classical control)
    probe_hybrid = execute_probe(openssl_bin, target, "forced_hybrid")
    parsed_hybrid = parse_openssl_output(probe_hybrid.stdout, probe_hybrid.stderr)
    res_hybrid = classify_test_result(
        parsed_hybrid,
        "forced_hybrid",
        classical_control_outcome=res_classical.outcome,
        is_timeout=probe_hybrid.is_timeout,
        timeout_reason=probe_hybrid.timeout_reason,
    )

    # Verdict derived strictly from default test
    verdict = derive_target_verdict(res_default)

    return {
        "target": target.host,
        "port": target.port,
        "timestamp": timestamp,
        "scanner": {"openssl_version": openssl_ver_str},
        "default": res_default.to_dict(),
        "forced_hybrid": res_hybrid.to_dict(),
        "forced_classical": res_classical.to_dict(),
        "verdict": verdict.value,
    }


def make_invalid_target_record(
    raw_target: str,
    error_msg: str,
    openssl_ver_str: str,
    default_port: int = 443,
) -> Dict[str, Any]:
    timestamp = get_current_timestamp()
    invalid_res = TestResult(
        group=None,
        tls_version=None,
        cipher=None,
        outcome=TestOutcome.INCONCLUSIVE,
        error_category="invalid_input",
        reason=error_msg,
        evidence=None,
    ).to_dict()

    return {
        "target": raw_target,
        "port": default_port,
        "timestamp": timestamp,
        "scanner": {"openssl_version": openssl_ver_str},
        "default": invalid_res,
        "forced_hybrid": invalid_res,
        "forced_classical": invalid_res,
        "verdict": TargetVerdict.INCONCLUSIVE.value,
    }


def format_human_readable(record: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"Y2Q  {record['target']}:{record['port']}")
    lines.append(f"scanner : {record['scanner']['openssl_version']}")

    def format_test_row(name: str, test_data: dict) -> str:
        group_str = test_data.get("group") or "-"
        outcome = test_data.get("outcome")
        if outcome == "NEGOTIATED":
            if test_data.get("group") == "X25519MLKEM768":
                status = "hybrid negotiated" if name == "default" else "accepted"
            else:
                status = "classical negotiated" if name == "default" else "accepted"
        elif outcome == "REJECTED":
            status = f"rejected ({test_data.get('reason') or 'group not supported'})"
        else:
            status = f"inconclusive ({test_data.get('reason') or 'no group negotiated'})"
        return f"{name:<16} {group_str:<16} {status}"

    lines.append(format_test_row("default", record["default"]))
    lines.append(format_test_row("forced_hybrid", record["forced_hybrid"]))
    lines.append(format_test_row("forced_classical", record["forced_classical"]))

    tls_ver = record["default"].get("tls_version") or "-"
    cipher = record["default"].get("cipher") or "-"
    lines.append(f"tls      {tls_ver:<8} {cipher}")
    lines.append(f"verdict  {record['verdict']}")
    return "\n".join(lines)


def sort_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    verdict_rank = {
        TargetVerdict.HYBRID_NEGOTIATED.value: 0,
        TargetVerdict.CLASSICAL_ONLY.value: 1,
        TargetVerdict.INCONCLUSIVE.value: 2,
    }

    return sorted(
        records,
        key=lambda r: (
            verdict_rank.get(r.get("verdict", ""), 99),
            r.get("target", ""),
            r.get("port", 0),
        ),
    )


def format_batch_csv(records: List[Dict[str, Any]]) -> str:
    output = io.StringIO()
    fieldnames = [
        "target",
        "port",
        "default_group",
        "default_outcome",
        "forced_hybrid_outcome",
        "forced_classical_outcome",
        "tls_version",
        "cipher",
        "verdict",
        "error_category",
        "timestamp",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()

    for r in records:
        def_test = r.get("default", {})
        hyb_test = r.get("forced_hybrid", {})
        cla_test = r.get("forced_classical", {})

        # error_category prioritizes default test's category, or hybrid/classical if default was inconclusive
        err_cat = (
            def_test.get("error_category")
            or hyb_test.get("error_category")
            or cla_test.get("error_category")
        )

        row = {
            "target": r.get("target"),
            "port": r.get("port"),
            "default_group": def_test.get("group"),
            "default_outcome": def_test.get("outcome"),
            "forced_hybrid_outcome": hyb_test.get("outcome"),
            "forced_classical_outcome": cla_test.get("outcome"),
            "tls_version": def_test.get("tls_version"),
            "cipher": def_test.get("cipher"),
            "verdict": r.get("verdict"),
            "error_category": err_cat,
            "timestamp": r.get("timestamp"),
        }
        writer.writerow(row)

    return output.getvalue()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="y2q",
        description="TLS 1.3 key-exchange scanner offering X25519MLKEM768 hybrid detection.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan target(s) for TLS 1.3 key exchange groups")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target hostname, IPv4 address, or bracketed IPv6 address",
    )
    scan_parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=443,
        help="Port to connect to (default: 443)",
    )
    scan_parser.add_argument(
        "--file",
        dest="target_file",
        help="Path to file containing list of targets",
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output to stdout",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args, unknown = parser.parse_known_args(argv)

    if args.command is None:
        parser.print_help(sys.stderr)
        return 2

    if args.command == "scan":
        if args.target is None and unknown:
            # Capture flag injection attempts passed as targets
            args.target = unknown[0]
            unknown = unknown[1:]

        if unknown:
            sys.stderr.write(f"Error: unrecognized arguments: {' '.join(unknown)}\n")
            return 2

        if not args.target and not args.target_file:
            sys.stderr.write("Error: either a target host or --file must be specified.\n")
            return 2

        try:
            openssl_bin = find_openssl_binary()
        except FileNotFoundError as err:
            sys.stderr.write(f"Error: {err}\n")
            return 2

        openssl_version_str = get_openssl_version(openssl_bin)
        if not check_native_mlkem_support(openssl_bin):
            sys.stderr.write("warning: OpenSSL build lacks native X25519MLKEM768 support; hybrid tests may return INCONCLUSIVE\n")

        # Batch mode
        if args.target_file:
            if not os.path.isfile(args.target_file):
                sys.stderr.write(f"Error: target file not found: {args.target_file}\n")
                return 2

            with open(args.target_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            parsed_lines = parse_target_lines(lines, default_port=args.port)
            records: List[Dict[str, Any]] = []

            for raw_line, target_obj, err_msg in parsed_lines:
                if target_obj is None:
                    # Invalid target line in batch: isolation means recording error without aborting
                    records.append(
                        make_invalid_target_record(
                            raw_line,
                            err_msg or "invalid input",
                            openssl_version_str,
                            default_port=args.port,
                        )
                    )
                else:
                    record = scan_single_target(target_obj, openssl_bin, openssl_version_str)
                    records.append(record)

            sorted_records = sort_records(records)

            if args.json:
                # JSON Lines: one object per line, not an array
                for rec in sorted_records:
                    sys.stdout.write(json.dumps(rec) + "\n")
                sys.stdout.flush()
            else:
                # CSV format
                csv_text = format_batch_csv(sorted_records)
                sys.stdout.write(csv_text)
                sys.stdout.flush()

            # Exit code: 0 if all targets conclusive, 2 if any target inconclusive
            any_inconclusive = any(
                r.get("verdict") == TargetVerdict.INCONCLUSIVE.value for r in sorted_records
            )
            return 2 if any_inconclusive else 0

        # Single target mode
        target_str = args.target
        try:
            target_obj = validate_target(target_str, default_port=args.port)
            record = scan_single_target(target_obj, openssl_bin, openssl_version_str)
        except ValueError as val_err:
            record = make_invalid_target_record(
                target_str,
                str(val_err),
                openssl_version_str,
                default_port=args.port,
            )

        if args.json:
            # Single JSON object
            sys.stdout.write(json.dumps(record, indent=2) + "\n")
            sys.stdout.flush()
        else:
            sys.stdout.write(format_human_readable(record) + "\n")
            sys.stdout.flush()

        is_conclusive = record.get("verdict") in (
            TargetVerdict.HYBRID_NEGOTIATED.value,
            TargetVerdict.CLASSICAL_ONLY.value,
        )
        return 0 if is_conclusive else 2

    return 2


if __name__ == "__main__":
    sys.exit(main())
