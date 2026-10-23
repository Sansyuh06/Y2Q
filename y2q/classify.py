from dataclasses import dataclass
from enum import Enum
from typing import Optional

from y2q.parse import ParsedOutput


class TestOutcome(str, Enum):
    __test__ = False
    NEGOTIATED = "NEGOTIATED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class TargetVerdict(str, Enum):
    HYBRID_NEGOTIATED = "HYBRID_NEGOTIATED"
    CLASSICAL_ONLY = "CLASSICAL_ONLY"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class TestResult:
    __test__ = False
    group: Optional[str]
    tls_version: Optional[str]
    cipher: Optional[str]
    outcome: TestOutcome
    error_category: Optional[str]
    reason: Optional[str]
    evidence: Optional[str]

    def to_dict(self) -> dict:
        return {
            "group": self.group,
            "tls_version": self.tls_version,
            "cipher": self.cipher,
            "outcome": self.outcome.value,
            "error_category": self.error_category,
            "reason": self.reason,
            "evidence": self.evidence,
        }


def classify_test_result(
    parsed: Optional[ParsedOutput],
    test_name: str,
    classical_control_outcome: Optional[TestOutcome] = None,
    is_timeout: bool = False,
    timeout_reason: Optional[str] = None,
    invalid_input_reason: Optional[str] = None,
) -> TestResult:
    """Classify an individual test outcome from parsed output and control state."""
    if invalid_input_reason is not None:
        return TestResult(
            group=None,
            tls_version=None,
            cipher=None,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="invalid_input",
            reason=invalid_input_reason,
            evidence=None,
        )

    if is_timeout:
        return TestResult(
            group=None,
            tls_version=None,
            cipher=None,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="timeout",
            reason=timeout_reason or "timeout",
            evidence=None,
        )

    if parsed is None:
        return TestResult(
            group=None,
            tls_version=None,
            cipher=None,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="parse_failure",
            reason="empty or unreadable output",
            evidence=None,
        )

    # Check connection-level failures first
    err_lower = (parsed.error_message or "").lower()
    combined_errors = " ".join(parsed.raw_errors).lower()

    if "dns resolution failed" in err_lower or "name or service not known" in combined_errors:
        return TestResult(
            group=None,
            tls_version=parsed.tls_version,
            cipher=parsed.cipher,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="dns",
            reason="dns resolution failed",
            evidence=None,
        )

    if "connection refused" in err_lower or "errno=111" in combined_errors or "errno=10061" in combined_errors:
        return TestResult(
            group=None,
            tls_version=parsed.tls_version,
            cipher=parsed.cipher,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="refused",
            reason="connection refused",
            evidence=None,
        )

    # Check TLS protocol downgrade
    if parsed.tls_version and parsed.tls_version != "TLSv1.3":
        return TestResult(
            group=parsed.group,
            tls_version=parsed.tls_version,
            cipher=parsed.cipher,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="tls_version",
            reason=f"downgraded to {parsed.tls_version}",
            evidence=None,
        )

    # Positive group identification
    if parsed.group:
        return TestResult(
            group=parsed.group,
            tls_version=parsed.tls_version,
            cipher=parsed.cipher,
            outcome=TestOutcome.NEGOTIATED,
            error_category=None,
            reason=None,
            evidence=None,
        )

    # Group was not negotiated: evaluate rejection evidence
    # 1. Strong evidence: explicit group rejection message
    if "no suitable key share" in err_lower or "no suitable key share" in combined_errors:
        evidence_str = "no suitable key share"
        if parsed.raw_errors:
            for line in parsed.raw_errors:
                if "no suitable key share" in line.lower():
                    evidence_str = line
                    break
        return TestResult(
            group=None,
            tls_version=parsed.tls_version,
            cipher=parsed.cipher,
            outcome=TestOutcome.REJECTED,
            error_category="tls_alert",
            reason="explicit group rejection (no suitable key share)",
            evidence=evidence_str,
        )

    # 2. Generic handshake failure (alert 40 or generic handshake failure)
    # A generic handshake_failure alert is weak evidence on its own.
    # It is only sufficient for REJECTED when forced_classical to the same host
    # succeeded in the same run as a control.
    is_handshake_failure = (
        parsed.alert_number == 40
        or "handshake failure" in err_lower
        or "handshake_failure" in combined_errors
        or (parsed.alert_number is not None and parsed.alert_number in (40, 47, 71, 109))
    )

    if is_handshake_failure:
        evidence_str = (
            f"SSL alert number {parsed.alert_number}"
            if parsed.alert_number
            else (parsed.error_message or "handshake failure")
        )
        if test_name == "forced_hybrid":
            if classical_control_outcome == TestOutcome.NEGOTIATED:
                return TestResult(
                    group=None,
                    tls_version=parsed.tls_version,
                    cipher=parsed.cipher,
                    outcome=TestOutcome.REJECTED,
                    error_category="tls_alert",
                    reason="handshake failure with successful classical control",
                    evidence=evidence_str,
                )
            else:
                return TestResult(
                    group=None,
                    tls_version=parsed.tls_version,
                    cipher=parsed.cipher,
                    outcome=TestOutcome.INCONCLUSIVE,
                    error_category="tls_alert",
                    reason="weak handshake failure without successful classical control",
                    evidence=None,
                )

        return TestResult(
            group=None,
            tls_version=parsed.tls_version,
            cipher=parsed.cipher,
            outcome=TestOutcome.INCONCLUSIVE,
            error_category="tls_alert",
            reason=f"handshake failure (alert {parsed.alert_number or 'unspecified'})",
            evidence=None,
        )

    # No recognizable group or specific alert
    return TestResult(
        group=None,
        tls_version=parsed.tls_version,
        cipher=parsed.cipher,
        outcome=TestOutcome.INCONCLUSIVE,
        error_category="parse_failure",
        reason="no negotiated group found in output",
        evidence=None,
    )


def derive_target_verdict(default_result: TestResult) -> TargetVerdict:
    """Derive per-target verdict strictly from the default test result."""
    if default_result.outcome == TestOutcome.NEGOTIATED:
        if default_result.group == "X25519MLKEM768":
            return TargetVerdict.HYBRID_NEGOTIATED
        return TargetVerdict.CLASSICAL_ONLY
    return TargetVerdict.INCONCLUSIVE
