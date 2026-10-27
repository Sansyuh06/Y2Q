from y2q.classify import (
    TargetVerdict,
    TestOutcome,
    TestResult,
    classify_test_result,
    derive_target_verdict,
)
from y2q.parse import ParsedOutput


def test_classify_timeout_is_inconclusive_not_rejected():
    res = classify_test_result(
        parsed=None,
        test_name="forced_hybrid",
        is_timeout=True,
        timeout_reason="timeout",
    )
    assert res.outcome == TestOutcome.INCONCLUSIVE
    assert res.error_category == "timeout"
    assert res.reason == "timeout"
    assert res.evidence is None


def test_classify_connection_refused_is_inconclusive():
    parsed = ParsedOutput(
        group=None,
        tls_version=None,
        cipher=None,
        alert_number=None,
        alert_description=None,
        error_message="connection refused",
        raw_errors=["BIO_connect:Connection refused:calling connect()"],
    )
    res = classify_test_result(parsed, test_name="forced_hybrid")
    assert res.outcome == TestOutcome.INCONCLUSIVE
    assert res.error_category == "refused"
    assert res.reason == "connection refused"


def test_classify_dns_failure_is_inconclusive():
    parsed = ParsedOutput(
        group=None,
        tls_version=None,
        cipher=None,
        alert_number=None,
        alert_description=None,
        error_message="dns resolution failed",
        raw_errors=["Name or service not known"],
    )
    res = classify_test_result(parsed, test_name="forced_hybrid")
    assert res.outcome == TestOutcome.INCONCLUSIVE
    assert res.error_category == "dns"
    assert res.reason == "dns resolution failed"


def test_classify_rejected_hybrid_with_successful_classical_control():
    # When forced_hybrid yields handshake failure (alert 40)
    # AND forced_classical succeeded in the same run, the failure is attributable to the group.
    parsed_hybrid = ParsedOutput(
        group=None,
        tls_version="TLSv1.3",
        cipher=None,
        alert_number=40,
        alert_description="handshake failure",
        error_message="tls alert: handshake failure",
        raw_errors=["ssl/tls alert handshake failure:SSL alert number 40"],
    )
    res = classify_test_result(
        parsed_hybrid,
        test_name="forced_hybrid",
        classical_control_outcome=TestOutcome.NEGOTIATED,
    )
    assert res.outcome == TestOutcome.REJECTED
    assert res.error_category == "tls_alert"
    assert res.evidence is not None
    assert "40" in res.evidence


def test_classify_rejected_hybrid_without_control_is_inconclusive():
    # Without successful classical control, a handshake failure alert is weak evidence
    # and must be classified as INCONCLUSIVE.
    parsed_hybrid = ParsedOutput(
        group=None,
        tls_version="TLSv1.3",
        cipher=None,
        alert_number=40,
        alert_description="handshake failure",
        error_message="tls alert: handshake failure",
        raw_errors=["ssl/tls alert handshake failure:SSL alert number 40"],
    )

    # 1. Classical control failed
    res_failed_control = classify_test_result(
        parsed_hybrid,
        test_name="forced_hybrid",
        classical_control_outcome=TestOutcome.INCONCLUSIVE,
    )
    assert res_failed_control.outcome == TestOutcome.INCONCLUSIVE
    assert res_failed_control.error_category == "tls_alert"
    assert res_failed_control.evidence is None

    # 2. Classical control not provided
    res_no_control = classify_test_result(
        parsed_hybrid,
        test_name="forced_hybrid",
        classical_control_outcome=None,
    )
    assert res_no_control.outcome == TestOutcome.INCONCLUSIVE
    assert res_no_control.error_category == "tls_alert"
    assert res_no_control.evidence is None


def test_classify_explicit_key_share_rejection():
    # "no suitable key share" is explicit strong evidence
    parsed = ParsedOutput(
        group=None,
        tls_version="TLSv1.3",
        cipher=None,
        alert_number=None,
        alert_description=None,
        error_message="no suitable key share",
        raw_errors=["tls_parse_ctos_key_share:no suitable key share"],
    )
    res = classify_test_result(parsed, test_name="forced_hybrid")
    assert res.outcome == TestOutcome.REJECTED
    assert res.error_category == "tls_alert"
    assert "no suitable key share" in res.evidence


def test_classify_tls12_downgrade():
    parsed = ParsedOutput(
        group="X25519",
        tls_version="TLSv1.2",
        cipher="ECDHE-RSA-AES256-GCM-SHA384",
        alert_number=None,
        alert_description=None,
        error_message=None,
        raw_errors=[],
    )
    res = classify_test_result(parsed, test_name="default")
    assert res.outcome == TestOutcome.INCONCLUSIVE
    assert res.error_category == "tls_version"
    assert "downgraded to TLSv1.2" in res.reason


def test_classify_alert_70_protocol_version():
    parsed = ParsedOutput(
        group=None,
        tls_version=None,
        cipher=None,
        alert_number=70,
        alert_description="protocol version",
        error_message="tls alert: protocol version",
        raw_errors=["ssl/tls alert protocol version:SSL alert number 70"],
    )
    res = classify_test_result(parsed, test_name="default")
    assert res.outcome == TestOutcome.INCONCLUSIVE
    assert res.error_category == "tls_version"
    assert "protocol version" in res.reason





def test_verdict_derivation():
    # 1. Default negotiated hybrid
    res_hybrid = TestResult(
        group="X25519MLKEM768",
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        outcome=TestOutcome.NEGOTIATED,
        error_category=None,
        reason=None,
        evidence=None,
    )
    assert derive_target_verdict(res_hybrid) == TargetVerdict.HYBRID_NEGOTIATED

    # 2. Default negotiated classical
    res_classical = TestResult(
        group="X25519",
        tls_version="TLSv1.3",
        cipher="TLS_AES_128_GCM_SHA256",
        outcome=TestOutcome.NEGOTIATED,
        error_category=None,
        reason=None,
        evidence=None,
    )
    assert derive_target_verdict(res_classical) == TargetVerdict.CLASSICAL_ONLY

    # 3. Default inconclusive
    res_inconclusive = TestResult(
        group=None,
        tls_version=None,
        cipher=None,
        outcome=TestOutcome.INCONCLUSIVE,
        error_category="timeout",
        reason="timeout",
        evidence=None,
    )
    assert derive_target_verdict(res_inconclusive) == TargetVerdict.INCONCLUSIVE
