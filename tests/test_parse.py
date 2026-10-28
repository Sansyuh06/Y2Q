from pathlib import Path

from y2q.parse import parse_openssl_output

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def read_fixture(name: str) -> str:
    path = FIXTURES_DIR / name
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def test_parse_successful_hybrid():
    content = read_fixture("successful_hybrid.txt")
    parsed = parse_openssl_output(content)
    assert parsed.group == "X25519MLKEM768"
    assert parsed.cipher == "TLS_AES_256_GCM_SHA384"
    assert parsed.tls_version == "TLSv1.3"


def test_parse_successful_classical():
    content = read_fixture("successful_classical.txt")
    parsed = parse_openssl_output(content)
    assert parsed.group == "X25519"
    assert parsed.cipher == "TLS_AES_128_GCM_SHA256"
    assert parsed.tls_version == "TLSv1.3"


def test_parse_explicit_rejection_no_key_share():
    content = read_fixture("explicit_rejection_no_key_share.txt")
    parsed = parse_openssl_output(content)
    # Must never invent a group when <NULL> or absent
    assert parsed.group is None
    assert parsed.error_message == "no suitable key share"


def test_parse_generic_handshake_failure():
    content = read_fixture("generic_handshake_failure.txt")
    parsed = parse_openssl_output(content)
    # Must never invent a group when <NULL> or absent
    assert parsed.group is None
    assert parsed.alert_number == 40
    assert "handshake failure" in (parsed.error_message or "").lower()


def test_parse_tls12_downgrade():
    content = read_fixture("tls12_downgrade.txt")
    parsed = parse_openssl_output(content)
    assert parsed.tls_version == "TLSv1.2"
    assert parsed.cipher == "ECDHE-RSA-AES256-GCM-SHA384"
    assert parsed.group == "X25519"


def test_parse_truncated_output():
    content = read_fixture("truncated_output.txt")
    parsed = parse_openssl_output(content)
    # Group must not be invented from incomplete output
    assert parsed.group is None
    assert parsed.cipher is None
    assert parsed.tls_version is None


def test_parse_empty_output():
    content = read_fixture("empty_output.txt")
    parsed = parse_openssl_output(content)
    assert parsed.group is None
    assert parsed.cipher is None
    assert parsed.tls_version is None


def test_parse_connection_refused():
    content = read_fixture("connection_refused.txt")
    parsed = parse_openssl_output("", stderr=content)
    assert parsed.group is None
    assert "connection refused" in (parsed.error_message or "").lower()


def test_parse_dns_failure():
    content = read_fixture("dns_failure.txt")
    parsed = parse_openssl_output("", stderr=content)
    assert parsed.group is None
    assert "dns resolution failed" in (parsed.error_message or "").lower()


def test_parse_alert_with_trailing_prose():
    content = read_fixture("alert_with_trailing_prose.txt")
    parsed = parse_openssl_output(content)
    assert parsed.alert_number == 40
    # Must match known alert name and not capture trailing prose
    assert parsed.alert_description == "handshake_failure"
    assert "trailing prose" not in (parsed.alert_description or "")

