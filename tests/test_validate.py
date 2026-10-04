import pytest
from y2q.validate import (
    parse_target_lines,
    validate_hostname,
    validate_target,
)


def test_valid_hostnames():
    t1 = validate_target("example.com")
    assert t1.host == "example.com"
    assert t1.port == 443
    assert not t1.is_ip
    assert t1.sni_hostname == "example.com"
    assert t1.connect_target == "example.com:443"

    t2 = validate_target("sub.domain.co.uk:8443")
    assert t2.host == "sub.domain.co.uk"
    assert t2.port == 8443
    assert not t2.is_ip


def test_valid_ipv4():
    t = validate_target("192.0.2.1:443")
    assert t.host == "192.0.2.1"
    assert t.port == 443
    assert t.is_ip
    # SNI must not carry an IP
    assert t.sni_hostname is None
    assert t.connect_target == "192.0.2.1:443"


def test_valid_bracketed_ipv6():
    t1 = validate_target("[2001:db8::1]:8443")
    assert t1.host == "2001:db8::1"
    assert t1.port == 8443
    assert t1.is_ip
    assert t1.sni_hostname is None
    assert t1.connect_target == "[2001:db8::1]:8443"

    t2 = validate_target("[::1]")
    assert t2.host == "::1"
    assert t2.port == 443
    assert t2.is_ip
    assert t2.sni_hostname is None
    assert t2.connect_target == "[::1]:443"


def test_flag_injection_rejection():
    with pytest.raises(ValueError, match="Target host cannot begin with '-'"):
        validate_target("-servername")

    with pytest.raises(ValueError, match="Target host cannot begin with '-'"):
        validate_target("--help")

    with pytest.raises(ValueError, match="Target host cannot begin with '-'"):
        validate_target("-connect:443")


def test_invalid_ports():
    with pytest.raises(ValueError, match="Port must be an integer"):
        validate_target("example.com:abc")

    with pytest.raises(ValueError, match="Port out of valid range"):
        validate_target("example.com:0")

    with pytest.raises(ValueError, match="Port out of valid range"):
        validate_target("example.com:65536")


def test_invalid_hostnames():
    # Empty
    with pytest.raises(ValueError):
        validate_target("")

    # Spaces or control chars
    with pytest.raises(ValueError):
        validate_target("example .com")

    # Label ending with '-'
    with pytest.raises(ValueError):
        validate_target("example-.com")

    # Label starting with '-'
    with pytest.raises(ValueError):
        validate_target("-example.com")

    # Empty label
    with pytest.raises(ValueError):
        validate_target("example..com")

    # Unbracketed IPv6
    with pytest.raises(ValueError, match="bracketed"):
        validate_target("2001:db8::1")


def test_batch_line_parsing():
    raw_lines = [
        "# this is a comment",
        "",
        "example.com",
        "  192.0.2.1:443  ",
        "example.com",  # duplicate, should be skipped
        "-flag-injection",  # invalid target, should record error
        "# another comment",
        "[2001:db8::1]:8443",
    ]
    results = parse_target_lines(raw_lines)
    assert len(results) == 4

    assert results[0][0] == "example.com"
    assert results[0][1].host == "example.com"
    assert results[0][2] is None

    assert results[1][0] == "192.0.2.1:443"
    assert results[1][1].host == "192.0.2.1"
    assert results[1][2] is None

    # Invalid host reported with error, not crashing
    assert results[2][0] == "-flag-injection"
    assert results[2][1] is None
    assert "Target host cannot begin with '-'" in results[2][2]

    assert results[3][0] == "[2001:db8::1]:8443"
    assert results[3][1].host == "2001:db8::1"
    assert results[3][2] is None
