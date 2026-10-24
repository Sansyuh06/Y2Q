import pytest
from y2q.classify import TargetVerdict
from y2q.cli import scan_single_target
from y2q.probe import find_openssl_binary, get_openssl_version
from y2q.validate import validate_target


@pytest.mark.integration
def test_integration_live_hybrid_negotiation():
    try:
        bin_path = find_openssl_binary()
    except FileNotFoundError:
        pytest.skip("openssl binary not available")

    ver_str = get_openssl_version(bin_path)
    target = validate_target("cloudflare.com", default_port=443)

    record = scan_single_target(target, bin_path, ver_str)
    assert record["target"] == "cloudflare.com"
    assert record["port"] == 443
    assert record["default"]["outcome"] == "NEGOTIATED"
    assert record["default"]["group"] == "X25519MLKEM768"
    assert record["verdict"] == TargetVerdict.HYBRID_NEGOTIATED.value


@pytest.mark.integration
def test_integration_live_classical_negotiation():
    try:
        bin_path = find_openssl_binary()
    except FileNotFoundError:
        pytest.skip("openssl binary not available")

    ver_str = get_openssl_version(bin_path)
    target = validate_target("wikipedia.org", default_port=443)

    record = scan_single_target(target, bin_path, ver_str)
    assert record["target"] == "wikipedia.org"
    assert record["port"] == 443
    assert record["default"]["outcome"] == "NEGOTIATED"
    assert record["default"]["group"] == "X25519"
    assert record["forced_classical"]["outcome"] == "NEGOTIATED"
    assert record["verdict"] == TargetVerdict.CLASSICAL_ONLY.value
