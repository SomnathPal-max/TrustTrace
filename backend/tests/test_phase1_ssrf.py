import pytest
from backend.app.core.ssrf import SSRFGuard, ssrf_guard
from backend.app.core.safe_client import defang_url, SafeHTTPClient

def test_blocked_schemes():
    for scheme in ["file:///etc/passwd", "ftp://evil.com/malware", "gopher://evil.com", "data:text/html,evil", "javascript:alert(1)"]:
        res = ssrf_guard.validate_url(scheme)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_DISALLOWED_SCHEME"

def test_blocked_loopback_and_localhost():
    test_urls = [
        "http://localhost:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:80",
        "http://0.0.0.0",
        "http://[::1]:80",
        "http://[0:0:0:0:0:0:0:1]",
        "http://[::ffff:127.0.0.1]"
    ]
    for url in test_urls:
        res = ssrf_guard.validate_url(url)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_LOOPBACK"

def test_blocked_cloud_metadata_and_link_local():
    test_urls = [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.1.1",
        "http://[fe80::1]"
    ]
    for url in test_urls:
        res = ssrf_guard.validate_url(url)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_CLOUD_METADATA"

def test_blocked_private_ip_ranges():
    private_urls = [
        "http://10.0.0.1",
        "http://10.255.255.255",
        "http://172.16.0.1",
        "http://172.31.255.255",
        "http://192.168.1.1",
        "http://192.168.0.254",
        "http://[fc00::1]",
        "http://[fd12:3456:789a:1::1]"
    ]
    for url in private_urls:
        res = ssrf_guard.validate_url(url)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_PRIVATE_IP"

def test_blocked_cgnat():
    cgnat_urls = [
        "http://100.64.0.1",
        "http://100.127.255.254"
    ]
    for url in cgnat_urls:
        res = ssrf_guard.validate_url(url)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_CGNAT"

def test_numeric_disguises():
    disguises = [
        "http://2130706433",     # 127.0.0.1 in decimal
        "http://0x7f000001",     # 127.0.0.1 in hex
        "http://0177.0.0.1",     # 127.0.0.1 in octal
        "http://127.1",          # 127.0.0.1 shortened
    ]
    for url in disguises:
        res = ssrf_guard.validate_url(url)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_LOOPBACK"

def test_disallowed_ports():
    ports_urls = [
        "http://example.com:22",
        "http://example.com:25",
        "http://example.com:3306",
        "http://example.com:21"
    ]
    for url in ports_urls:
        res = ssrf_guard.validate_url(url)
        assert not res.is_safe
        assert res.rule_blocked == "RULE_DISALLOWED_PORT"

def test_user_info_trick():
    # Attempt to spoof host with user info: http://google.com@127.0.0.1/
    url = "http://google.com@127.0.0.1/"
    res = ssrf_guard.validate_url(url)
    assert not res.is_safe
    assert res.rule_blocked == "RULE_LOOPBACK"
    assert res.parsed_host == "127.0.0.1"

def test_dns_resolving_to_private_address():
    # Resolver returns a private address
    mock_resolver = lambda host: ["192.168.1.100"]
    guard = SSRFGuard(dns_resolver=mock_resolver)
    res = guard.validate_url("http://internal-corp-portal.local")
    assert not res.is_safe
    assert res.rule_blocked == "RULE_PRIVATE_IP"

def test_valid_public_domain():
    # Resolver returns public address
    mock_resolver = lambda host: ["93.184.216.34"]
    guard = SSRFGuard(dns_resolver=mock_resolver)
    res = guard.validate_url("https://example.com")
    assert res.is_safe
    assert res.parsed_host == "example.com"
    assert res.parsed_port == 443

def test_bare_domain_normalization():
    mock_resolver = lambda host: ["93.184.216.34"]
    guard = SSRFGuard(dns_resolver=mock_resolver)
    
    # Bare domain without scheme
    res1 = guard.validate_url("github.com")
    assert res1.is_safe
    assert res1.parsed_host == "github.com"
    assert res1.parsed_port == 443
    
    # Bare domain with port
    res2 = guard.validate_url("sbi.co.in:8443")
    assert res2.is_safe
    assert res2.parsed_host == "sbi.co.in"
    assert res2.parsed_port == 8443

def test_defang_url():
    assert defang_url("http://example.com/login") == "hxxp://example[.]com/login"
    assert defang_url("https://malicious.tk/pan") == "hxxps://malicious[.]tk/pan"
