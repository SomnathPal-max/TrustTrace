import pytest
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.app.analyzers.tls_analyzer import TLSAnalyzer, match_hostname_san, HTTPS_DISCLAIMER
from backend.app.analyzers.header_analyzer import header_analyzer

def generate_self_signed_cert(hostname: str, key_size: int = 2048, expired: bool = False, sig_algo=hashes.SHA256()):
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=60)
        not_after = now - timedelta(days=10)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=365)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        )
        .sign(key, sig_algo)
    )
    from cryptography.hazmat.primitives import serialization
    return cert.public_bytes(serialization.Encoding.DER)

def test_match_hostname_san():
    assert match_hostname_san("example.com", ["example.com"])
    assert match_hostname_san("sub.example.com", ["*.example.com"])
    assert not match_hostname_san("evil.com", ["example.com"])
    assert not match_hostname_san("deep.sub.example.com", ["*.example.com"])

def test_expired_certificate_tls01():
    analyzer = TLSAnalyzer()
    der = generate_self_signed_cert("expired.example.com", expired=True)
    parsed = analyzer.parse_certificate(der)
    assert parsed["days_remaining"] < 0

def test_weak_rsa_key_tls04():
    analyzer = TLSAnalyzer()
    der = generate_self_signed_cert("weak.example.com", key_size=1024)
    parsed = analyzer.parse_certificate(der)
    assert parsed["public_key_size"] == 1024

def test_simulated_emudhra_fixture_tls06_and_wording():
    analyzer = TLSAnalyzer()
    res = analyzer.analyze("simulated-distrusted-ca.local", is_simulation=True)
    assert res["tls_available"] is True
    assert res["tls_report"].tls_verdict == "Potentially compromised trust"
    assert res["tls_report"].https_note == HTTPS_DISCLAIMER

    tls_06_findings = [f for f in res["findings"] if f.signal_id == "TLS-06"]
    assert len(tls_06_findings) == 1
    finding = tls_06_findings[0]
    assert finding.points == 45
    # Strict eMudhra guardrail wording checks (HC-12)
    assert "SIMULATED FIXTURE - not a live finding" in finding.description
    assert "This tool did not and cannot independently verify any internal key-generation weakness" in finding.description
    assert "hacked" not in finding.description.lower()
    assert "inspected the ca's key generation" not in finding.description.lower()

def test_security_headers_analyzer():
    # Test completely missing headers
    results, findings = header_analyzer.analyze_headers({})
    assert len(results) == 6
    assert all(not r.present for r in results)
    assert len(findings) == 6
    # Total points should be 12 before category cap
    total_points = sum(f.points for f in findings)
    assert total_points == 12

    # Test full secure headers
    secure_headers = {
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()"
    }
    sec_results, sec_findings = header_analyzer.analyze_headers(secure_headers)
    assert all(r.present for r in sec_results)
    assert len(sec_findings) == 0
