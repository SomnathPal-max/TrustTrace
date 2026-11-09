import hashlib
import json
import os
import socket
import ssl
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

from backend.app.core.ssrf import ssrf_guard
from backend.app.models import Finding, FindingCategory, Severity, TLSReport

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

def _load_distrusted_cas() -> List[Dict[str, Any]]:
    path = os.path.join(DATA_DIR, "distrusted_cas.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

DISTRUSTED_CAS = _load_distrusted_cas()

# Standard HTTPS disclaimer (Appendix F)
HTTPS_DISCLAIMER = (
    "A valid HTTPS certificate only means the connection is encrypted and the "
    "certificate matches the domain. It does not mean the website is trustworthy."
)

def match_hostname_san(hostname: str, san_list: List[str]) -> bool:
    """Checks if hostname matches any SAN pattern, including wildcards like *.example.com."""
    host = hostname.lower().strip(".")
    for pattern in san_list:
        p = pattern.lower().strip(".")
        if p == host:
            return True
        if p.startswith("*."):
            suffix = p[2:]
            # Must match a single label before suffix
            host_parts = host.split(".")
            suffix_parts = suffix.split(".")
            if len(host_parts) == len(suffix_parts) + 1 and host.endswith(suffix):
                return True
    return False

class TLSAnalyzer:
    def __init__(self, distrust_list=None, ct_timeout: float = 8.0):
        self.distrust_list = distrust_list or DISTRUSTED_CAS
        self.ct_timeout = ct_timeout

    def query_crt_sh(self, domain: str) -> Tuple[Dict[str, Any], bool]:
        """Queries crt.sh with an 8-second timeout for Certificate Transparency records."""
        url = f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "LinkAndScamDetective-Bot/1.0", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=self.ct_timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if isinstance(data, list):
                        issuers = set()
                        now = datetime.now(timezone.utc)
                        last_30_days = 0
                        for item in data:
                            issuer = item.get("issuer_name", "")
                            if issuer:
                                issuers.add(issuer)
                            entry_timestamp = item.get("entry_timestamp")
                            if entry_timestamp:
                                try:
                                    dt = datetime.fromisoformat(entry_timestamp.replace("Z", "+00:00"))
                                    if (now - dt).days <= 30:
                                        last_30_days += 1
                                except Exception:
                                    pass

                        summary = {
                            "total_logged_certificates": len(data),
                            "distinct_issuers_count": len(issuers),
                            "certificates_last_30_days": last_30_days,
                            "ct_available": True
                        }
                        return summary, True
        except Exception:
            pass

        return {"ct_available": False, "note": "crt.sh lookup timed out or unavailable."}, False

    def perform_handshake(self, hostname: str, connect_ip: str, port: int = 443) -> Tuple[Optional[List[bytes]], str, bool]:
        """
        Executes strict verified handshake first, then permissive unverified handshake.
        Returns: (der_cert_chain, trust_result, connection_succeeded)
        """
        trust_result = "trusted"
        
        # 1. Strict verified handshake
        strict_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((connect_ip, port), timeout=4.0) as sock:
                with strict_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    pass
        except ssl.SSLCertVerificationError as e:
            if "self-signed" in str(e).lower() or "self signed" in str(e).lower():
                trust_result = "self_signed"
            elif "unable to get local issuer certificate" in str(e).lower() or "incomplete" in str(e).lower():
                trust_result = "incomplete_chain"
            else:
                trust_result = "unknown_issuer"
        except Exception:
            trust_result = "unknown_issuer"

        # 2. Permissive unverified capture
        unverified_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((connect_ip, port), timeout=4.0) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get peer certificate DER
                    leaf_der = ssock.getpeercert(binary_form=True)
                    # Get verified chain if available
                    chain_ders = [leaf_der]
                    verified_chain = ssock.get_verified_chain() if hasattr(ssock, "get_verified_chain") else None
                    if verified_chain:
                        chain_ders = [c.public_bytes(serialization.Encoding.DER) for c in verified_chain]
                    return chain_ders, trust_result, True
        except Exception:
            return None, "unreachable", False

    def parse_certificate(self, der_bytes: bytes) -> Dict[str, Any]:
        """Parses X.509 DER certificate into structured metadata."""
        cert = x509.load_der_x509_certificate(der_bytes)
        
        # Subject and Issuer
        subject_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()
        
        # SANs
        sans = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass

        # Validity dates
        start_date = cert.not_valid_before_utc
        end_date = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        days_remaining = (end_date - now).days

        # Public key info
        pub_key = cert.public_key()
        pub_key_algo = "Unknown"
        pub_key_size = 0
        if isinstance(pub_key, rsa.RSAPublicKey):
            pub_key_algo = "RSA"
            pub_key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            pub_key_algo = f"EC-{pub_key.curve.name}"
            pub_key_size = pub_key.curve.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            pub_key_algo = "DSA"
            pub_key_size = pub_key.key_size

        # Signature algorithm
        sig_algo = cert.signature_algorithm_oid._name

        # Fingerprints
        cert_sha256 = cert.fingerprint(hashes.SHA256()).hex().lower()
        spki_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        spki_sha256 = hashlib.sha256(spki_bytes).hexdigest().lower()

        # Is CA
        is_ca = False
        try:
            bc_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
            is_ca = bc_ext.value.ca
        except Exception:
            pass

        # Revocation endpoints (CRL / OCSP)
        revocation_endpoints = []
        try:
            crl_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.CRL_DISTRIBUTION_POINTS)
            for dp in crl_ext.value:
                for name in dp.full_name or []:
                    revocation_endpoints.append(str(name.value))
        except Exception:
            pass

        # Embedded SCTs
        has_scts = False
        try:
            cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
            has_scts = True
        except Exception:
            pass

        return {
            "subject": subject_str,
            "san_list": sans,
            "issuer": issuer_str,
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat(),
            "days_remaining": days_remaining,
            "public_key_algorithm": pub_key_algo,
            "public_key_size": pub_key_size,
            "signature_algorithm": sig_algo,
            "cert_sha256": cert_sha256,
            "spki_sha256": spki_sha256,
            "is_ca": is_ca,
            "revocation_endpoints": revocation_endpoints,
            "has_embedded_scts": has_scts,
            "der_bytes": der_bytes
        }

    def analyze(
        self,
        hostname: str,
        connect_ip: Optional[str] = None,
        is_simulation: bool = False
    ) -> Dict[str, Any]:
        findings: List[Finding] = []
        now = datetime.now(timezone.utc)

        # Simulation Fixture (for eMudhra demonstration, Section 9 Phase 3 step 10)
        if is_simulation or hostname == "simulated-distrusted-ca.local":
            sim_cert_sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            sim_spki_sha256 = "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
            findings.append(Finding(
                id="F-TLS-06",
                signal_id="TLS-06",
                category=FindingCategory.TLS,
                title="Presented certificate chain includes a listed distrusted CA",
                description=(
                    "The certificate chain presented by this site includes a certificate authority certificate that appears "
                    "on a published distrust list (eMudhra Demo Simulation CA, Link & Scam Detective Simulated Distrust Fixture, 2026-11-09). "
                    "This means the certificate's trust may be compromised. This tool did not and cannot independently verify "
                    "any internal key-generation weakness. [SIMULATED FIXTURE - not a live finding.]"
                ),
                severity=Severity.HIGH,
                points=45,
                technical_evidence={
                    "matched_ca": "eMudhra Demo Simulation CA",
                    "fingerprint": sim_cert_sha256,
                    "source": "Link & Scam Detective Simulated Distrust Fixture",
                    "simulation": True
                },
                source="distrust list match",
                potential_impact="Certificate trust may be compromised, so the certificate may not reliably prove the site's identity.",
                recommendation="Replace the certificate with one from a currently trusted authority.",
                limitation="This is a match to a published list. The tool cannot verify any internal key-generation weakness."
            ))

            tls_report = TLSReport(
                subject=f"CN={hostname}",
                san_list=[hostname],
                issuer="CN=eMudhra Sub-CA Demo Simulation",
                validity_start=now.isoformat(),
                validity_end=datetime(now.year + 1, now.month, now.day, tzinfo=timezone.utc).isoformat(),
                days_remaining=365,
                public_key_algorithm="RSA",
                public_key_size=2048,
                signature_algorithm="sha256WithRSAEncryption",
                certificate_sha256=sim_cert_sha256,
                spki_sha256=sim_spki_sha256,
                chain_list=[f"CN={hostname}", "CN=eMudhra Sub-CA Demo Simulation (DISTRUSTED)"],
                trust_result="distrusted",
                ct_summary={"total_logged_certificates": 1, "ct_available": True},
                tls_verdict="Potentially compromised trust",
                https_note=HTTPS_DISCLAIMER
            )
            return {
                "tls_report": tls_report,
                "tls_available": True,
                "ct_available": True,
                "findings": findings
            }

        # Live TLS Handshake
        target_ip = connect_ip or hostname
        ders, trust_result, success = self.perform_handshake(hostname, target_ip, 443)
        if not success or not ders:
            return {
                "tls_report": None,
                "tls_available": False,
                "ct_available": False,
                "findings": []
            }

        # Parse leaf and intermediates
        parsed_chain = [self.parse_certificate(d) for d in ders]
        leaf = parsed_chain[0]

        # 1. TLS-01: Validity window and expired/not yet valid check
        if leaf["days_remaining"] < 0:
            findings.append(Finding(
                id="F-TLS-01",
                signal_id="TLS-01",
                category=FindingCategory.TLS,
                title="Certificate expired or not yet valid",
                description=f"The presented certificate expired {abs(leaf['days_remaining'])} days ago (end date: {leaf['end_date']}).",
                severity=Severity.HIGH,
                points=25,
                technical_evidence={"end_date": leaf["end_date"], "days_remaining": leaf["days_remaining"]},
                source="TLS handshake",
                potential_impact="Browsers warn users; identity cannot be relied on.",
                recommendation="Renew or fix the certificate dates.",
                limitation="Clock differences can affect edge cases."
            ))
        elif leaf["days_remaining"] <= 14:
            # Advisory note
            pass

        # 2. TLS-02: Hostname versus SAN list
        san_match = match_hostname_san(hostname, leaf["san_list"])
        if not san_match:
            findings.append(Finding(
                id="F-TLS-02",
                signal_id="TLS-02",
                category=FindingCategory.TLS,
                title="Hostname not covered by certificate SAN list",
                description=f"Hostname '{hostname}' does not match any name listed in the Subject Alternative Name (SAN) extension.",
                severity=Severity.HIGH,
                points=30,
                technical_evidence={"hostname": hostname, "san_list": leaf["san_list"]},
                source="TLS handshake",
                potential_impact="The certificate does not vouch for this site name.",
                recommendation="Issue a certificate that lists the correct names.",
                limitation="Based on the name list in the presented certificate."
            ))

        # 3. TLS-03: Trust result (self-signed, unknown issuer, incomplete chain)
        if trust_result != "trusted":
            findings.append(Finding(
                id="F-TLS-03",
                signal_id="TLS-03",
                category=FindingCategory.TLS,
                title="Untrusted or incomplete certificate chain",
                description=f"The certificate trust chain could not be verified by the operating system trust store ({trust_result}).",
                severity=Severity.HIGH,
                points=25,
                technical_evidence={"trust_result": trust_result, "issuer": leaf["issuer"]},
                source="TLS handshake",
                potential_impact="Browsers may reject the connection.",
                recommendation="Install the full chain from a trusted authority.",
                limitation="Trust stores differ slightly between systems."
            ))

        # 4. TLS-04: Weak public key (RSA < 2048 or EC < 256)
        if leaf["public_key_algorithm"] == "RSA" and leaf["public_key_size"] < 2048:
            findings.append(Finding(
                id="F-TLS-04",
                signal_id="TLS-04",
                category=FindingCategory.TLS,
                title="Weak public key size",
                description=f"RSA public key size is {leaf['public_key_size']} bits, below the industry minimum standard of 2048 bits.",
                severity=Severity.MEDIUM,
                points=15,
                technical_evidence={"algorithm": "RSA", "key_size": leaf["public_key_size"]},
                source="TLS handshake",
                potential_impact="Easier to attack than modern settings.",
                recommendation="Use RSA of at least 2048 bits or a 256-bit elliptic curve.",
                limitation="Does not show that any key was actually broken."
            ))

        # 5. TLS-05: Weak signature algorithm (SHA-1 or MD5)
        sig_lower = leaf["signature_algorithm"].lower()
        if "sha1" in sig_lower or "md5" in sig_lower:
            findings.append(Finding(
                id="F-TLS-05",
                signal_id="TLS-05",
                category=FindingCategory.TLS,
                title="Weak signature algorithm",
                description=f"Certificate was signed using deprecated algorithm '{leaf['signature_algorithm']}'.",
                severity=Severity.MEDIUM,
                points=15,
                technical_evidence={"signature_algorithm": leaf["signature_algorithm"]},
                source="TLS handshake",
                potential_impact="Easier to forge or produce collision attacks.",
                recommendation="Use SHA-256 or stronger signature algorithms.",
                limitation="Does not prove immediate exploitation."
            ))

        # 6. TLS-06 / TLS-06n: Distrust list check
        tls_06_fired = False
        for cert_item in parsed_chain:
            cert_fp = cert_item["cert_sha256"]
            spki_fp = cert_item["spki_sha256"]
            issuer_name = cert_item["issuer"].lower()

            for bad_ca in self.distrust_list:
                m_type = bad_ca.get("match_type")
                val = bad_ca.get("value", "").lower()
                status = bad_ca.get("status")

                if m_type == "certificate_sha256" and cert_fp == val and status == "verified":
                    tls_06_fired = True
                    findings.append(Finding(
                        id="F-TLS-06",
                        signal_id="TLS-06",
                        category=FindingCategory.TLS,
                        title="Presented certificate chain includes a listed distrusted CA",
                        description=(
                            f"The certificate chain presented by this site includes a certificate authority certificate that appears "
                            f"on a published distrust list ({bad_ca.get('ca_name')}, {bad_ca.get('source_name')}, {bad_ca.get('date_added')}). "
                            "This means the certificate's trust may be compromised. This tool did not and cannot independently verify "
                            "any internal key-generation weakness."
                        ),
                        severity=Severity.HIGH,
                        points=45,
                        technical_evidence={
                            "matched_ca": bad_ca.get("ca_name"),
                            "fingerprint": cert_fp,
                            "source_name": bad_ca.get("source_name"),
                            "source_url": bad_ca.get("source_url"),
                            "date": bad_ca.get("date_added")
                        },
                        source="distrust list match",
                        potential_impact="Certificate trust may be compromised, so the certificate may not reliably prove the site's identity.",
                        recommendation="Replace the certificate with one from a currently trusted authority.",
                        limitation="This is a match to a published list. The tool cannot verify any internal key-generation weakness."
                    ))
                    break

                elif m_type == "subject_name" and val in issuer_name and status == "unverified" and not tls_06_fired:
                    findings.append(Finding(
                        id="F-TLS-06n",
                        signal_id="TLS-06n",
                        category=FindingCategory.TLS,
                        title="Certificate issuer name matches distrusted CA family (advisory)",
                        description=(
                            f"Certificate issuer name matches an advisory entry for {bad_ca.get('ca_name')}. "
                            "Fingerprint match is unconfirmed and requires independent verification."
                        ),
                        severity=Severity.MEDIUM,
                        points=15,
                        technical_evidence={"issuer": cert_item["issuer"], "pattern": val},
                        source="distrust list match",
                        potential_impact="May indicate association with an untrusted certificate authority family.",
                        recommendation="Check the certificate issuer against browser root program advisories.",
                        limitation="Issuer names can be forged or used in separate non-distrusted PKI branches."
                    ))
                    break

        # 7. Certificate Transparency crt.sh query
        ct_summary, ct_success = self.query_crt_sh(hostname)

        # 8. Determine TLS Verdict
        if tls_06_fired:
            tls_verdict = "Potentially compromised trust"
        elif any(f.signal_id in ("TLS-02", "TLS-03") for f in findings) and len(findings) > 1:
            tls_verdict = "Suspicious"
        elif findings:
            tls_verdict = "Configuration problems"
        else:
            tls_verdict = "Valid configuration"

        tls_report = TLSReport(
            subject=leaf["subject"],
            san_list=leaf["san_list"],
            issuer=leaf["issuer"],
            validity_start=leaf["start_date"],
            validity_end=leaf["end_date"],
            days_remaining=leaf["days_remaining"],
            public_key_algorithm=leaf["public_key_algorithm"],
            public_key_size=leaf["public_key_size"],
            signature_algorithm=leaf["signature_algorithm"],
            certificate_sha256=leaf["cert_sha256"],
            spki_sha256=leaf["spki_sha256"],
            chain_list=[c["subject"] for c in parsed_chain],
            trust_result=trust_result if not tls_06_fired else "distrusted",
            ct_summary=ct_summary,
            tls_verdict=tls_verdict,
            https_note=HTTPS_DISCLAIMER
        )

        return {
            "tls_report": tls_report,
            "tls_available": True,
            "ct_available": ct_success,
            "findings": findings
        }

tls_analyzer = TLSAnalyzer()
