import socket
import time
import urllib.request
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple

from backend.app.models import Finding, FindingCategory, Severity

class DomainAnalyzer:
    def __init__(self, rdap_timeout: float = 4.0):
        self.rdap_timeout = rdap_timeout

    def resolve_dns(self, hostname: str) -> Tuple[List[str], bool]:
        """Resolves DNS A/AAAA records for the host."""
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            ips = []
            for item in addr_info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            return ips, True
        except Exception:
            return [], False

    def query_rdap(self, registrable_domain: str) -> Tuple[Optional[datetime], Optional[str], bool]:
        """
        Queries RDAP for registration date and registrar.
        Returns: (registration_date, registrar, is_available)
        """
        if not registrable_domain or "." not in registrable_domain:
            return None, None, False

        rdap_url = f"https://rdap.org/domain/{registrable_domain}"
        try:
            req = urllib.request.Request(
                rdap_url,
                headers={"User-Agent": "LinkAndScamDetective-Bot/1.0", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=self.rdap_timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    # Look for registration event
                    reg_date = None
                    events = data.get("events", [])
                    for ev in events:
                        if ev.get("eventAction") in ("registration", "registered", "created"):
                            try:
                                # Parse ISO timestamp e.g. 2026-01-15T10:00:00Z
                                date_str = ev.get("eventDate", "")
                                reg_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                break
                            except Exception:
                                pass
                    
                    # Registrar name
                    registrar = None
                    for ent in data.get("entities", []):
                        if "registrar" in ent.get("roles", []):
                            vcard = ent.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        registrar = item[3]
                                        break
                    return reg_date, registrar, True
        except Exception:
            pass

        return None, None, False

    def analyze(self, hostname: str, registrable_domain: str, is_official_match: bool = False) -> Dict[str, Any]:
        findings: List[Finding] = []
        resolved_ips, dns_success = self.resolve_dns(hostname)
        
        # Check DOM-03: Domain does not resolve in DNS
        if not dns_success or not resolved_ips:
            findings.append(Finding(
                id="F-DOM-03",
                signal_id="DOM-03",
                category=FindingCategory.DOMAIN,
                title="Domain does not resolve in DNS",
                description=f"Hostname '{hostname}' failed DNS resolution or has no active records.",
                severity=Severity.LOW,
                points=5,
                technical_evidence={"hostname": hostname, "dns_success": False},
                source="DNS",
                potential_impact="The website cannot currently be contacted. It may be offline or newly registered.",
                recommendation="Wait until DNS propagation finishes or verify the domain spelling.",
                limitation="Unreachable domains cannot be definitively classified as malicious."
            ))
            return {
                "resolved_ips": [],
                "dns_available": False,
                "rdap_available": False,
                "domain_age_days": None,
                "registrar": None,
                "findings": findings
            }

        # If domain resolves and is NOT an official match, check RDAP age
        reg_date, registrar, rdap_available = self.query_rdap(registrable_domain)
        age_days = None

        if reg_date:
            now = datetime.now(timezone.utc)
            age_days = (now - reg_date).days

            # DOM-01: Registered less than 30 days
            if age_days < 30 and not is_official_match:
                findings.append(Finding(
                    id="F-DOM-01",
                    signal_id="DOM-01",
                    category=FindingCategory.DOMAIN,
                    title="Newly registered domain (under 30 days)",
                    description=f"Domain was registered {age_days} days ago ({reg_date.strftime('%Y-%m-%d')}).",
                    severity=Severity.MEDIUM,
                    points=25,
                    technical_evidence={"registration_date": reg_date.isoformat(), "age_days": age_days, "registrar": registrar},
                    source="RDAP",
                    potential_impact="Phishing and scam campaigns predominantly operate on disposable, newly registered domains.",
                    recommendation="Treat newly created domains with heightened scrutiny.",
                    limitation="Brand-new legitimate startups and promotional sites also register new domains."
                ))
            # DOM-02: Registered between 30 and 90 days
            elif age_days <= 90 and not is_official_match:
                findings.append(Finding(
                    id="F-DOM-02",
                    signal_id="DOM-02",
                    category=FindingCategory.DOMAIN,
                    title="Young domain (under 90 days)",
                    description=f"Domain was registered {age_days} days ago ({reg_date.strftime('%Y-%m-%d')}).",
                    severity=Severity.LOW,
                    points=10,
                    technical_evidence={"registration_date": reg_date.isoformat(), "age_days": age_days, "registrar": registrar},
                    source="RDAP",
                    potential_impact="Young domains have limited established reputation history.",
                    recommendation="Exercise caution if this site requests sensitive credentials.",
                    limitation="Legitimate businesses register new domains continuously."
                ))

        return {
            "resolved_ips": resolved_ips,
            "dns_available": True,
            "rdap_available": rdap_available,
            "domain_age_days": age_days,
            "registrar": registrar,
            "findings": findings
        }

domain_analyzer = DomainAnalyzer()
