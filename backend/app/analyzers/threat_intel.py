import json
import os
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Any, Tuple

from backend.app.core.config import settings
from backend.app.models import (
    Finding, FindingCategory, Severity, ThreatIntelSummary, ThreatIntelMatch
)

DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

def _load_bundled_threats() -> List[Dict[str, Any]]:
    path = os.path.join(DATA_DIR, "threat_dataset.json")
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

BUNDLED_THREATS = _load_bundled_threats()

class ThreatIntelClient:
    def __init__(self, auth_key: Optional[str] = None, timeout: float = 5.0):
        self.auth_key = auth_key or settings.urlhaus_auth_key
        self.timeout = timeout
        self._cache: Dict[str, Tuple[float, Any]] = {}

    def _query_urlhaus_api(self, endpoint: str, data: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], bool]:
        if not self.auth_key:
            return None, False

        cache_key = f"{endpoint}:{json.dumps(data, sort_keys=True)}"
        now = time.time()
        if cache_key in self._cache:
            ts, val = self._cache[cache_key]
            if now - ts < 900:  # 15 min cache
                return val, True

        api_url = f"https://urlhaus-api.abuse.ch/v1/{endpoint}/"
        try:
            req_data = urllib.parse.urlencode(data).encode("utf-8")
            req = urllib.request.Request(
                api_url,
                data=req_data,
                headers={
                    "Auth-Key": self.auth_key,
                    "User-Agent": "LinkAndScamDetective-Bot/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    res_json = json.loads(resp.read().decode("utf-8"))
                    self._cache[cache_key] = (now, res_json)
                    return res_json, True
        except Exception:
            pass

        return None, False

    def query_urlhaus_url(self, target_url: str) -> Tuple[Optional[Dict[str, Any]], bool]:
        return self._query_urlhaus_api("url", {"url": target_url})

    def query_urlhaus_host(self, host: str) -> Tuple[Optional[Dict[str, Any]], bool]:
        return self._query_urlhaus_api("host", {"host": host})

    def analyze(self, target_url: str, hostname: str, registrable_domain: str) -> Dict[str, Any]:
        findings: List[Finding] = []
        matches: List[ThreatIntelMatch] = []
        feeds_queried: List[str] = []
        feeds_answered: List[str] = []
        feeds_unavailable: List[str] = []
        short_circuit_fetch = False

        # 1. URLhaus Query
        feeds_queried.append("URLhaus (abuse.ch)")
        if self.auth_key:
            # Query exact URL
            url_res, url_ok = self.query_urlhaus_url(target_url)
            # Query host
            host_res, host_ok = self.query_urlhaus_host(hostname)

            if url_ok or host_ok:
                feeds_answered.append("URLhaus (abuse.ch)")

                # INT-01: Exact URL match
                if url_ok and url_res and url_res.get("query_status") == "ok":
                    u_status = url_res.get("url_status", "unknown")
                    u_date = url_res.get("date_added", "unknown")
                    u_threat = url_res.get("threat", "malware_download")

                    matches.append(ThreatIntelMatch(
                        source_name="URLhaus (abuse.ch)",
                        listing_status=u_status,
                        listing_date=u_date,
                        threat_type=u_threat,
                        reference_url=url_res.get("urlhaus_reference")
                    ))

                    short_circuit_fetch = True
                    findings.append(Finding(
                        id="F-INT-01",
                        signal_id="INT-01",
                        category=FindingCategory.INTEL,
                        title="Exact URL listed as malicious on URLhaus",
                        description=f"Exact URL is listed on authoritative threat feed URLhaus (status: {u_status}, added: {u_date}, threat: {u_threat}).",
                        severity=Severity.CRITICAL,
                        points=100,  # Forces Confirmed Malicious
                        technical_evidence={"feed": "URLhaus", "status": u_status, "date_added": u_date, "threat": u_threat},
                        source="URLhaus",
                        potential_impact="Active malware distribution or verified malicious campaign endpoint.",
                        recommendation="Block access immediately; do not visit or download files.",
                        limitation="Feed classifications reflect reported incidents at the recorded time."
                    ))

                # INT-01 / INT-02 on Host
                elif host_ok and host_res and host_res.get("query_status") == "ok":
                    h_status = host_res.get("host_status", "offline")
                    h_first = host_res.get("firstseen", "unknown")
                    matches.append(ThreatIntelMatch(
                        source_name="URLhaus (abuse.ch)",
                        listing_status=h_status,
                        listing_date=h_first,
                        threat_type="Malicious Host",
                        reference_url=host_res.get("urlhaus_reference")
                    ))

                    if h_status == "online":
                        short_circuit_fetch = True
                        findings.append(Finding(
                            id="F-INT-01",
                            signal_id="INT-01",
                            category=FindingCategory.INTEL,
                            title="Active malicious host listed on URLhaus",
                            description=f"Host '{hostname}' is actively listed with online status on URLhaus (first seen: {h_first}).",
                            severity=Severity.CRITICAL,
                            points=100,  # Forces Confirmed Malicious
                            technical_evidence={"feed": "URLhaus", "status": h_status, "first_seen": h_first},
                            source="URLhaus",
                            potential_impact="Host is actively participating in malicious malware distribution.",
                            recommendation="Block network traffic to this host immediately.",
                            limitation="Shared hosting providers may host both malicious and clean tenants."
                        ))
                    else:
                        findings.append(Finding(
                            id="F-INT-02",
                            signal_id="INT-02",
                            category=FindingCategory.INTEL,
                            title="Historical or offline malicious host on URLhaus",
                            description=f"Host '{hostname}' was previously catalogued as malicious on URLhaus (status: {h_status}, first seen: {h_first}).",
                            severity=Severity.HIGH,
                            points=40,
                            technical_evidence={"feed": "URLhaus", "status": h_status, "first_seen": h_first},
                            source="URLhaus",
                            potential_impact="Indicates a domain with history of malicious compromise or threat actor registration.",
                            recommendation="Exercise elevated caution when inspecting this domain.",
                            limitation="Historical listings may include domains that have since been remediated or abandoned."
                        ))
            else:
                feeds_unavailable.append("URLhaus (abuse.ch)")
        else:
            feeds_unavailable.append("URLhaus (abuse.ch)")

        # 2. Bundled Documented Dataset (INT-03)
        # Runs always, serving as verified fallback or secondary source
        feeds_queried.append("Bundled Curated Threat Dataset")
        feeds_answered.append("Bundled Curated Threat Dataset")

        for item in BUNDLED_THREATS:
            i_type = item.get("indicator_type")
            i_val = item.get("value", "").lower()

            matched = False
            if i_type == "domain" and (hostname == i_val or registrable_domain == i_val):
                matched = True
            elif i_type == "url_pattern" and target_url.lower().startswith(i_val):
                matched = True

            if matched:
                matches.append(ThreatIntelMatch(
                    source_name=f"Bundled Dataset ({item.get('source')})",
                    listing_status="listed",
                    listing_date=item.get("date_added"),
                    threat_type=item.get("threat_type")
                ))

                findings.append(Finding(
                    id="F-INT-03",
                    signal_id="INT-03",
                    category=FindingCategory.INTEL,
                    title=f"Match in documented threat dataset ({item.get('category')})",
                    description=(
                        f"Target matches verified malicious indicator in the curated threat dataset for {item.get('category')}: "
                        f"{item.get('threat_type')} (Source: {item.get('source')}, Date: {item.get('date_added')})."
                    ),
                    severity=Severity.HIGH,
                    points=40,
                    technical_evidence={
                        "category": item.get("category"),
                        "threat_type": item.get("threat_type"),
                        "source": item.get("source"),
                        "date_added": item.get("date_added"),
                        "license": item.get("license")
                    },
                    source="bundled dataset",
                    potential_impact="Confirmed phishing or financial scam indicator catalogued in security benchmark datasets.",
                    recommendation="Do not access or submit information to this destination.",
                    limitation="Indicators reflect specific captured campaigns from benchmark datasets."
                ))
                break

        summary = ThreatIntelSummary(
            feeds_queried=feeds_queried,
            feeds_answered=feeds_answered,
            feeds_unavailable=feeds_unavailable,
            matches=matches
        )

        return {
            "summary": summary,
            "findings": findings,
            "short_circuit_fetch": short_circuit_fetch
        }

threat_intel_client = ThreatIntelClient()
