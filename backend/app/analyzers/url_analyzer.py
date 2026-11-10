import json
import os
import re
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

from backend.app.models import Finding, FindingCategory, Severity
from backend.app.core.safe_client import defang_url

# Load static data files
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))

def _load_json(filename: str, default: Any) -> Any:
    path = os.path.join(DATA_DIR, filename)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return default

BRANDS_DATA = _load_json("brands.json", [])
KEYWORDS_DATA = _load_json("keywords.json", {"phishing_keywords": [], "redirect_parameters": []})
TLD_DATA = _load_json("tlds_and_shorteners.json", {"suspicious_tlds": [], "url_shorteners": []})

PHISHING_KEYWORDS = set(KEYWORDS_DATA.get("phishing_keywords", []))
REDIRECT_PARAMS = set(KEYWORDS_DATA.get("redirect_parameters", []))
SUSPICIOUS_TLDS = set(TLD_DATA.get("suspicious_tlds", []))
URL_SHORTENERS = set(TLD_DATA.get("url_shorteners", []))

# Two-level public suffixes for accurate registrable domain splitting
TWO_LEVEL_TLDS = {
    "co.in", "gov.in", "org.in", "ac.in", "net.in", "res.in", "edu.in",
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "com.br", "org.br", "net.br",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.sg", "edu.sg", "gov.sg"
}

def parse_domain_parts(hostname: str) -> Tuple[str, str, str]:
    """Splits hostname into (subdomain, registrable_domain, suffix)."""
    parts = hostname.lower().strip(".").split(".")
    if len(parts) <= 1:
        return "", hostname.lower(), ""
    if len(parts) == 2:
        return "", hostname.lower(), parts[-1]

    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in TWO_LEVEL_TLDS and len(parts) >= 3:
        reg_domain = f"{parts[-3]}.{last_two}"
        suffix = last_two
        subdomain = ".".join(parts[:-3])
        return subdomain, reg_domain, suffix

    reg_domain = f"{parts[-2]}.{parts[-1]}"
    suffix = parts[-1]
    subdomain = ".".join(parts[:-2])
    return subdomain, reg_domain, suffix

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def normalize_confusables(text: str) -> str:
    """Normalizes typical confusable characters: 0->o, 1/!/|->l, rn->m, vv->w."""
    t = text.lower()
    t = t.replace("0", "o")
    t = t.replace("1", "l").replace("!", "l").replace("|", "l")
    t = t.replace("rn", "m")
    t = t.replace("vv", "w")
    return t

class URLAnalyzer:
    def __init__(self, brands=None, phishing_keywords=None, suspicious_tlds=None, shorteners=None):
        self.brands = brands or BRANDS_DATA
        self.phishing_keywords = phishing_keywords or PHISHING_KEYWORDS
        self.suspicious_tlds = suspicious_tlds or SUSPICIOUS_TLDS
        self.shorteners = shorteners or URL_SHORTENERS

    def normalize_url(self, raw_url: str) -> Dict[str, Any]:
        cleaned = raw_url.strip()
        # Assume https if no scheme
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
            cleaned = "https://" + cleaned

        parsed = urllib.parse.urlsplit(cleaned)
        host = (parsed.hostname or "").lower()

        # Punycode conversion
        unicode_host = host
        punycode_host = host
        is_punycode = False
        try:
            if host.startswith("xn--") or ".xn--" in host:
                unicode_host = host.encode("utf-8").decode("idna")
                is_punycode = True
            else:
                punycode_host = host.encode("idna").decode("utf-8")
                if punycode_host != host:
                    is_punycode = True
        except Exception:
            pass

        subdomain, reg_domain, suffix = parse_domain_parts(host)

        # Query parameters list
        query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

        return {
            "original_url": raw_url,
            "normalized_url": cleaned,
            "scheme": parsed.scheme.lower(),
            "host": host,
            "unicode_host": unicode_host,
            "punycode_host": punycode_host,
            "is_punycode": is_punycode,
            "port": parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
            "user_info": parsed.username or "",
            "subdomain": subdomain,
            "registrable_domain": reg_domain,
            "suffix": suffix,
            "path": parsed.path or "/",
            "query": parsed.query,
            "query_params": query_params,
            "fragment": parsed.fragment
        }

    def analyze(self, raw_url: str) -> Dict[str, Any]:
        norm = self.normalize_url(raw_url)
        findings: List[Finding] = []
        is_official_match = False
        matched_brand_name = None

        reg_domain = norm["registrable_domain"]
        host = norm["host"]
        subdomain = norm["subdomain"]
        path = norm["path"]
        suffix = norm["suffix"]

        # Check official match first (MIT-01)
        for b in self.brands:
            official_domains = [d.lower() for d in b.get("official_domains", [])]
            if reg_domain in official_domains:
                is_official_match = True
                matched_brand_name = b.get("brand")
                break

        # If official match, impersonation checks do NOT apply (MIT-01)
        if not is_official_match:
            # IMP-01: Brand keyword inside unofficial registrable domain
            # IMP-02: Levenshtein distance 1 or 2 of brand label, or confusable match
            # IMP-03: Brand keyword in subdomain or path of unrelated domain
            reg_second_level = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
            reg_norm_confusables = normalize_confusables(reg_second_level)

            for b in self.brands:
                b_name = b.get("brand")
                b_keywords = [k.lower() for k in b.get("keywords", [])]

                for kw in b_keywords:
                    # IMP-01: Exact brand keyword within registrable domain (e.g. sbi-update.com)
                    # Use token or boundary check to prevent spurious substring match (e.g. pineapple.com)
                    kw_pattern = rf"(?:^|[-_.]){re.escape(kw)}(?:[-_.]|$)"
                    if re.search(kw_pattern, reg_second_level):
                        findings.append(Finding(
                            id=f"F-{len(findings)+1:02d}",
                            signal_id="IMP-01",
                            category=FindingCategory.IMPERSONATION,
                            title=f"Brand impersonation in domain ({b_name})",
                            description=f"The registrable domain contains the brand keyword '{kw}' but is not an official domain of {b_name}.",
                            severity=Severity.HIGH,
                            points=40,
                            technical_evidence={"brand": b_name, "keyword": kw, "registrable_domain": reg_domain},
                            source="lexical analysis",
                            potential_impact="Users may enter credentials on a site pretending to be a known organisation.",
                            recommendation=f"Do not enter details; report the site to {b_name}.",
                            limitation="Lexical evidence suggests impersonation but is not proof of fraud."
                        ))
                        break

                    # IMP-02: Typosquatting (Levenshtein distance 1 or 2, or confusable chars)
                    dist = levenshtein_distance(reg_second_level, kw)
                    max_allowed_dist = 1 if len(kw) < 5 else 2
                    is_confusable_match = (reg_norm_confusables == kw or reg_norm_confusables == normalize_confusables(kw))

                    if (1 <= dist <= max_allowed_dist) or (is_confusable_match and reg_second_level != kw):
                        findings.append(Finding(
                            id=f"F-{len(findings)+1:02d}",
                            signal_id="IMP-02",
                            category=FindingCategory.IMPERSONATION,
                            title=f"Typosquatting or look-alike domain ({b_name})",
                            description=f"Domain '{reg_domain}' closely resembles brand '{kw}' (edit distance {dist} or confusable character substitution).",
                            severity=Severity.HIGH,
                            points=40,
                            technical_evidence={"brand": b_name, "target_keyword": kw, "edit_distance": dist, "domain_label": reg_second_level},
                            source="lexical analysis",
                            potential_impact="Users may mistakenly believe they are visiting the legitimate brand website.",
                            recommendation="Double-check the spelling of the domain before entering any information.",
                            limitation="Similar names can occasionally be registered legitimately."
                        ))
                        break

                    # IMP-03: Brand keyword only in subdomain or path of unrelated domain
                    sub_or_path = f"{subdomain} {path}".lower()
                    if re.search(kw_pattern, sub_or_path):
                        findings.append(Finding(
                            id=f"F-{len(findings)+1:02d}",
                            signal_id="IMP-03",
                            category=FindingCategory.IMPERSONATION,
                            title=f"Brand keyword in subdomain or path ({b_name})",
                            description=f"Brand keyword '{kw}' appears in the subdomain or path of unrelated domain '{reg_domain}'.",
                            severity=Severity.MEDIUM,
                            points=30,
                            technical_evidence={"brand": b_name, "keyword": kw, "host": host, "path": path},
                            source="lexical analysis",
                            potential_impact="Attackers frequently host phishing pages on third-party domains using branded subdomains.",
                            recommendation="Check the primary domain name at the end of the URL before trusting the page.",
                            limitation="Some multi-tenant services legitimately feature brand names in subdomains."
                        ))
                        break

            # IMP-04: Punycode or mixed-script / lookalike characters mimicking Latin letters
            if norm["is_punycode"] or norm["unicode_host"] != host:
                findings.append(Finding(
                    id=f"F-{len(findings)+1:02d}",
                    signal_id="IMP-04",
                    category=FindingCategory.IMPERSONATION,
                    title="Punycode or homograph domain detected",
                    description=f"The domain uses internationalized characters ({norm['unicode_host']}) mimicking standard Latin characters.",
                    severity=Severity.HIGH,
                    points=40,
                    technical_evidence={"punycode": host, "unicode": norm["unicode_host"]},
                    source="lexical analysis",
                    potential_impact="Visual homograph attacks fool users into thinking they are viewing an authentic website.",
                    recommendation="Do not enter passwords or credentials on homograph domains.",
                    limitation="International organizations legitimately use non-Latin domain names in regional contexts."
                ))

        # Structure checks (STR-01 to STR-07)
        # STR-01: Phishing keyword in hostname together with brand keyword
        found_phish_kw = [k for k in self.phishing_keywords if k in host]
        if found_phish_kw and any(f.signal_id.startswith("IMP") for f in findings):
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-01",
                category=FindingCategory.STRUCTURE,
                title="Phishing keyword combined with brand in hostname",
                description=f"The hostname combines brand references with phishing lures: {', '.join(found_phish_kw)}.",
                severity=Severity.MEDIUM,
                points=15,
                technical_evidence={"keywords_found": found_phish_kw, "hostname": host},
                source="lexical analysis",
                potential_impact="Commonly used to create high-urgency fake login or verification portals.",
                recommendation="Navigate to the service directly via bookmark or official search.",
                limitation="A legitimate site may occasionally use words like login or account."
            ))

        # STR-02: IP address used as host
        try:
            socket.inet_aton(host)
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-02",
                category=FindingCategory.STRUCTURE,
                title="IP address used as host",
                description="The URL uses a raw IP address instead of a domain name.",
                severity=Severity.MEDIUM,
                points=20,
                technical_evidence={"ip_host": host},
                source="lexical analysis",
                potential_impact="Raw IP URLs bypass domain reputation filters and are common in automated attacks.",
                recommendation="Avoid entering sensitive data on raw IP addresses.",
                limitation="Some development and router interfaces use IP addresses legitimately."
            ))
        except Exception:
            pass

        # STR-03: User-info section (the @ trick)
        if norm["user_info"]:
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-03",
                category=FindingCategory.STRUCTURE,
                title="User-info trick (@-sign in URL)",
                description=f"The URL contains user credentials '{norm['user_info']}' before the @-sign, which can disguise the true host.",
                severity=Severity.MEDIUM,
                points=20,
                technical_evidence={"user_info": norm["user_info"], "actual_host": host},
                source="lexical analysis",
                potential_impact="Browsers discard text before the @ symbol, tricking users about the destination.",
                recommendation="Inspect the host following the @ character.",
                limitation="Legacy HTTP basic authentication specs permitted user credentials in URLs."
            ))

        # STR-04: Excessive subdomains, hyphens, or long hostname
        sub_count = len(subdomain.split(".")) if subdomain else 0
        hyphen_count = host.count("-")
        is_long = len(host) > 60
        if sub_count >= 4 or hyphen_count >= 3 or is_long:
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-04",
                category=FindingCategory.STRUCTURE,
                title="Suspicious domain structure complexity",
                description=f"Hostname has excessive complexity: {sub_count} subdomain levels, {hyphen_count} hyphens, length {len(host)}.",
                severity=Severity.LOW,
                points=10,
                technical_evidence={"subdomain_count": sub_count, "hyphen_count": hyphen_count, "host_length": len(host)},
                source="lexical analysis",
                potential_impact="Adversaries use deep subdomains and hyphens to evade simple domain filtering.",
                recommendation="Verify the base domain identity carefully.",
                limitation="Some cloud services and CDN URLs naturally have multiple subdomains."
            ))

        # STR-05: Suspicious top-level domain
        if suffix.lower() in self.suspicious_tlds:
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-05",
                category=FindingCategory.STRUCTURE,
                title=f"Suspicious top-level domain (.{suffix})",
                description=f"The top-level domain '.{suffix}' is frequently abused in high-volume phishing and disposable infrastructure.",
                severity=Severity.LOW,
                points=8,
                technical_evidence={"tld": suffix},
                source="lexical analysis",
                potential_impact="Higher statistical probability of spam or abuse.",
                recommendation="Exercise caution when submitting credentials on this TLD.",
                limitation="Legitimate websites use these TLDs as well; this is a weak signal."
            ))

        # STR-06: Known URL shortener host
        if reg_domain in self.shorteners or host in self.shorteners:
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-06",
                category=FindingCategory.STRUCTURE,
                title="URL shortener service detected",
                description=f"The host '{host}' is a URL shortening service that conceals the ultimate destination.",
                severity=Severity.LOW,
                points=10,
                technical_evidence={"shortener": host},
                source="lexical analysis",
                potential_impact="Conceals destination domain, enabling attackers to bypass initial content inspection.",
                recommendation="Expand the shortener link safely before visiting.",
                limitation="Shorteners are routinely used for clean links on social media and SMS."
            ))

        # STR-07: Query parameter carries another URL (embedded redirect)
        has_embedded_redirect = False
        embedded_param = None
        for k, v in norm["query_params"]:
            if k.lower() in REDIRECT_PARAMS or re.match(r"^https?://", v.lower()):
                has_embedded_redirect = True
                embedded_param = (k, v)
                break

        if has_embedded_redirect:
            findings.append(Finding(
                id=f"F-{len(findings)+1:02d}",
                signal_id="STR-07",
                category=FindingCategory.STRUCTURE,
                title="Embedded redirect parameter detected",
                description=f"The query parameter '{embedded_param[0]}' contains a redirect target, potentially enabling an open redirect.",
                severity=Severity.LOW,
                points=10,
                technical_evidence={"param": embedded_param[0], "target": defang_url(embedded_param[1])},
                source="lexical analysis",
                potential_impact="Attackers exploit open redirects on legitimate sites to route victims to phishing pages.",
                recommendation="Inspect the final destination rather than trusting the visible domain.",
                limitation="OAuth and SSO flows legitimately use return and redirect query parameters."
            ))

        return {
            "normalization": norm,
            "is_official_match": is_official_match,
            "matched_brand": matched_brand_name,
            "findings": findings
        }

url_analyzer = URLAnalyzer()
