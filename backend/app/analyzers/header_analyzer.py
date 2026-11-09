from typing import Dict, List, Optional, Tuple, Any
from backend.app.models import Finding, FindingCategory, Severity, SecurityHeaderResult

class HeaderAnalyzer:
    def analyze_headers(self, headers: Dict[str, str]) -> Tuple[List[SecurityHeaderResult], List[Finding]]:
        findings: List[Finding] = []
        results: List[SecurityHeaderResult] = []

        # 1. Strict-Transport-Security (HSTS)
        hsts_val = headers.get("strict-transport-security")
        if hsts_val:
            results.append(SecurityHeaderResult(
                header_name="Strict-Transport-Security",
                present=True,
                observed_value=hsts_val,
                severity=Severity.INFO
            ))
        else:
            results.append(SecurityHeaderResult(
                header_name="Strict-Transport-Security",
                present=False,
                severity=Severity.MEDIUM
            ))
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-HSTS",
                category=FindingCategory.HEADERS,
                title="Missing Strict-Transport-Security",
                description="The server does not enforce HTTPS connections using the Strict-Transport-Security header.",
                severity=Severity.MEDIUM,
                points=2,
                technical_evidence={"header": "Strict-Transport-Security", "status": "missing"},
                source="header inspection",
                potential_impact="Browsers may connect over unencrypted HTTP first, exposing users to interception on hostile networks.",
                recommendation="Send the header with a long max-age (at least six months) over HTTPS and consider covering subdomains.",
                limitation="Observed on one response only; other paths may differ."
            ))

        # 2. Content-Security-Policy (CSP)
        csp_val = headers.get("content-security-policy")
        if csp_val:
            results.append(SecurityHeaderResult(
                header_name="Content-Security-Policy",
                present=True,
                observed_value=csp_val,
                severity=Severity.INFO
            ))
        else:
            results.append(SecurityHeaderResult(
                header_name="Content-Security-Policy",
                present=False,
                severity=Severity.MEDIUM
            ))
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-CSP",
                category=FindingCategory.HEADERS,
                title="Missing Content-Security-Policy",
                description="The server does not specify a Content-Security-Policy (CSP) header.",
                severity=Severity.MEDIUM,
                points=2,
                technical_evidence={"header": "Content-Security-Policy", "status": "missing"},
                source="header inspection",
                potential_impact="Weaker defence against injected scripts and content.",
                recommendation="Define a restrictive policy limiting where scripts, frames and other resources may load from.",
                limitation="A header proves nothing about whether the site contains vulnerable code."
            ))

        # 3. Frame Protection (X-Frame-Options or frame-ancestors in CSP)
        xfo_val = headers.get("x-frame-options")
        has_frame_ancestors = csp_val and "frame-ancestors" in csp_val.lower()
        if xfo_val or has_frame_ancestors:
            results.append(SecurityHeaderResult(
                header_name="X-Frame-Options",
                present=True,
                observed_value=xfo_val or "Handled via CSP frame-ancestors",
                severity=Severity.INFO
            ))
        else:
            results.append(SecurityHeaderResult(
                header_name="X-Frame-Options",
                present=False,
                severity=Severity.LOW
            ))
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-XFO",
                category=FindingCategory.HEADERS,
                title="Missing frame protection",
                description="The server does not provide clickjacking protection via X-Frame-Options or CSP frame-ancestors.",
                severity=Severity.LOW,
                points=2,
                technical_evidence={"header": "X-Frame-Options", "status": "missing"},
                source="header inspection",
                potential_impact="The site may be embedded in another page to trick users into clicking (clickjacking).",
                recommendation="Send X-Frame-Options: DENY or SAMEORIGIN, or a frame-ancestors directive.",
                limitation="Only the response headers were inspected."
            ))

        # 4. X-Content-Type-Options
        xcto_val = headers.get("x-content-type-options")
        if xcto_val and "nosniff" in xcto_val.lower():
            results.append(SecurityHeaderResult(
                header_name="X-Content-Type-Options",
                present=True,
                observed_value=xcto_val,
                severity=Severity.INFO
            ))
        else:
            results.append(SecurityHeaderResult(
                header_name="X-Content-Type-Options",
                present=False,
                severity=Severity.LOW
            ))
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-XCTO",
                category=FindingCategory.HEADERS,
                title="Missing X-Content-Type-Options",
                description="The server does not specify X-Content-Type-Options: nosniff.",
                severity=Severity.LOW,
                points=2,
                technical_evidence={"header": "X-Content-Type-Options", "status": "missing"},
                source="header inspection",
                potential_impact="Browsers may guess content types, which can enable some attacks.",
                recommendation="Send the header with the value nosniff.",
                limitation="Informational on its own."
            ))

        # 5. Referrer-Policy
        ref_val = headers.get("referrer-policy")
        if ref_val:
            results.append(SecurityHeaderResult(
                header_name="Referrer-Policy",
                present=True,
                observed_value=ref_val,
                severity=Severity.INFO
            ))
        else:
            results.append(SecurityHeaderResult(
                header_name="Referrer-Policy",
                present=False,
                severity=Severity.LOW
            ))
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-REF",
                category=FindingCategory.HEADERS,
                title="Missing Referrer-Policy",
                description="The server does not specify a Referrer-Policy header.",
                severity=Severity.LOW,
                points=2,
                technical_evidence={"header": "Referrer-Policy", "status": "missing"},
                source="header inspection",
                potential_impact="Full page addresses may leak to other sites.",
                recommendation="Set a restrictive referrer policy.",
                limitation="Informational on its own."
            ))

        # 6. Permissions-Policy
        perm_val = headers.get("permissions-policy")
        if perm_val:
            results.append(SecurityHeaderResult(
                header_name="Permissions-Policy",
                present=True,
                observed_value=perm_val,
                severity=Severity.INFO
            ))
        else:
            results.append(SecurityHeaderResult(
                header_name="Permissions-Policy",
                present=False,
                severity=Severity.LOW
            ))
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-PERM",
                category=FindingCategory.HEADERS,
                title="Missing Permissions-Policy",
                description="The server does not specify a Permissions-Policy header.",
                severity=Severity.LOW,
                points=2,
                technical_evidence={"header": "Permissions-Policy", "status": "missing"},
                source="header inspection",
                potential_impact="Browser features are not explicitly limited for embedded content.",
                recommendation="Set a policy that disables unneeded features.",
                limitation="Informational on its own."
            ))

        # 7. Server version disclosure
        server_val = headers.get("server")
        if server_val and any(char.isdigit() for char in server_val):
            findings.append(Finding(
                id=f"F-HDR-{len(findings)+1:02d}",
                signal_id="HDR-SERVER",
                category=FindingCategory.HEADERS,
                title="Server version disclosed",
                description=f"Server header discloses detailed software version: '{server_val}'.",
                severity=Severity.INFO,
                points=0,
                technical_evidence={"server_header": server_val},
                source="header inspection",
                potential_impact="Helps attackers choose known weaknesses for that version.",
                recommendation="Hide detailed version strings in web server configuration.",
                limitation="Not proof that the version is vulnerable."
            ))

        return results, findings

header_analyzer = HeaderAnalyzer()
