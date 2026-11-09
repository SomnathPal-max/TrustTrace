import http.client
import ipaddress
import ssl
import time
import urllib.parse
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

from backend.app.core.ssrf import ssrf_guard, SSRFValidationResult
from backend.app.models import RedirectHop

MAX_BODY_BYTES = 200 * 1024  # 200 KB
MAX_REDIRECT_HOPS = 5
CONNECT_TIMEOUT = 4.0
REQUEST_TIMEOUT = 10.0
USER_AGENT = "LinkAndScamDetective-Bot/1.0 (+https://github.com/apex-warcode/trusttrace; security-research)"

@dataclass
class SafeHTTPResponse:
    url: str
    status_code: int
    headers: Dict[str, str]
    body: bytes
    redirect_chain: List[RedirectHop]
    resolved_ips: List[str]
    truncated: bool = False
    duration_ms: int = 0
    error: Optional[str] = None

def defang_url(url_str: str) -> str:
    """Defangs a URL for safe display (e.g. hxxps://domain[.]com/path)."""
    if not url_str:
        return ""
    res = url_str.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Defang dots in the host portion
    parts = res.split("/", 3)
    if len(parts) >= 3:
        parts[2] = parts[2].replace(".", "[.]")
        return "/".join(parts)
    return res.replace(".", "[.]")

def get_registrable_domain_simple(hostname: str) -> str:
    """Extracts registrable domain (e.g. sbi.co.in, example.com)."""
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname.lower()
    # Check known two-level TLDs
    two_level_tlds = {"co.in", "gov.in", "org.in", "ac.in", "co.uk", "com.au", "com.br", "net.in"}
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in two_level_tlds:
        return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
    return f"{parts[-2]}.{parts[-1]}"

class SafeHTTPClient:
    def __init__(self, guard=None):
        self.guard = guard or ssrf_guard

    def get(self, url: str) -> SafeHTTPResponse:
        return self._request_with_redirects("GET", url)

    def head(self, url: str) -> SafeHTTPResponse:
        return self._request_with_redirects("HEAD", url)

    def _request_with_redirects(self, method: str, start_url: str) -> SafeHTTPResponse:
        t0 = time.time()
        current_url = start_url
        redirect_chain: List[RedirectHop] = []
        all_resolved_ips: List[str] = []

        initial_reg_domain = None

        for hop_index in range(MAX_REDIRECT_HOPS + 1):
            validation = self.guard.validate_url(current_url)
            if not validation.is_safe:
                return SafeHTTPResponse(
                    url=current_url,
                    status_code=0,
                    headers={},
                    body=b"",
                    redirect_chain=redirect_chain,
                    resolved_ips=all_resolved_ips,
                    error=f"Blocked by SSRF Guard: {validation.rule_blocked} ({validation.reason})"
                )

            if validation.resolved_ips:
                for ip in validation.resolved_ips:
                    if ip not in all_resolved_ips:
                        all_resolved_ips.append(ip)

            parsed = urllib.parse.urlsplit(current_url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            reg_domain = get_registrable_domain_simple(hostname)
            
            if initial_reg_domain is None:
                initial_reg_domain = reg_domain

            # Single hop request using anti-rebinding (connect to validated IP)
            status_code, headers, body, truncated, err = self._single_request(
                method=method,
                parsed=parsed,
                connect_ip=validation.resolved_ips[0] if validation.resolved_ips else hostname,
                port=port
            )

            if err:
                return SafeHTTPResponse(
                    url=current_url,
                    status_code=status_code or 0,
                    headers=headers,
                    body=b"",
                    redirect_chain=redirect_chain,
                    resolved_ips=all_resolved_ips,
                    duration_ms=int((time.time() - t0) * 1000),
                    error=err
                )

            # Record hop
            same_site = (reg_domain == initial_reg_domain)
            redirect_chain.append(
                RedirectHop(
                    url=defang_url(current_url),
                    status_code=status_code,
                    registrable_domain=reg_domain,
                    same_site=same_site
                )
            )

            # Check if redirect (301, 302, 303, 307, 308)
            if status_code in (301, 302, 303, 307, 308) and "location" in headers:
                location = headers["location"]
                next_url = urllib.parse.urljoin(current_url, location)
                if hop_index >= MAX_REDIRECT_HOPS:
                    return SafeHTTPResponse(
                        url=next_url,
                        status_code=status_code,
                        headers=headers,
                        body=body,
                        redirect_chain=redirect_chain,
                        resolved_ips=all_resolved_ips,
                        duration_ms=int((time.time() - t0) * 1000),
                        error="Maximum redirect hops (5) exceeded."
                    )
                current_url = next_url
                continue

            # Final destination reached
            return SafeHTTPResponse(
                url=current_url,
                status_code=status_code,
                headers=headers,
                body=body,
                redirect_chain=redirect_chain,
                resolved_ips=all_resolved_ips,
                truncated=truncated,
                duration_ms=int((time.time() - t0) * 1000)
            )

        return SafeHTTPResponse(
            url=current_url,
            status_code=0,
            headers={},
            body=b"",
            redirect_chain=redirect_chain,
            resolved_ips=all_resolved_ips,
            error="Exceeded maximum hops."
        )

    def _single_request(
        self,
        method: str,
        parsed: urllib.parse.SplitResult,
        connect_ip: str,
        port: int
    ) -> Tuple[int, Dict[str, str], bytes, bool, Optional[str]]:
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        headers = {
            "Host": parsed.hostname,
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close"
        }

        conn = None
        try:
            if parsed.scheme == "https":
                context = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    connect_ip,
                    port=port,
                    timeout=REQUEST_TIMEOUT,
                    context=context
                )
                # Anti-rebinding: set SNI hostname
                conn._tunnel_host = None
                conn.set_tunnel = lambda *a, **k: None
            else:
                conn = http.client.HTTPConnection(
                    connect_ip,
                    port=port,
                    timeout=REQUEST_TIMEOUT
                )

            conn.request(method, path, headers=headers)
            res = conn.getresponse()

            res_headers = {k.lower(): v for k, v in res.getheaders()}

            # Content-type check: abort if binary attachment
            ctype = res_headers.get("content-type", "")
            if any(b in ctype for b in ("application/octet-stream", "application/zip", "application/x-dosexec", "application/pdf")):
                return res.status, res_headers, b"", False, None

            # Read capped body up to 200 KB
            truncated = False
            chunks = []
            bytes_read = 0
            while bytes_read < MAX_BODY_BYTES:
                chunk = res.read(min(8192, MAX_BODY_BYTES - bytes_read))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)

            if bytes_read >= MAX_BODY_BYTES:
                truncated = True

            body = b"".join(chunks)
            return res.status, res_headers, body, truncated, None

        except socket.timeout:
            return 0, {}, b"", False, "Connection timed out."
        except Exception as e:
            return 0, {}, b"", False, str(e)
        finally:
            if conn:
                conn.close()

safe_client = SafeHTTPClient()
