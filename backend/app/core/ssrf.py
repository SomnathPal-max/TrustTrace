import ipaddress
import re
import socket
import urllib.parse
from typing import List, Optional, Tuple
from dataclasses import dataclass

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}

# CGNAT: 100.64.0.0/10
CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")
# Cloud Metadata
CLOUD_METADATA_IP = ipaddress.ip_address("169.254.169.254")
# NAT64 Well-Known Prefix (RFC 6052)
NAT64_NET = ipaddress.ip_network("64:ff9b::/96")

@dataclass
class SSRFValidationResult:
    is_safe: bool
    rule_blocked: Optional[str] = None
    reason: Optional[str] = None
    parsed_host: Optional[str] = None
    parsed_port: Optional[int] = None
    resolved_ips: List[str] = None

class SSRFGuard:
    def __init__(self, dns_resolver=None):
        self._dns_resolver = dns_resolver or self._default_resolver

    @staticmethod
    def _default_resolver(hostname: str) -> List[str]:
        try:
            # Resolve both IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, None)
            ips = []
            for item in addr_info:
                ip = item[4][0]
                if ip not in ips:
                    ips.append(ip)
            return ips
        except Exception:
            return []

    @staticmethod
    def parse_numeric_ip(host: str) -> Optional[ipaddress.IPv4Address]:
        """Handles numeric disguises: decimal (2130706433), hex (0x7f000001), octal (0177.0.0.1)"""
        host_stripped = host.strip()
        # Decimal integer representation: e.g. 2130706433
        if re.match(r"^\d+$", host_stripped):
            try:
                num = int(host_stripped)
                if 0 <= num <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(num)
            except ValueError:
                pass

        # Hex representation: e.g. 0x7f000001
        if re.match(r"^0x[0-9a-fA-F]+$", host_stripped):
            try:
                num = int(host_stripped, 16)
                if 0 <= num <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(num)
            except ValueError:
                pass

        # Octal or mixed dotted representation: e.g. 0177.0.0.1
        parts = host_stripped.split(".")
        if len(parts) == 4 and all(re.match(r"^(0[0-7]+|0x[0-9a-fA-F]+|\d+)$", p) for p in parts):
            try:
                converted = []
                for p in parts:
                    if p.startswith("0x") or p.startswith("0X"):
                        converted.append(str(int(p, 16)))
                    elif p.startswith("0") and len(p) > 1:
                        converted.append(str(int(p, 8)))
                    else:
                        converted.append(str(int(p)))
                normalized_ip = ".".join(converted)
                return ipaddress.IPv4Address(normalized_ip)
            except ValueError:
                pass

        # Shortened forms like 127.1 -> 127.0.0.1
        if 1 <= len(parts) <= 3 and all(p.isdigit() for p in parts):
            try:
                # Standard POSIX inet_aton style expansion
                # e.g., 127.1 is 127.0.0.1
                val = 0
                for i, p in enumerate(parts):
                    if i == len(parts) - 1:
                        val = (val << (8 * (4 - i))) + int(p)
                    else:
                        val = (val << 8) + int(p)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except Exception:
                pass

        return None

    @classmethod
    def check_ip_safety(cls, ip_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return False, "RULE_INVALID_IP", f"Invalid IP address: {ip_str}"

        # Unwrap IPv4-mapped IPv6 address (::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        # Unwrap NAT64 well-known prefix (64:ff9b::/96) to evaluate embedded IPv4
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj in NAT64_NET:
            ip_obj = ipaddress.IPv4Address(ip_obj.packed[-4:])

        # 1. Loopback (127.0.0.0/8, ::1)
        if ip_obj.is_loopback or str(ip_obj) == "0.0.0.0":
            return False, "RULE_LOOPBACK", "Loopback address is strictly prohibited."

        # 2. Cloud metadata (169.254.169.254) and link-local (169.254.0.0/16, fe80::/10)
        if ip_obj == CLOUD_METADATA_IP or ip_obj.is_link_local:
            return False, "RULE_CLOUD_METADATA", "Link-local and cloud metadata addresses are prohibited."

        # 3. Private ranges (RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16; IPv6 unique local fc00::/7)
        if ip_obj.is_private:
            return False, "RULE_PRIVATE_IP", "Private and internal networks are prohibited."

        # 4. Carrier-grade NAT (100.64.0.0/10)
        if isinstance(ip_obj, ipaddress.IPv4Address) and ip_obj in CGNAT_NET:
            return False, "RULE_CGNAT", "Carrier-grade NAT space is prohibited."

        # 5. Multicast, Reserved, Unspecified
        if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
            return False, "RULE_SPECIAL_IP", "Special, multicast, or reserved addresses are prohibited."

        return True, None, None

    def validate_url(self, raw_url: str) -> SSRFValidationResult:
        if not raw_url or not isinstance(raw_url, str):
            return SSRFValidationResult(is_safe=False, rule_blocked="RULE_EMPTY_URL", reason="URL is empty.")

        # Length check
        if len(raw_url) > 2048:
            return SSRFValidationResult(
                is_safe=False,
                rule_blocked="RULE_URL_TOO_LONG",
                reason="URL exceeds maximum length of 2,048 characters."
            )

        # Control characters check
        if any(ord(c) < 32 or ord(c) == 127 for c in raw_url):
            return SSRFValidationResult(
                is_safe=False,
                rule_blocked="RULE_CONTROL_CHARS",
                reason="URL contains forbidden control characters."
            )

        # Parse URL
        try:
            parsed = urllib.parse.urlsplit(raw_url.strip())
        except Exception as e:
            return SSRFValidationResult(is_safe=False, rule_blocked="RULE_PARSE_ERROR", reason=str(e))

        # 1. Scheme rule
        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            return SSRFValidationResult(
                is_safe=False,
                rule_blocked="RULE_DISALLOWED_SCHEME",
                reason=f"Scheme '{scheme}' is not allowed. Only HTTP and HTTPS are permitted."
            )

        # 2. Host presence & user-info trick prevention
        # e.g., http://google.com@127.0.0.1/ -> hostname is 127.0.0.1
        hostname = parsed.hostname
        if not hostname:
            return SSRFValidationResult(
                is_safe=False,
                rule_blocked="RULE_MISSING_HOST",
                reason="URL does not specify a valid host."
            )

        # Reject localhost explicitly
        if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
            return SSRFValidationResult(
                is_safe=False,
                rule_blocked="RULE_LOOPBACK",
                reason="localhost is prohibited.",
                parsed_host=hostname
            )

        # 3. Port rule
        port = parsed.port or (443 if scheme == "https" else 80)
        if port not in ALLOWED_PORTS:
            return SSRFValidationResult(
                is_safe=False,
                rule_blocked="RULE_DISALLOWED_PORT",
                reason=f"Port {port} is not permitted. Only 80, 443, 8080, and 8443 are allowed.",
                parsed_host=hostname,
                parsed_port=port
            )

        # Check if hostname is numeric disguised IP
        numeric_ip = self.parse_numeric_ip(hostname)
        if numeric_ip:
            is_safe, rule, reason = self.check_ip_safety(str(numeric_ip))
            if not is_safe:
                return SSRFValidationResult(
                    is_safe=False,
                    rule_blocked=rule,
                    reason=reason,
                    parsed_host=hostname,
                    parsed_port=port,
                    resolved_ips=[str(numeric_ip)]
                )
            return SSRFValidationResult(
                is_safe=True,
                parsed_host=hostname,
                parsed_port=port,
                resolved_ips=[str(numeric_ip)]
            )

        # 4. Check direct IP address literal
        try:
            ip_literal = ipaddress.ip_address(hostname)
            is_safe, rule, reason = self.check_ip_safety(str(ip_literal))
            if not is_safe:
                return SSRFValidationResult(
                    is_safe=False,
                    rule_blocked=rule,
                    reason=reason,
                    parsed_host=hostname,
                    parsed_port=port,
                    resolved_ips=[str(ip_literal)]
                )
            return SSRFValidationResult(
                is_safe=True,
                parsed_host=hostname,
                parsed_port=port,
                resolved_ips=[str(ip_literal)]
            )
        except ValueError:
            pass

        # 5. Domain DNS resolution rule: resolve every address and test all
        resolved_ips = self._dns_resolver(hostname)
        if not resolved_ips:
            # Domain does not resolve: not necessarily SSRF block, but cannot be connected
            return SSRFValidationResult(
                is_safe=True,
                parsed_host=hostname,
                parsed_port=port,
                resolved_ips=[]
            )

        for ip in resolved_ips:
            is_safe, rule, reason = self.check_ip_safety(ip)
            if not is_safe:
                return SSRFValidationResult(
                    is_safe=False,
                    rule_blocked=rule,
                    reason=f"Host resolved to forbidden address {ip}: {reason}",
                    parsed_host=hostname,
                    parsed_port=port,
                    resolved_ips=resolved_ips
                )

        return SSRFValidationResult(
            is_safe=True,
            parsed_host=hostname,
            parsed_port=port,
            resolved_ips=resolved_ips
        )

# Global singleton
ssrf_guard = SSRFGuard()
