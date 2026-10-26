"""Target checks that keep InfinityX on public infrastructure.

Remote text is treated as untrusted. Connections to loopback, private,
link-local, and metadata destinations are refused before any HTTP client runs.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

NON_PUBLIC_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:2::/48"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
)

BLOCKED_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "metadata",
    "metadata.google.internal",
    "metadata.google.com",
    "instance-data",
}

BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".home.arpa",
    ".lan",
)

SECRET_PATTERNS = (
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|authorization|sessionid|access[_-]?key)"
        r"\b\s*[:=]\s*\S+"
    ),
    re.compile(r"(?i)\b(bearer)\s+[a-z0-9._\-]{8,}"),
    re.compile(
        r"(?i)\b(aws_secret_access_key|aws_access_key_id|private[_-]?key)\b\s*[:=]\s*\S+"
    ),
)

SENSITIVE_HEADERS = {
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-auth-token",
}

ALLOWED_HTTP_PORTS = {80, 443}
MAX_TEXT = 200_000


class UnsafeTarget(ValueError):
    """The hostname, address, or URL is outside the public-target rules."""


def ip_is_public(value: str) -> bool:
    """Return True when an address is a normal public unicast address."""
    try:
        parsed = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return ip_is_public(str(parsed.ipv4_mapped))
    if (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    ):
        return False
    return not any(parsed in network for network in NON_PUBLIC_NETWORKS)


def assess_addresses(ips: list[str]) -> str | None:
    """Return an error when a resolution is empty or includes a non-public address."""
    if not ips:
        return "The hostname did not resolve to an address."
    blocked = [ip for ip in ips if not ip_is_public(ip)]
    if blocked:
        return "Resolution included a non-public address: " + ", ".join(blocked)
    return None


def hostname_blocked(host: str) -> str | None:
    """Return a reason when a hostname must not be contacted."""
    name = host.strip().lower().rstrip(".")
    if not name:
        return "The hostname is empty."
    if name in BLOCKED_HOSTS or any(name.endswith(suffix) for suffix in BLOCKED_SUFFIXES):
        return "The hostname is local, internal, or a metadata name."
    if name.isdigit():
        return "Numeric hostnames are not accepted."
    labels = name.split(".")
    if labels and all(label.isdigit() for label in labels):
        try:
            if not ip_is_public(name):
                return "The address is not a public IP address."
        except ValueError:
            return "The numeric hostname is ambiguous and was not accepted."
        return None
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return None
    if not ip_is_public(str(address)):
        return "The address is not a public IP address."
    return None


def same_site(hostname: str, domain: str) -> bool:
    """Return True when hostname is the domain or one of its subdomains."""
    host = hostname.lower().rstrip(".")
    root = domain.lower().rstrip(".")
    return host == root or host.endswith("." + root)


@dataclass(frozen=True)
class DestinationDecision:
    """What InfinityX will do with a redirect Location value."""

    action: str
    url: str
    reason: str


def decide_redirect(base_url: str, location: str, root_domain: str) -> DestinationDecision:
    """Decide whether a redirect may be followed, recorded, or blocked.

    Off-site public destinations are recorded and not fetched. Local, private,
    credentialed, and non-HTTP destinations are blocked.
    """
    target = urljoin(base_url, location.strip())
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"}:
        return DestinationDecision("block", target, "The redirect scheme is not HTTP or HTTPS.")
    if parsed.username or parsed.password:
        return DestinationDecision("block", target, "The redirect URL contains user credentials.")
    host = parsed.hostname
    if host is None:
        return DestinationDecision("block", target, "The redirect URL has no hostname.")
    blocked = hostname_blocked(host)
    if blocked:
        return DestinationDecision("block", target, blocked)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_HTTP_PORTS:
        return DestinationDecision("block", target, "The redirect port is not 80 or 443.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_literal = False
    else:
        is_literal = True
    if is_literal:
        return DestinationDecision(
            "record",
            target,
            "The redirect uses an IP address. InfinityX recorded it and did not connect to it.",
        )
    if not same_site(host, root_domain):
        return DestinationDecision(
            "record",
            target,
            "The redirect leaves the target domain. InfinityX recorded it and did not fetch it.",
        )
    return DestinationDecision("follow", target, "The redirect stays on the target domain.")


def clean_text(value: str | None, limit: int = 4000) -> str:
    """Drop control characters and secret-like assignments from untrusted text."""
    if value is None:
        return ""
    kept: list[str] = []
    for char in str(value):
        code = ord(char)
        if char in "\n\r\t" or code >= 32:
            kept.append(char)
        else:
            kept.append(" ")
    text = "".join(kept)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    text = text.strip()
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def clean_data(value: object, depth: int = 0) -> object:
    """Recursively sanitize strings stored in check data."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, str):
        return clean_text(value, limit=4000)
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return value
    if isinstance(value, float):
        return value
    if isinstance(value, list):
        return [clean_data(item, depth + 1) for item in value[:50]]
    if isinstance(value, tuple):
        return [clean_data(item, depth + 1) for item in value[:50]]
    if isinstance(value, dict):
        cleaned: dict[str, object] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 80:
                break
            cleaned[clean_text(str(key), limit=120)] = clean_data(item, depth + 1)
        return cleaned
    return clean_text(str(value), limit=1000)


def redact_header_value(name: str, value: str) -> str:
    """Omit cookie and authorization header values from reports and logs."""
    if name.lower() in SENSITIVE_HEADERS:
        return "[omitted]"
    return clean_text(value, limit=300)
