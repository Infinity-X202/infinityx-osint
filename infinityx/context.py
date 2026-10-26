"""Cached public lookups shared by the individual checks.

Each check calls these methods itself. The cache exists so overlapping checks
explain one retrieval instead of sending the same query again.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from infinityx.models import CertInfo, DnsAnswer, HttpSnapshot, WhoisInfo
from infinityx.net import (
    PRIMARY_RESOLVER,
    SECONDARY_RESOLVER,
    fetch_certificate,
    fetch_crtsh,
    fetch_ripe_geo,
    fetch_ripe_prefix,
    fetch_url,
    fetch_whois,
    query_dns,
    query_dnssec,
    query_ptr,
    resolve_public,
)

logger = logging.getLogger("infinityx")


class ScanContext:
    """State for one authorized domain scan."""

    def __init__(self, domain: str, raw_input: str, enable_traceroute: bool, logger_: logging.Logger | None = None) -> None:
        self.domain = domain
        self.raw_input = raw_input
        self.enable_traceroute = enable_traceroute
        self.logger = logger_ or logger
        self.artifacts: dict[str, str] = {}
        self._whois: WhoisInfo | None = None
        self._dns: dict[tuple[str, str, str], DnsAnswer] = {}
        self._http: dict[str, HttpSnapshot] = {}
        self._cert: CertInfo | None = None
        self._ips: list[str] | None = None
        self._ip_note: str | None = None
        self._ct: tuple[list[dict[str, Any]], str | None] | None = None
        self._ripe: dict[str, dict[str, Any]] = {}
        self._geo: dict[str, dict[str, Any]] = {}
        self._ptr: dict[str, DnsAnswer] = {}
        self._dnssec: dict[str, Any] | None = None
        self._last_http = 0.0

    def pace(self) -> None:
        """Keep a small gap between HTTP calls to public services and the target."""
        wait = 0.25 - (time.monotonic() - self._last_http)
        if wait > 0:
            time.sleep(wait)
        self._last_http = time.monotonic()

    def store(self, name: str, content: str) -> None:
        """Save original output for raw_results, with a hard size cap."""
        self.artifacts[name] = content[:200_000]

    def whois(self) -> WhoisInfo:
        """Return the shared public WHOIS result."""
        if self._whois is None:
            self.logger.info("WHOIS lookup started for %s", self.domain)
            self._whois = fetch_whois(self.domain)
            self.store("whois.txt", self._whois.raw or self._whois.error or "")
            self.logger.info("WHOIS lookup finished ok=%s servers=%s", self._whois.ok, len(self._whois.servers))
        return self._whois

    def dns(self, rtype: str, name: str | None = None, resolver: str = "primary") -> DnsAnswer:
        """Return a cached DNS answer from 1.1.1.1 or 8.8.8.8."""
        query_name = name or self.domain
        nameserver = PRIMARY_RESOLVER if resolver == "primary" else SECONDARY_RESOLVER
        key = (rtype.upper(), query_name, nameserver)
        if key not in self._dns:
            self.logger.info("DNS %s %s via %s", rtype, query_name, nameserver)
            self._dns[key] = query_dns(query_name, rtype, nameserver)
        return self._dns[key]

    def dnssec(self) -> dict[str, Any]:
        """Return cached DS, DNSKEY, and AD-flag observations."""
        if self._dnssec is None:
            self.logger.info("DNSSEC public query started")
            self._dnssec = query_dnssec(self.domain)
            self.store("dnssec.txt", str(self._dnssec))
        return self._dnssec

    def addresses(self) -> tuple[list[str], str | None]:
        """Resolve the target on two public resolvers and keep only public results."""
        if self._ips is None:
            ips, note = resolve_public(self.domain)
            self._ips = ips
            self._ip_note = note
            self.store("resolution.txt", "\n".join(ips) + ("\n" + note if note else ""))
            self.logger.info("Public resolution count=%s", len(ips))
        return self._ips, self._ip_note

    def http(self, scheme: str) -> HttpSnapshot:
        """Fetch the site root over http or https, following same-site redirects only."""
        scheme = scheme.lower()
        if scheme not in self._http:
            self.pace()
            url = f"{scheme}://{self.domain}/"
            self.logger.info("Fetching %s", url)
            snapshot = fetch_url(url, self.domain)
            self._http[scheme] = snapshot
            header_text = "\n".join(f"{key}: {value}" for key, value in snapshot.headers.items())
            self.store(
                f"{scheme}_homepage.txt",
                f"url: {url}\nerror: {snapshot.error}\nstatus: {snapshot.status_code}\n"
                f"final: {snapshot.final_url}\npinned: {snapshot.pinned_ip}\n"
                f"blocked: {snapshot.blocked_reason}\n\n{header_text}\n\n{snapshot.body[:100_000]}",
            )
        return self._http[scheme]

    def fetch_path(self, path: str) -> HttpSnapshot:
        """Fetch one same-site path over HTTPS, then HTTP if HTTPS cannot connect."""
        key = "path:" + path
        if key in self._http:
            return self._http[key]
        self.pace()
        https_url = f"https://{self.domain}{path}"
        snapshot = fetch_url(https_url, self.domain, max_hops=2)
        if not snapshot.ok and snapshot.status_code is None:
            self.pace()
            snapshot = fetch_url(f"http://{self.domain}{path}", self.domain, max_hops=2)
        self._http[key] = snapshot
        self.store(f"path_{path.strip('/').replace('/', '_') or 'root'}.txt", snapshot.body[:100_000] or snapshot.error or "")
        return snapshot

    def certificate(self) -> CertInfo:
        """Read the leaf certificate presented for this hostname."""
        if self._cert is None:
            ips, note = self.addresses()
            if not ips:
                self._cert = CertInfo(ok=False, error=note or "No public address was available for a TLS connection.")
            else:
                pin = _first_ipv4(ips)
                self.logger.info("TLS certificate read via %s", pin)
                self._cert = fetch_certificate(self.domain, pin)
                self.store("certificate.pem", self._cert.pem or self._cert.error or "")
        return self._cert

    def ptr(self, ip: str) -> DnsAnswer:
        """Return a cached PTR lookup for a public address."""
        if ip not in self._ptr:
            self._ptr[ip] = query_ptr(ip)
        return self._ptr[ip]

    def certificate_transparency(self) -> tuple[list[dict[str, Any]], str | None]:
        """Query crt.sh once for this exact domain."""
        if self._ct is None:
            self.pace()
            self.logger.info("Certificate transparency query started")
            rows, error, raw = fetch_crtsh(self.domain)
            self.store("crtsh.json", raw or error or "")
            self._ct = (rows, error)
        return self._ct

    def ripe(self, ip: str) -> dict[str, Any]:
        """Query RIPEstat prefix overview once per address."""
        if ip not in self._ripe:
            self.pace()
            payload, error, raw = fetch_ripe_prefix(ip)
            self.store(f"ripe_{ip.replace(':', '_')}.json", raw or error or "")
            self._ripe[ip] = {"payload": payload, "error": error}
        return self._ripe[ip]

    def geo(self, ip: str) -> dict[str, Any]:
        """Query RIPEstat geolocation once per address."""
        if ip not in self._geo:
            self.pace()
            payload, error, raw = fetch_ripe_geo(ip)
            self.store(f"geo_{ip.replace(':', '_')}.json", raw or error or "")
            self._geo[ip] = {"payload": payload, "error": error}
        return self._geo[ip]


def _first_ipv4(ips: list[str]) -> str:
    import ipaddress

    for ip in ips:
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip
        except ValueError:
            continue
    return ips[0]
