"""Public-network clients used by the scan context.

WHOIS uses the port-43 protocol. DNS uses dnspython against explicit public
resolvers. HTTP uses requests with redirects handled by InfinityX and the TCP
connection pinned to an address those resolvers already classified as public.
"""

from __future__ import annotations

import hashlib
import json
import logging
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

import dns.exception
import dns.flags
import dns.message
import dns.query
import dns.resolver
import dns.reversename
import requests
import urllib3.util.connection as urllib3_connection

from infinityx.models import CertInfo, DnsAnswer, HttpSnapshot, WhoisInfo
from infinityx.safety import (
    UnsafeTarget,
    assess_addresses,
    clean_text,
    decide_redirect,
    hostname_blocked,
    redact_header_value,
)

logger = logging.getLogger("infinityx")

PRIMARY_RESOLVER = "1.1.1.1"
SECONDARY_RESOLVER = "8.8.8.8"
USER_AGENT = "InfinityX-OSINT-Scanner/1.0 (authorized passive OSINT; local operator)"
MAX_BODY = 512 * 1024
MAX_WHOIS = 64 * 1024
HTTP_TIMEOUT = (4, 12)
_PIN_LOCK = threading.Lock()

_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%d-%b-%Y",
    "%Y.%m.%d",
    "%d.%m.%Y",
    "%Y/%m/%d",
    "%d/%m/%Y",
)


def parse_loose_date(value: str | None) -> datetime | None:
    """Parse a WHOIS or certificate date, assuming UTC when no zone is present."""
    if not value:
        return None
    text = value.strip().split("(")[0].strip().rstrip(".")
    text = text.replace(" UTC", "Z").replace(" GMT", "Z")
    if text.endswith("Z") and "T" not in text and " " in text:
        text = text[:-1].strip()
    candidates = [text, text.replace("Z", "+0000")]
    for candidate in candidates:
        for fmt in _DATE_FORMATS:
            try:
                parsed = datetime.strptime(candidate, fmt)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
    return None


def _txt(rdata: Any) -> str:
    parts: list[str] = []
    strings = getattr(rdata, "strings", None)
    if strings is not None:
        for item in strings:
            if isinstance(item, bytes):
                parts.append(item.decode("utf-8", "replace"))
            else:
                parts.append(str(item))
        return "".join(parts)
    return str(rdata).strip('"')


def query_dns(name: str, rtype: str, nameserver: str) -> DnsAnswer:
    """Query one public resolver and return a normalized answer. Never raises."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    cnames: list[str] = []
    try:
        if rtype.upper() == "A":
            try:
                cname_answer = resolver.resolve(name, "CNAME", lifetime=5.0)
                cnames = [str(item.target).rstrip(".") for item in cname_answer]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
                cnames = []
            except Exception:
                logger.debug("CNAME lookup failed for %s", name, exc_info=True)
                cnames = []
        answer = resolver.resolve(name, rtype, lifetime=5.0)
    except dns.resolver.NXDOMAIN:
        return DnsAnswer(name, rtype, nameserver, "nxdomain", cnames=cnames)
    except dns.resolver.NoAnswer:
        return DnsAnswer(name, rtype, nameserver, "noanswer", cnames=cnames)
    except dns.exception.Timeout:
        return DnsAnswer(name, rtype, nameserver, "timeout", error="The DNS query timed out.", cnames=cnames)
    except Exception as exc:
        logger.info("DNS %s %s via %s failed: %s", rtype, name, nameserver, type(exc).__name__)
        return DnsAnswer(
            name,
            rtype,
            nameserver,
            "error",
            error=clean_text(f"{type(exc).__name__}: {exc}", limit=300),
            cnames=cnames,
        )

    records: list[str] = []
    structured: list[dict[str, Any]] = []
    for rdata in answer:
        if rtype.upper() == "MX":
            exchange = str(rdata.exchange).rstrip(".").lower()
            null_mx = exchange == ""
            shown = "." if null_mx else exchange
            records.append(f"{rdata.preference} {shown}")
            structured.append({"preference": int(rdata.preference), "exchange": shown, "null_mx": null_mx})
        elif rtype.upper() == "SOA":
            mname = str(rdata.mname).rstrip(".").lower()
            rname = str(rdata.rname).rstrip(".").lower()
            rendered = (
                f"{mname} {rname} {rdata.serial} {rdata.refresh} "
                f"{rdata.retry} {rdata.expire} {rdata.minimum}"
            )
            records.append(rendered)
            structured.append(
                {
                    "mname": mname,
                    "rname": rname,
                    "serial": int(rdata.serial),
                    "refresh": int(rdata.refresh),
                    "retry": int(rdata.retry),
                    "expire": int(rdata.expire),
                    "minimum": int(rdata.minimum),
                }
            )
        elif rtype.upper() == "TXT":
            text = _txt(rdata)
            records.append(text)
            structured.append({"text": text[:1000]})
        elif rtype.upper() == "CAA":
            tag = str(rdata.tag)
            value = rdata.value.decode("utf-8", "replace") if isinstance(rdata.value, bytes) else str(rdata.value)
            rendered = f'{rdata.flags} {tag} "{value}"'
            records.append(rendered)
            structured.append({"flags": int(rdata.flags), "tag": tag, "value": value[:300]})
        else:
            text = str(rdata).strip().rstrip(".")
            records.append(text)
            structured.append({"value": text})
    return DnsAnswer(name, rtype, nameserver, "ok", records=records, structured=structured, cnames=cnames)


def resolve_public(hostname: str) -> tuple[list[str], str | None]:
    """Resolve a hostname on two public resolvers and reject non-public answers."""
    blocked = hostname_blocked(hostname)
    if blocked:
        return [], blocked
    found: list[str] = []
    errors: list[str] = []
    for nameserver in (PRIMARY_RESOLVER, SECONDARY_RESOLVER):
        family_hits: list[str] = []
        for rtype in ("A", "AAAA"):
            answer = query_dns(hostname, rtype, nameserver)
            if answer.status == "ok":
                family_hits.extend(answer.records)
            elif answer.status in {"timeout", "error"}:
                errors.append(f"{nameserver} {rtype}: {answer.error or answer.status}")
        private = [ip for ip in family_hits if not _public_or_false(ip)]
        if private:
            return [], "Resolution included a non-public address: " + ", ".join(private)
        found.extend(family_hits)
    unique = list(dict.fromkeys(found))
    problem = assess_addresses(unique)
    if problem:
        detail = problem if not errors else problem + " Resolver notes: " + "; ".join(errors[:4])
        return [], detail
    note = None
    if errors:
        note = "One or more resolver queries failed, but every returned address was public. " + "; ".join(errors[:4])
    return unique, note


def _public_or_false(ip: str) -> bool:
    from infinityx.safety import ip_is_public

    return ip_is_public(ip)


def query_ptr(ip: str) -> DnsAnswer:
    """Look up PTR records for one address through the primary public resolver."""
    try:
        reverse = str(dns.reversename.from_address(ip)).rstrip(".")
    except Exception as exc:
        return DnsAnswer(ip, "PTR", PRIMARY_RESOLVER, "error", error=clean_text(str(exc), 200))
    return query_dns(reverse, "PTR", PRIMARY_RESOLVER)


def query_dnssec(name: str) -> dict[str, Any]:
    """Collect DS, DNSKEY, and the AD flag from 1.1.1.1 without local chain validation."""
    result: dict[str, Any] = {"ds": [], "dnskey": [], "ad": None, "errors": []}
    for rtype, key in (("DS", "ds"), ("DNSKEY", "dnskey")):
        answer = query_dns(name, rtype, PRIMARY_RESOLVER)
        if answer.status == "ok":
            result[key] = answer.records
        elif answer.status in {"timeout", "error"}:
            result["errors"].append(f"{rtype}: {answer.error or answer.status}")
    try:
        question = dns.message.make_query(name, "A", want_dnssec=True)
        response = dns.query.udp(question, PRIMARY_RESOLVER, timeout=4)
        result["ad"] = bool(response.flags & dns.flags.AD)
    except Exception as exc:
        result["ad"] = None
        result["errors"].append(clean_text(f"AD flag query failed: {exc}", 240))
    return result


def _whois_socket(server: str, query: str, timeout: float = 8.0) -> str:
    chunks: list[bytes] = []
    total = 0
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode("ascii", "ignore"))
        while total < MAX_WHOIS:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            total += len(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _first(pattern: str, text: str) -> str | None:
    import re

    match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
    if not match:
        return None
    return clean_text(match.group(1), limit=300)


def _all(pattern: str, text: str) -> list[str]:
    import re

    values = []
    for match in re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE):
        item = clean_text(match.group(1), limit=200).rstrip(".").lower()
        if item and item not in values:
            values.append(item)
    return values


def parse_whois(raw: str, servers: list[str]) -> WhoisInfo:
    """Extract common public WHOIS fields. Missing fields stay empty."""
    creation_raw = _first(
        r"^\s*(?:Creation Date|Created On|Created|Registration Time|Registered on|Domain Registration Date):\s*(.+)$",
        raw,
    )
    expiration_raw = _first(
        r"^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expiry Date|Expiration Date|Expire Date|paid-till|Expiry):\s*(.+)$",
        raw,
    )
    updated_raw = _first(
        r"^\s*(?:Updated Date|Last Updated On|Last Updated|Last Modified|Modified|Changed):\s*(.+)$",
        raw,
    )
    return WhoisInfo(
        ok=True,
        error=None,
        raw=raw[:MAX_WHOIS],
        servers=servers,
        registrar=_first(r"^\s*(?:Registrar|Sponsoring Registrar):\s*(.+)$", raw),
        creation_raw=creation_raw,
        creation=parse_loose_date(creation_raw),
        expiration_raw=expiration_raw,
        expiration=parse_loose_date(expiration_raw),
        updated_raw=updated_raw,
        updated=parse_loose_date(updated_raw),
        nameservers=_all(r"^\s*(?:Name Server|nserver|Nameserver):\s*(\S+)", raw),
        statuses=_all(r"^\s*(?:Domain Status|Status):\s*(\S+)", raw),
    )


def fetch_whois(domain: str) -> WhoisInfo:
    """Query IANA and at most two referral servers. Never raises."""
    servers: list[str] = []
    try:
        tld = domain.rsplit(".", 1)[-1]
        iana = _whois_socket("whois.iana.org", tld)
        servers.append("whois.iana.org")
    except Exception as exc:
        logger.info("IANA WHOIS failed for %s", domain)
        return WhoisInfo(False, clean_text(f"IANA WHOIS failed: {exc}", 300), "", servers, None, None, None, None, None, None, None, [], [])
    import re

    refer = re.search(r"(?im)^(?:refer|whois):\s*(\S+)", iana)
    if not refer:
        parsed = parse_whois(iana, servers)
        parsed.ok = False
        parsed.error = "IANA did not publish a WHOIS referral for this TLD."
        return parsed
    referral = refer.group(1).strip().lower()
    raw_parts = [iana]
    try:
        registry = _whois_socket(referral, domain)
        servers.append(referral)
        raw_parts.append(registry)
    except Exception as exc:
        return WhoisInfo(
            False,
            clean_text(f"Registry WHOIS {referral} failed: {exc}", 300),
            "\n".join(raw_parts),
            servers,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            [],
            [],
        )
    next_server = re.search(r"(?im)^\s*Registrar WHOIS Server:\s*(\S+)", registry)
    combined = registry
    if next_server:
        registrar_server = next_server.group(1).strip().lower().rstrip(".")
        if registrar_server and registrar_server not in servers:
            try:
                registrar_text = _whois_socket(registrar_server, domain)
                servers.append(registrar_server)
                raw_parts.append(registrar_text)
                combined = registry + "\n" + registrar_text
            except Exception as exc:
                logger.info("Registrar WHOIS failed: %s", type(exc).__name__)
                combined = registry + f"\nRegistrar WHOIS server {registrar_server} could not be queried: {exc}"
    info = parse_whois(combined, servers)
    info.raw = "\n\n".join(raw_parts)[:MAX_WHOIS]
    upper = combined.upper()
    no_match = "NO MATCH FOR" in upper or "NOT FOUND" in upper or "NO OBJECT FOUND" in upper
    if no_match and not info.registrar and not info.nameservers:
        info.error = "The WHOIS servers did not return a matching registration."
    return info


class _PinnedDNS:
    """Temporarily send one hostname to one already-checked public address."""

    def __init__(self, host: str, ip: str) -> None:
        self.host = host
        self.ip = ip
        self._original = urllib3_connection.create_connection

    def __enter__(self) -> None:
        host = self.host
        ip = self.ip
        original = self._original

        def create_connection(address, *args, **kwargs):  # type: ignore[no-untyped-def]
            target_host, port = address
            if target_host == host:
                address = (ip, port)
            return original(address, *args, **kwargs)

        urllib3_connection.create_connection = create_connection

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        urllib3_connection.create_connection = self._original


def _header_map(response: requests.Response) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for name, value in response.headers.items():
        mapped[name] = redact_header_value(name, value)
    return mapped


def _read_body(response: requests.Response) -> tuple[str, int, bool]:
    chunks: list[bytes] = []
    size = 0
    truncated = False
    for chunk in response.iter_content(chunk_size=8192):
        if not chunk:
            continue
        chunks.append(chunk)
        size += len(chunk)
        if size >= MAX_BODY:
            truncated = True
            break
    raw = b"".join(chunks)[:MAX_BODY]
    encoding = response.encoding or "utf-8"
    try:
        text = raw.decode(encoding, errors="replace")
    except LookupError:
        text = raw.decode("utf-8", errors="replace")
    return text, len(raw), truncated


def fetch_url(url: str, domain: str, max_hops: int = 5) -> HttpSnapshot:
    """Fetch a URL, or return a blocked snapshot. Never raises.

    System proxy variables are ignored so a proxy cannot bypass the public-address check.
    """
    current = url
    chain: list[dict[str, Any]] = []
    session = requests.Session()
    session.trust_env = False
    session.headers.update(
        {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,text/plain;q=0.5,*/*;q=0.1",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
    )
    try:
        for _ in range(max_hops + 1):
            response = None
            parsed = urlsplit(current)
            host = parsed.hostname
            if host is None:
                return HttpSnapshot(url, False, error="The URL has no hostname.", chain=chain, blocked_reason="no hostname")
            blocked = hostname_blocked(host)
            if blocked:
                return HttpSnapshot(url, False, error=blocked, final_url=current, chain=chain, blocked_reason=blocked)
            ips, note = resolve_public(host)
            if not ips:
                return HttpSnapshot(
                    url,
                    False,
                    error=note or "The hostname could not be resolved to a public address.",
                    final_url=current,
                    chain=chain,
                    blocked_reason=note,
                )
            pin = _choose_pin(ips)
            started = time.perf_counter()
            try:
                with _PIN_LOCK:
                    with _PinnedDNS(host, pin):
                        response = session.get(
                            current,
                            allow_redirects=False,
                            timeout=HTTP_TIMEOUT,
                            stream=True,
                        )
                        elapsed = (time.perf_counter() - started) * 1000
                        headers = _header_map(response)
                        body, nbytes, truncated = _read_body(response)
                        status = response.status_code
                        location = response.headers.get("Location")
            except requests.exceptions.SSLError as exc:
                return HttpSnapshot(
                    url,
                    False,
                    error=clean_text(f"TLS verification failed: {exc}", 500),
                    final_url=current,
                    chain=chain,
                    pinned_ip=pin,
                    resolved_ips=ips,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
            except requests.RequestException as exc:
                return HttpSnapshot(
                    url,
                    False,
                    error=clean_text(f"HTTP request failed: {exc}", 500),
                    final_url=current,
                    chain=chain,
                    pinned_ip=pin,
                    resolved_ips=ips,
                )
            except Exception as exc:
                logger.info("HTTP fetch failed: %s", type(exc).__name__)
                return HttpSnapshot(
                    url,
                    False,
                    error=clean_text(f"HTTP request failed: {exc}", 500),
                    final_url=current,
                    chain=chain,
                    pinned_ip=pin,
                    resolved_ips=ips,
                )
            finally:
                if response is not None:
                    response.close()
            chain.append(
                {
                    "url": current,
                    "status": status,
                    "location": clean_text(location, 500) if location else None,
                    "pinned_ip": pin,
                    "resolver_note": note,
                }
            )
            if status in {301, 302, 303, 307, 308} and location:
                decision = decide_redirect(current, location, domain)
                chain[-1]["action"] = decision.action
                chain[-1]["decision"] = decision.reason
                if decision.action == "follow":
                    current = decision.url
                    continue
                if decision.action == "block":
                    return HttpSnapshot(
                        url,
                        True,
                        error=None,
                        status_code=status,
                        final_url=current,
                        headers=headers,
                        body="",
                        elapsed_ms=elapsed,
                        chain=chain,
                        blocked_reason=decision.reason,
                        pinned_ip=pin,
                        resolved_ips=ips,
                        bytes_read=0,
                    )
                return HttpSnapshot(
                    url,
                    True,
                    status_code=status,
                    final_url=decision.url,
                    headers=headers,
                    body="",
                    elapsed_ms=elapsed,
                    chain=chain,
                    blocked_reason=decision.reason,
                    pinned_ip=pin,
                    resolved_ips=ips,
                )
            return HttpSnapshot(
                url,
                True,
                status_code=status,
                final_url=current,
                headers=headers,
                body=body,
                truncated=truncated,
                elapsed_ms=elapsed,
                chain=chain,
                pinned_ip=pin,
                resolved_ips=ips,
                bytes_read=nbytes,
            )
        return HttpSnapshot(url, False, error="Too many same-site redirects.", chain=chain)
    finally:
        session.close()


def _choose_pin(ips: list[str]) -> str:
    import ipaddress

    for ip in ips:
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip
        except ValueError:
            continue
    return ips[0]


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _cert_from_der(der: bytes, pinned_ip: str, tls_version: str | None, cipher: str | None) -> CertInfo:
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    cert = x509.load_der_x509_certificate(der)
    sans: list[str] = []
    try:
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(item) for item in extension.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        sans = []
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = str(cns[0].value) if cns else None
    signature = None
    if cert.signature_hash_algorithm is not None:
        signature = cert.signature_hash_algorithm.name
    fingerprint = hashlib.sha256(der).hexdigest()
    pem = ssl.DER_cert_to_PEM_cert(der)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else _aware(cert.not_valid_before)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else _aware(cert.not_valid_after)
    return CertInfo(
        ok=True,
        issuer=cert.issuer.rfc4514_string(),
        subject=cert.subject.rfc4514_string(),
        common_name=common_name,
        not_before=_aware(not_before),
        not_after=_aware(not_after),
        sans=sans,
        tls_version=tls_version,
        cipher=cipher,
        signature_algorithm=signature,
        pinned_ip=pinned_ip,
        fingerprint_sha256=fingerprint,
        pem=pem,
    )


def fetch_certificate(hostname: str, ip: str) -> CertInfo:
    """Read the leaf certificate from a pinned address and test trust separately."""
    tls_version = None
    cipher_name = None
    der = b""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as secure:
                tls_version = secure.version()
                cipher = secure.cipher()
                cipher_name = cipher[0] if cipher else None
                der = secure.getpeercert(binary_form=True) or b""
    except Exception as exc:
        return CertInfo(ok=False, error=clean_text(f"TLS connection failed: {exc}", 400), pinned_ip=ip)
    if not der:
        return CertInfo(ok=False, error="The server did not present a certificate.", pinned_ip=ip, tls_version=tls_version)
    try:
        info = _cert_from_der(der, ip, tls_version, cipher_name)
    except Exception as exc:
        return CertInfo(
            ok=False,
            error=clean_text(f"The certificate could not be parsed: {exc}", 400),
            pinned_ip=ip,
            tls_version=tls_version,
            cipher=cipher_name,
        )
    try:
        verified = ssl.create_default_context()
        with socket.create_connection((ip, 443), timeout=8) as sock:
            with verified.wrap_socket(sock, server_hostname=hostname):
                info.trusted = True
                info.trust_error = None
    except Exception as exc:
        info.trusted = False
        info.trust_error = clean_text(str(exc), 400)
    return info


def fetch_json(url: str, timeout: float = 15.0, limit: int = 1_000_000) -> tuple[Any | None, str | None, str]:
    """GET a public JSON document with proxies disabled and a hard size cap."""
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(
            url,
            timeout=timeout,
            stream=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )
    except requests.RequestException as exc:
        session.close()
        return None, clean_text(f"Request failed: {exc}", 300), ""
    try:
        chunks: list[bytes] = []
        size = 0
        truncated = False
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            chunks.append(chunk)
            size += len(chunk)
            if size >= limit:
                truncated = True
                break
        raw = b"".join(chunks)[:limit]
        text = raw.decode("utf-8", "replace")
        if response.status_code != 200:
            return None, f"HTTP {response.status_code} from {urlsplit(url).hostname}.", text[:2000]
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None, "The server did not return JSON.", text[:2000]
        if truncated:
            return payload, "The response was truncated at the scanner size limit.", text[:2000]
        return payload, None, text[:200_000]
    finally:
        response.close()
        session.close()


def fetch_crtsh(domain: str) -> tuple[list[dict[str, Any]], str | None, str]:
    """Read public certificate-transparency rows from crt.sh for the exact name."""
    url = f"https://crt.sh/?q={quote(domain)}&output=json"
    payload, error, raw = fetch_json(url, timeout=20.0)
    if error and payload is None:
        return [], error, raw
    if not isinstance(payload, list):
        return [], "crt.sh returned a document that was not a list.", raw
    rows: list[dict[str, Any]] = []
    for item in payload[:200]:
        if not isinstance(item, dict):
            continue
        rows.append(
            {
                "common_name": clean_text(str(item.get("common_name", "")), 200),
                "name_value": clean_text(str(item.get("name_value", "")), 500),
                "issuer_name": clean_text(str(item.get("issuer_name", "")), 300),
                "not_before": clean_text(str(item.get("not_before", "")), 80),
                "not_after": clean_text(str(item.get("not_after", "")), 80),
            }
        )
    return rows, error, raw


def fetch_ripe_prefix(ip: str) -> tuple[dict[str, Any] | None, str | None, str]:
    """Ask RIPEstat prefix-overview for public ASN and prefix data."""
    url = f"https://stat.ripe.net/data/prefix-overview/data.json?resource={quote(ip)}"
    payload, error, raw = fetch_json(url, timeout=12.0)
    if not isinstance(payload, dict):
        return None, error or "RIPEstat did not return an object.", raw
    return payload, error, raw


def fetch_ripe_geo(ip: str) -> tuple[dict[str, Any] | None, str | None, str]:
    """Ask RIPEstat geoloc for an approximate public location."""
    url = f"https://stat.ripe.net/data/geoloc/data.json?resource={quote(ip)}"
    payload, error, raw = fetch_json(url, timeout=12.0)
    if not isinstance(payload, dict):
        return None, error or "RIPEstat did not return an object.", raw
    return payload, error, raw
