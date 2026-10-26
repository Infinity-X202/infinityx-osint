"""Ordered registry of the 50 InfinityX checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from infinityx.checks.dns_checks import (
    check_a,
    check_aaaa,
    check_caa,
    check_dnssec,
    check_mx,
    check_ns,
    check_ptr,
    check_second_resolver,
    check_soa,
    check_txt,
)
from infinityx.checks.email_checks import check_dkim_guidance, check_dmarc, check_spf
from infinityx.checks.http_checks import (
    check_canonical,
    check_content_length,
    check_content_type,
    check_description,
    check_headers,
    check_http_status,
    check_http_to_https,
    check_https_status,
    check_redirect_destination,
    check_robots,
    check_security_headers,
    check_security_txt,
    check_server_header,
    check_sitemap,
    check_timing,
    check_title,
    check_whatweb,
)
from infinityx.checks.infrastructure_checks import (
    check_asn,
    check_geo,
    check_public_ips,
    check_reverse_dns,
    check_traceroute,
)
from infinityx.checks.tls_checks import (
    check_ct,
    check_expiration_warning,
    check_hostname,
    check_issuer,
    check_sans,
    check_subject,
    check_validity,
)
from infinityx.checks.whois_checks import (
    check_creation_date,
    check_domain_status,
    check_expiration_date,
    check_normalize,
    check_registrar,
    check_updated_date,
    check_whois_nameservers,
    check_whois_record,
)
from infinityx.context import ScanContext
from infinityx.models import CheckResult

CheckFunc = Callable[[ScanContext], CheckResult]


@dataclass(frozen=True)
class CheckSpec:
    """Metadata and callable for one check."""

    number: int
    check_id: str
    name: str
    category: str
    func: CheckFunc


ALL_CHECKS: tuple[CheckSpec, ...] = (
    CheckSpec(1, "normalize-domain", "Normalize and validate the domain", "Domain and WHOIS", check_normalize),
    CheckSpec(2, "whois-record", "WHOIS registration information", "Domain and WHOIS", check_whois_record),
    CheckSpec(3, "registrar", "Registrar information", "Domain and WHOIS", check_registrar),
    CheckSpec(4, "creation-date", "Creation date", "Domain and WHOIS", check_creation_date),
    CheckSpec(5, "expiration-date", "Expiration date", "Domain and WHOIS", check_expiration_date),
    CheckSpec(6, "updated-date", "Updated date", "Domain and WHOIS", check_updated_date),
    CheckSpec(7, "whois-nameservers", "WHOIS nameservers", "Domain and WHOIS", check_whois_nameservers),
    CheckSpec(8, "domain-status", "Domain status codes", "Domain and WHOIS", check_domain_status),
    CheckSpec(9, "dns-a", "A records", "DNS intelligence", check_a),
    CheckSpec(10, "dns-aaaa", "AAAA records", "DNS intelligence", check_aaaa),
    CheckSpec(11, "dns-mx", "MX records", "DNS intelligence", check_mx),
    CheckSpec(12, "dns-ns", "NS records", "DNS intelligence", check_ns),
    CheckSpec(13, "dns-txt", "TXT records", "DNS intelligence", check_txt),
    CheckSpec(14, "dns-soa", "SOA record", "DNS intelligence", check_soa),
    CheckSpec(15, "dns-caa", "CAA records", "DNS intelligence", check_caa),
    CheckSpec(16, "dns-second-resolver", "Second-resolver comparison", "DNS intelligence", check_second_resolver),
    CheckSpec(17, "dns-ptr", "Reverse DNS for resolved IPs", "DNS intelligence", check_ptr),
    CheckSpec(18, "dns-dnssec", "DNSSEC public information", "DNS intelligence", check_dnssec),
    CheckSpec(19, "http-status", "HTTP response status", "Website and HTTP", check_http_status),
    CheckSpec(20, "https-status", "HTTPS response status", "Website and HTTP", check_https_status),
    CheckSpec(21, "http-https-redirect", "HTTP-to-HTTPS redirect behavior", "Website and HTTP", check_http_to_https),
    CheckSpec(22, "redirect-destination", "Redirect destination", "Website and HTTP", check_redirect_destination),
    CheckSpec(23, "response-headers", "Response headers", "Website and HTTP", check_headers),
    CheckSpec(24, "server-header", "Server header", "Website and HTTP", check_server_header),
    CheckSpec(25, "content-type", "Content-Type", "Website and HTTP", check_content_type),
    CheckSpec(26, "content-length", "Content-Length", "Website and HTTP", check_content_length),
    CheckSpec(27, "response-timing", "Response timing", "Website and HTTP", check_timing),
    CheckSpec(28, "page-title", "Page title", "Website and HTTP", check_title),
    CheckSpec(29, "meta-description", "Meta description", "Website and HTTP", check_description),
    CheckSpec(30, "canonical-url", "Canonical URL", "Website and HTTP", check_canonical),
    CheckSpec(31, "robots-txt", "robots.txt", "Website and HTTP", check_robots),
    CheckSpec(32, "sitemap", "Sitemap discovery", "Website and HTTP", check_sitemap),
    CheckSpec(33, "security-txt", "security.txt discovery", "Website and HTTP", check_security_txt),
    CheckSpec(34, "security-headers", "Public security headers", "Website and HTTP", check_security_headers),
    CheckSpec(35, "whatweb", "WhatWeb technology fingerprint", "Website and HTTP", check_whatweb),
    CheckSpec(36, "cert-issuer", "TLS certificate issuer", "TLS and certificates", check_issuer),
    CheckSpec(37, "cert-subject", "Certificate subject", "TLS and certificates", check_subject),
    CheckSpec(38, "cert-validity", "Certificate validity", "TLS and certificates", check_validity),
    CheckSpec(39, "cert-hostname", "Certificate hostname match", "TLS and certificates", check_hostname),
    CheckSpec(40, "cert-sans", "Certificate subject alternative names", "TLS and certificates", check_sans),
    CheckSpec(41, "cert-expiration-warning", "Certificate expiration warning", "TLS and certificates", check_expiration_warning),
    CheckSpec(42, "cert-transparency", "Certificate transparency", "TLS and certificates", check_ct),
    CheckSpec(43, "public-ips", "Public IP addresses", "Network and infrastructure", check_public_ips),
    CheckSpec(44, "asn-ownership", "IP ownership and ASN", "Network and infrastructure", check_asn),
    CheckSpec(45, "ip-geolocation", "Public IP geolocation estimate", "Network and infrastructure", check_geo),
    CheckSpec(46, "reverse-dns", "Infrastructure reverse DNS", "Network and infrastructure", check_reverse_dns),
    CheckSpec(47, "traceroute", "Traceroute", "Network and infrastructure", check_traceroute),
    CheckSpec(48, "spf", "SPF record analysis", "Email and public intelligence", check_spf),
    CheckSpec(49, "dmarc", "DMARC record analysis", "Email and public intelligence", check_dmarc),
    CheckSpec(50, "dkim-guidance", "DKIM discovery guidance", "Email and public intelligence", check_dkim_guidance),
)
