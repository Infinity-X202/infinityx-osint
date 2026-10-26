"""Explain scan results without adding facts that were not collected."""

from __future__ import annotations

from collections import Counter

from infinityx.models import CheckResult

_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNASSESSED": 5}
_HEADER_IDS = {"security-headers", "server-header", "whatweb"}
_SECURITY_IDS = _HEADER_IDS | {
    "http-https-redirect",
    "https-status",
    "cert-validity",
    "cert-hostname",
    "cert-expiration-warning",
    "cert-sans",
    "spf",
    "dmarc",
    "dkim-guidance",
    "security-txt",
    "expiration-date",
    "domain-status",
}


def apply_honesty_rules(item: CheckResult) -> None:
    """Keep banners and missing headers from being upgraded into vulnerabilities."""
    if item.check_id in _HEADER_IDS and item.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        item.severity = "INFORMATIONAL"
        item.observation_type = "informational"
        item.limitations = (
            item.limitations
            + " Severity stays informational because a banner, a technology name, or a missing header is not proof of a vulnerability."
        )


def build_narratives(domain: str, started: str, results: list[CheckResult], interrupted: bool) -> dict[str, str]:
    """Build the report sections from completed checks."""
    return {
        "executive_summary": _executive(domain, started, results, interrupted),
        "domain_intelligence": _domain(domain, results),
        "website_analysis": _website(results),
        "tls_email": _tls_email(results),
        "classification": _classification(results),
        "overall_assessment": _overall(domain, results, interrupted),
        "conclusion": _conclusion(domain, results),
    }


def counts(results: list[CheckResult]) -> dict[str, int]:
    """Count checks by status."""
    counter: Counter[str] = Counter(item.status for item in results)
    return {name: counter.get(name, 0) for name in ("OK", "WARNING", "FAILED", "SKIPPED")}


def severity_counts(results: list[CheckResult]) -> dict[str, int]:
    """Count checks by severity label."""
    counter: Counter[str] = Counter(item.severity for item in results)
    return {name: counter.get(name, 0) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNASSESSED")}


def top_findings(results: list[CheckResult], limit: int = 5) -> list[CheckResult]:
    """Prefer higher severities, then warnings, for the closing dashboard."""
    ranked = sorted(results, key=lambda item: (_ORDER.get(item.severity, 9), item.number))
    chosen = [item for item in ranked if item.severity in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}]
    return chosen[:limit]


def _by_id(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {item.check_id: item for item in results}


def _line(item: CheckResult | None, fallback: str) -> str:
    if item is None:
        return fallback
    text = item.summary
    if item.error and item.status in {"FAILED", "SKIPPED"}:
        text += " Reason: " + item.error
    return text


def _executive(domain: str, started: str, results: list[CheckResult], interrupted: bool) -> str:
    status = counts(results)
    discoveries = []
    index = _by_id(results)
    for check_id, label in (
        ("registrar", "Registrar"),
        ("dns-a", "IPv4"),
        ("public-ips", "Public addresses"),
        ("https-status", "HTTPS"),
        ("page-title", "Page title"),
        ("cert-issuer", "Certificate issuer"),
        ("cert-expiration-warning", "Certificate expiry"),
        ("spf", "SPF"),
        ("dmarc", "DMARC"),
        ("asn-ownership", "ASN"),
    ):
        item = index.get(check_id)
        if item and item.status in {"OK", "WARNING"}:
            discoveries.append(f"{label}: {item.summary}")
    issues = [
        item.summary
        for item in results
        if item.severity in {"HIGH", "MEDIUM", "LOW"} or item.observation_type == "verified_issue"
    ]
    missing = [f"{item.number}. {item.name} ({item.status})" for item in results if item.status in {"FAILED", "SKIPPED"}]
    parts = [
        f"InfinityX OSINT Scanner, created by Infinity, reviewed the public footprint of {domain} at {started}.",
        (
            f"The scan ran {len(results)} checks: {status['OK']} OK, {status['WARNING']} warning, "
            f"{status['FAILED']} failed, and {status['SKIPPED']} skipped."
        ),
        "Main discoveries: " + ("; ".join(discoveries) if discoveries else "No check both completed and produced a discovery line."),
        "Configuration items that deserve a look: " + ("; ".join(issues) if issues else "No low, medium, or high item was assigned from the evidence collected."),
        "Missing or unavailable information: " + (", ".join(missing) if missing else "Every check completed or returned an observation."),
    ]
    if interrupted:
        parts.append("The operator interrupted the scan. Checks that had not started are marked skipped and were not executed.")
    parts.append(
        "Overall, this is a passive picture of public data. It supports administrative review. "
        "It does not prove that the website is secure, and it does not prove that it has been compromised."
    )
    return "\n\n".join(parts)


def _domain(domain: str, results: list[CheckResult]) -> str:
    index = _by_id(results)
    paragraphs = [
        f"This section explains the registration and DNS facts collected for {domain}. Each statement comes from a check in this scan.",
        "WHOIS: " + _line(index.get("whois-record"), "WHOIS was not attempted."),
        "Registrar: " + _line(index.get("registrar"), "Registrar data is unavailable."),
        "Creation date: " + _line(index.get("creation-date"), "Creation date is unavailable.")
        + " A creation date says when the current published registration began. It does not describe the content of the website.",
        "Expiration date: " + _line(index.get("expiration-date"), "Expiration date is unavailable.")
        + " The countdown is calculated only when the published string had a recognized date format.",
        "Updated date: " + _line(index.get("updated-date"), "Updated date is unavailable.")
        + " An update means the registry recorded a change. It is not, by itself, evidence of an attack.",
        "Nameservers: " + _line(index.get("whois-nameservers"), "WHOIS nameservers are unavailable.")
        + " DNS nameservers: " + _line(index.get("dns-ns"), "DNS NS records are unavailable.")
        + " Nameservers are the hosts that publish the DNS zone. A difference between WHOIS and DNS is explained in the NS check and is not counted as two delegations.",
        "Status codes: " + _line(index.get("domain-status"), "Status codes are unavailable.")
        + " Codes such as clientTransferProhibited are registry locks. A hold or redemption code is a lifecycle warning.",
        "A records are IPv4 addresses. " + _line(index.get("dns-a"), "A records are unavailable."),
        "AAAA records are IPv6 addresses. " + _line(index.get("dns-aaaa"), "AAAA records are unavailable."),
        "MX records name inbound mail servers in preference order. " + _line(index.get("dns-mx"), "MX records are unavailable."),
        "TXT records are public text, including site-verification tokens and SPF. " + _line(index.get("dns-txt"), "TXT records are unavailable."),
        "The SOA record carries the zone serial, timers, and a contact-style RNAME. " + _line(index.get("dns-soa"), "SOA is unavailable."),
        "CAA records can restrict which certificate authorities may issue. " + _line(index.get("dns-caa"), "CAA is unavailable."),
        "The second resolver check compares 1.1.1.1 with 8.8.8.8. " + _line(index.get("dns-second-resolver"), "The comparison is unavailable."),
        "DNSSEC observations come from DS, DNSKEY, and the AD flag. They are not a local signature validation. "
        + _line(index.get("dns-dnssec"), "DNSSEC is unavailable."),
        "Public addresses used for hosting lookups: " + _line(index.get("public-ips"), "No public-address summary is available."),
        "ASN and prefix data, when present, name the network that announces the address: " + _line(index.get("asn-ownership"), "ASN data is unavailable."),
        "Geolocation is only an estimate: " + _line(index.get("ip-geolocation"), "Geolocation is unavailable."),
    ]
    return "\n\n".join(paragraphs)


def _website(results: list[CheckResult]) -> str:
    index = _by_id(results)
    blocks = [
        (
            "HTTP status",
            index.get("http-status"),
            "The HTTP status is the clear-text root response. A successful code means this URL answered. It does not certify the application.",
        ),
        (
            "HTTPS status",
            index.get("https-status"),
            "The HTTPS status is the encrypted root response after same-site redirects. A TLS error here means the encrypted site was not confirmed from this network.",
        ),
        (
            "Redirects",
            index.get("http-https-redirect"),
            "Redirect behavior says whether the HTTP root moved to HTTPS. Off-site and private destinations were not used as browse targets.",
        ),
        (
            "Redirect destination",
            index.get("redirect-destination"),
            "The destination is where the root request ended or the off-site Location that was recorded without a fetch.",
        ),
        (
            "Page title and description",
            index.get("page-title"),
            "The title and meta description are text from the stored HTML. JavaScript-rendered text is invisible to this scanner.",
        ),
        (
            "Technology fingerprint",
            index.get("whatweb"),
            "WhatWeb names are hints. A product name is not a verified vulnerability.",
        ),
        (
            "robots.txt and sitemap",
            index.get("robots-txt"),
            "robots.txt is a crawler policy, not access control. The sitemap check does not crawl the URLs it finds.",
        ),
        (
            "Security headers",
            index.get("security-headers"),
            "Present and absent headers are observations about one response. Absence is not proof of a vulnerability.",
        ),
    ]
    paragraphs = [
        "Website observations below are tied to the root URL and a few well-known paths. For each one: what was found, what it means, how it is classified, and what an administrator can do."
    ]
    for title, item, meaning in blocks:
        if item is None:
            paragraphs.append(f"{title}: this check did not run.")
            continue
        paragraphs.append(
            f"{title}. What was found: {item.summary} "
            f"What it means: {meaning} {item.explanation} "
            f"Classification: {item.observation_type}, severity {item.severity}, status {item.status}. "
            f"Administrator next step: {item.remediation}"
        )
    meta = index.get("meta-description")
    if meta:
        paragraphs.append(f"Meta description result: {meta.summary}")
    canonical = index.get("canonical-url")
    if canonical:
        paragraphs.append(f"Canonical URL result: {canonical.summary} The canonical target was not fetched.")
    robots = index.get("sitemap")
    if robots:
        paragraphs.append(f"Sitemap result: {robots.summary}")
    return "\n\n".join(paragraphs)


def _tls_email(results: list[CheckResult]) -> str:
    index = _by_id(results)
    paragraphs = [
        "TLS and email notes describe published keys, certificates, and mail policies. A missing mail policy is a configuration gap, not confirmation that spoofed mail was sent or that the website was compromised.",
        "Issuer: " + _line(index.get("cert-issuer"), "The issuer was not available."),
        "Subject: " + _line(index.get("cert-subject"), "The subject was not available."),
        "Validity and trust: " + _line(index.get("cert-validity"), "Validity was not available.")
        + " The local trust result uses this computer's trust store. It can differ from another network.",
        "Hostname match: " + _line(index.get("cert-hostname"), "Hostname matching was not available.")
        + " A match means the leaf names this domain. A mismatch means clients should warn. It does not identify the cause.",
        "Subject alternative names: " + _line(index.get("cert-sans"), "SANs were not available."),
        "Expiry warning: " + _line(index.get("cert-expiration-warning"), "Expiry was not assessed.")
        + " This warning uses the same dates as the validity check.",
        "Certificate transparency: " + _line(index.get("cert-transparency"), "Transparency logs were not assessed.")
        + " Log names can be historical. A logged name is not proof the host is live.",
        "SPF: " + _line(index.get("spf"), "SPF was not assessed.")
        + " SPF lists permitted mail senders. Includes were not expanded, so the ten-lookup limit was not fully counted.",
        "DMARC: " + _line(index.get("dmarc"), "DMARC was not assessed.")
        + " p=none is monitoring. p=quarantine and p=reject ask receivers to act. A missing record is not a verified breach.",
        "DKIM: " + _line(index.get("dkim-guidance"), "DKIM guidance did not run.")
        + " No selector was queried, so DKIM deployment is unknown rather than failed.",
    ]
    return "\n\n".join(paragraphs)


def _classification(results: list[CheckResult]) -> str:
    lines = [
        "Severity labels used by InfinityX: INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL, and UNASSESSED.",
        "CRITICAL is reserved for verified active exposure. This passive scan does not assign CRITICAL from a banner, a missing header, a technology name, or an incomplete response.",
        "UNASSESSED means the evidence was not strong enough, or the check did not return data.",
        "",
    ]
    for item in results:
        lines.append(
            f"{item.number}. {item.name} | {item.category} | status {item.status} | {item.severity} | {item.observation_type}"
        )
        if item.check_id in _SECURITY_IDS or item.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            lines.append(f"Evidence: {item.evidence}")
            lines.append(f"Impact: {item.impact}")
            lines.append(f"Confidence: {item.confidence}")
            lines.append(f"Limitations: {item.limitations}")
            lines.append(f"Remediation: {item.remediation}")
        lines.append("")
    return "\n".join(lines).strip()


def _overall(domain: str, results: list[CheckResult], interrupted: bool) -> str:
    useful = [item for item in results if item.status == "OK"]
    concerns = [item for item in results if item.severity in {"HIGH", "MEDIUM"}]
    gaps = [item.name for item in results if item.status in {"FAILED", "SKIPPED"}]
    best = ", ".join(item.name for item in useful[:8]) or "none"
    concern_text = "; ".join(item.summary for item in concerns) or "No high or medium item was assigned."
    gap_text = ", ".join(gaps) or "No check was failed or skipped."
    interrupted_text = " Part of the scan was interrupted, so those checks add nothing to the assessment." if interrupted else ""
    return "\n\n".join(
        [
            f"InfinityX discovered the public registration, DNS, website, certificate, and mail-policy facts that the individual checks were able to collect for {domain}.{interrupted_text}",
            f"The checks that produced the most useful completed results include: {best}.",
            f"Configuration concerns that deserve attention: {concern_text}",
            f"Areas that could not be assessed: {gap_text}. DKIM deployment is unassessed even when that check completes, because selectors are not guessed.",
            "An administrator who wants to go further, with the same authorization, could review CDN certificates in other regions, read DMARC aggregate reports, confirm DKIM from a real message header, and run an authenticated vulnerability scan from an approved scanner. Those steps are outside this passive tool.",
            "This assessment does not declare the website safe, and it does not declare it compromised.",
        ]
    )


def _conclusion(domain: str, results: list[CheckResult]) -> str:
    status = counts(results)
    return (
        f"InfinityX, created by Infinity, finished a passive public review of {domain}. "
        f"{status['OK']} checks completed cleanly, {status['WARNING']} raised a warning, "
        f"{status['FAILED']} failed, and {status['SKIPPED']} were skipped. "
        "The reports describe visible configuration and published records. "
        "They do not prove that the website is secure, and they do not prove that it has been compromised."
    )
