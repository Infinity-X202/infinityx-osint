"""Explain security-relevant evidence that a scan actually collected.

Severity stays low unless the stored evidence justifies it. A failed check
never becomes a vulnerability.
"""

from __future__ import annotations

from typing import Any

from infinityx.models import CheckResult


def analyze_findings(results: list[CheckResult], interrupted: bool) -> list[dict[str, str]]:
    """Return one row per security-relevant check, plus an incomplete-scan note."""
    index = {item.check_id: item for item in results}
    rows = [
        _spf(index.get("spf")),
        _dmarc(index.get("dmarc")),
        _dkim(index.get("dkim-guidance")),
        _redirect(index.get("http-https-redirect")),
        _headers(index.get("security-headers")),
        _hostname(index.get("cert-hostname")),
        _expiry(index.get("cert-expiration-warning")),
        _trust(index.get("cert-validity")),
    ]
    if interrupted:
        rows.append(
            _row(
                "scan",
                "Incomplete scan",
                "UNASSESSED",
                "low",
                "The operator stopped the scan. Checks that did not run have no evidence.",
                "Interrupted before every check finished.",
                "Run the scan again to completion before treating the report as complete.",
            )
        )
    return [row for row in rows if row is not None]


def analysis_text(rows: list[dict[str, str]]) -> str:
    """Render the analyzer for the written reports."""
    if not rows:
        return "The analyzer had no completed checks to read."
    elevated = [row for row in rows if row["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}]
    lines = []
    if not elevated:
        lines.append(
            "Nothing in the collected evidence was raised above informational. "
            "That does not mean the website is secure."
        )
    else:
        lines.append(
            f"{len(elevated)} item(s) were raised because the stored evidence supports them. "
            "No item was marked critical, and no vulnerability was claimed without that evidence."
        )
    for row in rows:
        lines.extend(
            [
                "",
                f"{row['title']} — {row['severity']} — confidence {row['confidence']}",
                f"Significance: {row['significance']}",
                f"Evidence: {row['evidence']}",
                f"Remediation: {row['remediation']}",
            ]
        )
    return "\n".join(lines)


def _spf(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "SPF", "The TXT lookup did not succeed, so no SPF policy was inferred.")
    if blocked:
        return blocked
    count = _count(item)
    if count < 0:
        return _row(item.check_id, "SPF", "UNASSESSED", "low", "The SPF check did not store a record count, so no policy finding was made.", item.summary, "Rerun the scan.")
    records = ", ".join(item.data.get("records") or []) or item.evidence
    if count == 0:
        return _row(
            item.check_id,
            "SPF",
            "LOW",
            "high",
            "Receivers are not given a list of hosts allowed to send mail for this domain. This is a mail-policy gap, not evidence that the website was compromised or that spoofed mail was sent.",
            "No apex TXT record starts with v=spf1.",
            "If the domain sends mail, publish one SPF record that lists the real senders. If it sends no mail, publish v=spf1 -all.",
        )
    if count > 1:
        return _row(
            item.check_id,
            "SPF",
            "MEDIUM",
            "high",
            "More than one SPF record was published. Receivers treat that as a broken SPF policy. This scan did not send mail and did not expand includes.",
            records,
            "Leave a single v=spf1 TXT record at the zone apex.",
        )
    qualifier = str((item.data or {}).get("all_qualifier") or "not recognized")
    return _row(
        item.check_id,
        "SPF",
        "INFORMATIONAL",
        "medium",
        f"One SPF record is published. The ending qualifier seen here is {qualifier}. Includes were not expanded, so this is not a review of every sender.",
        records,
        "Keep the record to one line and review it when a mail provider changes.",
    )


def _dmarc(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "DMARC", "The DMARC lookup did not succeed, so no policy was inferred.")
    if blocked:
        return blocked
    count = _count(item)
    if count < 0:
        return _row(item.check_id, "DMARC", "UNASSESSED", "low", "The DMARC check did not store a record count, so no policy finding was made.", item.summary, "Rerun the scan.")
    policy = str((item.data or {}).get("policy") or "none published")
    records = ", ".join(item.data.get("records") or []) or item.evidence
    if count == 0:
        return _row(
            item.check_id,
            "DMARC",
            "LOW",
            "high",
            "No DMARC policy was published at _dmarc. Receivers are not told what to do with mail that fails authentication. This is not evidence of a website compromise.",
            "No v=DMARC1 TXT record.",
            "Publish one DMARC record. p=none is a monitoring start. p=quarantine or p=reject comes later, after real mail is known to pass.",
        )
    if count > 1:
        return _row(
            item.check_id,
            "DMARC",
            "MEDIUM",
            "high",
            "More than one DMARC record was published. Receivers can ignore the policy until one remains.",
            records,
            "Keep a single TXT record at _dmarc.",
        )
    severity = "LOW" if policy == "none" else "INFORMATIONAL"
    significance = (
        f"A DMARC policy is published with p={policy}. "
        "p=none asks receivers to report rather than reject. This scan did not read aggregate reports."
        if policy == "none"
        else f"A DMARC policy is published with p={policy}. The scanner did not verify that real mail passes SPF or DKIM."
    )
    return _row(
        item.check_id,
        "DMARC",
        severity,
        "high" if policy != "none" else "high",
        significance,
        records,
        "Keep one record. Move from p=none only after legitimate mail is aligned.",
    )


def _dkim(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    return _row(
        item.check_id,
        "DKIM",
        "INFORMATIONAL",
        "high",
        "No DKIM selector was queried. DKIM is neither confirmed nor reported missing.",
        item.evidence or "Selectors queried: none.",
        "Check the selector your mail provider gave you in that provider's DNS. Do not guess selector names.",
    )


def _redirect(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "HTTP to HTTPS", "The HTTP root was not fetched, so redirect behavior was not assessed.")
    if blocked:
        return blocked
    final = str((item.data or {}).get("final_url") or "")
    locations = (item.data or {}).get("locations") or []
    moved = final.lower().startswith("https://") or any(str(item_location).lower().startswith("https://") for item_location in locations)
    if moved:
        return _row(
            item.check_id,
            "HTTP to HTTPS",
            "INFORMATIONAL",
            "medium",
            "The HTTP root sent clients toward HTTPS for this request. Other paths were not tested.",
            item.evidence or final,
            "Keep the redirect in place.",
        )
    return _row(
        item.check_id,
        "HTTP to HTTPS",
        "LOW",
        "medium",
        "The stored HTTP response did not show a move to HTTPS. Only the site root was requested.",
        item.evidence or f"Final URL: {final or 'not recorded'}",
        "Redirect the HTTP root to the HTTPS site with a permanent redirect.",
    )


def _headers(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "Security headers", "Homepage headers were not stored, so the header list was not assessed.")
    if blocked:
        return blocked
    absent = (item.data or {}).get("absent") or []
    present = (item.data or {}).get("present") or {}
    present_names = ", ".join(present) if isinstance(present, dict) else "none"
    absent_names = ", ".join(absent) if isinstance(absent, list) else "unknown"
    return _row(
        item.check_id,
        "Security headers",
        "INFORMATIONAL",
        "high",
        "These headers were observed on one homepage response. A missing header is an observation about that response. It is not proof of a vulnerability.",
        f"Present: {present_names or 'none'}. Not present: {absent_names or 'none'}.",
        "Add HSTS, a content security policy, nosniff, a framing policy, and a referrer policy only where they match how the site works.",
    )


def _hostname(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "Certificate name", "The leaf certificate was not collected, so the name was not checked.")
    if blocked:
        return blocked
    matched = (item.data or {}).get("match")
    if matched is True:
        return _row(
            item.check_id,
            "Certificate name",
            "INFORMATIONAL",
            "high",
            "The leaf presented on this connection names this domain.",
            item.evidence,
            "Keep renewal pointed at a certificate that still names this hostname.",
        )
    if matched is False:
        return _row(
            item.check_id,
            "Certificate name",
            "MEDIUM",
            "high",
            "The leaf presented on this connection does not name this domain. Clients that verify names should warn. The scan does not decide whether the cause is the wrong host, a CDN default, or interception.",
            item.evidence,
            "Serve a certificate whose names include this hostname.",
        )
    return _unavailable(item, "Certificate name", "The name comparison did not produce a yes or no result.")


def _expiry(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "Certificate expiry", "No certificate end date was stored, so expiry was not assessed.")
    if blocked:
        return blocked
    days = (item.data or {}).get("days_remaining")
    if not isinstance(days, int):
        return _unavailable(item, "Certificate expiry", "The end date was not a number of days, so no expiry finding was made.")
    if days < 0:
        severity, significance = "HIGH", f"The stored end date is about {abs(days)} days in the past."
        remediation = "Install a current certificate for this hostname."
    elif days <= 14:
        severity, significance = "MEDIUM", f"The stored end date is about {days} days away."
        remediation = "Renew before the end date."
    elif days <= 30:
        severity, significance = "LOW", f"The stored end date is about {days} days away."
        remediation = "Renew before the end date."
    else:
        severity, significance = "INFORMATIONAL", f"The certificate is outside the 30-day window, with about {days} days remaining."
        remediation = "Keep the existing renewal."
    return _row(item.check_id, "Certificate expiry", severity, "high", significance, item.evidence, remediation)


def _trust(item: CheckResult | None) -> dict[str, str] | None:
    if item is None:
        return None
    blocked = _unavailable(item, "Certificate trust", "The trust check did not complete, so trust was not assessed.")
    if blocked:
        return blocked
    trusted = (item.data or {}).get("trusted")
    if trusted is True:
        return _row(
            item.check_id,
            "Certificate trust",
            "INFORMATIONAL",
            "high",
            "This computer's trust store accepted the certificate at scan time. That is not a full security assessment.",
            item.evidence,
            "Continue normal renewal.",
        )
    if trusted is False:
        error = str((item.data or {}).get("trust_error") or item.evidence)
        return _row(
            item.check_id,
            "Certificate trust",
            "MEDIUM",
            "high",
            "This computer did not accept the certificate. The trust error is the evidence. The cause was not guessed.",
            error,
            "Read the trust error and install a publicly trusted certificate that matches this hostname.",
        )
    return _unavailable(item, "Certificate trust", "The trust result was empty, so no trust finding was made.")


def _unavailable(item: CheckResult, title: str, significance: str) -> dict[str, str] | None:
    if item.status not in {"FAILED", "SKIPPED"}:
        return None
    return _row(
        item.check_id,
        title,
        "UNASSESSED",
        "low",
        significance,
        item.error or item.summary,
        "Rerun the scan. Do not treat this gap as a vulnerability.",
    )


def _count(item: CheckResult) -> int:
    value = (item.data or {}).get("count")
    return value if isinstance(value, int) else -1


def _row(
    check_id: str,
    title: str,
    severity: str,
    confidence: str,
    significance: str,
    evidence: str,
    remediation: str,
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "significance": significance,
        "evidence": evidence or "No evidence text was stored.",
        "remediation": remediation,
    }
