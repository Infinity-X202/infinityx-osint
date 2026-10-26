"""Defensive security audit built from collected evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from infinityx.analyzer import analyze_findings
from infinityx.intel_models import AuditFinding
from infinityx.models import CheckResult


def run_security_audit(results: list[CheckResult], domain: str, interrupted: bool) -> list[dict[str, Any]]:
    """Return normalized audit rows. No exploitation or guessed vulnerabilities."""
    timestamp = datetime.now(timezone.utc).isoformat()
    rows: list[dict[str, Any]] = []
    counter = 0
    for item in analyze_findings(results, interrupted):
        counter += 1
        finding = AuditFinding(
            finding_id=f"AUD-{counter:04d}",
            title=item["title"],
            category=_category(item["check_id"]),
            asset=domain,
            severity=item["severity"],
            confidence=item["confidence"],
            evidence=item["evidence"],
            source=item["check_id"],
            timestamp=timestamp,
            explanation=item["significance"],
            impact=_impact(item["severity"]),
            remediation=item["remediation"],
            verification="observed" if item["severity"] != "UNASSESSED" else "unassessed",
        )
        rows.append(finding.as_dict())
    index = {item.check_id: item for item in results}
    rows.extend(_extra_audits(index, domain, timestamp, counter))
    return rows


def audit_summary_text(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "No audit findings were produced from the collected evidence."
    elevated = [row for row in rows if row["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}]
    return (
        f"{len(rows)} audit row(s) were derived from scan evidence. "
        f"{len(elevated)} are above informational. "
        "Missing headers and banners alone are not treated as confirmed vulnerabilities."
    )


def _category(check_id: str) -> str:
    mapping = {
        "spf": "email",
        "dmarc": "email",
        "dkim-guidance": "email",
        "http-https-redirect": "transport",
        "security-headers": "http",
        "cert-hostname": "tls",
        "cert-expiration-warning": "tls",
        "cert-validity": "tls",
        "scan": "process",
    }
    return mapping.get(check_id, "configuration")


def _impact(severity: str) -> str:
    if severity == "UNASSESSED":
        return "This area was not assessed."
    if severity in {"HIGH", "CRITICAL"}:
        return "Clients or mail receivers may reject or warn based on this evidence."
    if severity == "MEDIUM":
        return "Misconfiguration may affect trust or deliverability."
    if severity == "LOW":
        return "Policy or transport gap worth reviewing in context."
    return "Informational observation only."


def _extra_audits(index: dict[str, CheckResult], domain: str, timestamp: str, start: int) -> list[dict[str, Any]]:
    extra: list[dict[str, Any]] = []
    dnssec = index.get("dns-dnssec")
    if dnssec and dnssec.status not in {"FAILED", "SKIPPED"}:
        start += 1
        extra.append(
            AuditFinding(
                finding_id=f"AUD-{start:04d}",
                title="DNSSEC public signals",
                category="dns",
                asset=domain,
                severity="INFORMATIONAL",
                confidence="medium",
                evidence=dnssec.summary,
                source="dns-dnssec",
                timestamp=timestamp,
                explanation=dnssec.explanation[:500],
                impact="Informational DNS authentication posture. No forgery was demonstrated.",
                remediation=dnssec.remediation[:500],
                verification="observed",
            ).as_dict()
        )
    return extra
