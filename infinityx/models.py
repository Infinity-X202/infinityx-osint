"""Shared data types for checks, network snapshots, and finished scans."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

from infinityx.safety import clean_data, clean_text

STATUSES = ("OK", "WARNING", "FAILED", "SKIPPED")
SEVERITIES = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNASSESSED")
OBSERVATION_TYPES = (
    "informational",
    "configuration_observation",
    "verified_issue",
    "unavailable",
)


@dataclass
class CheckResult:
    """One completed, failed, or skipped information-gathering check."""

    check_id: str
    number: int
    name: str
    category: str
    status: str
    severity: str
    summary: str
    findings: list[str]
    data: dict[str, Any]
    method: str
    explanation: str
    usefulness: str
    limitations: str
    evidence: str
    impact: str
    confidence: str
    remediation: str
    observation_type: str = "informational"
    error: str | None = None
    duration_ms: float = 0.0
    overlaps: list[str] = field(default_factory=list)
    raw_ref: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-ready dictionary."""
        payload = asdict(self)
        payload["duration_ms"] = round(self.duration_ms, 1)
        return payload


def build_result(
    *,
    status: str,
    severity: str,
    summary: str,
    findings: list[str],
    data: dict[str, Any],
    method: str,
    explanation: str,
    usefulness: str,
    limitations: str,
    evidence: str,
    impact: str,
    confidence: str,
    remediation: str,
    observation_type: str = "informational",
    error: str | None = None,
    overlaps: list[str] | None = None,
    raw_ref: str | None = None,
) -> CheckResult:
    """Build a check result and sanitize untrusted text before it is stored."""
    if status not in STATUSES:
        raise ValueError(f"Unknown status: {status}")
    if severity not in SEVERITIES:
        raise ValueError(f"Unknown severity: {severity}")
    if observation_type not in OBSERVATION_TYPES:
        raise ValueError(f"Unknown observation type: {observation_type}")
    clean_findings = [clean_text(item, limit=1000) for item in findings[:30]]
    return CheckResult(
        check_id="",
        number=0,
        name="",
        category="",
        status=status,
        severity=severity,
        summary=clean_text(summary, limit=500).replace("\n", " "),
        findings=clean_findings,
        data=clean_data(data),
        method=clean_text(method, limit=800),
        explanation=clean_text(explanation, limit=4000),
        usefulness=clean_text(usefulness, limit=2000),
        limitations=clean_text(limitations, limit=2000),
        evidence=clean_text(evidence, limit=4000),
        impact=clean_text(impact, limit=2000),
        confidence=confidence,
        remediation=clean_text(remediation, limit=2000),
        observation_type=observation_type,
        error=clean_text(error, limit=1000) if error else None,
        overlaps=list(overlaps or []),
        raw_ref=raw_ref,
    )


@dataclass
class DnsAnswer:
    """Normalized answer from one DNS query."""

    name: str
    rtype: str
    resolver: str
    status: str
    records: list[str] = field(default_factory=list)
    structured: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    cnames: list[str] = field(default_factory=list)


@dataclass
class WhoisInfo:
    """Fields extracted from one public WHOIS conversation."""

    ok: bool
    error: str | None
    raw: str
    servers: list[str]
    registrar: str | None
    creation_raw: str | None
    creation: datetime | None
    expiration_raw: str | None
    expiration: datetime | None
    updated_raw: str | None
    updated: datetime | None
    nameservers: list[str]
    statuses: list[str]


@dataclass
class HttpSnapshot:
    """One bounded HTTP or HTTPS fetch, including any same-site redirect chain."""

    requested_url: str
    ok: bool
    error: str | None = None
    status_code: int | None = None
    final_url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    truncated: bool = False
    elapsed_ms: float = 0.0
    chain: list[dict[str, Any]] = field(default_factory=list)
    blocked_reason: str | None = None
    pinned_ip: str | None = None
    resolved_ips: list[str] = field(default_factory=list)
    bytes_read: int = 0


@dataclass
class CertInfo:
    """Leaf certificate observations from a pinned TLS handshake."""

    ok: bool
    error: str | None = None
    trusted: bool | None = None
    trust_error: str | None = None
    issuer: str | None = None
    subject: str | None = None
    common_name: str | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = field(default_factory=list)
    tls_version: str | None = None
    cipher: str | None = None
    signature_algorithm: str | None = None
    pinned_ip: str | None = None
    fingerprint_sha256: str | None = None
    pem: str = ""


@dataclass
class ScanOutcome:
    """Everything the reporter needs after the checks finish."""

    domain: str
    started_at: datetime
    finished_at: datetime
    results: list[CheckResult]
    narratives: dict[str, str]
    output_dir: str | None = None
    interrupted: bool = False
    authorization_confirmed: bool = True
    comparison: dict[str, Any] | None = None
    analysis: list[dict[str, Any]] = field(default_factory=list)
    history_id: int | None = None
    correlation: dict[str, Any] | None = None
    subdomains: dict[str, Any] | None = None
    audit: list[dict[str, Any]] = field(default_factory=list)
    ai_summary: dict[str, Any] | None = None
    plugin_results: list[CheckResult] = field(default_factory=list)
