"""Shared intelligence models used across modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Literal

DiffClass = Literal["ADDED", "REMOVED", "CHANGED", "UNCHANGED", "UNKNOWN"]
EntityKind = Literal[
    "domain",
    "subdomain",
    "ip",
    "dns_record",
    "asn",
    "nameserver",
    "mail_server",
    "certificate",
    "hostname",
    "http_service",
    "technology",
    "finding",
    "source",
]


@dataclass
class Asset:
    """One observed asset with a stable id inside a scan."""

    id: str
    kind: EntityKind
    value: str
    source: str
    observed_at: str
    confidence: str = "high"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Relationship:
    """A directed link supported by collected evidence."""

    id: str
    type: str
    from_id: str
    to_id: str
    source: str
    observed_at: str
    confidence: str
    direct: bool = True
    evidence: str = ""
    limitations: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AuditFinding:
    """One defensive audit row with traceable evidence."""

    finding_id: str
    title: str
    category: str
    asset: str
    severity: str
    confidence: str
    evidence: str
    source: str
    timestamp: str
    explanation: str
    impact: str
    remediation: str
    verification: str = "observed"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanSession:
    """Metadata for one authorized run."""

    domain: str
    started_at: datetime
    finished_at: datetime | None
    scanner_version: str
    profile: str
    interrupted: bool = False
    output_dir: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "scanner_version": self.scanner_version,
            "profile": self.profile,
            "interrupted": self.interrupted,
            "output_dir": self.output_dir,
        }


@dataclass
class PluginMetadata:
    name: str
    version: str
    description: str
    target_types: list[str]
    enabled: bool = True

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class NotificationResult:
    sent: bool
    reason: str
    message_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)
