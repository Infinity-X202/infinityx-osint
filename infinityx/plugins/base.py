"""Plugin interface for optional OSINT extensions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from infinityx.models import CheckResult, build_result


@dataclass
class PluginInfo:
    name: str
    version: str
    description: str
    target_types: list[str] = field(default_factory=lambda: ["domain"])
    timeout_seconds: int = 30

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "target_types": self.target_types,
            "timeout_seconds": self.timeout_seconds,
        }


class InfinityXPlugin(Protocol):
    info: PluginInfo

    def run(self, domain: str, context: dict[str, Any]) -> CheckResult: ...


def plugin_failed(info: PluginInfo, reason: str) -> CheckResult:
    return build_result(
        status="FAILED",
        severity="UNASSESSED",
        summary=reason,
        findings=[reason],
        data={},
        method=f"Plugin {info.name}",
        explanation=reason,
        usefulness="Plugin failure is isolated from the core scan.",
        limitations="No plugin evidence was added.",
        evidence=reason,
        impact="Plugin area not assessed.",
        confidence="high",
        remediation="Fix the plugin or disable it.",
        observation_type="unavailable",
        error=reason,
    )
