"""Example plugin: surface registrar from cached WHOIS."""

from __future__ import annotations

from infinityx.context import ScanContext
from infinityx.models import build_result
from infinityx.plugins.base import PluginInfo

INFO = PluginInfo(
    name="example_registrar",
    version="1.0.0",
    description="Reads the registrar from the shared WHOIS lookup.",
    target_types=["domain"],
)


def run(domain: str, context: dict) -> object:
    ctx: ScanContext = context["scan_context"]
    whois = ctx.whois()
    if not whois.ok:
        return build_result(
            status="FAILED",
            severity="UNASSESSED",
            summary="WHOIS was not available for the plugin.",
            findings=[whois.error or "WHOIS failed"],
            data={},
            method="Shared WHOIS cache",
            explanation="Plugin example.",
            usefulness="Demonstrates plugin output schema.",
            limitations="No second WHOIS query.",
            evidence=whois.error or "failed",
            impact="Plugin informational only.",
            confidence="high",
            remediation="Rerun scan.",
            observation_type="unavailable",
            error=whois.error,
        )
    registrar = whois.registrar or "unknown"
    return build_result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Registrar plugin observation: {registrar}",
        findings=[f"Registrar: {registrar}"],
        data={"registrar": registrar},
        method="Shared WHOIS cache",
        explanation="Example plugin using existing scan context.",
        usefulness="Shows plugin integration without duplicate network calls.",
        limitations="Same WHOIS text as the core registrar check.",
        evidence=registrar,
        impact="Informational.",
        confidence="high",
        remediation="None.",
    )
