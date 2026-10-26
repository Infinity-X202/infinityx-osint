"""Example plugin: count apex TXT records from cached DNS."""

from __future__ import annotations

from infinityx.context import ScanContext
from infinityx.models import build_result
from infinityx.plugins.base import PluginInfo

INFO = PluginInfo(
    name="example_txt_count",
    version="1.0.0",
    description="Counts TXT records at the zone apex using the shared DNS cache.",
    target_types=["domain"],
)


def run(domain: str, context: dict) -> object:
    ctx: ScanContext = context["scan_context"]
    answer = ctx.dns("TXT")
    count = len(answer.records) if answer.status not in {"timeout", "error"} else 0
    return build_result(
        status="OK" if answer.status not in {"timeout", "error"} else "FAILED",
        severity="INFORMATIONAL" if answer.status not in {"timeout", "error"} else "UNASSESSED",
        summary=f"Plugin TXT count: {count}",
        findings=[f"TXT records at apex: {count}"],
        data={"count": count},
        method="Shared DNS TXT cache",
        explanation="Example plugin without a new DNS query when TXT was already fetched.",
        usefulness="Demonstrates reuse of scan context.",
        limitations="Same TXT answer as the core DNS TXT check.",
        evidence=str(count),
        impact="Informational.",
        confidence="high",
        remediation="None.",
        error=answer.error,
    )
