"""Platform upgrade tests (no live network)."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from infinityx.ai_assistant import build_intelligence_summary
from infinityx.config import AppConfig
from infinityx.correlation import build_correlation_graph
from infinityx.diffscan import compare_snapshots
from infinityx.models import ScanOutcome, build_result
from infinityx.plugin_manager import list_plugins
from infinityx.subdomains import hostname_in_scope
from infinityx.telegram_alerts import send_scan_alert


def _check(check_id: str, **kwargs) -> object:
    data = kwargs.pop("data", {})
    item = build_result(
        status=kwargs.get("status", "OK"),
        severity=kwargs.get("severity", "INFORMATIONAL"),
        summary=kwargs.get("summary", "ok"),
        findings=[],
        data=data,
        method="test",
        explanation="test",
        usefulness="test",
        limitations="test",
        evidence="test",
        impact="test",
        confidence="high",
        remediation="test",
    )
    item.check_id = check_id
    item.number = 1
    item.name = check_id
    item.category = "test"
    return item


class PlatformTests(unittest.TestCase):
    def test_hostname_scope_rejects_outside_domain(self) -> None:
        self.assertTrue(hostname_in_scope("www.example.com", "example.com"))
        self.assertFalse(hostname_in_scope("evil.org", "example.com"))

    def test_correlation_dedupes_relationships(self) -> None:
        results = [
            _check("dns-a", data={"records": ["203.0.113.10"]}),
            _check("public-ips", data={"ips": ["203.0.113.10"]}),
        ]
        graph = build_correlation_graph("example.com", results)
        rel_types = [rel["type"] for rel in graph["relationships"]]
        self.assertIn("domain_resolves_to_ip", rel_types)
        self.assertTrue(any("Shared IP" in line for line in graph["limitations"]))

    def test_diff_classification_unknown_when_not_compared(self) -> None:
        older = {"dns": {"a": {"state": "present", "values": ["1.1.1.1"]}}, "ips": {"state": "unavailable", "values": []}}
        newer = {"dns": {"a": {"state": "unavailable", "values": []}}, "ips": {"state": "unavailable", "values": []}}
        diff = compare_snapshots(older, newer, older_label="a", newer_label="b", domain="example.com")
        section = next(s for s in diff["sections"] if s["name"] == "DNS A records")
        self.assertEqual(section["classification"], "UNKNOWN")

    def test_ai_local_when_disabled(self) -> None:
        from pathlib import Path

        config = AppConfig.load(Path("."))
        summary = build_intelligence_summary("example.com", {"total": 1, "ok": 1, "warning": 0, "failed": 0, "skipped": 0}, [], None, config)
        self.assertEqual(summary["mode"], "local")

    def test_telegram_disabled_without_config(self) -> None:
        from pathlib import Path

        config = AppConfig.load(Path("."))
        result = send_scan_alert(config, "test")
        self.assertFalse(result.sent)

    def test_plugins_register_examples(self) -> None:
        names = {row["name"] for row in list_plugins()}
        self.assertIn("example_registrar", names)
        self.assertIn("example_txt_count", names)


if __name__ == "__main__":
    unittest.main()
