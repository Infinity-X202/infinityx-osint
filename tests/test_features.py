"""History, comparison, and finding analysis. No network."""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from infinityx.analyzer import analyze_findings
from infinityx.diffscan import compare_snapshots
from infinityx.history import HistoryStore
from infinityx.models import ScanOutcome, build_result
from infinityx.snapshot import extract_snapshot
from infinityx.ui import authorization_accepted


def _check(check_id: str, status: str = "OK", severity: str = "INFORMATIONAL", data: dict | None = None, summary: str = "Stored.") -> object:
    item = build_result(
        status=status,
        severity=severity,
        summary=summary,
        findings=["evidence line"],
        data=data or {},
        method="unit test",
        explanation="Synthetic.",
        usefulness="Test.",
        limitations="Test.",
        evidence=summary,
        impact="Test.",
        confidence="high",
        remediation="None in this test.",
    )
    item.check_id = check_id
    item.number = 1
    item.name = check_id
    item.category = "test"
    return item


class AuthorizationTests(unittest.TestCase):
    def test_only_y_starts_a_scan(self) -> None:
        self.assertTrue(authorization_accepted("y"))
        self.assertTrue(authorization_accepted(" Y "))
        self.assertFalse(authorization_accepted("n"))
        self.assertFalse(authorization_accepted("N"))
        self.assertFalse(authorization_accepted("AGREE"))
        self.assertFalse(authorization_accepted("yes"))


class HistoryTests(unittest.TestCase):
    def test_save_list_and_findings_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            store = HistoryStore(Path(folder) / "infinityx.sqlite")
            started = datetime(2026, 10, 26, tzinfo=timezone.utc)
            results = [_check("dns-a", data={"records": ["203.0.113.10"]})]
            outcome = ScanOutcome("example.com", started, started, results, {})
            snapshot = extract_snapshot(results, False)
            scan_id = store.save(outcome, snapshot, [])
            listed = store.list_scans("example.com")
            self.assertEqual(listed[0]["id"], scan_id)
            self.assertEqual(listed[0]["domain"], "example.com")
            self.assertEqual(store.findings(scan_id)[0]["check_id"], "dns-a")
            self.assertIsNone(store.get(999))

    def test_failed_dns_is_not_reported_as_removal(self) -> None:
        older = extract_snapshot([_check("dns-a", data={"records": ["203.0.113.10"]}), _check("public-ips", data={"ips": ["203.0.113.10"]})], False)
        newer = extract_snapshot(
            [
                _check("dns-a", status="FAILED", severity="UNASSESSED", summary="timeout"),
                _check("public-ips", data={"ips": ["203.0.113.10", "203.0.113.11"]}),
            ],
            False,
        )
        diff = compare_snapshots(older, newer, older_label="1", newer_label="2", domain="example.com")
        sections = {item["name"]: item for item in diff["sections"]}
        self.assertEqual(sections["DNS A records"]["status"], "not_compared")
        self.assertEqual(sections["IP addresses"]["status"], "added")
        self.assertEqual(sections["IP addresses"]["added"], ["203.0.113.11"])
        self.assertEqual(sections["IP addresses"]["removed"], [])

    def test_header_and_name_changes(self) -> None:
        older = extract_snapshot(
            [
                _check("response-headers", data={"headers": {"Server": "A", "X-Test": "1"}}),
                _check("cert-sans", data={"sans": ["example.com"]}),
                _check("cert-transparency", status="FAILED", severity="UNASSESSED"),
            ],
            False,
        )
        newer = extract_snapshot(
            [
                _check("response-headers", data={"headers": {"Server": "B"}}),
                _check("cert-sans", data={"sans": ["example.com", "www.example.com"]}),
                _check("cert-transparency", status="FAILED", severity="UNASSESSED"),
            ],
            False,
        )
        diff = compare_snapshots(older, newer, older_label="1", newer_label="2", domain="example.com")
        sections = {item["name"]: item for item in diff["sections"]}
        self.assertIn("server", [item["field"] for item in sections["HTTP headers"]["changed"]])
        self.assertEqual(sections["HTTP headers"]["removed"], ["x-test"])
        self.assertEqual(sections["Subdomains and certificate names"]["added"], ["www.example.com"])

    def test_compare_requires_same_domain(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            store = HistoryStore(Path(folder) / "infinityx.sqlite")
            started = datetime(2026, 10, 26, tzinfo=timezone.utc)
            first = ScanOutcome("one.example", started, started, [_check("dns-a", data={"records": ["203.0.113.10"]})], {})
            second = ScanOutcome("two.example", started, started, [_check("dns-a", data={"records": ["203.0.113.11"]})], {})
            first_id = store.save(first, extract_snapshot(first.results, False), [])
            second_id = store.save(second, extract_snapshot(second.results, False), [])
            with self.assertRaises(ValueError):
                store.compare(first_id, second_id)


class AnalyzerTests(unittest.TestCase):
    def test_missing_spf_is_low_and_a_failed_lookup_is_not_a_vulnerability(self) -> None:
        missing = analyze_findings([_check("spf", status="WARNING", severity="LOW", data={"count": 0, "records": []}, summary="No SPF record was published.")], False)
        spf = next(row for row in missing if row["title"] == "SPF")
        self.assertEqual(spf["severity"], "LOW")
        self.assertIn("not evidence", spf["significance"])
        failed = analyze_findings([_check("spf", status="FAILED", severity="UNASSESSED", summary="timeout")], False)
        failed_spf = next(row for row in failed if row["title"] == "SPF")
        self.assertEqual(failed_spf["severity"], "UNASSESSED")
        self.assertNotIn("CRITICAL", failed_spf["severity"])

    def test_missing_headers_stay_informational(self) -> None:
        rows = analyze_findings(
            [_check("security-headers", data={"present": {}, "absent": ["content-security-policy"]})],
            False,
        )
        headers = next(row for row in rows if row["title"] == "Security headers")
        self.assertEqual(headers["severity"], "INFORMATIONAL")
        self.assertIn("not proof of a vulnerability", headers["significance"])

    def test_expired_certificate_uses_the_stored_day_count(self) -> None:
        rows = analyze_findings(
            [_check("cert-expiration-warning", data={"days_remaining": -3}, summary="expired")],
            False,
        )
        expiry = next(row for row in rows if row["title"] == "Certificate expiry")
        self.assertEqual(expiry["severity"], "HIGH")
        self.assertIn("3 days", expiry["significance"])

    def test_dkim_is_not_reported_as_missing(self) -> None:
        rows = analyze_findings([_check("dkim-guidance", data={"queried_selectors": [], "deployment_verified": False}, summary="not queried")], False)
        dkim = next(row for row in rows if row["title"] == "DKIM")
        self.assertEqual(dkim["severity"], "INFORMATIONAL")
        self.assertIn("neither confirmed nor reported missing", dkim["significance"])
