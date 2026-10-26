"""Offline tests for validation, safety, mail policy, TLS matching, and reports."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from infinityx.analysis import apply_honesty_rules, build_narratives
from infinityx.checks import ALL_CHECKS
from infinityx.checks.email_checks import analyze_dmarc, analyze_spf, check_spf
from infinityx.checks.http_checks import classify_security_headers, parse_page
from infinityx.checks.tls_checks import expiration_assessment, hostname_matches
from infinityx.checks.whois_checks import check_expiration_date
from infinityx.context import ScanContext
from infinityx.models import CheckResult, DnsAnswer, ScanOutcome, WhoisInfo, build_result
from infinityx.net import parse_whois
from infinityx.reporting import write_reports
from infinityx.safety import assess_addresses, clean_text, decide_redirect, hostname_blocked, ip_is_public
from infinityx.validation import normalize_domain


def _result(**kwargs) -> CheckResult:
    check_id = kwargs.pop("check_id", "sample")
    name = kwargs.pop("name", "Sample")
    item = build_result(**kwargs)
    item.check_id = check_id
    item.number = 1
    item.name = name
    item.category = "Test"
    return item


class SafetyTests(unittest.TestCase):
    def test_public_and_blocked_addresses(self) -> None:
        self.assertTrue(ip_is_public("8.8.8.8"))
        self.assertTrue(ip_is_public("2001:4860:4860::8888"))
        for blocked in ("127.0.0.1", "10.1.1.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "::1", "fc00::1", "fe80::1", "100.64.0.1", "192.0.2.1"):
            self.assertFalse(ip_is_public(blocked), blocked)

    def test_mixed_resolution_is_rejected(self) -> None:
        self.assertIsNone(assess_addresses(["8.8.8.8"]))
        self.assertIsNotNone(assess_addresses(["8.8.8.8", "127.0.0.1"]))
        self.assertIsNotNone(assess_addresses([]))

    def test_blocked_names(self) -> None:
        self.assertIsNotNone(hostname_blocked("localhost"))
        self.assertIsNotNone(hostname_blocked("metadata.google.internal"))
        self.assertIsNotNone(hostname_blocked("printer.local"))
        self.assertIsNone(hostname_blocked("example.com"))

    def test_redirect_policy(self) -> None:
        blocked = decide_redirect("https://example.com/", "http://127.0.0.1/admin", "example.com")
        self.assertEqual(blocked.action, "block")
        metadata = decide_redirect("https://example.com/", "http://169.254.169.254/latest", "example.com")
        self.assertEqual(metadata.action, "block")
        creds = decide_redirect("https://example.com/", "https://user:pass@example.com/", "example.com")
        self.assertEqual(creds.action, "block")
        offsite = decide_redirect("https://example.com/", "https://other.example.net/path", "example.com")
        self.assertEqual(offsite.action, "record")
        same = decide_redirect("https://example.com/", "https://www.example.com/path", "example.com")
        self.assertEqual(same.action, "follow")
        evil = decide_redirect("https://example.com/", "https://example.com.evil.com/", "example.com")
        self.assertEqual(evil.action, "record")
        file_url = decide_redirect("https://example.com/", "file:///etc/passwd", "example.com")
        self.assertEqual(file_url.action, "block")

    def test_secret_redaction(self) -> None:
        cleaned = clean_text("token=abcd1234 password: hunter2")
        self.assertNotIn("hunter2", cleaned)
        self.assertNotIn("abcd1234", cleaned)


class DomainTests(unittest.TestCase):
    def test_url_is_reduced_to_hostname(self) -> None:
        parsed = normalize_domain("https://Example.com/path?q=1")
        self.assertEqual(parsed.hostname, "example.com")
        self.assertEqual(parsed.discarded_path, "/path?q=1")

    def test_internal_names_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            normalize_domain("localhost")
        with self.assertRaises(ValueError):
            normalize_domain("http://127.0.0.1")
        with self.assertRaises(ValueError):
            normalize_domain("app.internal")


    def test_whois_fields_with_leading_spaces(self) -> None:
        raw = "\n".join(
            [
                "   Registrar: RESERVED-Internet Assigned Numbers Authority",
                "   Creation Date: 1995-08-14T04:00:00Z",
                "   Registry Expiry Date: 2027-08-13T04:00:00Z",
                "   Name Server: ELLIOTT.NS.CLOUDFLARE.COM",
                "   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
            ]
        )
        info = parse_whois(raw, ["whois.verisign-grs.com"])
        self.assertEqual(info.registrar, "RESERVED-Internet Assigned Numbers Authority")
        self.assertEqual(info.nameservers, ["elliott.ns.cloudflare.com"])
        self.assertEqual(info.statuses, ["clienttransferprohibited"])
        self.assertIsNotNone(info.creation)
        self.assertIsNotNone(info.expiration)
    def test_spf_and_dmarc_parsing(self) -> None:
        permissive = analyze_spf(["v=spf1 +all"])
        self.assertEqual(permissive["all_qualifier"], "+all")
        strict = analyze_spf(["v=spf1 include:_spf.example.com -all"])
        self.assertEqual(strict["count"], 1)
        self.assertEqual(strict["all_qualifier"], "-all")
        dmarc = analyze_dmarc(["v=DMARC1; p=none; rua=mailto:dmarc@example.com"])
        self.assertEqual(dmarc["policy"], "none")

    def test_spf_plus_all_is_a_verified_configuration_issue(self) -> None:
        ctx = ScanContext("example.com", "example.com", False)
        ctx._dns[("TXT", "example.com", "1.1.1.1")] = DnsAnswer(
            "example.com", "TXT", "1.1.1.1", "ok", records=["v=spf1 +all"]
        )
        item = check_spf(ctx)
        self.assertEqual(item.status, "WARNING")
        self.assertEqual(item.severity, "MEDIUM")
        self.assertEqual(item.observation_type, "verified_issue")

    def test_hostname_matching(self) -> None:
        self.assertTrue(hostname_matches("example.com", ["example.com"]))
        self.assertFalse(hostname_matches("example.com", ["www.example.com"]))
        self.assertTrue(hostname_matches("www.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("a.b.example.com", ["*.example.com"]))
        self.assertFalse(hostname_matches("evil.com", ["example.com"]))

    def test_expiration_thresholds(self) -> None:
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        expired = expiration_assessment(datetime(2025, 1, 1, tzinfo=timezone.utc), now)
        self.assertEqual(expired["severity"], "HIGH")
        soon = expiration_assessment(datetime(2026, 1, 10, tzinfo=timezone.utc), now)
        self.assertEqual(soon["severity"], "MEDIUM")
        later = expiration_assessment(datetime(2026, 12, 1, tzinfo=timezone.utc), now)
        self.assertEqual(later["severity"], "INFORMATIONAL")

    def test_whois_expiry_uses_shared_record(self) -> None:
        ctx = ScanContext("example.com", "example.com", False)
        ctx._whois = WhoisInfo(
            ok=True,
            error=None,
            raw="Registry Expiry Date: 2020-01-01T00:00:00Z",
            servers=["whois.example"],
            registrar="Example Registrar",
            creation_raw=None,
            creation=None,
            expiration_raw="2020-01-01T00:00:00Z",
            expiration=datetime(2020, 1, 1, tzinfo=timezone.utc),
            updated_raw=None,
            updated=None,
            nameservers=["ns1.example.com"],
            statuses=["clientTransferProhibited"],
        )
        item = check_expiration_date(ctx)
        self.assertEqual(item.status, "WARNING")
        self.assertEqual(item.severity, "HIGH")
        self.assertIn("whois-record", item.overlaps)

    def test_missing_security_header_stays_informational(self) -> None:
        classified = classify_security_headers({"Content-Type": "text/html"})
        self.assertIn("strict-transport-security", classified["absent"])
        item = _result(
            status="OK",
            severity="HIGH",
            summary="headers",
            findings=["missing"],
            data={},
            method="test",
            explanation="test",
            usefulness="test",
            limitations="test",
            evidence="test",
            impact="test",
            confidence="high",
            remediation="test",
            check_id="security-headers",
            name="Public security headers",
        )
        apply_honesty_rules(item)
        self.assertEqual(item.severity, "INFORMATIONAL")

    def test_html_parser_reads_title_and_ignores_script_text_as_data(self) -> None:
        parsed = parse_page("<html><title>Hello <b>there</title><meta name='description' content='About'><link rel='canonical' href='https://example.com/'></html>")
        self.assertEqual(parsed["title"], "Hello there")
        self.assertEqual(parsed["description"], "About")
        self.assertEqual(parsed["canonical"], "https://example.com/")


class ReportTests(unittest.TestCase):
    def test_reports_are_written_and_escaped(self) -> None:
        item = _result(
            status="OK",
            severity="INFORMATIONAL",
            summary="<script>alert(1)</script>",
            findings=["token=shouldhide value"],
            data={"note": "password=secret"},
            method="unit test",
            explanation="A synthetic result used to test the report writer.",
            usefulness="It proves the files exist.",
            limitations="It is not a live scan.",
            evidence="synthetic",
            impact="none",
            confidence="high",
            remediation="none",
            name="Synthetic check",
        )
        started = datetime(2026, 10, 26, tzinfo=timezone.utc)
        narratives = build_narratives("example.com", started.isoformat(), [item], False)
        outcome = ScanOutcome("example.com", started, started, [item], narratives, authorization_confirmed=True)
        with tempfile.TemporaryDirectory() as temp:
            paths = write_reports(outcome, Path(temp), {"whois.txt": "Registrar: Example"})
            html = Path(paths["html"]).read_text(encoding="utf-8")
            self.assertIn("&lt;script&gt;", html)
            self.assertNotIn("<script>alert", html)
            payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            self.assertEqual(payload["created_by"], "Infinity")
            self.assertEqual(payload["domain"], "example.com")
            self.assertIn("[redacted]", payload["checks"][0]["findings"][0])
            self.assertTrue((Path(temp) / "raw_results" / "whois.txt").exists())
            self.assertIn("do not prove that the website is secure", Path(paths["txt"]).read_text(encoding="utf-8").lower())

    def test_registry_has_fifty_real_checks(self) -> None:
        numbers = [spec.number for spec in ALL_CHECKS]
        ids = [spec.check_id for spec in ALL_CHECKS]
        self.assertEqual(numbers, list(range(1, 51)))
        self.assertEqual(len(set(ids)), 50)
        for spec in ALL_CHECKS:
            self.assertTrue(callable(spec.func))
            self.assertTrue(spec.name)
            self.assertTrue(spec.category)

    def test_sources_do_not_use_shell_true(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for path in list((root / "infinityx").rglob("*.py")) + [root / "main.py"]:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("shell=True", text)
            self.assertNotIn("os.system(", text)
            self.assertNotIn("TODO", text)


class ImportTests(unittest.TestCase):
    def test_modules_import(self) -> None:
        import main
        from infinityx import ui, runner, reporting, net, context

        self.assertTrue(main.TOOL_NAME)
        self.assertTrue(ui.LOGO)
        self.assertTrue(runner.ALL_CHECKS)
        self.assertTrue(reporting.write_reports)
        self.assertTrue(net.fetch_url)
        self.assertTrue(context.ScanContext)


if __name__ == "__main__":
    unittest.main()
