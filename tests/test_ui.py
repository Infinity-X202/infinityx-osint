"""Presentation tests. They do not contact the network."""

from __future__ import annotations

import io
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from infinityx import __version__
from infinityx.models import CheckResult, ScanOutcome, build_result
from infinityx.ui import (
    BANNER_PATH,
    ScanBoard,
    authorization_accepted,
    list_report_dirs,
    move_selection,
    print_dashboard,
    render_checks,
    render_header,
)


def _console(width: int) -> tuple[Console, io.StringIO]:
    stream = io.StringIO()
    console = Console(file=stream, width=width, force_terminal=False, highlight=False, color_system=None)
    return console, stream


def _sample() -> CheckResult:
    item = build_result(
        status="OK",
        severity="INFORMATIONAL",
        summary="A public record was read.",
        findings=["example"],
        data={},
        method="unit test",
        explanation="Synthetic presentation row.",
        usefulness="It exercises the live board.",
        limitations="It is not a scan.",
        evidence="synthetic",
        impact="none",
        confidence="high",
        remediation="none",
    )
    item.number = 9
    item.name = "A records"
    item.category = "DNS intelligence"
    item.check_id = "dns-a"
    item.duration_ms = 12
    return item


class InterfaceTests(unittest.TestCase):
    def test_header_uses_real_version_on_wide_and_narrow_screens(self) -> None:
        for width in (100, 48):
            console, stream = _console(width)
            console.print(render_header(console))
            text = stream.getvalue()
            self.assertIn("InfinityX", text)
            self.assertIn(__version__, text)
            self.assertIn("Created by Infinity", text)
            self.assertIn("report.html", text)

    def test_selection_wraps(self) -> None:
        self.assertEqual(move_selection(0, "up", 6), 5)
        self.assertEqual(move_selection(5, "down", 6), 0)

    def test_authorization_word_is_exact(self) -> None:
        self.assertTrue(authorization_accepted("AGREE"))
        self.assertTrue(authorization_accepted("  AGREE  "))
        self.assertFalse(authorization_accepted("agree"))
        self.assertFalse(authorization_accepted("YES"))

    def test_live_board_renders_a_real_result(self) -> None:
        console, stream = _console(80)
        board = ScanBoard(console, 50)
        board.on_progress(type("Spec", (), {"name": "A records", "category": "DNS intelligence"})(), 8)
        board.on_result(_sample())
        console.print(board.render())
        text = stream.getvalue()
        self.assertIn("A records", text)
        self.assertIn("DNS Intelligence", text)
        self.assertIn("1/50", text)

    def test_check_catalog_lists_every_registered_check(self) -> None:
        console, stream = _console(100)
        console.print(render_checks())
        text = stream.getvalue()
        self.assertIn("Normalize and validate the domain", text)
        self.assertIn("DKIM discovery guidance", text)

    def test_previous_reports_are_only_real_folders(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "notes").mkdir()
            real = root / "20260101_000000_example.com"
            real.mkdir()
            (real / "report.json").write_text("{}", encoding="utf-8")
            found = list_report_dirs(root)
            self.assertEqual(found, [real])

    def test_brand_file_is_in_the_project(self) -> None:
        self.assertTrue(BANNER_PATH.is_file())
        self.assertGreater(BANNER_PATH.stat().st_size, 1000)

    def test_dashboard_prints_on_a_legacy_code_page(self) -> None:
        raw = io.BytesIO()
        stream = io.TextIOWrapper(raw, encoding="cp1252", errors="strict")
        console = Console(file=stream, width=48, force_terminal=False, highlight=False, safe_box=True, legacy_windows=False, color_system=None)
        now = datetime.now(timezone.utc)
        outcome = ScanOutcome(
            domain="example.com",
            started_at=now,
            finished_at=now,
            results=[_sample()],
            narratives={"conclusion": "Passive collection finished."},
        )
        console.print(render_header(console))
        board = ScanBoard(console, 50)
        board.on_result(_sample())
        console.print(board.render())
        print_dashboard(console, outcome, {"directory": "reports/example", "txt": "report.txt", "json": "report.json", "html": "report.html", "raw": "raw", "logs": "logs"})
        stream.flush()
        text = raw.getvalue().decode("cp1252")
        self.assertIn("example.com", text)
        self.assertIn("Passive collection finished.", text)


if __name__ == "__main__":
    unittest.main()
