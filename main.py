#!/usr/bin/env python3
"""InfinityX OSINT Scanner — Created by Infinity."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from infinityx import TOOL_NAME, TOOL_SUMMARY, __version__
from infinityx.cli_actions import (
    plugin_manager,
    run_subdomain_intel,
    show_audit,
    show_correlation,
    show_reports,
    telegram_settings,
)
from infinityx.config import AppConfig
from infinityx.comparison_export import export_comparison
from infinityx.history import HistoryStore
from infinityx.runner import run_scan
from infinityx.ui import (
    ProgressDisplay,
    ask_domain,
    ask_main_menu,
    confirm_authorization,
    make_console,
    print_banner,
    print_check_row,
    print_comparison,
    print_dashboard,
    print_history,
    print_results_header,
)
from infinityx.validation import normalize_domain

ROOT = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="infinityx",
        description=TOOL_SUMMARY,
        epilog=(
            "Type y or n before any collection starts. "
            f"{TOOL_NAME} was created by Infinity."
        ),
    )
    parser.add_argument("--domain", help="Domain to assess. Authorization is still required.")
    parser.add_argument("--history", action="store_true", help="Show local scan history.")
    parser.add_argument("--compare", nargs=2, type=int, metavar=("OLDER", "NEWER"), help="Compare two stored scans.")
    parser.add_argument("--telegram-test", action="store_true", help="Send a Telegram test message when configured.")
    parser.add_argument("--reports-dir", default=str(ROOT / "reports"), help="Report output directory.")
    parser.add_argument("--enable-traceroute", action="store_true", help="Enable traceroute when installed.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} (created by Infinity)")
    return parser


def refuse_root(console) -> None:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        console.print("[error]Refusing to run as root.[/] Use a normal user account.")
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = make_console()
    refuse_root(console)
    print_banner(console)
    reports_dir = Path(args.reports_dir)
    history = HistoryStore(reports_dir / "infinityx.sqlite")
    config = AppConfig.load(reports_dir)

    if args.history:
        print_history(console, history.list_scans())
        return 0
    if args.compare:
        return _show_comparison(console, history, args.compare[0], args.compare[1])
    if args.telegram_test:
        from infinityx.telegram_alerts import send_test_notification

        result = send_test_notification(config)
        console.print("[ok]Test sent." if result.sent else f"[warning]{result.reason}")
        return 0 if result.sent else 2
    if args.domain:
        return _run_domain_scan(console, args.domain, reports_dir, history, config, args.enable_traceroute)

    while True:
        try:
            choice = ask_main_menu(console)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[muted]Goodbye.[/]")
            return 0
        if choice == "0":
            return 0
        if choice == "1":
            code = _interactive_scan(console, reports_dir, history, config, args.enable_traceroute)
            if code != 0:
                return code
            continue
        if choice == "2":
            raw = ask_domain(console)
            if raw:
                code = run_subdomain_intel(console, raw, reports_dir)
                if code != 0:
                    return code
            continue
        if choice == "3":
            print_history(console, history.list_scans())
            continue
        if choice == "4":
            code = _compare_from_prompt(console, history, reports_dir)
            if code != 0:
                return code
            continue
        if choice == "5":
            show_correlation(console, history)
            continue
        if choice == "6":
            show_audit(console, history)
            continue
        if choice == "7":
            rows = history.list_scans(limit=1)
            if rows and rows[0].get("output_dir"):
                console.print(f"[info]Latest AI summary is in {rows[0]['output_dir']}/report.txt (section L).[/]")
            else:
                console.print("[muted]Run a scan first.[/]")
            continue
        if choice == "8":
            show_reports(console, reports_dir)
            continue
        if choice == "9":
            telegram_settings(console, config)
            continue
        if choice == "10":
            plugin_manager(console)
            continue
        console.print("[warning]Unknown choice.[/]")


def _interactive_scan(console, reports_dir, history, config, traceroute: bool) -> int:
    raw = ask_domain(console)
    if not raw:
        return 0
    return _run_domain_scan(console, raw, reports_dir, history, config, traceroute)


def _run_domain_scan(console, raw: str, reports_dir: Path, history: HistoryStore, config: AppConfig, traceroute: bool) -> int:
    try:
        normalized = normalize_domain(raw)
    except ValueError as exc:
        console.print(f"[error]{exc}[/]")
        return 2
    try:
        if not confirm_authorization(console, normalized.hostname):
            console.print("[warning]Authorization was not confirmed. No scan was started.[/]")
            return 2
    except (EOFError, KeyboardInterrupt):
        console.print("\n[warning]Authorization was not confirmed. No scan was started.[/]")
        return 2

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = reports_dir / f"{stamp}_{normalized.hostname}"
    console.print(f"\n[info]Scan folder:[/] {folder}")
    print_results_header(console)
    display: ProgressDisplay | None = None

    def on_start(total: int) -> None:
        nonlocal display
        display = ProgressDisplay(console, total)
        display.__enter__()

    def on_progress(spec, index: int) -> None:
        if display is not None:
            display.update(spec.name, index)

    def on_result(item) -> None:
        print_check_row(console, item)
        if display is not None:
            display.update(item.name, item.number)

    try:
        outcome, paths = run_scan(
            normalized.hostname,
            raw,
            folder,
            enable_traceroute=traceroute,
            history=history,
            app_config=config,
            on_start=on_start,
            on_progress=on_progress,
            on_result=on_result,
        )
    except KeyboardInterrupt:
        console.print("\n[warning]Interrupted before the report could be written.[/]")
        return 130
    finally:
        if display is not None:
            display.progress.stop()

    print_dashboard(console, outcome, paths)
    return 0


def _show_comparison(console, history: HistoryStore, older_id: int, newer_id: int) -> int:
    try:
        diff = history.compare(older_id, newer_id)
    except ValueError as exc:
        console.print(f"[warning]{exc}[/]")
        return 2
    print_comparison(console, diff)
    return 0


def _compare_from_prompt(console, history: HistoryStore, reports_dir: Path) -> int:
    rows = history.list_scans()
    print_history(console, rows)
    if len(rows) < 2:
        console.print("[warning]At least two stored scans are required.[/]")
        return 2
    try:
        older = console.input("[accent]Earlier scan number:[/] ").strip()
        newer = console.input("[accent]Later scan number:[/] ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[warning]Cancelled.[/]")
        return 2
    if not older.isdigit() or not newer.isdigit():
        console.print("[warning]Enter two scan numbers from the table.[/]")
        return 2
    try:
        diff = history.compare(int(older), int(newer))
    except ValueError as exc:
        console.print(f"[warning]{exc}[/]")
        return 2
    print_comparison(console, diff)
    folder = reports_dir / "comparisons" / f"{older}_vs_{newer}"
    paths = export_comparison(diff, folder)
    console.print(f"[info]Exported:[/] {paths['directory']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
