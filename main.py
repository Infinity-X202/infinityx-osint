#!/usr/bin/env python3
"""InfinityX OSINT Scanner.

Created by Infinity. Passive public information gathering for one authorized domain.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime
from pathlib import Path

from infinityx import TOOL_NAME, TOOL_SUMMARY, __version__
from infinityx.history import HistoryStore
from infinityx.runner import run_scan
from infinityx.ui import (
    ProgressDisplay,
    ask_action,
    ask_domain,
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
    """Define the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="infinityx",
        description=TOOL_SUMMARY,
        epilog=(
            "The scanner always asks you to type y or n before it collects anything. "
            "It does not exploit vulnerabilities, guess passwords, or scan ports. "
            f"{TOOL_NAME} was created by Infinity."
        ),
    )
    parser.add_argument("--domain", help="Domain to assess, such as example.com. Authorization is still required.")
    parser.add_argument("--history", action="store_true", help="Show scans stored on this computer. Nothing is collected.")
    parser.add_argument(
        "--compare",
        nargs=2,
        type=int,
        metavar=("OLDER", "NEWER"),
        help="Compare two stored scan numbers for the same domain. Nothing is collected.",
    )
    parser.add_argument(
        "--reports-dir",
        default=str(ROOT / "reports"),
        help="Directory where the timestamped scan folder is created. Default: ./reports next to main.py.",
    )
    parser.add_argument(
        "--enable-traceroute",
        action="store_true",
        help="Send traceroute probes if the traceroute command is installed. Off by default.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__} (created by Infinity)")
    return parser


def refuse_root(console) -> None:
    """Do not run the scanner as root."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        console.print("[error]Refusing to run as root.[/] Use a normal user account.")
        raise SystemExit(1)


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, confirm authorization, scan, and write reports."""
    parser = build_parser()
    args = parser.parse_args(argv)
    console = make_console()
    refuse_root(console)
    print_banner(console)
    history = HistoryStore(Path(args.reports_dir) / "infinityx.sqlite")
    if args.history:
        print_history(console, history.list_scans())
        return 0
    if args.compare:
        return _show_comparison(console, history, args.compare[0], args.compare[1])
    if not args.domain:
        try:
            choice = ask_action(console)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[warning]Cancelled.[/]")
            return 2
        if choice == "2":
            print_history(console, history.list_scans())
            return 0
        if choice == "3":
            return _compare_from_prompt(console, history)

    raw = args.domain.strip() if args.domain else ""
    while not raw:
        try:
            raw = ask_domain(console)
        except (EOFError, KeyboardInterrupt):
            console.print("\n[warning]Cancelled.[/]")
            return 2
        if not raw:
            console.print("[muted]No domain entered. Exiting.[/]")
            return 2
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
    folder = Path(args.reports_dir) / f"{stamp}_{normalized.hostname}"
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
            enable_traceroute=args.enable_traceroute,
            history=history,
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
    """Print one stored comparison. A bad id does not start a scan."""
    try:
        diff = history.compare(older_id, newer_id)
    except ValueError as exc:
        console.print(f"[warning]{exc}[/]")
        return 2
    print_comparison(console, diff)
    return 0


def _compare_from_prompt(console, history: HistoryStore) -> int:
    """Let the operator pick two stored scans. No check is repeated."""
    rows = history.list_scans()
    print_history(console, rows)
    if len(rows) < 2:
        console.print("[warning]At least two stored scans are required before a comparison.[/]")
        return 2
    try:
        older = console.input("[accent]Earlier scan number:[/] ").strip()
        newer = console.input("[accent]Later scan number:[/] ").strip()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[warning]Cancelled.[/]")
        return 2
    if not older.isdigit() or not newer.isdigit():
        console.print("[warning]Enter the two scan numbers from the history table.[/]")
        return 2
    return _show_comparison(console, history, int(older), int(newer))


if __name__ == "__main__":
    sys.exit(main())
