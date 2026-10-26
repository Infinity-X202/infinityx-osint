#!/usr/bin/env python3
"""InfinityX OSINT Scanner.

Created by Infinity. Passive public information gathering for one authorized domain.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from infinityx import TOOL_NAME, TOOL_SUMMARY, __version__
from infinityx.runner import run_scan
from infinityx.ui import launch, make_console

ROOT = Path(__file__).resolve().parent


def build_parser() -> argparse.ArgumentParser:
    """Define the command-line interface."""
    parser = argparse.ArgumentParser(
        prog="infinityx",
        description=TOOL_SUMMARY,
        epilog=(
            "With no domain, InfinityX opens the interactive intelligence center. "
            "The scanner always asks you to type AGREE before it collects anything. "
            "It does not exploit vulnerabilities, guess passwords, or scan ports. "
            f"{TOOL_NAME} was created by Infinity."
        ),
    )
    parser.add_argument("--domain", help="Domain to assess, such as example.com. Authorization is still required.")
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
    """Open the interactive center, or scan one authorized domain."""
    parser = build_parser()
    args = parser.parse_args(argv)
    console = make_console()
    refuse_root(console)

    def scan(domain: str, raw: str, folder: Path, traceroute: bool, on_start, on_progress, on_result):
        return run_scan(
            domain,
            raw,
            folder,
            enable_traceroute=traceroute,
            on_start=on_start,
            on_progress=on_progress,
            on_result=on_result,
        )

    return launch(
        console,
        reports_dir=Path(args.reports_dir),
        enable_traceroute=args.enable_traceroute,
        domain=(args.domain or "").strip(),
        scan=scan,
    )


if __name__ == "__main__":
    sys.exit(main())
