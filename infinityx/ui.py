"""Terminal interface. Completed rows stay on screen."""

from __future__ import annotations

from rich.align import Align
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from infinityx import AUTHOR, TOOL_NAME, TOOL_SUMMARY, __version__
from infinityx.analysis import counts, severity_counts, top_findings
from infinityx.models import CheckResult, ScanOutcome

THEME = Theme(
    {
        "accent": "bold bright_cyan",
        "ok": "green",
        "warning": "yellow",
        "error": "bold red",
        "muted": "bright_black",
        "info": "white",
    }
)

LOGO = r"""
██╗███╗   ██╗███████╗██╗███╗   ██╗██╗████████╗██╗   ██╗██╗  ██╗
██║████╗  ██║██╔════╝██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝╚██╗██╔╝
██║██╔██╗ ██║█████╗  ██║██╔██╗ ██║██║   ██║    ╚████╔╝  ╚███╔╝
██║██║╚██╗██║██╔══╝  ██║██║╚██╗██║██║   ██║     ╚██╔╝   ██╔██╗
██║██║ ╚████║██║     ██║██║ ╚████║██║   ██║      ██║   ██╔╝ ██╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
""".rstrip()

STATUS_STYLE = {"OK": "ok", "WARNING": "warning", "FAILED": "error", "SKIPPED": "muted"}


def make_console() -> Console:
    """Return the themed console used by the scanner."""
    return Console(theme=THEME, highlight=False)


def print_banner(console: Console) -> None:
    """Show the logo, author, and a plain explanation of the tool."""
    encoding = getattr(getattr(console, "file", None), "encoding", None) or "utf-8"
    try:
        LOGO.encode(encoding)
        art = LOGO
    except UnicodeEncodeError:
        art = "INFINITYX OSINT SCANNER"
    body = Text(justify="center")
    body.append(art + "\n", style="bold bright_cyan")
    body.append(f"\n{TOOL_NAME}  ·  v{__version__}\n", style="bold bright_white")
    body.append(f"Created by {AUTHOR}\n\n", style="bold bright_magenta")
    body.append(TOOL_SUMMARY + "\n\n", style="bright_white")
    body.append(
        "It collects public WHOIS, DNS, HTTP, TLS, hosting, and email-policy data for one domain, "
        "then writes report.txt, report.json, and report.html. "
        "It does not guess passwords, exploit services, or scan ports.\n",
        style="bright_white",
    )
    console.print(
        Panel(
            Align.center(body),
            border_style="bright_cyan",
            title="[bold bright_cyan]InfinityX[/]",
            subtitle="[bold bright_magenta]passive authorized OSINT[/]",
            padding=(1, 2),
        )
    )


def ask_domain(console: Console) -> str:
    """Prompt for a domain without erasing the banner."""
    console.print("\n[accent]Enter the domain to assess[/] (example.com). Empty input quits.")
    return console.input("[accent]Domain:[/] ").strip()


def authorization_accepted(answer: str) -> bool:
    """Accept only y. n and every other answer cancel the scan."""
    return answer.strip().lower() == "y"


def confirm_authorization(console: Console, domain: str) -> bool:
    """Ask for y or n before any collection starts."""
    console.print(
        Panel(
            "\n".join(
                [
                    f"Target: {domain}",
                    "",
                    "InfinityX will query public WHOIS, public DNS resolvers 1.1.1.1 and 8.8.8.8,",
                    "the website on ports 80 and 443, certificate transparency via crt.sh,",
                    "and RIPEstat for ASN and a geolocation estimate.",
                    "Optional WhatWeb or traceroute runs only when available and, for traceroute, enabled.",
                    "",
                    "Continue only if you own this domain or have permission to assess it.",
                    "Type y to start the scan, or n to cancel.",
                ]
            ),
            title="Authorization",
            border_style="bright_cyan",
        )
    )
    answer = console.input("[accent]Continue? [y/n]:[/] ").strip()
    return authorization_accepted(answer)


def ask_action(console: Console) -> str:
    """Choose a scan, the local history, or a comparison. Enter keeps the scan."""
    console.print("\n[accent]1[/] Scan a domain    [accent]2[/] Scan history    [accent]3[/] Compare two scans")
    choice = console.input("[accent]Choice[/] [muted][1][/]: ").strip() or "1"
    return choice


def print_results_header(console: Console) -> None:
    """Print a persistent header for live check rows."""
    console.print("\n[accent]Live results[/]  [muted]completed rows stay on screen[/]\n")


def print_check_row(console: Console, item: CheckResult) -> None:
    """Append one finished check. Remote text is escaped so it cannot restyle the UI."""
    style = STATUS_STYLE.get(item.status, "info")
    summary = escape(item.summary)
    name = escape(item.name)
    console.print(
        f"[{style}]{item.status:<8}[/] [muted]{item.number:02d}[/] {name:<42} "
        f"[muted]{item.duration_ms:8.0f} ms[/]  {summary}"
    )


class ProgressDisplay:
    """A progress bar that does not replace the result rows printed above it."""

    def __init__(self, console: Console, total: int) -> None:
        self.progress = Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[accent]{task.description}"),
            BarColumn(bar_width=36, complete_style="bright_cyan", finished_style="green"),
            TextColumn("{task.percentage:>5.1f}%"),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        )
        self.task = None
        self.total = total

    def __enter__(self) -> "ProgressDisplay":
        self.progress.start()
        self.task = self.progress.add_task("Starting", total=self.total)
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.progress.stop()

    def update(self, name: str, completed: int) -> None:
        """Show the check that is about to run."""
        if self.task is not None:
            self.progress.update(self.task, description=escape(name)[:48], completed=completed)


def print_dashboard(console: Console, outcome: ScanOutcome, paths: dict[str, str]) -> None:
    """Show the closing summary without clearing the live results."""
    status = counts(outcome.results)
    severity = severity_counts(outcome.results)
    table = Table(title="Scan summary", border_style="bright_cyan", header_style="bold bright_cyan")
    table.add_column("Item")
    table.add_column("Value")
    table.add_row("Target", outcome.domain)
    table.add_row("Finished", outcome.finished_at.strftime("%Y-%m-%d %H:%M:%S"))
    table.add_row("Checks", str(len(outcome.results)))
    table.add_row("OK", str(status["OK"]))
    table.add_row("Warning", str(status["WARNING"]))
    table.add_row("Failed", str(status["FAILED"]))
    table.add_row("Skipped", str(status["SKIPPED"]))
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNASSESSED"):
        table.add_row(name, str(severity[name]))
    console.print()
    console.print(table)

    highlights = Table(title="Findings to read first", border_style="bright_cyan", header_style="bold bright_cyan")
    highlights.add_column("#", justify="right")
    highlights.add_column("Severity")
    highlights.add_column("Finding")
    chosen = top_findings(outcome.results)
    if not chosen:
        highlights.add_row("-", "—", "No low, medium, or high item was assigned. This does not mean the site is secure.")
    for item in chosen:
        highlights.add_row(str(item.number), item.severity, item.summary)
    console.print(highlights)

    problems = [item for item in outcome.results if item.status in {"FAILED", "SKIPPED"}]
    if problems:
        console.print("\n[accent]Failed or skipped checks[/]")
        for item in problems:
            console.print(f"  [muted]{item.number:02d}[/] {escape(item.name)} — {escape(item.summary)}")

    console.print(
        Panel(
            "\n".join(
                [
                    f"Folder: {paths.get('directory', '')}",
                    f"History id: {outcome.history_id if outcome.history_id else 'not stored'}",
                    f"Text report: {paths.get('txt', '')}",
                    f"JSON report: {paths.get('json', '')}",
                    f"HTML report: {paths.get('html', '')}",
                    f"Raw outputs: {paths.get('raw', '')}",
                    f"Log: {paths.get('logs', '')}",
                ]
            ),
            title="Reports",
            border_style="bright_cyan",
        )
    )
    console.print(Panel(outcome.narratives.get("conclusion", ""), title="Conclusion", border_style="bright_cyan"))
    console.print(Panel(outcome.narratives.get("historical_comparison", ""), title="Historical comparison", border_style="bright_cyan"))
    console.print(Panel(outcome.narratives.get("security_analysis", ""), title="Security analysis", border_style="bright_cyan"))


def print_history(console: Console, rows: list[dict]) -> None:
    """Show stored scans. An empty history stays an empty table."""
    table = Table(title="Scan history", border_style="bright_cyan", header_style="bold bright_cyan")
    table.add_column("Id", justify="right")
    table.add_column("Domain")
    table.add_column("Finished")
    table.add_column("OK", justify="right")
    table.add_column("Warning", justify="right")
    table.add_column("Failed", justify="right")
    table.add_column("Skipped", justify="right")
    if not rows:
        console.print("[muted]No scans are stored yet.[/]")
        return
    for row in rows:
        table.add_row(
            str(row["id"]),
            str(row["domain"]),
            str(row["finished_at"]),
            str(row["status_ok"]),
            str(row["status_warning"]),
            str(row["status_failed"]),
            str(row["status_skipped"]),
        )
    console.print(table)


def print_comparison(console: Console, diff: dict) -> None:
    """Show a stored comparison without repeating the scan."""
    console.print(Panel("\n".join(diff.get("notes") or []), title="Comparison", border_style="bright_cyan"))
    table = Table(title=diff.get("domain", "Comparison"), border_style="bright_cyan", header_style="bold bright_cyan")
    table.add_column("Fact")
    table.add_column("Result")
    table.add_column("Detail")
    for section in diff.get("sections") or []:
        detail = section.get("detail") or ""
        if section.get("added"):
            detail = (detail + " Added: " + ", ".join(section["added"])).strip()
        if section.get("removed"):
            detail = (detail + " Removed: " + ", ".join(section["removed"])).strip()
        for change in section.get("changed") or []:
            detail = (detail + f" {change['field']}: {change['before']} -> {change['after']}").strip()
        table.add_row(section["name"], section["status"].replace("_", " "), detail)
    console.print(table)
