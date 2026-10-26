"""Premium terminal presentation for InfinityX.

This module only draws the interface. Scan execution stays in the runner.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

from rich.align import Align
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from infinityx import AUTHOR, DISCLAIMER, TOOL_NAME, TOOL_SUMMARY, __version__
from infinityx.analysis import counts, severity_counts, top_findings
from infinityx.checks import ALL_CHECKS
from infinityx.models import CheckResult, ScanOutcome

THEME = Theme(
    {
        "accent": "bold bright_cyan",
        "crimson": "bright_cyan",
        "silver": "white",
        "cyan": "cyan",
        "ok": "green",
        "warning": "yellow",
        "error": "bold red",
        "muted": "bright_black",
        "info": "white",
    }
)

BANNER_PATH = Path(__file__).resolve().parents[1] / "assets" / "infinityx-banner.jpg"

LOGO = r"""
██╗███╗   ██╗███████╗██╗███╗   ██╗██╗████████╗██╗   ██╗██╗  ██╗
██║████╗  ██║██╔════╝██║████╗  ██║██║╚══██╔══╝╚██╗ ██╔╝╚██╗██╔╝
██║██╔██╗ ██║█████╗  ██║██╔██╗ ██║██║   ██║    ╚████╔╝  ╚███╔╝
██║██║╚██╗██║██╔══╝  ██║██║╚██╗██║██║   ██║     ╚██╔╝   ██╔██╗
██║██║ ╚████║██║     ██║██║ ╚████║██║   ██║      ██║   ██╔╝ ██╗
╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝
""".rstrip("\n")

MENU_ITEMS = (
    ("1", "Start OSINT Scan"),
    ("2", "View Previous Reports"),
    ("3", "View Available Checks"),
    ("4", "Settings"),
    ("5", "About InfinityX"),
    ("0", "Exit"),
)

RESULT_ITEMS = (
    ("1", "View detailed results"),
    ("2", "Open the report folder"),
    ("3", "View the scan summary"),
    ("4", "Return to the main menu"),
    ("0", "Exit"),
)

GROUP_LABELS = {
    "Domain and WHOIS": "Domain Intelligence",
    "DNS intelligence": "DNS Intelligence",
    "Website and HTTP": "HTTP Analysis",
    "TLS and certificates": "TLS and Certificates",
    "Network and infrastructure": "Infrastructure",
    "Email and public intelligence": "Email Security",
}

STATUS_STYLE = {"OK": "ok", "WARNING": "warning", "FAILED": "error", "SKIPPED": "muted"}


def make_console() -> Console:
    """Return the themed console used by the scanner.

    Narrow or non-Unicode terminals get ASCII boxes so the interface still prints.
    """
    encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
    try:
        "━┌∞".encode(encoding)
        can_unicode = True
    except UnicodeEncodeError:
        can_unicode = False
    return Console(theme=THEME, highlight=False, safe_box=not can_unicode, legacy_windows=False)


def _mark(console: Console) -> str:
    """Arrow used in prompts. Plain terminals get an ASCII mark."""
    return "›" if _unicode_ok(console) else ">"


def _unicode_ok(console: Console) -> bool:
    encoding = getattr(getattr(console, "file", None), "encoding", None) or "utf-8"
    try:
        "∞━─".encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


def system_facts() -> list[tuple[str, str]]:
    """Facts the interface can verify from this process. Nothing here is estimated."""
    host = platform.node().strip() or "unavailable"
    system = platform.system().strip() or "unavailable"
    release = platform.release().strip()
    operating = f"{system} {release}".strip()
    return [
        ("Version", __version__),
        ("Checks", str(len(ALL_CHECKS))),
        ("Host", host),
        ("System", operating),
        ("Time", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        ("Status", "engine loaded"),
    ]


def render_header(console: Console) -> Panel:
    """Show the tool name, author, and explanation, centered."""
    compact = console.width < 78 or not _unicode_ok(console)
    body = Text(justify="center")
    if compact:
        body.append("INFINITYX\n", style="bold bright_cyan")
    else:
        body.append(LOGO + "\n", style="bold bright_cyan")
    body.append(f"\n{TOOL_NAME}  ·  v{__version__}\n", style="bold bright_white")
    body.append(f"Created by {AUTHOR}\n\n", style="bold bright_magenta")
    body.append(TOOL_SUMMARY + "\n\n", style="bright_white")
    body.append(
        "It collects public WHOIS, DNS, HTTP, TLS, hosting, and email-policy data for one domain, "
        "then writes report.txt, report.json, and report.html. "
        "It does not guess passwords, exploit services, or scan ports.\n",
        style="bright_white",
    )
    return Panel(
        Align.center(body),
        border_style="bright_cyan",
        title="[bold bright_cyan]InfinityX[/]",
        subtitle="[bold bright_magenta]passive authorized OSINT[/]",
        padding=(1, 2),
    )


def print_banner(console: Console) -> None:
    """Show the header without erasing later scan output."""
    console.print(render_header(console))


def authorization_accepted(answer: str) -> bool:
    """Return True only for the exact authorization word."""
    return answer.strip() == "AGREE"


def ask_domain(console: Console) -> str:
    """Prompt for a domain. Blank input returns the caller to the previous screen."""
    console.print(
        Panel(
            "\n".join(
                [
                    "Enter the domain you own or are authorized to assess.",
                    "A full URL is accepted. InfinityX keeps the hostname and drops the path.",
                    "Leave the line empty to go back.",
                ]
            ),
            title="Target",
            border_style="bright_cyan",
        )
    )
    return console.input(f"[bright_cyan]Domain[/] [white]{_mark(console)}[/] ").strip()


def confirm_authorization(console: Console, domain: str) -> bool:
    """Require the exact word AGREE before any collection starts."""
    console.print(
        Panel(
            "\n".join(
                [
                    f"Target hostname: {domain}",
                    "",
                    "The existing engine will query public WHOIS, DNS at 1.1.1.1 and 8.8.8.8,",
                    "HTTP and HTTPS on ports 80 and 443, crt.sh, and RIPEstat.",
                    "Traceroute runs only when it is enabled and the command exists.",
                    "",
                    "Continue only if you own this domain or have permission to assess it.",
                    "Type AGREE in capital letters. Any other answer cancels the scan.",
                ]
            ),
            title="Authorization",
            border_style="bright_cyan",
        )
    )
    answer = console.input(f"[accent]Type AGREE to confirm authorization[/] [white]{_mark(console)}[/] ")
    return authorization_accepted(answer)


def move_selection(index: int, action: str, size: int) -> int:
    """Move a menu cursor without leaving the list."""
    if size <= 0:
        return 0
    if action == "up":
        return (index - 1) % size
    if action == "down":
        return (index + 1) % size
    return index


def render_menu(index: int, *, title: str, items: tuple[tuple[str, str], ...], hint: str, fancy: bool = True) -> Panel:
    """Draw one menu. The highlighted row is the keyboard selection."""
    pointer = "▸" if fancy else ">"
    lines = Text()
    for position, (key, label) in enumerate(items):
        if position == index:
            lines.append(f"  {pointer} [{key}] {label}\n", style="bold black on bright_cyan")
        else:
            lines.append(f"    [{key}] {label}\n", style="white")
    lines.append("\n" + hint, style="bright_black")
    return Panel(lines, title=f"[bold white]{title}[/]", border_style="bright_cyan", padding=(1, 2))


def read_key() -> str:
    """Read one navigation key. Restores the terminal mode after each read."""
    if os.name == "nt":
        import msvcrt

        char = msvcrt.getwch()
        if char in {"\x00", "\xe0"}:
            extra = msvcrt.getwch()
            return {"H": "up", "P": "down"}.get(extra, "")
        if char == "\x03":
            raise KeyboardInterrupt
        if char in {"\r", "\n"}:
            return "enter"
        if char == "\x1b":
            return "back"
        return char
    import termios
    import tty

    fd = sys.stdin.fileno()
    previous = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        char = sys.stdin.read(1)
        if char == "\x1b":
            follow = sys.stdin.read(2)
            if follow == "[A":
                return "up"
            if follow == "[B":
                return "down"
            return "back"
        if char == "\x03":
            raise KeyboardInterrupt
        if char in {"\r", "\n"}:
            return "enter"
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, previous)
    return char


def choose(console: Console, title: str, items: tuple[tuple[str, str], ...], hint: str) -> str | None:
    """Return the selected item key, or None when the operator goes back."""
    keys = {key: key for key, _label in items}
    if not sys.stdin.isatty():
        for key, label in items:
            console.print(f"  [{key}] {label}")
        try:
            entered = console.input(f"[bright_cyan]Select[/] [white]{_mark(console)}[/] ").strip()
        except EOFError:
            return None
        return entered if entered in keys else None
    from rich.live import Live

    index = 0
    with Live(render_menu(index, title=title, items=items, hint=hint, fancy=_unicode_ok(console)), console=console, auto_refresh=False, transient=True) as live:
        while True:
            live.update(render_menu(index, title=title, items=items, hint=hint, fancy=_unicode_ok(console)), refresh=True)
            action = read_key()
            if action in {"up", "down"}:
                index = move_selection(index, action, len(items))
            elif action in keys:
                return action
            elif action == "enter":
                return items[index][0]
            elif action in {"back", "q"}:
                return None


def list_report_dirs(reports_dir: Path) -> list[Path]:
    """Return real scan folders that already contain a JSON report."""
    if not reports_dir.is_dir():
        return []
    found = [path for path in reports_dir.iterdir() if path.is_dir() and (path / "report.json").is_file()]
    return sorted(found, key=lambda path: path.name, reverse=True)


def render_checks() -> Table:
    """List the registered checks. This is the engine registry, not a sample."""
    table = Table(title="Available checks", border_style="bright_cyan", header_style="bold bright_cyan", expand=True)
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Group", style="white")
    table.add_column("Check", style="white")
    for spec in ALL_CHECKS:
        table.add_row(f"{spec.number:02d}", GROUP_LABELS.get(spec.category, spec.category), spec.name)
    return table


def _bar(done: int, total: int, width: int, fancy: bool) -> str:
    width = max(12, width)
    filled = 0 if total <= 0 else min(width, round(width * done / total))
    mark = "━" if fancy else "#"
    rest = "─" if fancy else "-"
    return mark * filled + rest * (width - filled)


def _spinner(fancy: bool) -> str:
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if fancy else "|/-\\"
    return frames[int(time.monotonic() * 8) % len(frames)]


class ScanBoard:
    """One live region updated from real runner callbacks."""

    def __init__(self, console: Console, total: int) -> None:
        from rich.live import Live

        self.console = console
        self.total = total
        self.finished = 0
        self.current_name = "Waiting for the first check"
        self.current_category = ""
        self.rows: list[CheckResult] = []
        self.started = time.monotonic()
        self.live = Live(
            self.render(),
            console=console,
            refresh_per_second=8,
            transient=False,
            get_renderable=self.render,
        )

    def __enter__(self) -> "ScanBoard":
        self.live.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.live.stop()

    def on_start(self, total: int) -> None:
        self.total = total

    def on_progress(self, spec, index: int) -> None:
        self.current_name = spec.name
        self.current_category = GROUP_LABELS.get(spec.category, spec.category)
        self.finished = index

    def on_result(self, item: CheckResult) -> None:
        self.rows.append(item)
        self.finished = len(self.rows)

    def render(self):
        fancy = _unicode_ok(self.console)
        percent = 0.0 if self.total <= 0 else (self.finished / self.total) * 100
        elapsed = time.monotonic() - self.started
        header = Text()
        header.append(f" {_spinner(fancy)} ", style="bold bright_cyan")
        header.append(escape(self.current_name), style="bold white")
        if self.current_category:
            header.append("   ", style="white")
            header.append(escape(self.current_category), style="cyan")
        header.append(f"\n {percent:5.1f}%   {self.finished}/{self.total}   {elapsed:6.1f}s", style="bright_black")
        width = max(16, min(56, self.console.width - 8))
        bar = Text(_bar(self.finished, self.total, width, fancy), style="bright_cyan")
        groups = Table.grid(expand=True, padding=(0, 2))
        groups.add_column(style="bright_black")
        groups.add_column(justify="right", style="cyan")
        totals: dict[str, int] = {}
        done: dict[str, int] = {}
        for spec in ALL_CHECKS:
            label = GROUP_LABELS.get(spec.category, spec.category)
            totals[label] = totals.get(label, 0) + 1
        for item in self.rows:
            label = GROUP_LABELS.get(item.category, item.category)
            done[label] = done.get(label, 0) + 1
        for label, count in totals.items():
            groups.add_row(label, f"{done.get(label, 0)}/{count}")
        status = counts(self.rows)
        counters = Text.assemble(
            ("  OK ", "bright_black"),
            (str(status["OK"]), "green"),
            ("   Warning ", "bright_black"),
            (str(status["WARNING"]), "yellow"),
            ("   Failed ", "bright_black"),
            (str(status["FAILED"]), "red"),
            ("   Skipped ", "bright_black"),
            (str(status["SKIPPED"]), "bright_black"),
        )
        table = Table(border_style="bright_cyan", header_style="bold bright_cyan", expand=True, show_edge=False)
        table.add_column("#", justify="right", style="cyan", no_wrap=True)
        table.add_column("Status", no_wrap=True)
        table.add_column("Check")
        table.add_column("ms", justify="right", style="bright_black")
        visible = self.rows[-8:]
        for item in visible:
            style = STATUS_STYLE.get(item.status, "white")
            table.add_row(f"{item.number:02d}", f"[{style}]{item.status}[/]", escape(item.name), f"{item.duration_ms:.0f}")
        if len(self.rows) > len(visible):
            caption = f"Latest {len(visible)} of {len(self.rows)} completed checks. The full list is saved in the report."
        else:
            caption = "Completed checks appear here as the engine finishes them."
        rule = Rule(characters="─" if fancy else "-", style="bright_cyan")
        return Panel(
            Group(header, bar, rule, groups, counters, rule, table, Text(caption, style="bright_black")),
            title="[bold white]Live scan[/]",
            border_style="bright_cyan",
            padding=(1, 1),
        )


def print_results_header(console: Console) -> None:
    """Keep the older call working. The live board draws its own header."""
    console.print(Rule(title="Live scan", style="bright_cyan"))


def print_check_row(console: Console, item: CheckResult) -> None:
    """Print one finished check when a live board is not in use."""
    style = STATUS_STYLE.get(item.status, "info")
    console.print(
        f"[{style}]{item.status:<8}[/] [cyan]{item.number:02d}[/] {escape(item.name)} "
        f"[bright_black]{item.duration_ms:7.0f} ms[/]  {escape(item.summary)}"
    )


class ProgressDisplay:
    """Compatibility progress bar. The interactive app uses ScanBoard instead."""

    def __init__(self, console: Console, total: int) -> None:
        self.progress = Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[bright_cyan]{task.description}"),
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
        if self.task is not None:
            self.progress.update(self.task, description=escape(name)[:48], completed=completed)


def print_dashboard(console: Console, outcome: ScanOutcome, paths: dict[str, str]) -> None:
    """Show the closing summary from the outcome the engine already produced."""
    status = counts(outcome.results)
    severity = severity_counts(outcome.results)
    duration = (outcome.finished_at - outcome.started_at).total_seconds()
    summary = Table(title="Scan summary", border_style="bright_cyan", header_style="bold bright_cyan", expand=True)
    summary.add_column("Item", style="bright_black")
    summary.add_column("Value", style="white")
    summary.add_row("Target", outcome.domain)
    summary.add_row("Finished", outcome.finished_at.strftime("%Y-%m-%d %H:%M:%S"))
    summary.add_row("Duration", f"{duration:.1f} s")
    summary.add_row("Checks", str(len(outcome.results)))
    summary.add_row("Successful", str(status["OK"]))
    summary.add_row("Warnings", str(status["WARNING"]))
    summary.add_row("Failed", str(status["FAILED"]))
    summary.add_row("Skipped", str(status["SKIPPED"]))
    for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNASSESSED"):
        summary.add_row(name, str(severity[name]))
    console.print(summary)

    highlights = Table(title="Findings to read first", border_style="bright_cyan", header_style="bold bright_cyan", expand=True)
    highlights.add_column("#", justify="right", style="cyan")
    highlights.add_column("Severity")
    highlights.add_column("Group")
    highlights.add_column("Finding")
    chosen = top_findings(outcome.results)
    if not chosen:
        highlights.add_row("-", "-", "-", "No low, medium, or high item was assigned. This does not mean the site is secure.")
    for item in chosen:
        highlights.add_row(
            str(item.number),
            item.severity,
            GROUP_LABELS.get(item.category, item.category),
            escape(item.summary),
        )
    console.print(highlights)
    console.print(
        Panel(
            "\n".join(
                [
                    f"Folder: {paths.get('directory', '')}",
                    f"Text:   {paths.get('txt', '')}",
                    f"JSON:   {paths.get('json', '')}",
                    f"HTML:   {paths.get('html', '')}",
                    f"Raw:    {paths.get('raw', '')}",
                    f"Log:    {paths.get('logs', '')}",
                ]
            ),
            title="Reports",
            border_style="bright_cyan",
        )
    )
    console.print(Panel(outcome.narratives.get("conclusion", ""), title="Conclusion", border_style="bright_cyan"))


def print_details(console: Console, outcome: ScanOutcome) -> None:
    """Print every check the engine returned."""
    table = Table(title="Detailed results", border_style="bright_cyan", header_style="bold bright_cyan", expand=True)
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Check")
    table.add_column("Summary")
    for item in outcome.results:
        style = STATUS_STYLE.get(item.status, "white")
        table.add_row(
            f"{item.number:02d}",
            f"[{style}]{item.status}[/]",
            item.severity,
            escape(item.name),
            escape(item.summary),
        )
    console.print(table)


def open_report_folder(path: str) -> str:
    """Open a real report folder when the platform can, and always return the path."""
    if not path or not os.path.isdir(path):
        return "The report folder is not available on disk."
    try:
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        else:
            opener = shutil.which("xdg-open")
            if opener:
                subprocess.run([opener, path], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return f"{path}\nThe folder could not be opened: {exc}"
    return path


def maybe_preview_banner() -> str | None:
    """Optionally draw the brand image. The CLI never requires this."""
    if os.environ.get("INFINITYX_BANNER") != "1" or not BANNER_PATH.is_file() or not sys.stdout.isatty():
        return None
    for tool in ("chafa", "timg"):
        binary = shutil.which(tool)
        if not binary:
            continue
        subprocess.run([binary, "--", str(BANNER_PATH)], check=False)
        return tool
    return None


def show_about(console: Console) -> None:
    """Explain the product with the text already shipped in the package."""
    preview = maybe_preview_banner()
    lines = [
        TOOL_SUMMARY,
        "",
        DISCLAIMER,
        "",
        f"Created by {AUTHOR}. Version {__version__}.",
        f"Registered checks: {len(ALL_CHECKS)}.",
        f"Brand artwork: {BANNER_PATH}",
    ]
    if preview:
        lines.append(f"Banner preview used {preview}.")
    elif not BANNER_PATH.is_file():
        lines.append("Brand artwork file was not found next to the project.")
    else:
        lines.append("Set INFINITYX_BANNER=1 and install chafa or timg for an optional image preview.")
    console.print(Panel("\n".join(lines), title="About InfinityX", border_style="bright_cyan"))


def show_reports(console: Console, reports_dir: Path) -> None:
    """List report folders that exist. An empty directory stays empty."""
    folders = list_report_dirs(reports_dir)
    if not folders:
        console.print(Panel(f"No completed reports in {reports_dir}", title="Reports", border_style="bright_cyan"))
        return
    table = Table(title="Previous reports", border_style="bright_cyan", header_style="bold bright_cyan", expand=True)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Folder")
    for number, folder in enumerate(folders[:20], start=1):
        table.add_row(str(number), str(folder))
    console.print(table)
    if not sys.stdin.isatty():
        return
    entered = console.input(f"[bright_cyan]Report number, or Enter to go back[/] [white]{_mark(console)}[/] ").strip()
    if not entered.isdigit():
        return
    chosen = int(entered)
    if not 1 <= chosen <= min(20, len(folders)):
        console.print("[warning]That report number is not in the list.[/]")
        return
    folder = folders[chosen - 1]
    console.print(
        Panel(
            "\n".join(
                [
                    str(folder),
                    str(folder / "report.txt"),
                    str(folder / "report.json"),
                    str(folder / "report.html"),
                ]
            ),
            title="Selected report",
            border_style="bright_cyan",
        )
    )


def show_settings(console: Console, reports_dir: Path, traceroute: bool) -> bool:
    """Toggle the existing traceroute switch. Returns the new value."""
    console.print(
        Panel(
            "\n".join(
                [
                    f"Traceroute: {'enabled' if traceroute else 'disabled'}",
                    "Traceroute still runs only when the traceroute command exists.",
                    f"Reports directory: {reports_dir}",
                    "",
                    "Type T to toggle traceroute, or press Enter to go back.",
                ]
            ),
            title="Settings",
            border_style="bright_cyan",
        )
    )
    entered = console.input(f"[bright_cyan]Settings[/] [white]{_mark(console)}[/] ").strip().lower()
    if entered == "t":
        return not traceroute
    return traceroute


def run_result_menu(console: Console, outcome: ScanOutcome, paths: dict[str, str]) -> str:
    """Offer post-scan actions. Non-interactive runs keep the printed summary and return."""
    if not sys.stdin.isatty():
        return "exit"
    while True:
        choice = choose(
            console,
            "Scan complete",
            RESULT_ITEMS,
            "Arrows or a number select an action. Esc returns to the main menu.",
        )
        if choice in {None, "4"}:
            return "menu"
        if choice == "0":
            return "exit"
        if choice == "1":
            print_details(console, outcome)
        elif choice == "2":
            console.print(Panel(open_report_folder(paths.get("directory", "")), title="Report folder", border_style="bright_cyan"))
        elif choice == "3":
            print_dashboard(console, outcome, paths)
        else:
            return "exit"


def run_one_scan(console: Console, scan, *, domain: str, raw: str, folder: Path, traceroute: bool):
    """Drive the existing scan callback through one live board."""
    board = ScanBoard(console, len(ALL_CHECKS))
    try:
        with board:
            return scan(
                domain,
                raw,
                folder,
                traceroute,
                on_start=board.on_start,
                on_progress=board.on_progress,
                on_result=board.on_result,
            )
    except KeyboardInterrupt:
        console.print("\n[warning]Interrupted. A partial report is written when the engine already started.[/]")
        raise


def launch(console: Console, *, reports_dir: Path, enable_traceroute: bool, domain: str, scan) -> int:
    """Run the interactive center, or one authorized scan when a domain was supplied."""
    traceroute = enable_traceroute
    print_banner(console)
    if domain:
        action = _scan_from_argument(console, scan, reports_dir, traceroute, domain)
        return 130 if action == "interrupt" else (2 if action == "rejected" else 0)
    hint = "Arrows move. Enter or a number selects. Esc or Q leaves a screen."
    while True:
        try:
            choice = choose(console, "DOMAIN INTELLIGENCE CENTER", MENU_ITEMS, hint)
        except KeyboardInterrupt:
            console.print("\n[warning]Closed.[/]")
            return 130
        if choice in {None, "0"}:
            console.print("[bright_black]InfinityX closed.[/]")
            return 0
        if choice == "1":
            action = _scan_from_prompt(console, scan, reports_dir, traceroute)
            if action == "interrupt":
                return 130
            if action == "exit":
                return 0
        elif choice == "2":
            show_reports(console, reports_dir)
        elif choice == "3":
            console.print(render_checks())
        elif choice == "4":
            traceroute = show_settings(console, reports_dir, traceroute)
        elif choice == "5":
            show_about(console)


def _scan_from_prompt(console: Console, scan, reports_dir: Path, traceroute: bool) -> str:
    try:
        raw = ask_domain(console)
    except (EOFError, KeyboardInterrupt):
        return "interrupt"
    if not raw:
        return "menu"
    from infinityx.validation import normalize_domain

    try:
        normalized = normalize_domain(raw)
    except ValueError as exc:
        console.print(Panel(str(exc), title="Domain not accepted", border_style="bright_cyan"))
        return "menu"
    return _confirm_and_scan(console, scan, reports_dir, traceroute, normalized.hostname, raw)


def _scan_from_argument(console: Console, scan, reports_dir: Path, traceroute: bool, raw: str) -> str:
    from infinityx.validation import normalize_domain

    try:
        normalized = normalize_domain(raw)
    except ValueError as exc:
        console.print(Panel(str(exc), title="Domain not accepted", border_style="bright_cyan"))
        return "rejected"
    return _confirm_and_scan(console, scan, reports_dir, traceroute, normalized.hostname, raw)


def _confirm_and_scan(
    console: Console,
    scan,
    reports_dir: Path,
    traceroute: bool,
    hostname: str,
    raw: str,
) -> str:
    try:
        allowed = confirm_authorization(console, hostname)
    except (EOFError, KeyboardInterrupt):
        console.print("\n[warning]Authorization was not confirmed. No scan was started.[/]")
        return "rejected"
    if not allowed:
        console.print("[warning]Authorization was not confirmed. No scan was started.[/]")
        return "rejected"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = reports_dir / f"{stamp}_{hostname}"
    console.print(Panel(f"Reports will be written to\n{folder}", title="Output", border_style="bright_cyan"))
    try:
        outcome, paths = run_one_scan(
            console,
            scan,
            domain=hostname,
            raw=raw,
            folder=folder,
            traceroute=traceroute,
        )
    except KeyboardInterrupt:
        return "interrupt"
    print_dashboard(console, outcome, paths)
    return run_result_menu(console, outcome, paths)
