"""CLI actions for the expanded InfinityX menu."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from rich.panel import Panel

from infinityx.comparison_export import export_comparison
from infinityx.config import AppConfig
from infinityx.context import ScanContext
from infinityx.correlation import correlation_summary_text
from infinityx.history import HistoryStore
from infinityx.subdomains import discover_subdomains, subdomain_table_text, write_subdomain_report
from infinityx.telegram_alerts import send_test_notification
from infinityx.ui import confirm_authorization, print_comparison, print_history
from infinityx.validation import normalize_domain
from infinityx.plugin_manager import list_plugins, set_plugin_enabled


def run_subdomain_intel(console, domain_raw: str, reports_dir: Path) -> int:
    try:
        normalized = normalize_domain(domain_raw)
    except ValueError as exc:
        console.print(f"[error]{exc}[/]")
        return 2
    if not confirm_authorization(console, normalized.hostname):
        console.print("[warning]Authorization was not confirmed.[/]")
        return 2
    ctx = ScanContext(normalized.hostname, domain_raw, enable_traceroute=False)
    payload = discover_subdomains(ctx, resolve_dns=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = reports_dir / f"subdomains_{stamp}_{normalized.hostname}"
    paths = write_subdomain_report(folder, payload)
    console.print(Panel(subdomain_table_text(payload), title="Subdomain intelligence", border_style="bright_cyan"))
    console.print(f"[info]Saved:[/] {paths['directory']}")
    return 0


def show_correlation(console, history: HistoryStore) -> int:
    rows = history.list_scans(limit=1)
    if not rows:
        console.print("[muted]Run a scan first.[/]")
        return 0
    graph = rows[0].get("correlation") or {}
    if not graph:
        console.print("[muted]No correlation graph stored for the latest scan.[/]")
        return 0
    console.print(Panel(correlation_summary_text(graph), title="Intelligence correlation", border_style="bright_cyan"))
    return 0


def show_audit(console, history: HistoryStore) -> int:
    rows = history.list_scans(limit=1)
    if not rows or not rows[0].get("audit"):
        console.print("[muted]No audit rows stored yet.[/]")
        return 0
    lines = [f"{row['finding_id']} {row['title']} — {row['severity']} — {row['evidence']}" for row in rows[0]["audit"][:12]]
    console.print(Panel("\n".join(lines), title="Security audit", border_style="bright_cyan"))
    return 0


def show_reports(console, reports_dir: Path) -> int:
    folders = sorted(reports_dir.glob("*_*"), key=lambda p: p.stat().st_mtime, reverse=True)[:15]
    if not folders:
        console.print("[muted]No report folders yet.[/]")
        return 0
    for folder in folders:
        console.print(f"  {folder}")
    console.print("[muted]Open report.html in a browser. Graph exports live in intel/ inside each scan folder.[/]")
    return 0


def telegram_settings(console, config: AppConfig) -> int:
    status = "enabled" if config.telegram_enabled else "disabled"
    console.print(Panel(f"Telegram alerts: {status}\nSet TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, INFINITYX_TELEGRAM_ALERTS=1", title="Telegram", border_style="bright_cyan"))
    answer = console.input("[accent]Send test message? [y/n]:[/] ").strip().lower()
    if answer != "y":
        return 0
    result = send_test_notification(config)
    if result.sent:
        console.print(f"[ok]{result.reason}")
    else:
        console.print(f"[warning]{result.reason}")
    return 0


def plugin_manager(console) -> int:
    rows = list_plugins()
    lines = [f"{row['name']} v{row['version']} — {'on' if row['enabled'] else 'off'} — {row['description']}" for row in rows]
    console.print(Panel("\n".join(lines) or "No plugins found.", title="Plugins", border_style="bright_cyan"))
    name = console.input("[accent]Toggle plugin name (or Enter to skip):[/] ").strip()
    if not name:
        return 0
    current = next((row for row in rows if row["name"] == name), None)
    if current is None:
        console.print("[warning]Unknown plugin.[/]")
        return 2
    set_plugin_enabled(name, not current["enabled"])
    console.print(f"[info]{name} is now {'enabled' if not current['enabled'] else 'disabled'}.[/]")
    return 0


def export_last_comparison(console, history: HistoryStore, reports_dir: Path) -> int:
    rows = history.list_scans()
    if len(rows) < 2:
        console.print("[warning]Need two stored scans.[/]")
        return 2
    diff = history.compare(rows[1]["id"], rows[0]["id"])
    folder = reports_dir / "comparisons" / f"{rows[1]['id']}_vs_{rows[0]['id']}"
    paths = export_comparison(diff, folder)
    print_comparison(console, diff)
    console.print(f"[info]Exported:[/] {paths['directory']}")
    return 0
