"""Run the check list, survive Ctrl+C, and write the automatic reports."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from infinityx.analysis import apply_honesty_rules, build_narratives
from infinityx.analyzer import analysis_text, analyze_findings
from infinityx.checks import ALL_CHECKS, CheckSpec
from infinityx.context import ScanContext
from infinityx.diffscan import compare_snapshots, comparison_text
from infinityx.history import HistoryStore
from infinityx.models import CheckResult, ScanOutcome, build_result
from infinityx.reporting import write_reports
from infinityx.safety import clean_text
from infinityx.snapshot import extract_snapshot

logger = logging.getLogger("infinityx")


class RedactFilter(logging.Filter):
    """Remove secret-like assignments before a log line is written."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = clean_text(str(record.msg), limit=1000)
        if isinstance(record.args, tuple):
            record.args = tuple(clean_text(arg, limit=300) if isinstance(arg, str) else arg for arg in record.args)
        return True


def configure_logging(log_path: Path) -> logging.Logger:
    """Write a redacted execution log inside the scan folder."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    scan_logger = logging.getLogger("infinityx")
    scan_logger.handlers.clear()
    scan_logger.setLevel(logging.INFO)
    scan_logger.propagate = False
    handler = logging.FileHandler(log_path, encoding="utf-8")
    handler.addFilter(RedactFilter())
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    scan_logger.addHandler(handler)
    return scan_logger


def execute_check(spec: CheckSpec, ctx: ScanContext) -> CheckResult:
    """Run one check and always return a result."""
    started = datetime.now(timezone.utc)
    try:
        item = spec.func(ctx)
    except Exception as exc:
        logger.exception("Check %s crashed", spec.check_id)
        item = build_result(
            status="FAILED",
            severity="UNASSESSED",
            summary=f"{spec.name} crashed and was contained.",
            findings=[clean_text(str(exc), 400)],
            data={},
            method="The check function was called and raised an unexpected error.",
            explanation="The failure was caught so the rest of the scan could continue. No result was invented for this check.",
            usefulness="A contained crash still appears in the report instead of aborting the process.",
            limitations="The traceback is in the scan log with secret-like text redacted.",
            evidence=clean_text(str(exc), 400),
            impact="This check was not assessed.",
            confidence="high",
            remediation="Rerun the scan. If it repeats, review logs/scan.log for this check name.",
            observation_type="unavailable",
            error=clean_text(str(exc), 400),
        )
    item.check_id = spec.check_id
    item.number = spec.number
    item.name = spec.name
    item.category = spec.category
    item.duration_ms = (datetime.now(timezone.utc) - started).total_seconds() * 1000
    apply_honesty_rules(item)
    logger.info("check %s status %s duration_ms %.0f", spec.check_id, item.status, item.duration_ms)
    return item


def skipped_check(spec: CheckSpec, reason: str) -> CheckResult:
    """Record a check that was not executed."""
    item = build_result(
        status="SKIPPED",
        severity="UNASSESSED",
        summary=reason,
        findings=[reason],
        data={"executed": False},
        method="Not executed.",
        explanation=reason,
        usefulness="The report stays complete by listing checks that did not run.",
        limitations="A skipped check contributes no evidence.",
        evidence="Not executed.",
        impact="This area was not assessed.",
        confidence="high",
        remediation="Rerun the scan to completion if this area matters.",
        observation_type="unavailable",
        error=reason,
    )
    item.check_id = spec.check_id
    item.number = spec.number
    item.name = spec.name
    item.category = spec.category
    return item


def run_scan(
    domain: str,
    raw_input: str,
    output_dir: Path,
    enable_traceroute: bool = False,
    on_start=None,
    on_progress=None,
    on_result=None,
    history: HistoryStore | None = None,
) -> tuple[ScanOutcome, dict[str, str]]:
    """Execute every check and write reports, including after Ctrl+C."""
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "logs").mkdir(exist_ok=True)
    configure_logging(output_dir / "logs" / "scan.log")
    started = datetime.now(timezone.utc)
    logger.info("scan started domain=%s", domain)
    ctx = ScanContext(domain, raw_input, enable_traceroute)
    results: list[CheckResult] = []
    interrupted = False
    if on_start:
        on_start(len(ALL_CHECKS))
    for index, spec in enumerate(ALL_CHECKS):
        if on_progress:
            on_progress(spec, index)
        try:
            results.append(execute_check(spec, ctx))
        except KeyboardInterrupt:
            interrupted = True
            logger.info("scan interrupted by operator")
            results.append(skipped_check(spec, "The operator interrupted the scan before this check finished."))
            if on_result:
                on_result(results[-1])
            for pending in ALL_CHECKS[index + 1 :]:
                results.append(skipped_check(pending, "The operator interrupted the scan before this check started."))
                if on_result:
                    on_result(results[-1])
            break
        else:
            if on_result:
                on_result(results[-1])
    finished = datetime.now(timezone.utc)
    narratives = build_narratives(domain, started.isoformat(), results, interrupted)
    snapshot = extract_snapshot(results, interrupted)
    analysis = analyze_findings(results, interrupted)
    comparison = _previous_comparison(history, domain, snapshot)
    narratives["historical_comparison"] = comparison_text(comparison)
    narratives["security_analysis"] = analysis_text(analysis)
    outcome = ScanOutcome(
        domain=domain,
        started_at=started,
        finished_at=finished,
        results=results,
        narratives=narratives,
        interrupted=interrupted,
        authorization_confirmed=True,
        comparison=comparison,
        analysis=analysis,
    )
    outcome.output_dir = str(output_dir)
    if history is not None:
        outcome.history_id = history.save(outcome, snapshot, analysis)
        logger.info("history id=%s", outcome.history_id)
    paths = write_reports(outcome, output_dir, ctx.artifacts)
    logger.info("scan finished reports=%s", paths.get("directory"))
    return outcome, paths


def _previous_comparison(history: HistoryStore | None, domain: str, snapshot: dict) -> dict | None:
    """Compare this scan with the newest stored snapshot of the same domain."""
    if history is None:
        return None
    previous = history.latest(domain)
    if previous is None:
        return None
    return compare_snapshots(
        previous["snapshot"],
        snapshot,
        older_label=f"scan {previous['id']} at {previous['finished_at']}",
        newer_label="this scan",
        domain=domain,
    )
