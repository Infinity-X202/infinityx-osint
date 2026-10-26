"""Local SQLite history of finished scans."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from infinityx.analysis import counts
from infinityx.diffscan import compare_snapshots
from infinityx.models import ScanOutcome
from infinityx.safety import clean_text


class HistoryStore:
    """Store scan metadata, findings, and the comparison snapshot on disk."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._ensure()

    def save(self, outcome: ScanOutcome, snapshot: dict[str, Any], analysis: list[dict[str, str]]) -> int:
        """Insert one scan and its finding rows. Returns the new id."""
        status = counts(outcome.results)
        with self._session() as connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    domain, started_at, finished_at, output_dir, interrupted,
                    status_ok, status_warning, status_failed, status_skipped,
                    snapshot_json, analysis_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    outcome.domain,
                    outcome.started_at.isoformat(),
                    outcome.finished_at.isoformat(),
                    outcome.output_dir or "",
                    1 if outcome.interrupted else 0,
                    status["OK"],
                    status["WARNING"],
                    status["FAILED"],
                    status["SKIPPED"],
                    json.dumps(snapshot, ensure_ascii=False),
                    json.dumps(analysis, ensure_ascii=False),
                ),
            )
            scan_id = int(cursor.lastrowid)
            connection.executemany(
                """
                INSERT INTO findings (
                    scan_id, check_id, number, name, status, severity, summary, confidence, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        scan_id,
                        item.check_id,
                        item.number,
                        item.name,
                        item.status,
                        item.severity,
                        clean_text(item.summary, 500),
                        item.confidence,
                        clean_text(item.evidence, 1000),
                    )
                    for item in outcome.results
                ],
            )
            return scan_id

    def latest(self, domain: str) -> dict[str, Any] | None:
        """Return the newest stored scan for a domain."""
        with self._session() as connection:
            row = connection.execute(
                "SELECT * FROM scans WHERE domain = ? ORDER BY id DESC LIMIT 1",
                (domain,),
            ).fetchone()
        return _scan_row(row) if row else None

    def get(self, scan_id: int) -> dict[str, Any] | None:
        """Return one scan, or None when the id does not exist."""
        with self._session() as connection:
            row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _scan_row(row) if row else None

    def findings(self, scan_id: int) -> list[dict[str, Any]]:
        """Return the finding rows stored for one scan."""
        with self._session() as connection:
            rows = connection.execute(
                "SELECT check_id, number, name, status, severity, summary, confidence, evidence FROM findings WHERE scan_id = ? ORDER BY number",
                (scan_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_scans(self, domain: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
        """List recent scans, newest first."""
        query = "SELECT * FROM scans"
        values: tuple[Any, ...] = ()
        if domain:
            query += " WHERE domain = ?"
            values = (domain,)
        query += " ORDER BY id DESC LIMIT ?"
        values = (*values, limit)
        with self._session() as connection:
            rows = connection.execute(query, values).fetchall()
        return [_scan_row(row) for row in rows]

    def compare(self, older_id: int, newer_id: int) -> dict[str, Any]:
        """Compare two saved scans of the same domain without running checks."""
        older = self.get(older_id)
        newer = self.get(newer_id)
        if older is None or newer is None:
            raise ValueError("One of those scan numbers is not in the local history.")
        if older["domain"] != newer["domain"]:
            raise ValueError("Those scans are for different domains. Compare two scans of the same domain.")
        first, second = (older, newer) if older["finished_at"] <= newer["finished_at"] else (newer, older)
        return compare_snapshots(
            first["snapshot"],
            second["snapshot"],
            older_label=f"scan {first['id']} at {first['finished_at']}",
            newer_label=f"scan {second['id']} at {second['finished_at']}",
            domain=first["domain"],
        )

    def _ensure(self) -> None:
        with self._session() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    domain TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    output_dir TEXT,
                    interrupted INTEGER NOT NULL,
                    status_ok INTEGER NOT NULL,
                    status_warning INTEGER NOT NULL,
                    status_failed INTEGER NOT NULL,
                    status_skipped INTEGER NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    analysis_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY,
                    scan_id INTEGER NOT NULL REFERENCES scans(id),
                    check_id TEXT,
                    number INTEGER,
                    name TEXT,
                    status TEXT,
                    severity TEXT,
                    summary TEXT,
                    confidence TEXT,
                    evidence TEXT
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain, id)")

    @contextmanager
    def _session(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        finally:
            connection.close()


def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
    payload = dict(row)
    payload["interrupted"] = bool(payload["interrupted"])
    payload["snapshot"] = json.loads(payload.pop("snapshot_json"))
    payload["analysis"] = json.loads(payload.pop("analysis_json"))
    return payload
