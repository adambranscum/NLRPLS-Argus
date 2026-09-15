import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class StateStore:
    """Tracks event fingerprints so the same standing issue doesn't get re-classified
    and re-written every poll cycle. Answers one question: is this new, ongoing, or resolved?"""

    def __init__(self, db_path: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS event_state (
                fingerprint TEXT PRIMARY KEY,
                source TEXT,
                host TEXT,
                severity TEXT,
                message TEXT,
                first_seen TEXT,
                last_seen TEXT,
                status TEXT DEFAULT 'open'   -- open | resolved
            )
        """)
        self.conn.commit()

    def check_and_update(self, event) -> str:
        """Returns 'new', 'ongoing', or 'reopened'. Always updates last_seen."""
        now = datetime.now(timezone.utc).isoformat()
        fp = event.fingerprint()
        row = self.conn.execute(
            "SELECT status FROM event_state WHERE fingerprint = ?", (fp,)
        ).fetchone()

        if row is None:
            self.conn.execute(
                """INSERT INTO event_state
                   (fingerprint, source, host, severity, message, first_seen, last_seen, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'open')""",
                (fp, event.source, event.host,
                 event.severity, event.message, now, now),
            )
            self.conn.commit()
            return "new"

        status = row[0]
        self.conn.execute(
            "UPDATE event_state SET last_seen = ?, severity = ?, status = 'open' WHERE fingerprint = ?",
            (now, event.severity, fp),
        )
        self.conn.commit()
        return "reopened" if status == "resolved" else "ongoing"

    def check_and_update_raw(self, fingerprint: str, source: str, host: str,
                             severity: str, message: str) -> str:
        """Same as check_and_update, but for callers that don't have a NormalizedEvent
        object handy — e.g. the agent's report_finding tool, which builds its own
        fingerprint directly from the model's arguments."""
        now = datetime.now(timezone.utc).isoformat()
        row = self.conn.execute(
            "SELECT status FROM event_state WHERE fingerprint = ?", (
                fingerprint,)
        ).fetchone()

        if row is None:
            self.conn.execute(
                """INSERT INTO event_state
                   (fingerprint, source, host, severity, message, first_seen, last_seen, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'open')""",
                (fingerprint, source, host, severity, message, now, now),
            )
            self.conn.commit()
            return "new"

        status = row[0]
        self.conn.execute(
            "UPDATE event_state SET last_seen = ?, severity = ?, status = 'open' WHERE fingerprint = ?",
            (now, severity, fingerprint),
        )
        self.conn.commit()
        return "reopened" if status == "resolved" else "ongoing"

    def get_history(self, fingerprint: str) -> dict | None:
        """Returns first_seen/last_seen/status for a fingerprint, or None if never seen.
        Used by report_finding to tell the model how long an issue has persisted —
        that's the actual signal for deciding 'monitor' vs 'escalate now', not severity alone."""
        row = self.conn.execute(
            "SELECT first_seen, last_seen, status FROM event_state WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            return None
        return {"first_seen": row[0], "last_seen": row[1], "status": row[2]}

    def mark_resolved(self, fingerprint: str):
        self.conn.execute(
            "UPDATE event_state SET status = 'resolved' WHERE fingerprint = ?", (
                fingerprint,)
        )
        self.conn.commit()

    def stale_open_fingerprints(self, source: str, seen_fingerprints: set[str]) -> list[str]:
        """Call once per source per cycle with the set of fingerprints seen THIS poll.
        Anything still 'open' in the DB for that source but absent from this cycle
        is presumed resolved (e.g. the alert cleared)."""
        rows = self.conn.execute(
            "SELECT fingerprint FROM event_state WHERE source = ? AND status = 'open'", (
                source,)
        ).fetchall()
        return [r[0] for r in rows if r[0] not in seen_fingerprints]
