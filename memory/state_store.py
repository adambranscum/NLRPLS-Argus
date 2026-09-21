import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class StateStore:
    """Tracks event fingerprints so the same standing issue doesn't get re-classified
    and re-written every poll cycle. Answers one question: is this new, ongoing, or resolved?
    Also tracks the last collection timestamp (so the collector pulls only the real gap
    since last run, not a fixed window every time) and a watch-list of soft suspicions
    the model wants to keep an eye on across cycles without it being a confirmed finding."""

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
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS collector_meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS watch_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT,
                source TEXT,
                note TEXT,
                created_at TEXT,
                last_updated TEXT,
                status TEXT DEFAULT 'active'   -- active | resolved
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
                (fp, event.source, event.host, event.severity, event.message, now, now),
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
            "SELECT status FROM event_state WHERE fingerprint = ?", (fingerprint,)
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
            "UPDATE event_state SET status = 'resolved' WHERE fingerprint = ?", (fingerprint,)
        )
        self.conn.commit()

    def stale_open_fingerprints(self, source: str, seen_fingerprints: set[str]) -> list[str]:
        """Call once per source per cycle with the set of fingerprints seen THIS poll.
        Anything still 'open' in the DB for that source but absent from this cycle
        is presumed resolved (e.g. the alert cleared)."""
        rows = self.conn.execute(
            "SELECT fingerprint FROM event_state WHERE source = ? AND status = 'open'", (source,)
        ).fetchall()
        return [r[0] for r in rows if r[0] not in seen_fingerprints]

    # --- Collector timing: pull only the real gap since last run, not a fixed window ---

    def get_last_collection_time(self):
        """Returns the ISO timestamp of the last collection pass, or None if this is the first run."""
        row = self.conn.execute(
            "SELECT value FROM collector_meta WHERE key = 'last_collection_time'"
        ).fetchone()
        return row[0] if row else None

    def set_last_collection_time(self, iso_timestamp: str):
        self.conn.execute(
            "INSERT INTO collector_meta (key, value) VALUES ('last_collection_time', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (iso_timestamp,),
        )
        self.conn.commit()

    # --- Watch-list: soft suspicions the model wants to keep tracking across cycles,
    # short of a confirmed report_finding. ---

    def add_watch_item(self, host: str, source: str, note: str) -> int:
        now = datetime.now(timezone.utc).isoformat()
        cur = self.conn.execute(
            "INSERT INTO watch_items (host, source, note, created_at, last_updated, status) "
            "VALUES (?, ?, ?, ?, ?, 'active')",
            (host, source, note, now, now),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_watch_item(self, item_id: int, note: str):
        self.conn.execute(
            "UPDATE watch_items SET note = ?, last_updated = ? WHERE id = ?",
            (note, datetime.now(timezone.utc).isoformat(), item_id),
        )
        self.conn.commit()

    def resolve_watch_item(self, item_id: int):
        self.conn.execute(
            "UPDATE watch_items SET status = 'resolved', last_updated = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), item_id),
        )
        self.conn.commit()

    def get_active_watch_items(self) -> list[dict]:
        rows = self.conn.execute(
            "SELECT id, host, source, note, created_at, last_updated FROM watch_items "
            "WHERE status = 'active' ORDER BY created_at ASC"
        ).fetchall()
        return [
            {"id": r[0], "host": r[1], "source": r[2], "note": r[3],
             "created_at": r[4], "last_updated": r[5]}
            for r in rows
        ]
