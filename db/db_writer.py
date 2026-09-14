import os
import pymysql


class DBWriter:
    """Writes findings to a remote MySQL table, same ON DUPLICATE KEY UPDATE
    pattern as your existing ithelpdesk heartbeat table."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.table = cfg["table"]

    def _connect(self):
        return pymysql.connect(
            host=self.cfg["host"],
            port=self.cfg.get("port", 3306),
            user=self.cfg["user"],
            password=os.environ["REMOTE_DB_PASSWORD"],
            database=self.cfg["database"],
            autocommit=True,
        )

    def ensure_table(self):
        ddl = f"""
        CREATE TABLE IF NOT EXISTS {self.table} (
            fingerprint VARCHAR(24) PRIMARY KEY,
            source VARCHAR(32),
            host VARCHAR(128),
            severity VARCHAR(16),
            summary TEXT,
            status VARCHAR(16) DEFAULT 'open',
            first_seen DATETIME,
            last_seen DATETIME
        )
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(ddl)

    def upsert_finding(self, fingerprint: str, source: str, host: str, severity: str,
                        summary: str, status: str = "open"):
        sql = f"""
        INSERT INTO {self.table} (fingerprint, source, host, severity, summary, status, first_seen, last_seen)
        VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            severity = VALUES(severity),
            summary = VALUES(summary),
            status = VALUES(status),
            last_seen = NOW()
        """
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (fingerprint, source, host, severity, summary, status))

    def mark_resolved(self, fingerprint: str):
        sql = f"UPDATE {self.table} SET status = 'resolved', last_seen = NOW() WHERE fingerprint = %s"
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, (fingerprint,))
