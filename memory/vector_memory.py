import sqlite3
import json
import struct
from pathlib import Path
import requests

# Same sqlite-vec approach as your /opt/rag CLI. Requires the sqlite-vec extension
# available (pip install sqlite-vec) and loadable via conn.enable_load_extension.


class VectorMemory:
    """Stores embedded summaries of past incidents + how they were resolved (if known),
    so the classifier can ask 'has this happened before' instead of reasoning cold."""

    def __init__(self, db_path: str, llm_base_url: str, embedding_model: str):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.llm_base_url = llm_base_url.rstrip("/")
        self.embedding_model = embedding_model

        self.conn = sqlite3.connect(db_path)
        self.conn.enable_load_extension(True)
        import sqlite_vec
        sqlite_vec.load(self.conn)
        self.conn.enable_load_extension(False)

        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT,
                source TEXT,
                summary TEXT,
                resolution TEXT DEFAULT '',
                created_at TEXT
            )
        """)
        self.conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS incidents_vec USING vec0(
                embedding float[1024]
            )
        """)  # dimension must match your embedding model's output — verify in LM Studio
        self.conn.commit()

    def _embed(self, text: str) -> list[float]:
        resp = requests.post(
            f"{self.llm_base_url}/embeddings",
            json={"model": self.embedding_model, "input": text},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["data"][0]["embedding"]

    def add_incident(self, fingerprint: str, source: str, summary: str, resolution: str = ""):
        from datetime import datetime, timezone
        embedding = self._embed(summary)
        cur = self.conn.execute(
            "INSERT INTO incidents (fingerprint, source, summary, resolution, created_at) VALUES (?, ?, ?, ?, ?)",
            (fingerprint, source, summary, resolution, datetime.now(timezone.utc).isoformat()),
        )
        incident_id = cur.lastrowid
        self.conn.execute(
            "INSERT INTO incidents_vec (rowid, embedding) VALUES (?, ?)",
            (incident_id, struct.pack(f"{len(embedding)}f", *embedding)),
        )
        self.conn.commit()

    def find_similar(self, summary: str, k: int = 3) -> list[dict]:
        embedding = self._embed(summary)
        packed = struct.pack(f"{len(embedding)}f", *embedding)
        rows = self.conn.execute(
            """
            SELECT i.summary, i.resolution, i.created_at, v.distance
            FROM incidents_vec v
            JOIN incidents i ON i.id = v.rowid
            WHERE v.embedding MATCH ?
            ORDER BY v.distance
            LIMIT ?
            """,
            (packed, k),
        ).fetchall()
        return [
            {"summary": r[0], "resolution": r[1], "created_at": r[2], "distance": r[3]}
            for r in rows
        ]
