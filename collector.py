"""
Runs a fixed set of broad + targeted queries directly (no LLM involved, no tokens
spent), stores every result to a local SQLite table, then hands back one combined
digest of everything gathered. The agent loop then gets to reason over a mostly-
complete picture from the start instead of rebuilding it one tool call at a time --
far fewer completions needed per cycle, even though this collection pass itself
takes real wall-clock time.
"""
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import tools


def _ensure_table(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cycle_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cycle_id TEXT,
            source TEXT,
            target TEXT,
            result TEXT,
            collected_at TEXT
        )
    """)
    # Structured numeric time series -- unlike cycle_snapshots (raw text, fine for the
    # model to read but useless for math), this is what actual trend/prediction work
    # runs on. Same schema regardless of source, so Security Onion's event counts slot
    # in later (source="security_onion") without any redesign -- just new rows.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS metric_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cycle_id TEXT,
            host TEXT,
            source TEXT,
            metric_name TEXT,
            value REAL,
            collected_at TEXT
        )
    """)
    conn.commit()


def _extract_hosts(wazuh_text: str) -> list[str]:
    """Wazuh alert lines look like '- [10] HOSTNAME: description (...)' -- pull
    out the distinct hostnames so we know what to dig into further."""
    hosts = re.findall(r"- \[\d+\] ([^:]+):", wazuh_text)
    seen = []
    for h in hosts:
        h = h.strip()
        if h and h not in seen:
            seen.append(h)
    return seen


def _extract_heartbeat_metrics(text: str) -> dict:
    """Pulls CPU%/RAM% out of query_heartbeat_status's 'Current (...): CPU=X% RAM=Y%' line."""
    m = re.search(r"CPU=([\d.]+)%\s+RAM=([\d.]+)%", text)
    if not m:
        return {}
    return {"cpu_percent": float(m.group(1)), "ram_percent": float(m.group(2))}


def _count_wazuh_alerts(text: str) -> int:
    return len(re.findall(r"^- \[\d+\]", text, flags=re.MULTILINE))


def _count_list_lines(text: str) -> int:
    """Generic counter for any '- ...' list-style tool output (heartbeat critical scan,
    etc.) that doesn't have Wazuh's '[level]' bracket prefix."""
    if text.strip().lower().startswith("no ") or not text.strip():
        return 0
    return len(re.findall(r"^- ", text, flags=re.MULTILINE))


def _count_semaphore_errors(text: str) -> int:
    return len(re.findall(r"^- Task #", text, flags=re.MULTILINE))


def _count_freepbx_unavailable(text: str) -> int:
    return len(re.findall(r"Unavailable", text))


def run_collection_pass(db_path: str, state, max_hosts_to_dig: int = 6, max_window_minutes: int = 1440) -> str:
    """Runs the broad + targeted queries directly, stores each to SQLite under this
    cycle's id, and returns one formatted digest string ready to hand to the model.

    `state` is the shared StateStore -- used to figure out how far back to look (the
    real gap since the last collection pass, not a fixed window every time) and to
    pull in any active watch items so they carry forward into this cycle's digest."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    _ensure_table(conn)

    now = datetime.now(timezone.utc)
    last_run_iso = state.get_last_collection_time()
    if last_run_iso:
        last_run = datetime.fromisoformat(last_run_iso)
        window_minutes = int((now - last_run).total_seconds() / 60) + 1  # +1 to avoid a zero/negative window
        window_minutes = min(window_minutes, max_window_minutes)  # cap after a long gap (e.g. Mac was asleep)
    else:
        window_minutes = 60  # first run ever -- no prior timestamp to measure from

    cycle_id = now.isoformat()
    entries = []  # list of (source, target, result) for building the digest

    def collect(source: str, target: str, result: str):
        conn.execute(
            "INSERT INTO cycle_snapshots (cycle_id, source, target, result, collected_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (cycle_id, source, target, result, datetime.now(timezone.utc).isoformat()),
        )
        entries.append((source, target, result))

    def record_metric(host: str, source: str, metric_name: str, value: float):
        conn.execute(
            "INSERT INTO metric_snapshots (cycle_id, host, source, metric_name, value, collected_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (cycle_id, host, source, metric_name, value, datetime.now(timezone.utc).isoformat()),
        )

    # --- Broad scans, no host needed. Window = actual time since last collection pass. ---
    wazuh_high = _safe(lambda: tools.query_wazuh_alerts(min_severity="high", minutes=window_minutes))
    collect("wazuh", "high-severity-scan", wazuh_high)
    record_metric("fleet", "wazuh", "high_severity_alert_count", _count_wazuh_alerts(wazuh_high))

    heartbeat_critical = _safe(lambda: tools.query_heartbeat_status())
    collect("heartbeat", "fleet-critical-scan", heartbeat_critical)
    record_metric("fleet", "heartbeat", "critical_host_count", _count_list_lines(heartbeat_critical))

    semaphore_errors = _safe(lambda: tools.query_semaphore_tasks(status_filter="error", limit=20))
    collect("semaphore", "recent-errors", semaphore_errors)
    record_metric("fleet", "semaphore", "error_task_count", _count_semaphore_errors(semaphore_errors))

    freepbx_status = _safe(lambda: tools.query_freepbx_status())
    collect("freepbx", "all-endpoints", freepbx_status)
    record_metric("fleet", "freepbx", "unavailable_endpoint_count", _count_freepbx_unavailable(freepbx_status))

    # --- Targeted follow-up: for every host flagged in the Wazuh scan, pull its
    # heartbeat trend and recent Loki activity too, so the model doesn't have to
    # ask for these one at a time. ---
    hosts = _extract_hosts(wazuh_high)[:max_hosts_to_dig]
    for host in hosts:
        hb = _safe(lambda h=host: tools.query_heartbeat_status(host=h))
        collect("heartbeat", host, hb)
        metrics = _extract_heartbeat_metrics(hb)
        for metric_name, value in metrics.items():
            record_metric(host, "heartbeat", metric_name, value)

        loki = _safe(lambda h=host: tools.query_loki(f'{{host="{h}"}}', minutes=window_minutes))
        collect("loki", host, loki)

    conn.commit()
    conn.close()

    state.set_last_collection_time(cycle_id)  # mark now as the watermark for next cycle's window

    watch_items = state.get_active_watch_items()
    return _build_digest(cycle_id, entries, window_minutes, watch_items)


def _safe(fn):
    try:
        return fn()
    except Exception as e:
        return f"(query failed: {e})"


def _build_digest(cycle_id: str, entries: list[tuple[str, str, str]], window_minutes: int,
                   watch_items: list[dict]) -> str:
    lines = [f"=== Pre-gathered data for this cycle ({cycle_id}) ==="]
    lines.append(f"Window covered: last {window_minutes} minutes (the actual gap since the last cycle ran).")

    if watch_items:
        lines.append("\n=== Active watch items from previous cycles ===")
        for item in watch_items:
            lines.append(
                f"- #{item['id']} [{item['host']}/{item['source']}] {item['note']} "
                f"(first noted {item['created_at']}, last updated {item['last_updated']})"
            )
        lines.append(
            "Check whether fresh data below confirms, contradicts, or is unrelated to these. "
            "Resolve them via resolve_watch_item if they're no longer relevant, or escalate to "
            "report_finding if now confirmed."
        )

    for source, target, result in entries:
        lines.append(f"\n--- {source} / {target} ---")
        lines.append(result[:2000])  # cap any single result so the digest stays bounded
    lines.append(
        "\nThis data was collected directly, not by you -- you don't need to re-run "
        "these same queries. Use the tools only for follow-up digs on something "
        "specific this data raises, or to call report_finding / escalate_to_ticket / "
        "note_watch_item / investigation_complete once you've reasoned through what's here."
    )
    return "\n".join(lines)
