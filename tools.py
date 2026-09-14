"""
The model's "senses" and its one "action." Each QUERY_* function is read-only —
the model can look at any of these sources with specific arguments it chooses.
report_finding is the only tool that writes anything — it's how the model ends
an investigation with a concrete result.

Call init_tools(cfg, db_writer, vector_memory) once at agent startup before the
loop runs; the query functions close over those shared resources.
"""
import os
import socket
import requests
from datetime import datetime, timezone, timedelta

requests.packages.urllib3.disable_warnings()

_cfg = None
_db = None
_memory = None
_state = None


def init_tools(cfg: dict, db_writer, vector_memory, state_store):
    global _cfg, _db, _memory, _state
    _cfg = cfg
    _db = db_writer
    _memory = vector_memory
    _state = state_store


# ---------------------------------------------------------------------------
# Tool schemas — what the model sees when deciding what to call
# ---------------------------------------------------------------------------

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "query_wazuh_alerts",
            "description": "Search Wazuh security alerts. Use to check a specific host for recent "
            "security events, or to scan for anything above a severity level fleet-wide.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Agent/host name to filter to, or omit for all hosts"},
                    "min_severity": {"type": "string", "enum": ["low", "medium", "high", "critical"],
                                     "description": "Minimum severity to return, default medium"},
                    "minutes": {"type": "integer", "description": "How far back to look, default 60"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_loki",
            "description": "Run a LogQL query against Loki for raw log lines from any source already "
            "flowing there (wazuh, heartbeat, os-updates, software, fax). Use this to pull "
            "context around something you found elsewhere, e.g. all recent lines for a "
            "specific host across every log source, or fax server activity via "
            "'{source=\"fax\"}'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "logql_query": {"type": "string", "description": "e.g. '{source=\"heartbeat\"} |= \"THUB16\"'"},
                    "minutes": {"type": "integer", "description": "How far back to look, default 60"},
                },
                "required": ["logql_query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_security_onion",
            "description": "Search Security Onion network/traffic alerts. NOT YET DEPLOYED — will "
            "return an empty result with a note until the sensor is live.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Source IP/host to filter to, or omit for all"},
                    "min_severity": {"type": "integer", "description": "Minimum SO/Suricata severity, default 3"},
                    "minutes": {"type": "integer", "description": "How far back to look, default 60"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_semaphore_tasks",
            "description": "Check recent Ansible/Semaphore playbook run history. Use to see if a "
            "scheduled job failed, or check a specific playbook's recent runs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "status_filter": {"type": "string", "enum": ["any", "error", "success"],
                                      "description": "default 'any'"},
                    "limit": {"type": "integer", "description": "Max tasks to return, default 20"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_freepbx_status",
            "description": "Get live SIP/PJSIP peer registration status from FreePBX. Use when "
            "investigating call quality issues or checking whether a specific trunk/peer "
            "is currently registered.",
            "parameters": {
                "type": "object",
                "properties": {
                    "peer": {"type": "string", "description": "Specific peer/extension to check, or omit for all"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_fax_log",
            "description": "Search recent lines from the fax server's Asterisk log. Only works if the "
            "agent has access to that log path — will note if it doesn't.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Text/regex to filter for, or omit for all recent lines"},
                    "lines": {"type": "integer", "description": "How many recent lines to scan, default 200"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "query_heartbeat_status",
            "description": "Check machine resource status (CPU/RAM/disk) from Ansible's heartbeat data. "
            "Omit host to see only machines CURRENTLY flagged critical (breach threshold). "
            "Give a specific host to see its current status plus its recent history, so "
            "you can tell whether it's a one-off spike or a real climbing trend.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string", "description": "Device name or partial name to check (e.g. 'THUB16' matches 'NLR-LAM-THUB16.laman.local'), or omit for fleet-wide critical scan"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": "Log a confirmed issue to the findings record. This does NOT create a "
            "ticket or alert anyone — it's a quiet record. Call this for anything you've "
            "confirmed is real, regardless of severity. You'll be told whether this is the "
            "first time this issue has been seen or whether it's been open across prior "
            "cycles — use that, plus the severity and your own judgment, to separately "
            "decide whether escalate_to_ticket is also warranted right now.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
                    "host": {"type": "string"},
                    "source": {"type": "string", "description": "Which system this finding is about, e.g. 'wazuh', 'freepbx'"},
                    "summary": {"type": "string", "description": "One or two sentence description of the issue"},
                    "evidence": {"type": "string", "description": "Key facts/log lines that support this finding"},
                },
                "required": ["severity", "host", "source", "summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "escalate_to_ticket",
            "description": "Creates a real ticket a human will see and act on. This is a DELIBERATE "
            "decision, separate from report_finding — do not call this reflexively just "
            "because something is severity=high or critical. Reasonable reasons to escalate: "
            "the issue is actively ongoing and getting worse, it directly threatens security "
            "or availability right now, or it's been open across multiple cycles without "
            "resolving on its own. Reasonable reasons to hold off: this is the first time "
            "you're seeing it and it could be transient, you're not fully certain it's real, "
            "or it's something worth watching for another cycle before involving a person. "
            "You must give a real justification for why escalation is needed now, not later.",
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {"type": "string"},
                    "source": {"type": "string"},
                    "summary": {"type": "string", "description": "One or two sentence description for the ticket subject/body"},
                    "justification": {"type": "string", "description": "Why this needs a ticket NOW rather than continued monitoring"},
                },
                "required": ["host", "source", "summary", "justification"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "investigation_complete",
            "description": "Call this when you've checked what's relevant and found NOTHING worth "
            "reporting. Ends the cycle cleanly without writing anything.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


# ---------------------------------------------------------------------------
# Real implementations
# ---------------------------------------------------------------------------

_SEVERITY_TO_LEVEL = {"low": 0, "medium": 7, "high": 10, "critical": 13}


def query_wazuh_alerts(host: str = None, min_severity: str = "medium", minutes: int = 60) -> str:
    wazuh_cfg = _cfg["sources"]["wazuh"]
    user = os.environ["WAZUH_USER"]
    password = os.environ["WAZUH_PASSWORD"]
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    must = [
        {"range": {"rule.level": {
            "gte": _SEVERITY_TO_LEVEL.get(min_severity, 7)}}},
        {"range": {"timestamp": {"gte": since.isoformat()}}},
    ]
    if host:
        must.append({"match": {"agent.name": host}})

    resp = requests.post(
        f"{wazuh_cfg['base_url'].rstrip('/')}/wazuh-alerts-4.x-*/_search",
        json={"query": {"bool": {"must": must}},
              "sort": [{"timestamp": "desc"}], "size": 30},
        auth=(user, password), verify=wazuh_cfg.get("verify_ssl", False), timeout=20,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    if not hits:
        return "No matching Wazuh alerts found."
    lines = [
        f"- [{h['_source'].get('rule', {}).get('level')}] {h['_source'].get('agent', {}).get('name')}: "
        f"{h['_source'].get('rule', {}).get('description')} ({h['_source'].get('timestamp')})"
        for h in hits
    ]
    return "\n".join(lines)


def query_loki(logql_query: str, minutes: int = 60) -> str:
    loki_cfg = _cfg["sources"]["loki"]
    now_ns = datetime.now(timezone.utc).timestamp() * 1_000_000_000
    start_ns = now_ns - minutes * 60 * 1_000_000_000

    resp = requests.get(
        f"{loki_cfg['base_url'].rstrip('/')}/loki/api/v1/query_range",
        params={"query": logql_query, "start": int(
            start_ns), "end": int(now_ns), "limit": 50},
        timeout=15,
    )
    resp.raise_for_status()
    results = resp.json().get("data", {}).get("result", [])
    if not results:
        return "No matching log lines found."
    lines = []
    for stream in results:
        for ts, line in stream.get("values", []):
            lines.append(line[:300])
    return "\n".join(lines[:50])


def query_security_onion(host: str = None, min_severity: int = 3, minutes: int = 60) -> str:
    so_cfg = _cfg["sources"]["security_onion"]
    if not so_cfg.get("enabled") or "TODO" in so_cfg.get("base_url", ""):
        return "Security Onion is not deployed yet — see docs/security-onion-setup.md."

    user = os.environ.get("SECURITY_ONION_USER")
    password = os.environ.get("SECURITY_ONION_PASSWORD")
    since = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    must = [
        {"range": {"event.severity": {"gte": min_severity}}},
        {"range": {"@timestamp": {"gte": since.isoformat()}}},
    ]
    if host:
        must.append({"match": {"source.ip": host}})

    resp = requests.post(
        f"{so_cfg['base_url'].rstrip('/')}/so-*/_search",
        json={"query": {"bool": {"must": must}}, "sort": [
            {"@timestamp": "desc"}], "size": 30},
        auth=(user, password) if user else None,
        verify=so_cfg.get("verify_ssl", False), timeout=20,
    )
    resp.raise_for_status()
    hits = resp.json().get("hits", {}).get("hits", [])
    if not hits:
        return "No matching Security Onion alerts found."
    lines = [
        f"- {h['_source'].get('rule', {}).get('name', 'unknown rule')} from "
        f"{h['_source'].get('source', {}).get('ip', 'unknown')} ({h['_source'].get('@timestamp')})"
        for h in hits
    ]
    return "\n".join(lines)


def query_semaphore_tasks(status_filter: str = "any", limit: int = 20) -> str:
    sem_cfg = _cfg["sources"]["semaphore"]
    project_id = sem_cfg.get("project_id", 1)
    token = os.environ["SEMAPHORE_API_TOKEN"]

    resp = requests.get(
        f"{sem_cfg['base_url'].rstrip('/')}/api/project/{project_id}/tasks",
        headers={"Authorization": f"Bearer {token}"},
        timeout=15,
    )
    resp.raise_for_status()
    tasks = resp.json()[:limit]

    if status_filter != "any":
        tasks = [t for t in tasks if t.get("status") == status_filter]
    if not tasks:
        return "No matching Semaphore tasks found."
    lines = [
        f"- Task #{t.get('id')} ({t.get('template_name', '?')}): status={t.get('status')} "
        f"start={t.get('start', '?')}"
        for t in tasks
    ]
    return "\n".join(lines)


def query_freepbx_status(peer: str = None) -> str:
    fb_cfg = _cfg["sources"]["freepbx"]
    user = os.environ["FREEPBX_AMI_USER"]
    secret = os.environ["FREEPBX_AMI_SECRET"]

    with socket.create_connection((fb_cfg["host"], fb_cfg.get("ami_port", 5038)), timeout=10) as sock:
        sock.settimeout(5)
        sock.recv(4096)  # banner
        login = f"Action: Login\r\nUsername: {user}\r\nSecret: {secret}\r\n\r\n"
        sock.sendall(login.encode())
        sock.recv(4096)  # login response

        cmd = "Action: Command\r\nCommand: pjsip show endpoints\r\n\r\n"
        sock.sendall(cmd.encode())
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass

    output = buf.decode("utf-8", errors="ignore")
    if peer:
        matching = [line for line in output.splitlines() if peer in line]
        return "\n".join(matching) if matching else f"No endpoint data found matching '{peer}'."
    return output[:2000]  # cap length


def query_fax_log(pattern: str = None, lines: int = 200) -> str:
    fax_cfg = _cfg["sources"]["faxserver"]
    log_path = fax_cfg["log_path"]
    try:
        with open(log_path, "r", errors="ignore") as f:
            all_lines = f.readlines()[-lines:]
    except FileNotFoundError:
        return "Fax log not accessible from this machine — agent likely isn't running on the fax server."

    if pattern:
        import re
        rx = re.compile(pattern)
        matched = [l.strip() for l in all_lines if rx.search(l)]
        return "\n".join(matched) if matched else f"No lines matched pattern '{pattern}'."
    return "\n".join(l.strip() for l in all_lines[-50:])


def query_heartbeat_status(host: str = None) -> str:
    import pymysql
    conn = pymysql.connect(
        host=_cfg["remote_db"]["host"],
        port=_cfg["remote_db"].get("port", 3306),
        user=_cfg["remote_db"]["user"],
        password=os.environ["REMOTE_DB_PASSWORD"],
        database=_cfg["remote_db"]["database"],
    )
    try:
        with conn.cursor() as cur:
            if host:
                cur.execute(
                    "SELECT device_name, cpu_percent, ram_percent, disk_status, last_checked, status "
                    "FROM heartbeat WHERE device_name LIKE %s LIMIT 1", (
                        f"%{host}%",)
                )
                current = cur.fetchone()
                if not current:
                    return f"No heartbeat data found for '{host}'."
                # exact stored name, e.g. includes .laman.local suffix
                real_name = current[0]

                cur.execute(
                    "SELECT cpu_percent, ram_percent, recorded_at FROM heartbeat_history "
                    "WHERE device_name = %s ORDER BY recorded_at DESC LIMIT 10", (
                        real_name,)
                )
                history = cur.fetchall()

                lines = [f"Current ({real_name}): CPU={current[1]}% RAM={current[2]}% status={current[5]} "
                         f"as of {current[4]}. Disk: {current[3]}"]
                lines.append("Recent history (most recent first):")
                for cpu, ram, ts in history:
                    lines.append(f"  {ts}: CPU={cpu}% RAM={ram}%")
                return "\n".join(lines)
            else:
                cur.execute(
                    "SELECT device_name, cpu_percent, ram_percent, disk_status, last_checked "
                    "FROM heartbeat WHERE status = 'critical'"
                )
                rows = cur.fetchall()
                if not rows:
                    return "No machines currently in critical status."
                lines = [
                    f"- {name}: CPU={cpu}% RAM={ram}% disk={disk} (as of {ts})"
                    for name, cpu, ram, disk, ts in rows
                ]
                return "\n".join(lines)
    finally:
        conn.close()


def report_finding(severity: str, host: str, source: str, summary: str, evidence: str = "") -> str:
    import hashlib
    fingerprint = hashlib.sha256(
        f"{source}|{host}|{summary[:120]}".encode()).hexdigest()[:24]

    # check BEFORE updating, so we know true prior state
    history = _state.get_history(fingerprint)
    transition = _state.check_and_update_raw(
        fingerprint, source, host, severity, summary)

    if transition == "ongoing":
        return (f"Already tracked (unchanged). First seen: {history['first_seen']}. "
                f"This has been open since then without you needing to log it again. "
                f"Consider whether it now warrants escalate_to_ticket given how long it's persisted.")

    _db.upsert_finding(
        fingerprint=fingerprint, source=source, host=host,
        severity=severity, summary=summary, status="open",
    )
    _memory.add_incident(fingerprint=fingerprint, source=source,
                         summary=f"{summary} | evidence: {evidence}")

    if transition == "new":
        return (f"Finding recorded (first time seen): [{severity}] {host}: {summary}. "
                f"This is brand new — consider whether it's worth escalating now or watching "
                f"for the next cycle before creating a ticket.")
    else:  # reopened
        return (f"Finding recorded (reopened — was previously resolved, now back): "
                f"[{severity}] {host}: {summary}. A recurring issue may warrant escalation "
                f"even at lower severity, since it didn't stay fixed.")


def escalate_to_ticket(host: str, source: str, summary: str, justification: str) -> str:
    subject = f"[{source}] Agent-detected issue on {host}"
    body = f"{summary}\n\nJustification for escalation: {justification}"
    _db.insert_ticket(subject=subject, body=body,
                      device_name=host, problem_type="Monitoring Alert")
    return f"Ticket created for {host}: {subject}"


def investigation_complete() -> str:
    return "No issues found this cycle."


TOOL_FUNCTIONS = {
    "query_wazuh_alerts": query_wazuh_alerts,
    "query_loki": query_loki,
    "query_security_onion": query_security_onion,
    "query_semaphore_tasks": query_semaphore_tasks,
    "query_freepbx_status": query_freepbx_status,
    "query_fax_log": query_fax_log,
    "query_heartbeat_status": query_heartbeat_status,
    "report_finding": report_finding,
    "escalate_to_ticket": escalate_to_ticket,
    "investigation_complete": investigation_complete,
}
