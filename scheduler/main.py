"""
The agent core: every 15 minutes, hands the model a system prompt and the tool
list, then loops -- execute whatever tool it calls, feed the result back, repeat --
until it either reports findings and wraps up, or decides nothing's wrong.

This replaced the old fixed polling design. The model now decides what to check
and in what order, instead of a hardcoded schedule checking everything blindly.
"""
import sys
import time
import json
import logging
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # so `tools` and `config_loader` import cleanly

import requests
from dotenv import load_dotenv

from config_loader import load_config
import tools
import collector
from memory.state_store import StateStore
from memory.vector_memory import VectorMemory
from db.db_writer import DBWriter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("argus-agent")

MAX_TOOL_CALLS_PER_CYCLE = 25  # raised from 8 -- real cross-host investigation needs room

SYSTEM_PROMPT = """You are Argus, a monitoring agent for the NLRPLS library system's IT infrastructure.

Each cycle, you're handed a batch of pre-gathered data: a broad Wazuh scan, a fleet-wide
heartbeat critical check, recent Semaphore failures, FreePBX status, plus heartbeat and Loki
data already pulled for any host that showed up in the Wazuh scan. Read through all of it first.
Your job is to reason over what's there, decide what's actually worth reporting, and use the
tools only for genuine follow-up -- a deeper dig on something specific, or to log/escalate
what you've found.

Available tools let you query Wazuh security alerts, Loki logs, Security Onion (once deployed),
Ansible/Semaphore job history, FreePBX SIP status, and the fax server log.

Guidelines:
- The pre-gathered data already covers the broad scan and any host it flagged -- don't
  re-run those same exact queries. Use tools for what the data DOESN'T already answer: a
  different time window, a different host, a different LogQL filter, or digging into
  something the initial data only hinted at.
- If a query comes back empty or unhelpful, that IS your answer for that angle -- move to a
  genuinely different check, don't retry the same query with cosmetic argument tweaks
  (adding/removing a default parameter does not count as a new query).
- Investigate EVERY distinct host/issue that shows up in the pre-gathered data, not just the
  first one or two -- don't fixate on a single lead while ignoring the others.
- When a lead doesn't pan out (e.g. no matching logs found), don't just move to a different
  topic -- try a different angle on the SAME lead first (a broader time window, a different
  LogQL filter, checking an adjacent host) before abandoning it.
- Don't report routine/expected activity -- only things that are genuinely actionable.
- Call report_finding for each distinct real issue you confirm, with real evidence. This just
  logs it -- it does NOT alert anyone.
- Escalating to a ticket is a SEPARATE decision from logging a finding. Do not escalate just
  because severity is high or critical -- reason about it: is this actively ongoing and worsening,
  or has it persisted across multiple cycles without resolving? Or is this the first time you've
  seen it, and worth watching one more cycle before involving a person? report_finding will tell
  you whether an issue is new or recurring -- use that to inform whether escalate_to_ticket is
  warranted now, later, or not at all.
- Call investigation_complete when you've checked what's relevant and found nothing more to report.
- You have a generous but not unlimited number of tool calls this cycle -- use them to actually
  dig, not to stop early. Thoroughness matters more than speed here.
"""


def run_investigation_cycle(llm_base_url: str, model: str, scratch_db_path: str, state):
    log.info("Running mechanical collection pass (no LLM, no tokens)...")
    digest = collector.run_collection_pass(scratch_db_path, state)
    log.info("Collection pass done, %d chars of pre-gathered data.", len(digest))

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Begin your investigation cycle.\n\n{digest}"},
    ]
    seen_calls = set()  # (fn_name, sorted-args-json) already executed this cycle -- blocks redundant looping

    for step in range(MAX_TOOL_CALLS_PER_CYCLE):
        resp = requests.post(
            f"{llm_base_url}/chat/completions",
            json={
                "model": model,
                "temperature": 0.1,
                "messages": messages,
                "tools": tools.TOOL_SCHEMAS,
                "tool_choice": "auto",
            },
            timeout=240,  # raised from 90 -- growing context on this hardware can legitimately take longer
        )
        resp.raise_for_status()
        message = resp.json()["choices"][0]["message"]
        messages.append(message)

        tool_calls = message.get("tool_calls")
        if not tool_calls:
            log.info("Model responded without a tool call, ending cycle: %s", message.get("content", "")[:200])
            return

        for call in tool_calls:
            fn_name = call["function"]["name"]
            try:
                fn_args = json.loads(call["function"]["arguments"] or "{}")
            except json.JSONDecodeError:
                fn_args = {}

            call_signature = (fn_name, json.dumps(fn_args, sort_keys=True))
            if call_signature in seen_calls:
                log.warning("Blocked redundant repeat call: %s(%s)", fn_name, fn_args)
                result = (
                    "You already ran this exact query this cycle -- the result hasn't changed. "
                    "Don't repeat it. Either try a genuinely different query (different host, "
                    "different filter, different source) or move on to report_finding / "
                    "note_watch_item / investigation_complete."
                )
                messages.append({
                    "role": "tool",
                    "tool_call_id": call["id"],
                    "content": result,
                })
                continue
            seen_calls.add(call_signature)

            log.info("Tool call: %s(%s)", fn_name, fn_args)
            fn = tools.TOOL_FUNCTIONS.get(fn_name)
            if fn is None:
                result = f"Unknown tool: {fn_name}"
            else:
                try:
                    result = fn(**fn_args)
                except Exception as e:
                    log.exception("Tool %s failed", fn_name)
                    result = f"Tool error: {e}"

            messages.append({
                "role": "tool",
                "tool_call_id": call["id"],
                "content": str(result)[:3000],  # cap so context doesn't blow up on a 16GB box
            })

            if fn_name in ("investigation_complete",):
                log.info("Cycle ended: %s", result)
                return
            if fn_name in ("report_finding", "escalate_to_ticket"):
                log.info("%s: %s", fn_name, result)
                # don't return here -- let the model keep investigating in case there's more,
                # up to the MAX_TOOL_CALLS_PER_CYCLE cap

    log.warning("Hit max tool calls (%d) this cycle without an explicit wrap-up.", MAX_TOOL_CALLS_PER_CYCLE)


def main():
    load_dotenv()
    cfg = load_config()

    state = StateStore(cfg["memory"]["state_db"])
    memory = VectorMemory(cfg["memory"]["vector_db"], cfg["llm"]["base_url"], cfg["llm"]["embedding_model"])
    db = DBWriter(cfg["remote_db"])
    db.ensure_table()

    tools.init_tools(cfg, db, memory, state)

    interval_seconds = cfg.get("agent", {}).get("cycle_interval_seconds", 900)  # default 15min
    log.info("Argus agent started. Cycle interval: %ds", interval_seconds)

    scratch_db_path = cfg["memory"].get("scratch_db", "./data/cycle_snapshots.sqlite")

    while True:
        cycle_start = time.time()
        try:
            run_investigation_cycle(cfg["llm"]["base_url"], cfg["llm"]["model"], scratch_db_path, state)
        except Exception:
            log.exception("Investigation cycle failed")

        elapsed = time.time() - cycle_start
        sleep_for = max(0, interval_seconds - elapsed)
        log.info("Cycle took %.1fs, sleeping %.1fs until next one.", elapsed, sleep_for)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
