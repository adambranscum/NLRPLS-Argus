import time
import logging
import yaml
from pathlib import Path
from dotenv import load_dotenv

from connectors.wazuh import WazuhConnector
from connectors.loki import LokiConnector
from connectors.semaphore import SemaphoreConnector
from connectors.freepbx import FreePBXConnector
from connectors.faxserver import FaxServerConnector
from connectors.security_onion import SecurityOnionConnector

from memory.state_store import StateStore
from memory.vector_memory import VectorMemory
from llm.classifier import Classifier
from db.db_writer import DBWriter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("monitor-agent")

CONNECTOR_CLASSES = {
    "wazuh": WazuhConnector,
    "loki": LokiConnector,
    "semaphore": SemaphoreConnector,
    "freepbx": FreePBXConnector,
    "faxserver": FaxServerConnector,
    "security_onion": SecurityOnionConnector,
}


def load_config() -> dict:
    config_path = Path(__file__).parent.parent / "config" / "config.yaml"
    with open(config_path) as f:
        return yaml.safe_load(f)


def build_connectors(cfg: dict) -> dict:
    connectors = {}
    for name, source_cfg in cfg["sources"].items():
        if not source_cfg.get("enabled", False):
            log.info("Skipping disabled source: %s", name)
            continue
        connectors[name] = CONNECTOR_CLASSES[name](source_cfg)
    return connectors


def process_events(events, source_name, state, memory, classifier, db, interval_cfg):
    seen_fingerprints = set()

    for event in events:
        fp = event.fingerprint()
        seen_fingerprints.add(fp)
        transition = state.check_and_update(event)

        if transition == "ongoing":
            continue  # already open and classified; last_seen already bumped

        similar = memory.find_similar(event.message, k=3)
        result = classifier.classify(event, similar)

        if not result.get("report_worthy", True):
            log.info("[%s] not report-worthy, skipping: %s", source_name, event.message[:80])
            continue

        db.upsert_finding(
            fingerprint=fp, source=event.source, host=event.host,
            severity=result["severity"], summary=result["summary"], status="open",
        )
        memory.add_incident(fingerprint=fp, source=event.source, summary=result["summary"])
        log.info("[%s] %s: %s (%s)", source_name, transition, result["summary"], result["severity"])

    # anything open in the DB for this source but not seen this cycle -> presumed resolved
    for stale_fp in state.stale_open_fingerprints(source_name, seen_fingerprints):
        state.mark_resolved(stale_fp)
        db.mark_resolved(stale_fp)
        log.info("[%s] resolved: %s", source_name, stale_fp)


def main():
    load_dotenv()
    cfg = load_config()

    state = StateStore(cfg["memory"]["state_db"])
    memory = VectorMemory(
        cfg["memory"]["vector_db"],
        cfg["llm"]["base_url"],
        cfg["llm"]["embedding_model"],
    )
    classifier = Classifier(cfg["llm"]["base_url"], cfg["llm"]["model"], cfg["llm"].get("temperature", 0.1))
    db = DBWriter(cfg["remote_db"])
    db.ensure_table()

    connectors = build_connectors(cfg)
    next_run = {name: 0.0 for name in connectors}

    log.info("Started with sources: %s", list(connectors.keys()))

    while True:
        now = time.time()
        for name, connector in connectors.items():
            if now < next_run[name]:
                continue
            interval = cfg["sources"][name]["poll_interval_seconds"]
            next_run[name] = now + interval
            try:
                events = connector.poll()
            except Exception:
                log.exception("[%s] poll failed", name)
                continue
            if events:
                try:
                    process_events(events, name, state, memory, classifier, db, interval)
                except Exception:
                    log.exception("[%s] processing failed", name)
        time.sleep(5)  # tick rate; actual per-source cadence controlled by next_run


if __name__ == "__main__":
    main()
