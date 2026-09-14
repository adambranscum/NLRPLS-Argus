import os
import requests
from datetime import datetime, timezone, timedelta
from .base import BaseConnector, NormalizedEvent

requests.packages.urllib3.disable_warnings()  # self-signed cert on wfl-wazuh01

_SEVERITY_MAP = {  # Wazuh rule level -> our severity bucket
    range(0, 7): "low",
    range(7, 10): "medium",
    range(10, 13): "high",
    range(13, 16): "critical",
}


def _bucket(level: int) -> str:
    for r, name in _SEVERITY_MAP.items():
        if level in r:
            return name
    return "critical" if level >= 15 else "low"


class WazuhConnector(BaseConnector):
    """Queries the Wazuh indexer (OpenSearch, port 9200) directly.
    The old manager API's /alerts endpoint (port 55000) no longer exists on
    this version -- confirmed 404 against a live 4.14.7 install. Alert data
    lives in the indexer under the wazuh-alerts-4.x-* daily index pattern."""

    name = "wazuh"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        # base_url should now point at the INDEXER (port 9200), not the manager API (55000).
        # e.g. "https://192.168.13.14:9200" -- update config.yaml accordingly.
        self.base_url = cfg["base_url"].rstrip("/")
        self.verify_ssl = cfg.get("verify_ssl", False)
        self.min_level = cfg.get("min_level", 10)
        self._last_poll_time = None  # watermark so we don't re-fetch old alerts

    def poll(self) -> list[NormalizedEvent]:
        # now expects the indexer "admin" user
        user = os.environ["WAZUH_USER"]
        # its password, from wazuh-install-files/wazuh-passwords.txt
        password = os.environ["WAZUH_PASSWORD"]

        now = datetime.now(timezone.utc)
        since = self._last_poll_time or (
            now - timedelta(minutes=5))  # first run: last 5min
        self._last_poll_time = now

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"rule.level": {"gte": self.min_level}}},
                        {"range": {"timestamp": {
                            "gte": since.isoformat(), "lte": now.isoformat()}}},
                    ]
                }
            },
            "sort": [{"timestamp": "desc"}],
            "size": 200,
        }

        resp = requests.post(
            f"{self.base_url}/wazuh-alerts-4.x-*/_search",
            json=query,
            auth=(user, password),
            verify=self.verify_ssl,
            timeout=20,
        )
        resp.raise_for_status()

        events = []
        for hit in resp.json().get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            level = src.get("rule", {}).get("level", 0)
            events.append(NormalizedEvent(
                source="wazuh",
                host=src.get("agent", {}).get("name", "unknown"),
                severity=_bucket(level),
                message=src.get("rule", {}).get(
                    "description", "no description"),
                raw_timestamp=src.get("timestamp", ""),
                rule_id=str(src.get("rule", {}).get("id", "")),
            ))
        return events
