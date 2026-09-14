import os
import requests
from .base import BaseConnector, NormalizedEvent

requests.packages.urllib3.disable_warnings()


class SecurityOnionConnector(BaseConnector):
    """Queries Security Onion's internal Elasticsearch (so-elastic) for alerts.
    See docs/security-onion-setup.md for deployment status — this stays disabled
    in config.yaml until that box exists and base_url is a real host."""

    name = "security_onion"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.base_url = cfg.get("base_url", "")
        self.verify_ssl = cfg.get("verify_ssl", False)
        self.min_severity = cfg.get("min_severity", 3)
        self._last_seen_ts = None

    def poll(self) -> list[NormalizedEvent]:
        if not self.enabled or "TODO" in self.base_url:
            return []  # not deployed yet — see docs/security-onion-setup.md

        user = os.environ.get("SECURITY_ONION_USER")
        password = os.environ.get("SECURITY_ONION_PASSWORD")

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"event.severity": {"gte": self.min_severity}}},
                    ]
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "size": 100,
        }
        resp = requests.post(
            f"{self.base_url.rstrip('/')}/so-*/_search",
            json=query,
            auth=(user, password) if user else None,
            verify=self.verify_ssl,
            timeout=15,
        )
        resp.raise_for_status()

        events = []
        for hit in resp.json().get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            severity_num = src.get("event", {}).get("severity", 0)
            severity = "critical" if severity_num >= 5 else "high" if severity_num >= 3 else "medium"
            events.append(NormalizedEvent(
                source="security_onion",
                host=src.get("source", {}).get("ip", src.get("host", {}).get("name", "unknown")),
                severity=severity,
                message=src.get("rule", {}).get("name", src.get("message", "no description")),
                raw_timestamp=src.get("@timestamp", ""),
                rule_id=str(src.get("rule", {}).get("uuid", "")),
            ))
        return events
