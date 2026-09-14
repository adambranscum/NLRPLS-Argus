import os
import requests
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
    name = "wazuh"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.base_url = cfg["base_url"].rstrip("/")
        self.verify_ssl = cfg.get("verify_ssl", False)
        self.min_level = cfg.get("min_level", 10)
        self._token = None

    def _authenticate(self):
        user = os.environ["WAZUH_USER"]
        password = os.environ["WAZUH_PASSWORD"]
        resp = requests.get(
            f"{self.base_url}/security/user/authenticate",
            auth=(user, password),
            verify=self.verify_ssl,
            timeout=10,
        )
        resp.raise_for_status()
        self._token = resp.json()["data"]["token"]

    def poll(self) -> list[NormalizedEvent]:
        if not self._token:
            self._authenticate()
        headers = {"Authorization": f"Bearer {self._token}"}
        params = {
            "level": f"{self.min_level}..15",
            "sort": "-timestamp",
            "limit": 100,
        }
        resp = requests.get(
            f"{self.base_url}/security/alerts" if False else f"{self.base_url}/alerts",
            headers=headers, params=params, verify=self.verify_ssl, timeout=15,
        )
        if resp.status_code == 401:
            self._authenticate()
            headers = {"Authorization": f"Bearer {self._token}"}
            resp = requests.get(f"{self.base_url}/alerts", headers=headers,
                                 params=params, verify=self.verify_ssl, timeout=15)
        resp.raise_for_status()

        events = []
        for item in resp.json().get("data", {}).get("affected_items", []):
            level = item.get("rule", {}).get("level", 0)
            events.append(NormalizedEvent(
                source="wazuh",
                host=item.get("agent", {}).get("name", "unknown"),
                severity=_bucket(level),
                message=item.get("rule", {}).get("description", "no description"),
                raw_timestamp=item.get("timestamp", ""),
                rule_id=str(item.get("rule", {}).get("id", "")),
            ))
        return events
