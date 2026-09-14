import time
import requests
from .base import BaseConnector, NormalizedEvent


class LokiConnector(BaseConnector):
    name = "loki"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.base_url = cfg["base_url"].rstrip("/")
        self.queries = cfg.get("queries", [])
        self._last_end_ns = {}  # per-query watermark so we don't re-fetch old lines

    def poll(self) -> list[NormalizedEvent]:
        events = []
        now_ns = time.time_ns()
        for query in self.queries:
            start_ns = self._last_end_ns.get(query, now_ns - 5 * 60 * 1_000_000_000)  # first run: last 5min
            resp = requests.get(
                f"{self.base_url}/loki/api/v1/query_range",
                params={"query": query, "start": start_ns, "end": now_ns, "limit": 200},
                timeout=15,
            )
            resp.raise_for_status()
            for stream in resp.json().get("data", {}).get("result", []):
                labels = stream.get("stream", {})
                for ts_ns, line in stream.get("values", []):
                    events.append(NormalizedEvent(
                        source="loki",
                        host=labels.get("host", labels.get("instance", "unknown")),
                        severity="medium",  # Loki has no native severity; classifier refines this
                        message=line[:500],
                        raw_timestamp=ts_ns,
                        rule_id=labels.get("source", query),
                    ))
            self._last_end_ns[query] = now_ns
        return events
