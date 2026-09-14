"""Shared types for all source connectors."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib


@dataclass
class NormalizedEvent:
    source: str          # "wazuh", "loki", "semaphore", "freepbx", "faxserver", "security_onion"
    host: str
    severity: str        # "low" | "medium" | "high" | "critical"
    message: str
    raw_timestamp: str
    fetched_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rule_id: str = ""    # source-specific rule/event id if available, else derived from message

    def fingerprint(self) -> str:
        """Stable hash used for dedupe. Same underlying issue -> same fingerprint,
        regardless of exact timestamp."""
        key = f"{self.source}|{self.host}|{self.rule_id or self.message[:120]}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]


class BaseConnector:
    """Every connector implements poll() and returns a list[NormalizedEvent].
    Connectors must be side-effect-free except for their own read-only API/log calls —
    all state/dedupe/writing happens outside, in the orchestrator."""

    name: str = "base"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.enabled = cfg.get("enabled", False)

    def poll(self) -> list[NormalizedEvent]:
        raise NotImplementedError
