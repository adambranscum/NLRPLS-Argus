import re
from .base import BaseConnector, NormalizedEvent


class FaxServerConnector(BaseConnector):
    """Tails the Asterisk full.log looking for the known fax failure patterns
    (UDPTL init errors, T.38 negotiation failures, ReceiveFax failures).
    Note: this assumes the agent runs ON the fax server, or the log is mounted/synced
    locally — no remote log-tailing here. If the agent runs elsewhere, this needs
    an SSH-tail or a syslog forward to Loki instead (simpler: just add a Loki query)."""

    name = "faxserver"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.log_path = cfg["log_path"]
        self.patterns = [re.compile(p) for p in cfg.get("error_patterns", [])]
        self._offset = 0

    def poll(self) -> list[NormalizedEvent]:
        events = []
        try:
            with open(self.log_path, "r", errors="ignore") as f:
                f.seek(self._offset)
                new_lines = f.readlines()
                self._offset = f.tell()
        except FileNotFoundError:
            return []  # log not present on this host — agent isn't running on the fax server

        for line in new_lines:
            for pattern in self.patterns:
                if pattern.search(line):
                    events.append(NormalizedEvent(
                        source="faxserver",
                        host="WFL-FAXSVR01",
                        severity="medium",
                        message=line.strip()[:500],
                        raw_timestamp="",
                        rule_id=pattern.pattern,
                    ))
                    break
        return events
