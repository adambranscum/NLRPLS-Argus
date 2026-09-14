import os
import socket
from .base import BaseConnector, NormalizedEvent

# Asterisk Manager Interface (AMI): plain-text protocol over a persistent TCP socket.
# We connect, read whatever events accumulated since last poll, and disconnect —
# simple and safe for a 10min poll interval; a real always-on listener would keep
# the socket open, but that's a bigger change than this project needs right now.

_BAD_HANGUP_CAUSES = {"1", "17", "34", "38"}  # unallocated, busy, no circuit, network out of order


class FreePBXConnector(BaseConnector):
    name = "freepbx"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.host = cfg["host"]
        self.port = cfg.get("ami_port", 5038)

    def _read_until_prompt(self, sock, timeout=5) -> str:
        sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        return buf.decode("utf-8", errors="ignore")

    def poll(self) -> list[NormalizedEvent]:
        user = os.environ["FREEPBX_AMI_USER"]
        secret = os.environ["FREEPBX_AMI_SECRET"]

        events = []
        with socket.create_connection((self.host, self.port), timeout=10) as sock:
            self._read_until_prompt(sock, timeout=2)  # banner
            login = f"Action: Login\r\nUsername: {user}\r\nSecret: {secret}\r\nEvents: call\r\n\r\n"
            sock.sendall(login.encode())
            self._read_until_prompt(sock, timeout=2)  # login response

            raw = self._read_until_prompt(sock, timeout=8)  # accumulated events

        for block in raw.split("\r\n\r\n"):
            fields = dict(
                line.split(": ", 1) for line in block.splitlines() if ": " in line
            )
            event_type = fields.get("Event", "")
            if event_type == "Hangup" and fields.get("Cause") in _BAD_HANGUP_CAUSES:
                events.append(NormalizedEvent(
                    source="freepbx",
                    host=fields.get("Channel", "unknown"),
                    severity="medium",
                    message=f"Hangup cause={fields.get('Cause')} ({fields.get('Cause-txt','')}) on {fields.get('Channel','?')}",
                    raw_timestamp="",
                    rule_id=f"hangup-{fields.get('Cause')}",
                ))
            elif event_type == "PeerStatus" and fields.get("PeerStatus") == "Unregistered":
                events.append(NormalizedEvent(
                    source="freepbx",
                    host=fields.get("Peer", "unknown"),
                    severity="high",
                    message=f"SIP peer {fields.get('Peer','?')} unregistered",
                    raw_timestamp="",
                    rule_id="peer-unregistered",
                ))
        return events
