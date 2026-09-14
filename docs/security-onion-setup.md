# Security Onion Setup

Tracked here so this project owns the full pipeline (deploy SO -> connector -> agent -> DB),
not just the connector stub.

## Decisions already made
- Runs on dedicated PHYSICAL hardware — repurposed old wfl-wazuh01 mini PC. NOT a VM.
  (Packet capture needs a real NIC in promiscuous mode; can't share the Hyper-V host the
  way Wazuh/Loki/Ansible do.)
- This box's role: switch/firewall/network-device monitoring (SonicWall, Aruba AOS-CX
  switches, Netgear L2 switches) — explicitly OUT of Wazuh's scope, moved here instead.

## Open decisions (resolve before install)
- [ ] Capture scope: WAN-uplink-only vs WAN + core switch combined
- [ ] Old wfl-wazuh01 box's IP must change (its old IP is now reused by the new Wazuh VM)
- [ ] Which physical switch ports get SPAN/mirror config, and which switches support it
      (confirm Aruba 6200F + Netgear L2 SPAN capability)

## Build steps
1. **Repurpose hardware** — wipe old wfl-wazuh01 mini PC, assign new static IP (off the
   Wazuh-reused range), rack/connect in whatever spot has access to the mirrored traffic.
2. **Install Security Onion** — standalone/eval install mode is enough for a single-sensor
   deployment (no distributed grid needed at this scale). ISO install, then `so-setup`.
3. **Configure SPAN/mirror ports** — on the deciding switch(es), mirror the WAN uplink
   (and core switch, if that scope is chosen) to the port SO's monitor NIC is on.
4. **Verify capture** — confirm Suricata/Zeek are seeing traffic (`so-status`, check
   Kibana/so-elastic for incoming events) before wiring anything downstream.
5. **Open SO's Elasticsearch API to the agent** — same pattern as Wazuh: the monitor-agent
   queries SO's so-elastic index (default port 9200) for alerts above a severity threshold.
   Confirm auth method (SO uses its own internal ES, typically behind so-nginx/TLS).
6. **Flip connector on** — set `sources.security_onion.enabled: true` in config.yaml,
   fill in `base_url` + credentials in `.env`, tune `min_severity` once real traffic volume
   is visible (don't guess this number cold — watch a day of alerts first).

## Not yet started
Hardware repurposing hasn't begun. This doc is the checklist to work through when it does;
the connector code (`connectors/security_onion.py`) is already built against SO's expected
Elasticsearch-alert shape and just needs a real endpoint.
