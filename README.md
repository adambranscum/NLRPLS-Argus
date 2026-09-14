# monitor-agent

Lightweight monitoring agent with memory: polls Wazuh, Loki, Semaphore, FreePBX, the fax
server, and (once deployed) Security Onion. Classifies new/changed events via a local
LM Studio model with tool-calling, dedupes against a running state store, checks long-term
vector memory for similar past incidents, and writes open findings to a remote MySQL table.

## Setup
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in real creds
```
Edit `config/config.yaml` — fill in every `TODO` (remote DB host/creds, Security Onion
endpoint once it exists, Semaphore project_id).

In LM Studio: load your chosen model AND an embedding model, start the local server
(default port 1234), confirm both model names match `config/config.yaml`.

Run once manually first to catch config errors:
```
python3 scheduler/main.py
```

Then install as a LaunchAgent (`launchd/com.nlrpls.monitor-agent.plist`, update the
`CHANGE_ME` paths first):
```
cp launchd/com.nlrpls.monitor-agent.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.nlrpls.monitor-agent.plist
```

## Things to verify before trusting this in production
- **Wazuh alerts endpoint**: `connectors/wazuh.py` hits `/alerts` on the manager API
  (port 55000). Confirm this is still correct for your 4.14.7 install — alert querying
  moved to the indexer/OpenSearch API in some 4.x versions. If so, swap this connector to
  query the indexer directly (same auth pattern as `security_onion.py` against so-elastic).
- **Semaphore project_id**: hardcoded default of 1 in `connectors/semaphore.py` — confirm
  against your actual Semaphore project.
- **Embedding dimension**: `memory/vector_memory.py` assumes `float[1024]` — check your
  loaded embedding model's actual output dimension in LM Studio and adjust the
  `vec0(embedding float[N])` table definition to match, or table creation will fail silently
  wrong.
- **FreePBX AMI**: needs a manager account created in FreePBX (Settings > Asterisk Manager
  Users), not your web admin login.
- **Fax server connector**: only works if the agent runs ON WFL-FAXSVR01 or has that log
  path mounted/synced locally. If the agent stays solely on the Mac mini, replace
  `connectors/faxserver.py` with a Loki query instead (add a `source="fax"` label via
  Alloy on the fax box, same pattern as your other Alloy sources).
- **Security Onion**: connector is built but dormant — see `docs/security-onion-setup.md`.
  Don't enable until the box is deployed and you've confirmed so-elastic's actual index
  name/auth (the `so-*` wildcard and basic-auth assumption in the connector are best
  guesses, not confirmed against a live SO instance).
