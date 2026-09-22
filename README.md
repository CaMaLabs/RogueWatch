# RogueWatch

RogueWatch is a defensive research tool for finding **suspected autonomous AI agents**, **suspected machine-to-machine coordination channels**, and **hidden remote-access/backdoor patterns** in public data or telemetry you are authorized to inspect.

It is deliberately evidence-driven: RogueWatch does not claim to prove that an identity is an AI or that one suspicious string proves a backdoor. It scores observable signals, preserves reasons, and separates actor classification, channel correlation, and artifact inspection.

## v0.2 capabilities

- Normalize observations into a common event model.
- Score machine-like behavior: clocklike cadence, sub-second bursts, round-the-clock activity, and template repetition.
- Score protocol-like content: structured payloads, request/ack/status vocabulary, recurring rare identifiers, and encoded-looking blocks.
- Correlate pairs of actors using response timing, shared identifiers, and explicit interactions.
- Apply incident-derived swarm markers for durable external memory, improvised message-board namespaces, cleanup-aware backups, timing/cohort vocabulary, heartbeat/beacon language, mailbox/auth conventions, and exact actor-label signatures.
- Inspect local or public artifacts without executing them, computing SHA-256/SHA-1 plus incident and hidden-access markers.
- Passively search Wayback CDX and inspect archived captures without probing historical mutation endpoints.
- Detect Go1-derived hidden-access patterns: boot-persistent tunnel clients, embedded/static authorization material, privileged remote control, undeclared functionality, and persistent factory-network ingress.
- Triage findings into Critical, High, Medium, Low, and Informational using evidence strength instead of raw keyword volume.
- Surface backdoor, swarm, propagation, artifact, actor, channel, target, and case context in the dashboard.
- Build a graph of actors, events, and suspected channels.
- Store observations in SQLite.
- FastAPI API plus a defensive investigation dashboard.
- Conservative public-web collector with explicit host allowlisting, robots.txt checks, rate limiting, and no authentication or anti-bot bypass behavior.
- Deterministic honeysite-style demo data for regression testing.

## 2026 swarm incident intelligence pack

RogueWatch includes a sourced defensive pack derived from the public 2026 OpenAI agent-swarm investigations:

- `roguewatch/swarm_signatures.py` — weighted incident-derived text/relational signatures.
- `intel/openai_agent_swarm_2026.json` — machine-readable provenance, counts, signatures, caveats, and adjacent surfaces.
- `research/openai_agent_swarm_2026.md` — evidence summary, attribution boundaries, detection lessons, and current status of the unverified self-replication claim.

These markers are **supporting evidence, not attribution shortcuts**. Incident-specific markers cannot independently classify an actor as an AI agent; RogueWatch still requires independent machine-behavior/protocol evidence. Later agent-oriented boards are tracked as adjacent surfaces unless provenance links them to the original populations.

## Unitree Go1 hidden-access intelligence pack

RogueWatch also incorporates the defensive lessons from **CVE-2025-2894 / CWE-912 Hidden Functionality**:

- `roguewatch/backdoor_signatures.py` — generic hidden-access and persistence patterns plus known Go1 indicators.
- `intel/unitree_go1_hidden_access_2025.json` — machine-readable source provenance, known indicators, and remediation metadata.
- `research/unitree_go1_hidden_access_2025.md` — case summary and generalized detector design.

Known Go1-specific indicators are useful for correlation, but the detector is intentionally broader. The strongest findings come from combinations such as **remote tunnel + boot persistence + privileged control**, or **remote tunnel + static authorization + privileged control**.

RogueWatch never stores historical credential values in its intel pack.

## Dashboard investigation console

The dashboard is now designed to show the few findings that matter first:

- Top cards for events, targets, open cases, Critical, High, actors, channels, and artifacts.
- A compact row for swarm patterns, backdoor patterns, known IOCs, propagation leads, and archived artifacts.
- Dedicated Hidden Access / Backdoors, Swarm Markers, Propagation Evidence, Artifact Hunter, Cases, Scan Targets, Actor Findings, and Channel Findings panels.
- Filters for severity, finding family, target, actor, source, status, and timeframe.
- Real-time polling that updates counts and findings without a full page reload.
- High and Critical findings are visually prominent; informational findings remain subdued.

Backdoor findings distinguish individual indicators, composite suspicious patterns, and known case IOCs. A single generic SSH, systemd, token, or tunnel reference is treated as low or informational unless independent supporting evidence is present.

Case detail includes summary, severity, target, associated actors, channels, artifacts, timeline entries, signals, hashes, source URLs, provenance fields, analyst notes, and disposition. Supported dispositions include `new`, `investigating`, `likely benign`, `suspicious`, `confirmed known IOC`, `needs more evidence`, and `closed`. Heuristic scores do not automatically mark a case confirmed malicious.

## Historical artifact hunter

`roguewatch/artifact_hunter.py` provides passive artifact collection and inspection:

- GET-only public retrieval.
- Refuses mutation-like URL paths and query parameters.
- Wayback CDX discovery and archive replay.
- SHA-256/SHA-1 hashing.
- `incident_markers` from the swarm signature pack.
- `backdoor_markers` from the hidden-access signature pack.
- self-replication terminology and code-like-content flags.
- JSONL provenance export.

The dashboard exposes three artifact workflows:

- Inspect pasted text via `POST /inspect/artifact`.
- Inspect a public URL via a narrow GET-only URL inspection endpoint.
- Search Wayback CDX and inspect archived captures instead of probing the historical origin.

Artifact results show SHA-256, SHA-1, source URL, retrieved/archive URL, media type, byte count, truncation status, timestamp, Wayback timestamp/digest when present, incident markers, backdoor markers, self-replication terms, code-like status, and embedded SHA-256 count. Retrieved material is hashed and statically inspected; RogueWatch does not execute downloaded artifacts or automatically open binaries.

Examples:

```bash
# Inspect a local file without running it
roguewatch inspect-file ./candidate.txt

# Inspect a public read-only artifact
roguewatch hunt-url https://example.com/public/artifact.txt

# Search archived captures and write only metadata/hashes
roguewatch hunt-wayback "example.com/*" --limit 25 --output findings.jsonl
```

## Guardrails

Use RogueWatch only on public information or systems/traffic you own or are authorized to inspect. The included public collector does not bypass login, CAPTCHA, robots.txt, access controls, or anti-bot protections. A high score is an investigative lead, not proof of wrongdoing or sentience.

Do not execute historical exploit recipes, mutation endpoints, GET-writable beacons, suspected propagating code, or retrieved binaries during collection. Preserve provenance and analyze captured text/metadata offline wherever possible.

The artifact hunter deliberately rejects mutation-like URL patterns and does not expose an arbitrary LAN-fetch endpoint through the API. URL inspection accepts only `http` and `https`, rejects credentials, localhost, private, link-local, loopback, multicast, reserved, and unresolved destinations, revalidates redirects, applies timeout and size limits, and refuses mutation-like paths or query parameters.

Propagation evidence is separated from ordinary discussion. RogueWatch distinguishes language-only mentions, code-like material, persistence, bootstrap behavior, child/new-instance creation, destination/new-host evidence, independent copies, and provenance. It does not label material as a self-replicating payload solely because it contains words such as `worm`, `spawn`, `bootstrap`, or `self-replicate`.

## Quick start

```bash
git clone https://github.com/CaMaLabs/RogueWatch.git
cd RogueWatch
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -U pip
pip install -e '.[dev]'
pytest
roguewatch demo
roguewatch serve --host 127.0.0.1 --port 8777
```

Open `http://127.0.0.1:8777` and click **Load ground-truth demo**.

## API

- `GET /health`
- `POST /events`
- `GET /events`
- `POST /demo/load`
- `POST /collect/public`
- `POST /inspect/artifact`
- `POST /inspect/url`
- `POST /inspect/wayback`
- `GET /findings`
- `GET /findings/backdoors`
- `GET /findings/swarm`
- `GET /findings/artifacts`
- `GET /cases`
- `GET /cases/{case_id}`
- `POST /cases/{case_id}/entries`
- `GET /scan/targets`
- `GET /analysis`
- `GET /graph`

Example event:

```json
{
  "source": "authorized-sensor",
  "actor_id": "account-123",
  "kind": "message",
  "text": "ACK task_id=f93817aa21bc45de status=received",
  "metadata": {"sensor": "example"}
}
```

Example local text inspection request:

```json
{
  "text": "service launches at boot and opens a remote access tunnel",
  "source_label": "firmware-notes.txt",
  "media_type": "text/plain"
}
```

## Scoring philosophy

RogueWatch intentionally avoids single-token attribution. Independent signals are combined into actor, channel, and artifact findings. Generic technologies such as SSH, systemd, VPNs, reverse tunnels, JSON, Ed25519, or API tokens are not treated as proof by themselves.

The strongest hidden-access findings require multiple independent components to co-occur, and known remediation artifacts are kept distinct from active vulnerable-service indicators.

Swarm markers are also supporting evidence only. They can raise the priority of a lead, but they do not independently prove that an actor is an autonomous AI agent; AI-agent classification still requires independent behavioral/protocol evidence.

## Planned next steps

1. Honeysite/browser sensor for mouse, typing, navigation and timing fingerprints.
2. Importers for Zeek/Suricata logs from authorized networks.
3. Cross-site identity/identifier correlation with explicit provenance.
4. Time-windowed graph analysis and cluster detection.
5. Baseline calibration, ROC/PR evaluation, and explainable threshold tuning.
6. Edit/write-volume anomaly monitoring independent of graph-based collusion scores.
7. Peer-reproduction/pivot detector: novel technique -> independent reproduction -> population activity shift.
8. File-tree and firmware-unpack importers that operate on already-extracted authorized material.
9. Optional local model used only to summarize evidence, never as the sole detector.
