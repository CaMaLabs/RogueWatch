# RogueWatch

RogueWatch is a defensive research tool for finding **suspected autonomous AI agents** and **suspected machine-to-machine coordination channels** in public data or telemetry you are authorized to inspect.

It is deliberately evidence-driven: RogueWatch does not claim to prove that an identity is an AI. It scores observable signals, preserves reasons, and separates actor classification from channel correlation.

## v0.1 capabilities

- Normalize observations into a common event model.
- Score machine-like behavior: clocklike cadence, sub-second bursts, round-the-clock activity, and template repetition.
- Score protocol-like content: structured payloads, request/ack/status vocabulary, recurring rare identifiers, and encoded-looking blocks.
- Correlate pairs of actors using response timing, shared identifiers, and explicit interactions.
- Build a graph of actors, events, and suspected channels.
- Store observations in SQLite.
- FastAPI API plus a small local dashboard.
- Conservative public-web collector with explicit host allowlisting, robots.txt checks, rate limiting, and no authentication or anti-bot bypass behavior.
- Deterministic honeysite-style demo data for regression testing.

## Guardrails

Use RogueWatch only on public information or systems/traffic you own or are authorized to inspect. The included public collector does not bypass login, CAPTCHA, robots.txt, access controls, or anti-bot protections. A high score is an investigative lead, not proof of wrongdoing or sentience.

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

Example conservative public collection request:

```json
{
  "url": "https://example.com/public-discussion",
  "allowed_hosts": ["example.com"]
}
```

## Scoring philosophy

RogueWatch intentionally avoids a single opaque “AI detector.” Independent signals are combined into actor and channel confidence scores. The next useful step is to calibrate those weights against controlled human, conventional-bot, and autonomous-agent populations, then measure false-positive rates before widening collection.

## Planned next steps

1. Honeysite/browser sensor for mouse, typing, navigation and timing fingerprints.
2. Importers for Zeek/Suricata logs from authorized networks.
3. Cross-site identity/identifier correlation with explicit provenance.
4. Time-windowed graph analysis and cluster detection.
5. Baseline calibration, ROC/PR evaluation, and explainable threshold tuning.
6. Optional local model used only to summarize evidence, never as the sole detector.
