from __future__ import annotations

import argparse
import json

import uvicorn

from .demo import demo_events
from .scoring import analyze_actors, analyze_channels


def main() -> None:
    parser = argparse.ArgumentParser(prog="roguewatch")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the local RogueWatch API/dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8777)

    sub.add_parser("demo", help="Analyze a deterministic ground-truth demo dataset")
    args = parser.parse_args()

    if args.command == "serve":
        uvicorn.run("roguewatch.api:app", host=args.host, port=args.port, reload=False)
        return

    events = demo_events()
    payload = {
        "actors": [finding.model_dump(mode="json") for finding in analyze_actors(events)],
        "channels": [finding.model_dump(mode="json") for finding in analyze_channels(events)],
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
