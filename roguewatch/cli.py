from __future__ import annotations

import argparse
import asyncio
import json

import uvicorn

from .artifact_hunter import HistoricalArtifactHunter, inspect_local_file, write_jsonl
from .demo import demo_events
from .scoring import analyze_actors, analyze_channels


def _record_payload(record) -> dict:
    return json.loads(record.to_json())


def main() -> None:
    parser = argparse.ArgumentParser(prog="roguewatch")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="Run the local RogueWatch API/dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8777)

    sub.add_parser("demo", help="Analyze a deterministic ground-truth demo dataset")

    inspect_file_cmd = sub.add_parser(
        "inspect-file",
        help="Hash and inspect a local artifact without executing it",
    )
    inspect_file_cmd.add_argument("path")
    inspect_file_cmd.add_argument("--max-bytes", type=int, default=2_000_000)

    hunt_url_cmd = sub.add_parser(
        "hunt-url",
        help="GET a public read-only URL and inspect its returned artifact",
    )
    hunt_url_cmd.add_argument("url")
    hunt_url_cmd.add_argument("--max-bytes", type=int, default=2_000_000)

    hunt_wayback_cmd = sub.add_parser(
        "hunt-wayback",
        help="Search Wayback CDX and inspect archived captures only",
    )
    hunt_wayback_cmd.add_argument("patterns", nargs="+")
    hunt_wayback_cmd.add_argument("--limit", type=int, default=25)
    hunt_wayback_cmd.add_argument("--max-bytes", type=int, default=2_000_000)
    hunt_wayback_cmd.add_argument("--output")

    args = parser.parse_args()

    if args.command == "serve":
        uvicorn.run("roguewatch.api:app", host=args.host, port=args.port, reload=False)
        return

    if args.command == "inspect-file":
        record = inspect_local_file(args.path, max_bytes=args.max_bytes)
        print(json.dumps(_record_payload(record), indent=2))
        return

    if args.command == "hunt-url":
        hunter = HistoricalArtifactHunter(max_bytes=args.max_bytes)
        record = asyncio.run(hunter.fetch_public(args.url))
        print(json.dumps(_record_payload(record), indent=2))
        return

    if args.command == "hunt-wayback":
        hunter = HistoricalArtifactHunter(max_bytes=args.max_bytes)
        records = asyncio.run(
            hunter.hunt_wayback(
                args.patterns,
                per_pattern_limit=max(1, min(args.limit, 200)),
            )
        )
        if args.output:
            write_jsonl(records, args.output)
            print(json.dumps({"ok": True, "written": len(records), "path": args.output}))
        else:
            print(json.dumps([_record_payload(record) for record in records], indent=2))
        return

    events = demo_events()
    payload = {
        "actors": [finding.model_dump(mode="json") for finding in analyze_actors(events)],
        "channels": [finding.model_dump(mode="json") for finding in analyze_channels(events)],
    }
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
