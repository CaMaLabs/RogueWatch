from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .collectors import PublicHttpCollector
from .demo import demo_events
from .graph import build_graph
from .models import Event
from .scoring import analyze_actors, analyze_channels
from .storage import EventStore

app = FastAPI(title="RogueWatch", version="0.1.0", description="Defensive AI-agent and covert coordination anomaly hunter")
store = EventStore(os.getenv("ROGUEWATCH_DB", "roguewatch.db"))


class CollectRequest(BaseModel):
    url: str
    allowed_hosts: list[str] = Field(min_length=1)


@app.get("/health")
def health() -> dict:
    return {"ok": True, "events": store.count(), "version": "0.1.0"}


@app.post("/events")
def ingest(event: Event) -> dict:
    store.add(event)
    return {"ok": True, "id": event.id}


@app.get("/events")
def list_events(limit: int = 1000) -> list[Event]:
    return store.all(limit=max(1, min(limit, 5000)))


@app.post("/demo/load")
def load_demo() -> dict:
    events = demo_events()
    for event in events:
        store.add(event)
    return {"ok": True, "loaded": len(events)}


@app.post("/collect/public")
async def collect_public(request: CollectRequest) -> dict:
    try:
        collector = PublicHttpCollector(allowed_hosts=set(request.allowed_hosts))
        events = await collector.collect_page(request.url)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Collection failed: {exc}") from exc
    for event in events:
        store.add(event)
    return {"ok": True, "collected": len(events)}


@app.get("/analysis")
def analysis() -> dict:
    events = store.all()
    actors = analyze_actors(events)
    channels = analyze_channels(events)
    return {"actors": actors, "channels": channels, "event_count": len(events)}


@app.get("/graph")
def graph() -> dict:
    events = store.all()
    actors = analyze_actors(events)
    channels = analyze_channels(events)
    return build_graph(events, actors, channels)


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    path = Path(__file__).resolve().parent.parent / "static" / "index.html"
    return path.read_text(encoding="utf-8")
