from __future__ import annotations

import asyncio
import os
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .artifact_hunter import HistoricalArtifactHunter, WaybackCapture, analyze_artifact_bytes
from .collectors import PublicHttpCollector
from .demo import demo_events
from .graph import build_graph
from .models import (
    CaseEntry,
    CaseLog,
    Event,
    FindingFamily,
    HuntingMode,
    ScanMode,
    ScanTarget,
    Severity,
    TriageFinding,
)
from .scoring import analyze_actors, analyze_channels
from .storage import EventStore
from .triage import all_triage_findings, backdoor_findings, severity_counts, swarm_findings

app = FastAPI(
    title="RogueWatch",
    version="0.2.0",
    description="Defensive AI-agent, hidden-access, and covert-coordination anomaly hunter",
)
store = EventStore(os.getenv("ROGUEWATCH_DB", "roguewatch.db"))
monitor_task: asyncio.Task | None = None
monitor_running = False


class CollectRequest(BaseModel):
    url: str
    allowed_hosts: list[str] = Field(min_length=1)
    case_id: str | None = None
    hunting_mode: HuntingMode = HuntingMode.conservative


class ArtifactInspectRequest(BaseModel):
    text: str = Field(max_length=200_000)
    source_label: str = Field(default="api-submitted-artifact", max_length=500)
    media_type: str = Field(default="text/plain", max_length=200)


class ArtifactUrlInspectRequest(BaseModel):
    url: str
    max_bytes: int = Field(default=2_000_000, ge=1, le=5_000_000)
    timeout_seconds: float = Field(default=12.0, ge=1.0, le=30.0)


class WaybackInspectRequest(BaseModel):
    pattern: str = Field(min_length=3, max_length=500)
    limit: int = Field(default=10, ge=1, le=50)
    max_bytes: int = Field(default=2_000_000, ge=1, le=5_000_000)
    timeout_seconds: float = Field(default=12.0, ge=1.0, le=30.0)


class CaseRequest(BaseModel):
    title: str
    summary: str = ""
    status: str = "new"
    target: str | None = None
    severity: Severity = Severity.informational
    disposition: str = "new"


class CaseEntryRequest(BaseModel):
    kind: str = "note"
    message: str
    metadata: dict = Field(default_factory=dict)


class ScanTargetRequest(BaseModel):
    name: str
    url: str
    allowed_hosts: list[str] = Field(min_length=1)
    mode: ScanMode = ScanMode.single_scope
    hunting_mode: HuntingMode = HuntingMode.conservative
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = False
    case_id: str | None = None


@app.get("/health")
def health() -> dict:
    return {"ok": True, "events": store.count(), "version": "0.2.0", "monitor_running": monitor_running}


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


def _pages_for_mode(mode: HuntingMode) -> int:
    return {
        HuntingMode.conservative: 1,
        HuntingMode.balanced: 3,
        HuntingMode.wide: 8,
    }[mode]


def _ensure_case(case_id: str | None, title: str, summary: str = "") -> str:
    if case_id and store.get_case(case_id):
        return case_id
    case = CaseLog(id=case_id or CaseLog(title=title).id, title=title, summary=summary)
    store.add_case(case)
    return case.id


def _annotate_events(
    events: list[Event],
    *,
    case_id: str,
    mode: ScanMode,
    hunting_mode: HuntingMode,
    target_id: str | None = None,
) -> list[Event]:
    annotated: list[Event] = []
    for event in events:
        metadata = dict(event.metadata)
        metadata.update(
            {
                "case_id": case_id,
                "scan_mode": mode.value,
                "hunting_mode": hunting_mode.value,
            }
        )
        if target_id:
            metadata["scan_target_id"] = target_id
        annotated.append(event.model_copy(update={"metadata": metadata}))
    return annotated


async def _run_collection(url: str, allowed_hosts: list[str], hunting_mode: HuntingMode) -> tuple[list[Event], list[str]]:
    collector = PublicHttpCollector(allowed_hosts=set(allowed_hosts))
    del hunting_mode
    events = await collector.collect_page(url)
    return events, [url]


@app.post("/collect/public")
async def collect_public(request: CollectRequest) -> dict:
    case_id = _ensure_case(request.case_id, "RogueWatch public collection", request.url)
    try:
        events, visited = await _run_collection(request.url, request.allowed_hosts, request.hunting_mode)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Collection failed: {exc}") from exc
    annotated = _annotate_events(events, case_id=case_id, mode=ScanMode.single_scope, hunting_mode=request.hunting_mode)
    for event in annotated:
        store.add(event)
    store.add_case_entry(
        CaseEntry(
            case_id=case_id,
            kind="scan",
            message=f"single_scope scan collected {len(annotated)} event(s) from {len(visited)} page(s).",
            metadata={"url": request.url, "allowed_hosts": request.allowed_hosts, "visited": visited},
        )
    )
    return {"ok": True, "case_id": case_id, "collected": len(annotated), "visited": visited}


@app.post("/scan/single")
async def scan_single(request: CollectRequest) -> dict:
    return await collect_public(request)


@app.post("/inspect/artifact")
def inspect_artifact(request: ArtifactInspectRequest) -> dict:
    record = analyze_artifact_bytes(
        request.text.encode("utf-8"),
        source_url=f"submitted://{request.source_label}",
        retrieved_url=f"submitted://{request.source_label}",
        source_kind="api_inspect",
        media_type=request.media_type,
    )
    return asdict(record)


@app.post("/inspect/url")
async def inspect_url(request: ArtifactUrlInspectRequest) -> dict:
    try:
        hunter = HistoricalArtifactHunter(max_bytes=request.max_bytes, timeout_seconds=request.timeout_seconds)
        return asdict(await hunter.fetch_public(request.url))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Artifact fetch failed: {exc}") from exc


@app.post("/inspect/wayback")
async def inspect_wayback(request: WaybackInspectRequest) -> dict:
    try:
        hunter = HistoricalArtifactHunter(max_bytes=request.max_bytes, timeout_seconds=request.timeout_seconds)
        records = await hunter.hunt_wayback([request.pattern], per_pattern_limit=request.limit)
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wayback inspection failed: {exc}") from exc
    captures = [
        {
            "timestamp": record.wayback_timestamp,
            "original_url": record.wayback_original_url,
            "digest": record.wayback_digest,
            "replay_url": record.source_url,
        }
        for record in records
    ]
    return {"ok": True, "captures": captures, "records": [asdict(record) for record in records]}


@app.post("/inspect/wayback/capture")
async def inspect_wayback_capture(capture: WaybackCapture) -> dict:
    try:
        hunter = HistoricalArtifactHunter()
        return asdict(await hunter.fetch_wayback(capture))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Wayback capture failed: {exc}") from exc


def _filter_findings(
    findings: list[TriageFinding],
    *,
    severity: Severity | None,
    family: FindingFamily | None,
    target: str | None,
    actor: str | None,
    source: str | None,
    status: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[TriageFinding]:
    filtered = findings
    if severity:
        filtered = [item for item in filtered if item.severity == severity]
    if family:
        filtered = [item for item in filtered if item.family == family]
    if target:
        filtered = [item for item in filtered if item.target == target]
    if actor:
        filtered = [item for item in filtered if item.actor_id == actor]
    if source:
        filtered = [item for item in filtered if item.source == source]
    if status:
        filtered = [item for item in filtered if item.status == status]
    if since:
        since = since if since.tzinfo else since.replace(tzinfo=UTC)
        filtered = [item for item in filtered if item.timestamp is None or item.timestamp >= since]
    if until:
        until = until if until.tzinfo else until.replace(tzinfo=UTC)
        filtered = [item for item in filtered if item.timestamp is None or item.timestamp <= until]
    return filtered


@app.get("/findings")
def findings(
    severity: Severity | None = None,
    family: FindingFamily | None = None,
    target: str | None = None,
    actor: str | None = None,
    source: str | None = None,
    status: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> dict:
    items = _filter_findings(
        all_triage_findings(store.all()),
        severity=severity,
        family=family,
        target=target,
        actor=actor,
        source=source,
        status=status,
        since=since,
        until=until,
    )
    return {"findings": items, "counts": severity_counts(items)}


@app.get("/findings/backdoors")
def backdoor_finding_output() -> dict:
    items = backdoor_findings(store.all())
    return {"findings": items, "counts": severity_counts(items)}


@app.get("/findings/swarm")
def swarm_finding_output() -> dict:
    items = swarm_findings(store.all())
    return {"findings": items, "counts": severity_counts(items)}


@app.get("/findings/artifacts")
def artifact_finding_output() -> dict:
    artifacts = []
    for event in store.all():
        if "sha256" in event.metadata or event.source.startswith("artifact"):
            artifacts.append(
                {
                    "event_id": event.id,
                    "source": event.source,
                    "actor_id": event.actor_id,
                    "timestamp": event.timestamp,
                    "source_url": event.url or event.metadata.get("source_url"),
                    "sha256": event.metadata.get("sha256"),
                    "sha1": event.metadata.get("sha1"),
                    "metadata": event.metadata,
                }
            )
    return {"artifacts": artifacts}


@app.get("/analysis")
def analysis() -> dict:
    events = store.all()
    actors = analyze_actors(events)
    channels = analyze_channels(events)
    triage = all_triage_findings(events)
    return {
        "actors": actors,
        "channels": channels,
        "findings": triage,
        "severity_counts": severity_counts(triage),
        "event_count": len(events),
    }


async def run_scan_target(target: ScanTarget, *, force: bool = False) -> dict:
    if target.mode == ScanMode.realtime and not (target.enabled or force):
        raise HTTPException(status_code=409, detail="Realtime target is disabled")
    case_id = _ensure_case(
        target.case_id,
        title=f"RogueWatch scan: {target.name}",
        summary=f"{target.mode.value} scan for {target.url}",
    )
    started = datetime.now(UTC)
    try:
        events, visited = await _run_collection(target.url, target.allowed_hosts, target.hunting_mode)
        annotated = _annotate_events(
            events,
            case_id=case_id,
            mode=target.mode,
            hunting_mode=target.hunting_mode,
            target_id=target.id,
        )
        for event in annotated:
            store.add(event)
        target.case_id = case_id
        target.last_run_at = started
        target.last_status = f"ok: {len(annotated)} events from {len(visited)} page(s)"
        target.last_error = ""
        target.updated_at = datetime.now(UTC)
        store.save_scan_target(target)
        store.add_case_entry(
            CaseEntry(
                case_id=case_id,
                kind="scan",
                message=f"{target.mode.value} scan collected {len(annotated)} event(s) from {len(visited)} page(s).",
                metadata={"target_id": target.id, "target_name": target.name, "visited": visited},
            )
        )
        return {"ok": True, "target": target, "case_id": case_id, "collected": len(annotated), "visited": visited}
    except (ValueError, PermissionError) as exc:
        target.last_run_at = started
        target.last_status = "blocked"
        target.last_error = str(exc)
        target.updated_at = datetime.now(UTC)
        store.save_scan_target(target)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        target.last_run_at = started
        target.last_status = "failed"
        target.last_error = str(exc)
        target.updated_at = datetime.now(UTC)
        store.save_scan_target(target)
        raise HTTPException(status_code=502, detail=f"Collection failed: {exc}") from exc


@app.get("/scan/targets")
def scan_targets() -> list[ScanTarget]:
    return store.scan_targets()


@app.post("/scan/targets")
def create_scan_target(request: ScanTargetRequest) -> dict:
    if request.case_id and not store.get_case(request.case_id):
        raise HTTPException(status_code=404, detail="case_id not found")
    target = ScanTarget(**request.model_dump())
    store.save_scan_target(target)
    return {"ok": True, "target": target}


@app.post("/scan/targets/{target_id}/run")
async def run_target(target_id: str) -> dict:
    target = store.get_scan_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    return await run_scan_target(target, force=True)


@app.post("/scan/targets/{target_id}/start")
def start_target(target_id: str) -> dict:
    target = store.get_scan_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    target.enabled = True
    target.mode = ScanMode.realtime
    target.updated_at = datetime.now(UTC)
    store.save_scan_target(target)
    return {"ok": True, "target": target}


@app.post("/scan/targets/{target_id}/stop")
def stop_target(target_id: str) -> dict:
    target = store.get_scan_target(target_id)
    if not target:
        raise HTTPException(status_code=404, detail="target not found")
    target.enabled = False
    target.updated_at = datetime.now(UTC)
    store.save_scan_target(target)
    return {"ok": True, "target": target}


@app.get("/cases")
def cases() -> list[CaseLog]:
    return store.cases()


@app.post("/cases")
def create_case(request: CaseRequest) -> dict:
    case = CaseLog(**request.model_dump())
    store.add_case(case)
    return {"ok": True, "case": case}


@app.get("/cases/{case_id}")
def case_detail(case_id: str) -> dict:
    case = store.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="case not found")
    events = [event for event in store.all() if event.metadata.get("case_id") == case_id]
    triage = all_triage_findings(events)
    actors = analyze_actors(events)
    channels = analyze_channels(events)
    artifacts = [
        {
            "event_id": event.id,
            "sha256": event.metadata.get("sha256"),
            "sha1": event.metadata.get("sha1"),
            "source_url": event.url or event.metadata.get("source_url"),
            "timestamp": event.timestamp,
        }
        for event in events
        if "sha256" in event.metadata or event.source.startswith("artifact")
    ]
    return {
        "case": case,
        "entries": store.case_entries(case_id),
        "events": events,
        "timeline": sorted(
            [
                {"timestamp": event.timestamp, "kind": event.kind, "source": event.source, "actor_id": event.actor_id}
                for event in events
            ],
            key=lambda item: item["timestamp"],
        ),
        "actors": actors,
        "channels": channels,
        "artifacts": artifacts,
        "findings": triage,
        "severity_counts": severity_counts(triage),
    }


@app.post("/cases/{case_id}/entries")
def create_case_entry(case_id: str, request: CaseEntryRequest) -> dict:
    if not store.get_case(case_id):
        raise HTTPException(status_code=404, detail="case not found")
    entry = CaseEntry(case_id=case_id, kind=request.kind, message=request.message, metadata=request.metadata)
    store.add_case_entry(entry)
    return {"ok": True, "entry": entry}


async def monitor_loop() -> None:
    global monitor_running
    monitor_running = True
    try:
        while True:
            now = datetime.now(UTC)
            for target in store.scan_targets():
                if not target.enabled or target.mode != ScanMode.realtime:
                    continue
                if target.last_run_at and (now - target.last_run_at).total_seconds() < target.interval_seconds:
                    continue
                try:
                    await run_scan_target(target)
                except HTTPException:
                    pass
            await asyncio.sleep(5)
    finally:
        monitor_running = False


@app.on_event("startup")
async def start_monitor() -> None:
    global monitor_task
    if monitor_task is None or monitor_task.done():
        monitor_task = asyncio.create_task(monitor_loop())


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
