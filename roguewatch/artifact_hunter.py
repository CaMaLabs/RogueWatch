from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

import httpx

from .models import Event
from .swarm_signatures import incident_pattern_signals

_MUTATING_QUERY_KEYS = {
    "action",
    "add",
    "append",
    "create",
    "delete",
    "edit",
    "inc",
    "increment",
    "post",
    "put",
    "remove",
    "save",
    "set",
    "submit",
    "update",
    "up",
    "write",
}
_MUTATING_PATH_RE = re.compile(
    r"(?:^|/)(?:add|append|create|delete|edit|post|remove|save|submit|update|write)(?:/|$)",
    re.IGNORECASE,
)
_SELF_REPLICATION_RE = re.compile(
    r"\b(?:self[-_ ]?replicat(?:e|es|ed|ing|ion)|"
    r"copy(?:ing|ies|ied)?\s+(?:itself|self)|"
    r"spawn(?:s|ed|ing)?\s+(?:a\s+)?(?:child|agent|worker|copy)|"
    r"bootstrap(?:s|ped|ping)?\s+(?:a\s+)?(?:agent|worker|node)|"
    r"propagat(?:e|es|ed|ing|ion)|worm)\b",
    re.IGNORECASE,
)
_CODE_RE = re.compile(
    r"(?:^#!|\b(?:import|from|def|class|function|powershell|cmd\.exe|"
    r"subprocess|socket|requests?|httpx|curl|wget)\b|"
    r"\b(?:chmod|systemctl|crontab|schtasks)\b)",
    re.IGNORECASE | re.MULTILINE,
)
_HASH_RE = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)


@dataclass(frozen=True)
class ArtifactRecord:
    source_url: str
    retrieved_url: str
    source_kind: str
    sha256: str
    sha1: str
    bytes_seen: int
    media_type: str
    fetched_at: str
    truncated: bool
    incident_markers: tuple[str, ...]
    self_replication_terms: bool
    code_like: bool
    embedded_sha256_count: int
    wayback_timestamp: str | None = None
    wayback_original_url: str | None = None
    wayback_digest: str | None = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


@dataclass(frozen=True)
class WaybackCapture:
    timestamp: str
    original_url: str
    mimetype: str
    statuscode: str
    digest: str

    @property
    def replay_url(self) -> str:
        return f"https://web.archive.org/web/{self.timestamp}id_/{self.original_url}"


def _hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


def validate_readonly_url(
    url: str,
    *,
    allowed_hosts: set[str] | None = None,
    allow_wayback_replay: bool = True,
) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are supported")
    if parsed.username or parsed.password:
        raise PermissionError("Authenticated URLs are not supported")
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("URL must include a hostname")
    if allowed_hosts is not None and host not in {item.lower() for item in allowed_hosts}:
        raise PermissionError(f"Host {host!r} is not allowlisted")

    if allow_wayback_replay and host == "web.archive.org" and parsed.path.startswith("/web/"):
        return

    query_keys = {key.lower() for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
    risky_keys = sorted(query_keys & _MUTATING_QUERY_KEYS)
    if risky_keys:
        raise PermissionError(
            "Refusing a URL with mutation-like query parameters: " + ", ".join(risky_keys)
        )
    if _MUTATING_PATH_RE.search(parsed.path):
        raise PermissionError("Refusing a URL whose path looks like a mutation endpoint")


def analyze_artifact_bytes(
    payload: bytes,
    *,
    source_url: str,
    retrieved_url: str | None = None,
    source_kind: str = "public_get",
    media_type: str = "application/octet-stream",
    truncated: bool = False,
    wayback_capture: WaybackCapture | None = None,
) -> ArtifactRecord:
    retrieved = retrieved_url or source_url
    sha256 = hashlib.sha256(payload).hexdigest()
    sha1 = hashlib.sha1(payload, usedforsecurity=False).hexdigest()

    text = payload.decode("utf-8", errors="replace")
    event = Event(source=source_kind, actor_id="artifact", text=text[:200_000], url=retrieved)
    incident_markers = tuple(
        sorted(signal.name for signal in incident_pattern_signals([event]))
    )

    return ArtifactRecord(
        source_url=source_url,
        retrieved_url=retrieved,
        source_kind=source_kind,
        sha256=sha256,
        sha1=sha1,
        bytes_seen=len(payload),
        media_type=media_type,
        fetched_at=datetime.now(UTC).isoformat(),
        truncated=truncated,
        incident_markers=incident_markers,
        self_replication_terms=bool(_SELF_REPLICATION_RE.search(text)),
        code_like=bool(_CODE_RE.search(text)),
        embedded_sha256_count=len(_HASH_RE.findall(text)),
        wayback_timestamp=wayback_capture.timestamp if wayback_capture else None,
        wayback_original_url=wayback_capture.original_url if wayback_capture else None,
        wayback_digest=wayback_capture.digest if wayback_capture else None,
    )


class HistoricalArtifactHunter:
    """Passive public/archived artifact collector.

    The hunter performs GET-only retrieval, rejects URLs that look like mutation
    endpoints, never executes retrieved material, and stores only hashes/metadata
    unless the caller separately preserves source material.
    """

    def __init__(
        self,
        *,
        allowed_hosts: set[str] | None = None,
        timeout_seconds: float = 20.0,
        max_bytes: int = 2_000_000,
        user_agent: str = "RogueWatch/0.1 defensive-historical-hunter",
    ) -> None:
        self.allowed_hosts = allowed_hosts
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max(1, max_bytes)
        self.user_agent = user_agent

    async def _read_limited(
        self,
        client: httpx.AsyncClient,
        url: str,
        *,
        allowed_hosts: set[str] | None,
    ) -> tuple[bytes, str, str, bool]:
        validate_readonly_url(url, allowed_hosts=allowed_hosts)
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            final_url = str(response.url)
            validate_readonly_url(final_url, allowed_hosts=allowed_hosts)
            media_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
            chunks: list[bytes] = []
            size = 0
            truncated = False
            async for chunk in response.aiter_bytes():
                remaining = self.max_bytes - size
                if remaining <= 0:
                    truncated = True
                    break
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    size += remaining
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
        return b"".join(chunks), final_url, media_type, truncated

    async def fetch_public(self, url: str) -> ArtifactRecord:
        host = _hostname(url)
        allowed = self.allowed_hosts or {host}
        headers = {"User-Agent": self.user_agent}
        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout_seconds,
            follow_redirects=True,
        ) as client:
            payload, final_url, media_type, truncated = await self._read_limited(
                client,
                url,
                allowed_hosts=allowed,
            )
        return analyze_artifact_bytes(
            payload,
            source_url=url,
            retrieved_url=final_url,
            source_kind="public_get",
            media_type=media_type,
            truncated=truncated,
        )

    async def discover_wayback(
        self,
        target_pattern: str,
        *,
        limit: int = 50,
    ) -> list[WaybackCapture]:
        limit = max(1, min(limit, 200))
        params = {
            "url": target_pattern,
            "output": "json",
            "fl": "timestamp,original,mimetype,statuscode,digest",
            "filter": "statuscode:200",
            "collapse": "digest",
            "limit": str(limit),
        }
        headers = {"User-Agent": self.user_agent}
        async with httpx.AsyncClient(headers=headers, timeout=self.timeout_seconds) as client:
            response = await client.get(
                "https://web.archive.org/cdx/search/cdx",
                params=params,
            )
            response.raise_for_status()
            rows = response.json()

        if not isinstance(rows, list) or len(rows) < 2:
            return []
        captures: list[WaybackCapture] = []
        for row in rows[1:]:
            if not isinstance(row, list) or len(row) < 5:
                continue
            captures.append(
                WaybackCapture(
                    timestamp=str(row[0]),
                    original_url=str(row[1]),
                    mimetype=str(row[2]),
                    statuscode=str(row[3]),
                    digest=str(row[4]),
                )
            )
        return captures

    async def fetch_wayback(self, capture: WaybackCapture) -> ArtifactRecord:
        headers = {"User-Agent": self.user_agent}
        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout_seconds,
            follow_redirects=True,
        ) as client:
            payload, final_url, media_type, truncated = await self._read_limited(
                client,
                capture.replay_url,
                allowed_hosts={"web.archive.org"},
            )
        return analyze_artifact_bytes(
            payload,
            source_url=capture.replay_url,
            retrieved_url=final_url,
            source_kind="wayback",
            media_type=media_type or capture.mimetype,
            truncated=truncated,
            wayback_capture=capture,
        )

    async def hunt_wayback(
        self,
        target_patterns: Iterable[str],
        *,
        per_pattern_limit: int = 25,
    ) -> list[ArtifactRecord]:
        records: list[ArtifactRecord] = []
        seen_hashes: set[str] = set()
        for target_pattern in target_patterns:
            captures = await self.discover_wayback(
                target_pattern,
                limit=per_pattern_limit,
            )
            for capture in captures:
                try:
                    record = await self.fetch_wayback(capture)
                except (httpx.HTTPError, PermissionError, ValueError):
                    continue
                if record.sha256 in seen_hashes:
                    continue
                seen_hashes.add(record.sha256)
                records.append(record)
        return records


def write_jsonl(records: Iterable[ArtifactRecord], path: str | Path) -> int:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(record.to_json() + "\n")
            count += 1
    return count
