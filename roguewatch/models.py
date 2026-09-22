from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator


class ActorClass(str, Enum):
    human = "HUMAN"
    conventional_bot = "CONVENTIONAL_BOT"
    ai_agent = "AI_AGENT"
    coordinated_agents = "SUSPECTED_COORDINATED_AGENTS"
    unknown = "UNKNOWN"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


class FindingFamily(str, Enum):
    actor = "actor"
    channel = "channel"
    backdoor = "backdoor"
    swarm = "swarm"
    propagation = "propagation"
    artifact = "artifact"


class ScanMode(str, Enum):
    single_scope = "single_scope"
    realtime = "realtime"
    hunt = "hunt"


class HuntingMode(str, Enum):
    conservative = "conservative"
    balanced = "balanced"
    wide = "wide"


class Event(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    source: str
    actor_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    kind: str = "message"
    text: str = ""
    url: str | None = None
    parent_actor_id: str | None = None
    reply_to_event_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Signal(BaseModel):
    name: str
    score: float = Field(ge=0.0, le=1.0)
    reason: str
    evidence: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    actor_id: str
    classification: ActorClass
    confidence: float = Field(ge=0.0, le=1.0)
    signals: list[Signal]


class ChannelFinding(BaseModel):
    actor_a: str
    actor_b: str
    confidence: float = Field(ge=0.0, le=1.0)
    interaction_count: int
    signals: list[Signal]


class TriageFinding(BaseModel):
    id: str
    family: FindingFamily
    severity: Severity
    name: str
    score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    matched_components: list[str] = Field(default_factory=list)
    source: str | None = None
    target: str | None = None
    actor_id: str | None = None
    artifact: str | None = None
    status: str = "new"
    timestamp: datetime | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    cve: str | None = None
    cwe: str | None = None
    provenance_url: str | None = None
    source_url: str | None = None
    hashes: dict[str, str] = Field(default_factory=dict)
    group_count: int = 1
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def normalize_finding_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class CaseLog(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    title: str
    summary: str = ""
    status: str = "new"
    target: str | None = None
    severity: Severity = Severity.informational
    disposition: str = "new"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at", "updated_at")
    @classmethod
    def normalize_case_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class CaseEntry(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    case_id: str
    kind: str = "note"
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("created_at")
    @classmethod
    def normalize_entry_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class ScanTarget(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    name: str
    url: str
    allowed_hosts: list[str] = Field(min_length=1)
    mode: ScanMode = ScanMode.single_scope
    hunting_mode: HuntingMode = HuntingMode.conservative
    interval_seconds: int = Field(default=300, ge=30, le=86400)
    enabled: bool = False
    case_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_run_at: datetime | None = None
    last_status: str = "never"
    last_error: str = ""

    @field_validator("created_at", "updated_at", "last_run_at")
    @classmethod
    def normalize_target_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
