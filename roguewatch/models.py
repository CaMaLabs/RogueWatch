from __future__ import annotations

from datetime import datetime, timezone
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


class Event(BaseModel):
    id: str = Field(default_factory=lambda: uuid4().hex)
    source: str
    actor_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
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
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


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
