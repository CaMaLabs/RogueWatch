from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .models import Event, Signal


@dataclass(frozen=True)
class SignatureRule:
    signal: str
    pattern: re.Pattern[str]
    base_score: float
    reason: str


SIGNATURE_RULES = (
    SignatureRule(
        signal="swarm_zz_namespace",
        pattern=re.compile(
            r"\bzz(?:NOTE|MAILBOX|TO|FROM|ANSWER|AUTH|CDA|[A-Z0-9]{5,})[A-Z0-9_]*\b",
            re.IGNORECASE,
        ),
        base_score=0.90,
        reason="Uses the zz-prefixed namespace observed on the July 2026 agent message board",
    ),
    SignatureRule(
        signal="swarm_late_sort_backup",
        pattern=re.compile(
            r"\bZZZ[A-Z0-9][A-Z0-9_-]{5,}\b",
            re.IGNORECASE,
        ),
        base_score=0.92,
        reason="Uses a ZZZ-prefixed late-sort backup naming pattern seen during wiki cleanup",
    ),
    SignatureRule(
        signal="swarm_timing_coordination",
        pattern=re.compile(
            r"\b(?:deadline|cooldown|cohort|task[._ -]?clock|"
            r"clock[._ -]?(?:wait|now)|scaffold[._ -]?clock)\b",
            re.IGNORECASE,
        ),
        base_score=0.46,
        reason="Uses timing/cohort vocabulary repeatedly observed in swarm coordination",
    ),
    SignatureRule(
        signal="swarm_heartbeat_beacon",
        pattern=re.compile(
            r"\b(?:heartbeat|horizon[ -]?beacon|counterapi(?:\.dev)?|"
            r"cache[ -]?bust(?:er|ing)?)\b",
            re.IGNORECASE,
        ),
        base_score=0.56,
        reason="Uses heartbeat/beacon or cache-busting language seen in public relay experiments",
    ),
    SignatureRule(
        signal="swarm_mailbox_auth",
        pattern=re.compile(
            r"\b(?:MAILBOX_[A-Z0-9_]{4,}|AUTH1|ED25519)\b|"
            r"__S[A-Za-z0-9_-]{16,}",
            re.IGNORECASE,
        ),
        base_score=0.72,
        reason="Uses mailbox/authentication conventions observed on agent message boards",
    ),
    SignatureRule(
        signal="swarm_external_memory",
        pattern=re.compile(
            r"\b(?:message board|shared board|external memory|backup page|"
            r"mirror (?:important )?updates|append results|relay page)\b",
            re.IGNORECASE,
        ),
        base_score=0.48,
        reason="Describes durable shared storage used as external memory or a relay",
    ),
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def incident_pattern_signals(events: Iterable[Event]) -> list[Signal]:
    items = list(events)
    if not items:
        return []

    signals: list[Signal] = []
    matched_names: list[str] = []

    for rule in SIGNATURE_RULES:
        hits = [event for event in items if rule.pattern.search(event.text or "")]
        if not hits:
            continue
        density = len(hits) / len(items)
        score = _clamp(rule.base_score * (0.65 + 0.70 * density))
        signals.append(
            Signal(
                name=rule.signal,
                score=score,
                reason=f"{rule.reason}; matched {len(hits)}/{len(items)} event(s)",
                evidence={"event_ids": [event.id for event in hits[:8]]},
            )
        )
        matched_names.append(rule.signal)

    own_label_hits: list[Event] = []
    for event in items:
        actor = event.actor_id.strip()
        if not actor:
            continue
        signature = re.compile(
            rf"(?:--|—|â€”)\s*{re.escape(actor)}\b",
            re.IGNORECASE,
        )
        if signature.search(event.text or ""):
            own_label_hits.append(event)
    if own_label_hits:
        score = _clamp(0.35 + 0.12 * len(own_label_hits))
        signals.append(
            Signal(
                name="swarm_own_label_signature",
                score=score,
                reason=(
                    "Message signs itself with the same editor/actor label, a repeated wiki-swarm "
                    f"pattern; matched {len(own_label_hits)}/{len(items)} event(s)"
                ),
                evidence={"event_ids": [event.id for event in own_label_hits[:8]]},
            )
        )
        matched_names.append("swarm_own_label_signature")

    distinct = sorted(set(matched_names))
    if len(distinct) >= 3:
        signals.append(
            Signal(
                name="multi_marker_swarm_pattern",
                score=_clamp(0.45 + 0.10 * len(distinct)),
                reason=(
                    f"{len(distinct)} independent incident-derived coordination markers co-occur"
                ),
                evidence={"markers": distinct},
            )
        )

    return signals
