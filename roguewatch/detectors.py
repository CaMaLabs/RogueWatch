from __future__ import annotations

import base64
import binascii
import json
import re
from collections import Counter
from collections.abc import Iterable
from itertools import pairwise
from statistics import mean, pstdev

from .models import Event, Signal

TOKEN_RE = re.compile(r"\b[a-f0-9]{12,64}\b", re.IGNORECASE)
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
KV_RE = re.compile(
    r"\b(?:task|job|request|response|ack|status|result|nonce|session|seq|sequence)"
    r"[_-]?id?\s*[:=]",
    re.IGNORECASE,
)
ACK_RE = re.compile(
    r"\b(?:ack|accepted|received|complete|completed|done|retry|heartbeat|ping|pong)\b",
    re.IGNORECASE,
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def protocol_signals(events: Iterable[Event]) -> list[Signal]:
    items = list(events)
    if not items:
        return []
    texts = [event.text or "" for event in items]
    structured = 0
    machine_vocab = 0
    opaque = 0
    identifiers: Counter[str] = Counter()

    for text in texts:
        stripped = text.strip()
        if stripped:
            try:
                obj = json.loads(stripped)
                if isinstance(obj, (dict, list)):
                    structured += 1
            except json.JSONDecodeError:
                pass
        if KV_RE.search(text) or ACK_RE.search(text):
            machine_vocab += 1
        identifiers.update(TOKEN_RE.findall(text))
        for match in BASE64_RE.findall(text):
            try:
                raw = base64.b64decode(match + "===", validate=False)
            except (binascii.Error, ValueError):
                continue
            if raw and sum(32 <= b < 127 for b in raw) / len(raw) < 0.55:
                opaque += 1

    n = len(items)
    reused = sum(1 for count in identifiers.values() if count >= 2)
    signals = []
    if structured:
        score = _clamp(structured / max(3, n * 0.6))
        signals.append(
            Signal(
                name="structured_payloads",
                score=score,
                reason=f"{structured}/{n} events contain JSON-like structured payloads",
            )
        )
    if machine_vocab:
        score = _clamp(machine_vocab / max(3, n * 0.7))
        signals.append(
            Signal(
                name="machine_protocol_vocabulary",
                score=score,
                reason=f"{machine_vocab}/{n} events use request/ack/status vocabulary",
            )
        )
    if reused:
        signals.append(
            Signal(
                name="persistent_identifiers",
                score=_clamp(reused / 4),
                reason=f"{reused} rare identifier(s) repeat across events",
                evidence={
                    "identifiers": [
                        token for token, count in identifiers.items() if count >= 2
                    ][:8]
                },
            )
        )
    if opaque:
        signals.append(
            Signal(
                name="opaque_encoded_blocks",
                score=_clamp(opaque / max(2, n * 0.4)),
                reason=f"{opaque} event(s) contain high-entropy encoded-looking blocks",
            )
        )
    return signals


def behavior_signals(events: Iterable[Event]) -> list[Signal]:
    items = sorted(events, key=lambda e: e.timestamp)
    if len(items) < 4:
        return []
    stamps = [event.timestamp.timestamp() for event in items]
    gaps = [b - a for a, b in pairwise(stamps) if b >= a]
    if not gaps:
        return []
    avg = mean(gaps)
    std = pstdev(gaps) if len(gaps) > 1 else 0.0
    cv = std / avg if avg > 0 else 0.0
    signals: list[Signal] = []

    if len(gaps) >= 4 and cv < 0.18:
        signals.append(
            Signal(
                name="clocklike_cadence",
                score=_clamp((0.18 - cv) / 0.18),
                reason=f"Inter-event timing is unusually regular (CV={cv:.3f})",
                evidence={"mean_gap_seconds": round(avg, 3)},
            )
        )

    hours = {event.timestamp.hour for event in items}
    days = {event.timestamp.date().isoformat() for event in items}
    if len(days) >= 2 and len(hours) >= 12:
        signals.append(
            Signal(
                name="round_the_clock_activity",
                score=_clamp(len(hours) / 20),
                reason=f"Activity spans {len(hours)} UTC hours across {len(days)} days",
            )
        )

    very_fast = sum(1 for gap in gaps if gap <= 1.0)
    if very_fast >= 3:
        signals.append(
            Signal(
                name="machine_latency_bursts",
                score=_clamp(very_fast / max(4, len(gaps) * 0.6)),
                reason=f"{very_fast} transitions occur within one second",
            )
        )
    return signals


def text_repetition_signal(events: Iterable[Event]) -> Signal | None:
    texts = [
        re.sub(r"\s+", " ", event.text.strip().lower())
        for event in events
        if event.text.strip()
    ]
    if len(texts) < 4:
        return None
    counts = Counter(texts)
    repeats = sum(count - 1 for count in counts.values() if count > 1)
    ratio = repeats / len(texts)
    if ratio < 0.2:
        return None
    return Signal(
        name="template_repetition",
        score=_clamp(ratio * 1.5),
        reason=f"{ratio:.0%} of observed messages are exact template repeats",
    )


def pair_signals(events_a: Iterable[Event], events_b: Iterable[Event]) -> list[Signal]:
    a = sorted(events_a, key=lambda e: e.timestamp)
    b = sorted(events_b, key=lambda e: e.timestamp)
    if not a or not b:
        return []
    signals: list[Signal] = []

    latencies: list[float] = []
    for left in a:
        later = [right for right in b if right.timestamp >= left.timestamp]
        if later:
            latencies.append((later[0].timestamp - left.timestamp).total_seconds())
    tight = [x for x in latencies if 0 <= x <= 5]
    if len(tight) >= 3:
        avg = mean(tight)
        spread = pstdev(tight) if len(tight) > 1 else 0.0
        score = _clamp(
            (len(tight) / max(4, len(a) * 0.7)) * (1.0 / (1.0 + spread))
        )
        signals.append(
            Signal(
                name="timing_correlation",
                score=score,
                reason=(
                    f"{len(tight)} B-events follow A within 5s; mean latency {avg:.2f}s"
                ),
                evidence={
                    "mean_latency_seconds": round(avg, 3),
                    "std_latency_seconds": round(spread, 3),
                },
            )
        )

    ids_a: set[str] = set()
    ids_b: set[str] = set()
    for event in a:
        ids_a.update(TOKEN_RE.findall(event.text))
    for event in b:
        ids_b.update(TOKEN_RE.findall(event.text))
    shared = sorted(ids_a & ids_b)
    if shared:
        signals.append(
            Signal(
                name="shared_rare_identifiers",
                score=_clamp(len(shared) / 3),
                reason=f"Actors share {len(shared)} rare identifier(s)",
                evidence={"identifiers": shared[:8]},
            )
        )

    replies = sum(1 for event in b if event.parent_actor_id == a[0].actor_id)
    if replies >= 3:
        signals.append(
            Signal(
                name="explicit_interaction",
                score=_clamp(replies / 6),
                reason=f"{replies} events explicitly reference the other actor",
            )
        )
    return signals
