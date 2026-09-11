from __future__ import annotations

from collections import defaultdict
from itertools import combinations

from .detectors import behavior_signals, pair_signals, protocol_signals, text_repetition_signal
from .models import ActorClass, ChannelFinding, Event, Finding, Signal

SIGNAL_WEIGHTS = {
    "structured_payloads": 0.17,
    "machine_protocol_vocabulary": 0.18,
    "persistent_identifiers": 0.16,
    "opaque_encoded_blocks": 0.10,
    "clocklike_cadence": 0.16,
    "round_the_clock_activity": 0.08,
    "machine_latency_bursts": 0.10,
    "template_repetition": 0.10,
}

CHANNEL_WEIGHTS = {
    "timing_correlation": 0.42,
    "shared_rare_identifiers": 0.38,
    "explicit_interaction": 0.20,
}


def weighted_score(signals: list[Signal], weights: dict[str, float]) -> float:
    total_weight = sum(weights.get(signal.name, 0.0) for signal in signals)
    if not total_weight:
        return 0.0
    raw = sum(weights.get(signal.name, 0.0) * signal.score for signal in signals)
    return min(1.0, raw)


def classify(confidence: float, signals: list[Signal]) -> ActorClass:
    names = {signal.name for signal in signals}
    if confidence >= 0.36 and ("machine_protocol_vocabulary" in names or "structured_payloads" in names) and ("clocklike_cadence" in names or "machine_latency_bursts" in names):
        return ActorClass.ai_agent
    if confidence >= 0.38 and ("clocklike_cadence" in names or "template_repetition" in names):
        return ActorClass.conventional_bot
    if confidence <= 0.12:
        return ActorClass.unknown
    return ActorClass.unknown


def analyze_actors(events: list[Event]) -> list[Finding]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.actor_id].append(event)

    findings: list[Finding] = []
    for actor_id, actor_events in grouped.items():
        signals = behavior_signals(actor_events) + protocol_signals(actor_events)
        repeated = text_repetition_signal(actor_events)
        if repeated:
            signals.append(repeated)
        confidence = weighted_score(signals, SIGNAL_WEIGHTS)
        findings.append(Finding(actor_id=actor_id, classification=classify(confidence, signals), confidence=round(confidence, 4), signals=sorted(signals, key=lambda s: s.score, reverse=True)))
    return sorted(findings, key=lambda finding: finding.confidence, reverse=True)


def analyze_channels(events: list[Event]) -> list[ChannelFinding]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.actor_id].append(event)

    findings: list[ChannelFinding] = []
    for actor_a, actor_b in combinations(sorted(grouped), 2):
        forward = pair_signals(grouped[actor_a], grouped[actor_b])
        reverse = pair_signals(grouped[actor_b], grouped[actor_a])
        signals_by_name: dict[str, Signal] = {}
        for signal in forward + reverse:
            previous = signals_by_name.get(signal.name)
            if previous is None or signal.score > previous.score:
                signals_by_name[signal.name] = signal
        signals = list(signals_by_name.values())
        confidence = weighted_score(signals, CHANNEL_WEIGHTS)
        if confidence < 0.18:
            continue
        findings.append(ChannelFinding(actor_a=actor_a, actor_b=actor_b, confidence=round(confidence, 4), interaction_count=len(grouped[actor_a]) + len(grouped[actor_b]), signals=sorted(signals, key=lambda s: s.score, reverse=True)))
    return sorted(findings, key=lambda finding: finding.confidence, reverse=True)
