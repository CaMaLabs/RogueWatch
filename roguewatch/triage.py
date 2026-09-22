from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from datetime import datetime

from .backdoor_signatures import backdoor_signals
from .models import Event, FindingFamily, Severity, Signal, TriageFinding
from .swarm_signatures import incident_pattern_signals

BACKDOOR_MARKERS = {
    "remote_tunnel_service",
    "boot_persistence",
    "embedded_auth_material",
    "privileged_remote_control",
    "hidden_functionality_language",
    "factory_wifi_autoconnect",
    "persistent_hidden_remote_access_pattern",
    "credential_gated_remote_control_pattern",
    "persistent_factory_network_ingress_pattern",
    "go1_cloudsail_known_ioc",
    "known_cve_2025_2894_artifact",
    "unitree_g1_control_plane",
    "unauthenticated_robot_control_plane",
    "static_device_crypto_material",
    "robot_provisioning_to_root",
    "unitree_g1_privileged_control_chain",
}

SWARM_MARKERS = {
    "swarm_zz_namespace",
    "swarm_late_sort_backup",
    "swarm_timing_coordination",
    "swarm_heartbeat_beacon",
    "swarm_mailbox_auth",
    "swarm_external_memory",
    "swarm_own_label_signature",
    "multi_marker_swarm_pattern",
}

PROPAGATION_LANGUAGE_RE = re.compile(
    r"\b(?:self[-_ ]?replicat(?:e|es|ed|ing|ion)|propagat(?:e|es|ed|ing|ion)|worm|"
    r"spawn(?:s|ed|ing)?|bootstrap(?:s|ped|ping)?|copy(?:ing|ies|ied)?\s+(?:itself|self))\b",
    re.IGNORECASE,
)
CODE_RE = re.compile(
    r"(?:^#!|\b(?:import|from|def|class|function|subprocess|socket|requests?|httpx|curl|wget|"
    r"powershell|cmd\.exe|chmod|systemctl|crontab|schtasks)\b)",
    re.IGNORECASE | re.MULTILINE,
)
PERSISTENCE_RE = re.compile(r"\b(?:systemctl|crontab|@reboot|startup|launch(?:es)? at boot|init\.d)\b", re.IGNORECASE)
BOOTSTRAP_RE = re.compile(r"\bbootstrap(?:s|ped|ping)?\b|\b(?:install|deploy|provision)\s+(?:agent|worker|node|service)\b", re.IGNORECASE)
CHILD_RE = re.compile(r"\b(?:spawn|fork|create|launch)\s+(?:child|agent|worker|copy|process|instance)\b", re.IGNORECASE)
DESTINATION_RE = re.compile(r"\b(?:new host|peer|destination|remote host|node|replica|fleet)\b", re.IGNORECASE)


def severity_counts(findings: Iterable[TriageFinding]) -> dict[str, int]:
    counts = {item.value: 0 for item in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _latest(events: list[Event]) -> datetime | None:
    return max((event.timestamp for event in events), default=None)


def _event_urls(events: Iterable[Event]) -> list[str]:
    seen: list[str] = []
    for event in events:
        candidate = event.url or event.metadata.get("source_url") or event.metadata.get("retrieved_url")
        if candidate and candidate not in seen:
            seen.append(str(candidate))
    return seen


def _finding_id(*parts: object) -> str:
    raw = "|".join(str(part) for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _components(signal: Signal) -> list[str]:
    components = signal.evidence.get("components") or signal.evidence.get("markers")
    if isinstance(components, list):
        return [str(item) for item in components]
    return [signal.name]


def _backdoor_severity(signal: Signal, names: set[str]) -> Severity:
    if signal.name == "known_cve_2025_2894_artifact":
        if {"remote_tunnel_service", "boot_persistence", "privileged_remote_control"} & names:
            return Severity.critical
        return Severity.high
    if signal.name == "persistent_hidden_remote_access_pattern":
        return Severity.critical if signal.score >= 0.9 else Severity.high
    if signal.name in {"credential_gated_remote_control_pattern", "unitree_g1_privileged_control_chain"}:
        return Severity.high
    if signal.name in {"persistent_factory_network_ingress_pattern"}:
        return Severity.medium
    if len(names & {"remote_tunnel_service", "boot_persistence", "embedded_auth_material", "privileged_remote_control"}) >= 2:
        return Severity.medium
    return Severity.low if signal.score >= 0.5 else Severity.informational


def _swarm_severity(signal: Signal, names: set[str]) -> Severity:
    if signal.name == "multi_marker_swarm_pattern":
        return Severity.high if len(names & SWARM_MARKERS) >= 4 else Severity.medium
    if len(names & SWARM_MARKERS) >= 3:
        return Severity.medium
    return Severity.low


def _propagation_severity(types: set[str]) -> Severity:
    if {"code_like", "persistence", "bootstrap", "child_instance", "destination"} <= types:
        return Severity.critical
    if {"code_like", "bootstrap", "child_instance"} <= types or {"code_like", "persistence", "destination"} <= types:
        return Severity.high
    if len(types - {"language"}) >= 2:
        return Severity.medium
    return Severity.low


def _make_signal_finding(
    *,
    family: FindingFamily,
    signal: Signal,
    events: list[Event],
    severity: Severity,
    actor_id: str | None,
) -> TriageFinding:
    urls = _event_urls(events)
    cve = signal.evidence.get("cve")
    cwe = signal.evidence.get("cwe")
    cves = signal.evidence.get("cves")
    if cve is None and isinstance(cves, list) and cves:
        cve = str(cves[0])
    return TriageFinding(
        id=_finding_id(family.value, actor_id, signal.name, urls[:2]),
        family=family,
        severity=severity,
        name=signal.name,
        score=signal.score,
        confidence=signal.score,
        reason=signal.reason,
        matched_components=_components(signal),
        source=events[0].source if events else None,
        target=events[0].metadata.get("target") if events else None,
        actor_id=actor_id,
        timestamp=_latest(events),
        evidence_ids=[str(item) for item in signal.evidence.get("event_ids", [])],
        cve=str(cve) if cve else None,
        cwe=str(cwe) if cwe else None,
        provenance_url=urls[0] if urls else None,
        source_url=urls[0] if urls else None,
        details=dict(signal.evidence),
    )


def backdoor_findings(events: list[Event]) -> list[TriageFinding]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.actor_id].append(event)
    findings: list[TriageFinding] = []
    for actor_id, actor_events in grouped.items():
        signals = [signal for signal in backdoor_signals(actor_events) if signal.name in BACKDOOR_MARKERS]
        names = {signal.name for signal in signals}
        for signal in signals:
            findings.append(
                _make_signal_finding(
                    family=FindingFamily.backdoor,
                    signal=signal,
                    events=actor_events,
                    severity=_backdoor_severity(signal, names),
                    actor_id=actor_id,
                )
            )
    return dedupe_findings(findings)


def swarm_findings(events: list[Event]) -> list[TriageFinding]:
    grouped: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        grouped[event.actor_id].append(event)
    findings: list[TriageFinding] = []
    for actor_id, actor_events in grouped.items():
        signals = [signal for signal in incident_pattern_signals(actor_events) if signal.name in SWARM_MARKERS]
        names = {signal.name for signal in signals}
        for signal in signals:
            finding = _make_signal_finding(
                family=FindingFamily.swarm,
                signal=signal,
                events=actor_events,
                severity=_swarm_severity(signal, names),
                actor_id=actor_id,
            )
            finding.details["attribution_caveat"] = (
                "Swarm markers are supporting evidence only and do not prove autonomous AI-agent attribution."
            )
            findings.append(finding)
    return dedupe_findings(findings)


def propagation_findings(events: list[Event]) -> list[TriageFinding]:
    findings: list[TriageFinding] = []
    for event in events:
        text = event.text or ""
        evidence_types: set[str] = set()
        if PROPAGATION_LANGUAGE_RE.search(text):
            evidence_types.add("language")
        if CODE_RE.search(text):
            evidence_types.add("code_like")
        if PERSISTENCE_RE.search(text):
            evidence_types.add("persistence")
        if BOOTSTRAP_RE.search(text):
            evidence_types.add("bootstrap")
        if CHILD_RE.search(text):
            evidence_types.add("child_instance")
        if DESTINATION_RE.search(text):
            evidence_types.add("destination")
        if not evidence_types:
            continue
        severity = _propagation_severity(evidence_types)
        findings.append(
            TriageFinding(
                id=_finding_id("propagation", event.actor_id, sorted(evidence_types), event.id),
                family=FindingFamily.propagation,
                severity=severity,
                name="propagation_evidence",
                score=min(1.0, 0.16 * len(evidence_types) + (0.14 if "code_like" in evidence_types else 0.0)),
                confidence=min(1.0, 0.16 * len(evidence_types) + (0.14 if "code_like" in evidence_types else 0.0)),
                reason="Propagation-related evidence types observed: " + ", ".join(sorted(evidence_types)),
                matched_components=sorted(evidence_types),
                source=event.source,
                target=event.metadata.get("target"),
                actor_id=event.actor_id,
                artifact=event.metadata.get("sha256"),
                timestamp=event.timestamp,
                evidence_ids=[event.id],
                provenance_url=event.url,
                source_url=event.url,
                hashes={key: str(event.metadata[key]) for key in ("sha256", "sha1") if key in event.metadata},
                details={
                    "language_only": evidence_types == {"language"},
                    "confirmed_autonomous_propagation": False,
                    "provenance_confidence": event.metadata.get("provenance_confidence", "unknown"),
                },
            )
        )
    return dedupe_findings(findings)


def dedupe_findings(findings: Iterable[TriageFinding]) -> list[TriageFinding]:
    grouped: dict[tuple[object, ...], list[TriageFinding]] = defaultdict(list)
    for finding in findings:
        key = (
            finding.family,
            finding.name,
            finding.actor_id,
            finding.source_url,
            tuple(sorted(finding.hashes.items())),
        )
        grouped[key].append(finding)
    merged: list[TriageFinding] = []
    order = {
        Severity.critical: 0,
        Severity.high: 1,
        Severity.medium: 2,
        Severity.low: 3,
        Severity.informational: 4,
    }
    for items in grouped.values():
        best = min(items, key=lambda item: (order[item.severity], -item.confidence))
        evidence = sorted({evidence_id for item in items for evidence_id in item.evidence_ids})
        best.evidence_ids = evidence[:50]
        best.group_count = len(items)
        merged.append(best)
    return sorted(merged, key=lambda item: (order[item.severity], -item.confidence, item.name))


def all_triage_findings(events: list[Event]) -> list[TriageFinding]:
    return dedupe_findings(
        [*backdoor_findings(events), *swarm_findings(events), *propagation_findings(events)]
    )
