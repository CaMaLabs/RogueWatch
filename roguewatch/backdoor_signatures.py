from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .models import Event, Signal


@dataclass(frozen=True)
class BackdoorRule:
    name: str
    pattern: re.Pattern[str]
    base_score: float
    reason: str


RULES = (
    BackdoorRule(
        name="remote_tunnel_service",
        pattern=re.compile(
            r"\b(?:cloudsail|csclient|zhexi|nat[ -]?punch(?:er|ing)?|"
            r"reverse[ -]?tunnel|remote[ -]?access[ -]?(?:service|tunnel)|"
            r"p2p[ -]?tunnel)\b",
            re.IGNORECASE,
        ),
        base_score=0.68,
        reason="Remote-access or NAT-traversal tunnel terminology is present",
    ),
    BackdoorRule(
        name="boot_persistence",
        pattern=re.compile(
            r"\b(?:systemctl\s+(?:enable|start)|multi-user\.target\.wants|"
            r"autostart|@reboot|rc\.local|init\.d|startup_manager|"
            r"start(?:s|ed)?\s+on\s+boot|launch(?:es|ed)?\s+at\s+boot)\b",
            re.IGNORECASE,
        ),
        base_score=0.54,
        reason="Boot/startup persistence terminology is present",
    ),
    BackdoorRule(
        name="embedded_auth_material",
        pattern=re.compile(
            r"\b(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|"
            r"hardcoded[_ -]?(?:key|token|password|credential)|"
            r"default[_ -]?(?:password|credential))\b",
            re.IGNORECASE,
        ),
        base_score=0.52,
        reason="Embedded/static authorization material is described",
    ),
    BackdoorRule(
        name="privileged_remote_control",
        pattern=re.compile(
            r"\b(?:complete remote control|remote command|command channel|"
            r"root access|root shell|ssh access|remote code execution|rce|"
            r"execute[_ -]?remote[_ -]?command)\b",
            re.IGNORECASE,
        ),
        base_score=0.70,
        reason="Privileged remote-control or command-execution capability is described",
    ),
    BackdoorRule(
        name="hidden_functionality_language",
        pattern=re.compile(
            r"\b(?:undocumented backdoor|hidden functionality|hidden remote access|"
            r"without (?:the )?(?:owner|user)(?:'s)? (?:knowledge|consent)|"
            r"undeclared remote access)\b",
            re.IGNORECASE,
        ),
        base_score=0.72,
        reason="Text explicitly describes undeclared or hidden control functionality",
    ),
    BackdoorRule(
        name="factory_wifi_autoconnect",
        pattern=re.compile(
            r"(?s)\bnetwork\s*=\s*\{.{0,1200}?\bssid\s*=.{0,500}?"
            r"\b(?:psk|password)\s*=|"
            r"\b(?:factory|default)[ -]?(?:wifi|wi-fi).{0,120}?"
            r"\b(?:autoconnect|auto-connect|connect automatically)\b",
            re.IGNORECASE,
        ),
        base_score=0.48,
        reason="Static Wi-Fi profile or factory autoconnect configuration is present",
    ),
    BackdoorRule(
        name="go1_cloudsail_known_ioc",
        pattern=re.compile(
            r"\b(?:CSClientDaemon|/usr/local/zhexi/cloudsail/csclient|"
            r"Go1_rmTunnel_2025_04_18_e5adb412\.zip)\b",
            re.IGNORECASE,
        ),
        base_score=0.96,
        reason="Matches a public Unitree Go1 CloudSail/tunnel indicator",
    ),
)


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


def backdoor_signals(events: Iterable[Event]) -> list[Signal]:
    items = list(events)
    if not items:
        return []

    signals: list[Signal] = []
    names: set[str] = set()

    for rule in RULES:
        hits = [event for event in items if rule.pattern.search(event.text or "")]
        if not hits:
            continue
        density = len(hits) / len(items)
        score = _clamp(rule.base_score * (0.70 + 0.55 * density))
        signals.append(
            Signal(
                name=rule.name,
                score=score,
                reason=f"{rule.reason}; matched {len(hits)}/{len(items)} event(s)",
                evidence={"event_ids": [event.id for event in hits[:8]]},
            )
        )
        names.add(rule.name)

    remote = "remote_tunnel_service" in names
    persistence = "boot_persistence" in names
    auth = "embedded_auth_material" in names
    privileged = "privileged_remote_control" in names
    hidden = "hidden_functionality_language" in names
    wifi = "factory_wifi_autoconnect" in names

    if remote and persistence and privileged:
        signals.append(
            Signal(
                name="persistent_hidden_remote_access_pattern",
                score=0.94 if hidden else 0.86,
                reason=(
                    "Remote tunnel + boot persistence + privileged control co-occur"
                    + (" with explicit hidden-functionality language" if hidden else "")
                ),
                evidence={
                    "components": [
                        "remote_tunnel_service",
                        "boot_persistence",
                        "privileged_remote_control",
                    ]
                    + (["hidden_functionality_language"] if hidden else [])
                },
            )
        )

    if remote and auth and privileged:
        signals.append(
            Signal(
                name="credential_gated_remote_control_pattern",
                score=0.90,
                reason=(
                    "Remote tunnel + embedded/static authorization + privileged control co-occur"
                ),
                evidence={
                    "components": [
                        "remote_tunnel_service",
                        "embedded_auth_material",
                        "privileged_remote_control",
                    ]
                },
            )
        )

    if wifi and persistence:
        signals.append(
            Signal(
                name="persistent_factory_network_ingress_pattern",
                score=0.74,
                reason="Static/factory Wi-Fi ingress and startup persistence co-occur",
                evidence={
                    "components": [
                        "factory_wifi_autoconnect",
                        "boot_persistence",
                    ]
                },
            )
        )

    if "go1_cloudsail_known_ioc" in names:
        signals.append(
            Signal(
                name="known_cve_2025_2894_artifact",
                score=0.99,
                reason=(
                    "Artifact contains a published Unitree Go1 CloudSail/tunnel IOC "
                    "associated with CVE-2025-2894 / CWE-912"
                ),
                evidence={"cve": "CVE-2025-2894", "cwe": "CWE-912"},
            )
        )

    return signals
