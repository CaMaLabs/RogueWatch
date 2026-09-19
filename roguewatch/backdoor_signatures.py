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
        name="unitree_g1_control_plane",
        pattern=re.compile(
            r"\b(?:chat_go|bashrunner|btgatt-server|wpa_connect\.sh|"
            r"webrtc(?:-to-)?dds|tcp(?: port)?\s*9991|0xFFE2)\b",
            re.IGNORECASE,
        ),
        base_score=0.82,
        reason="Matches a component or interface documented in the Unitree G1 EDU root-RCE disclosures",
    ),
    BackdoorRule(
        name="unauthenticated_robot_control_plane",
        pattern=re.compile(
            r"\b(?:unauthenticated\s+(?:webrtc|dds|ble|gatt|control|remote)|"
            r"without\s+(?:ble\s+)?pairing|no\s+(?:pairing|credentials)|"
            r"missing authentication for critical function)\b",
            re.IGNORECASE,
        ),
        base_score=0.78,
        reason="Unauthenticated access to a robot control or provisioning plane is described",
    ),
    BackdoorRule(
        name="static_device_crypto_material",
        pattern=re.compile(
            r"\b(?:static|hardcoded|world-readable|device-specific)\s+"
            r"(?:aes(?:-128)?\s+)?(?:key|crypto(?:graphic)?\s+key|secret)\b",
            re.IGNORECASE,
        ),
        base_score=0.70,
        reason="Static or exposed device cryptographic material is described",
    ),
    BackdoorRule(
        name="robot_provisioning_to_root",
        pattern=re.compile(
            r"\b(?:wifi|wi-fi|ble|gatt)\b.{0,180}\b(?:provisioning|ssid|wpa_supplicant)\b"
            r"|\b(?:provisioning|ssid|wpa_supplicant)\b.{0,180}\b(?:root|system\(\)|rce)\b",
            re.IGNORECASE,
        ),
        base_score=0.76,
        reason="Robot provisioning/network configuration is linked to privileged execution",
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

    if "unitree_g1_control_plane" in names and "privileged_remote_control" in names:
        components = ["unitree_g1_control_plane", "privileged_remote_control"]
        for candidate in (
            "unauthenticated_robot_control_plane",
            "static_device_crypto_material",
            "robot_provisioning_to_root",
        ):
            if candidate in names:
                components.append(candidate)
        signals.append(
            Signal(
                name="unitree_g1_privileged_control_chain",
                score=0.96 if len(components) >= 3 else 0.88,
                reason="Unitree G1 control-plane indicators co-occur with privileged execution",
                evidence={
                    "components": components,
                    "cves": ["CVE-2026-76639", "CVE-2026-76640"],
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
