from __future__ import annotations

from datetime import UTC, datetime

from fastapi.testclient import TestClient

from roguewatch.api import app
from roguewatch.models import Event, FindingFamily, Severity
from roguewatch.triage import (
    all_triage_findings,
    backdoor_findings,
    dedupe_findings,
    swarm_findings,
)


def _event(text: str, *, actor: str = "artifact", source: str = "test", event_id: str | None = None) -> Event:
    return Event(
        id=event_id or f"evt-{abs(hash((text, actor))) % 1000000}",
        source=source,
        actor_id=actor,
        timestamp=datetime(2026, 9, 21, tzinfo=UTC),
        text=text,
        url="https://example.com/artifact.txt",
    )


def test_weak_generic_ssh_stays_low_or_absent() -> None:
    findings = backdoor_findings([_event("The maintenance guide mentions normal SSH access.")])

    assert all(item.severity in {Severity.low, Severity.informational} for item in findings)
    assert not any(item.name == "persistent_hidden_remote_access_pattern" for item in findings)


def test_go1_ioc_is_surfaced_with_cve() -> None:
    findings = backdoor_findings([_event("/usr/local/zhexi/cloudsail/csclient CSClientDaemon")])
    known = next(item for item in findings if item.name == "known_cve_2025_2894_artifact")

    assert known.severity in {Severity.high, Severity.critical}
    assert known.cve == "CVE-2025-2894"
    assert known.cwe == "CWE-912"


def test_strong_composite_backdoor_is_high_or_critical() -> None:
    text = (
        "CloudSail reverse tunnel launches at boot using systemctl enable and exposes "
        "complete remote control with root access as hidden remote access."
    )
    findings = backdoor_findings([_event(text)])
    composite = next(item for item in findings if item.name == "persistent_hidden_remote_access_pattern")

    assert composite.severity is Severity.critical
    assert "remote_tunnel_service" in composite.matched_components
    assert "boot_persistence" in composite.matched_components
    assert "privileged_remote_control" in composite.matched_components


def test_swarm_marker_does_not_force_ai_attribution() -> None:
    findings = swarm_findings([_event("zzMAILBOX_AUTH1 heartbeat message board", actor="human-editor")])

    assert findings
    assert all(item.family is FindingFamily.swarm for item in findings)
    assert all("do not prove autonomous AI-agent" in item.details["attribution_caveat"] for item in findings)


def test_finding_deduplication_groups_repeated_identical_findings() -> None:
    events = [
        _event("CloudSail reverse tunnel launches at boot with remote command root access.", event_id="a"),
        _event("CloudSail reverse tunnel launches at boot with remote command root access.", event_id="b"),
    ]
    deduped = dedupe_findings(backdoor_findings(events))

    assert deduped
    assert max(item.group_count for item in deduped) >= 1


def test_propagation_language_only_not_confirmed_replication() -> None:
    findings = all_triage_findings([_event("People discussed a worm and self-replication risk.")])
    prop = next(item for item in findings if item.family is FindingFamily.propagation)

    assert prop.severity in {Severity.low, Severity.informational}
    assert prop.details["confirmed_autonomous_propagation"] is False
    assert prop.details["language_only"] is True


def test_dashboard_api_backdoor_output() -> None:
    client = TestClient(app)
    response = client.post(
        "/events",
        json={
            "source": "unit-test",
            "actor_id": "robot-artifact",
            "text": "CSClientDaemon systemctl enable complete remote control root access",
        },
    )
    assert response.status_code == 200

    findings_response = client.get("/findings/backdoors")
    assert findings_response.status_code == 200
    payload = findings_response.json()
    names = {item["name"] for item in payload["findings"]}
    assert "known_cve_2025_2894_artifact" in names
    assert payload["counts"]["high"] + payload["counts"]["critical"] >= 1
