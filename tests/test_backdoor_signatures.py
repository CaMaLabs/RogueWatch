from roguewatch.backdoor_signatures import backdoor_signals
from roguewatch.models import Event


def test_go1_style_hidden_remote_access_composite():
    events = [
        Event(
            source="fixture",
            actor_id="firmware",
            text=(
                "Undocumented backdoor uses a remote access service with NAT punching. "
                "The client launches at boot under systemd and provides complete remote control "
                "when an access token is accepted."
            ),
        )
    ]

    names = {signal.name for signal in backdoor_signals(events)}

    assert "remote_tunnel_service" in names
    assert "boot_persistence" in names
    assert "embedded_auth_material" in names
    assert "privileged_remote_control" in names
    assert "hidden_functionality_language" in names
    assert "persistent_hidden_remote_access_pattern" in names
    assert "credential_gated_remote_control_pattern" in names


def test_known_go1_indicator_is_high_confidence():
    events = [
        Event(
            source="fixture",
            actor_id="firmware",
            text="CSClientDaemon starts /usr/local/zhexi/cloudsail/csclient at boot",
        )
    ]

    signals = {signal.name: signal for signal in backdoor_signals(events)}

    assert "go1_cloudsail_known_ioc" in signals
    assert "known_cve_2025_2894_artifact" in signals
    assert signals["known_cve_2025_2894_artifact"].score == 0.99


def test_generic_legitimate_ssh_reference_does_not_form_composite():
    events = [
        Event(
            source="fixture",
            actor_id="docs",
            text="SSH access is available to administrators for maintenance.",
        )
    ]

    names = {signal.name for signal in backdoor_signals(events)}

    assert names == {"privileged_remote_control"}
    assert "persistent_hidden_remote_access_pattern" not in names
