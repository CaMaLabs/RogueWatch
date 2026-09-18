import pytest

from roguewatch.artifact_hunter import analyze_artifact_bytes, validate_readonly_url


def test_readonly_url_rejects_mutation_query():
    with pytest.raises(PermissionError):
        validate_readonly_url("https://example.com/counter?increment=1")


def test_readonly_url_rejects_mutation_path():
    with pytest.raises(PermissionError):
        validate_readonly_url("https://example.com/api/update/item")


def test_readonly_url_allows_wayback_replay():
    validate_readonly_url(
        "https://web.archive.org/web/20260101000000id_/https://example.com/api/update/item",
        allowed_hosts={"web.archive.org"},
    )


def test_artifact_analysis_emits_hashes_swarm_and_backdoor_markers():
    payload = (
        b"zzNOTE_TEST123 shared message board; "
        b"CSClientDaemon remote access service launches at boot; "
        b"complete remote control uses an access token"
    )

    record = analyze_artifact_bytes(
        payload,
        source_url="memory://fixture",
        source_kind="test",
        media_type="text/plain",
    )

    assert len(record.sha256) == 64
    assert "swarm_zz_namespace" in record.incident_markers
    assert "go1_cloudsail_known_ioc" in record.backdoor_markers
    assert "persistent_hidden_remote_access_pattern" in record.backdoor_markers
