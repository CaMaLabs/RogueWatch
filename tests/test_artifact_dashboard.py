from __future__ import annotations

import socket

import pytest

from roguewatch.artifact_hunter import WaybackCapture, analyze_artifact_bytes, validate_readonly_url


def test_artifact_hash_output_and_marker_fields() -> None:
    record = analyze_artifact_bytes(
        b"CloudSail reverse tunnel with CSClientDaemon launches at boot using systemctl enable",
        source_url="submitted://sample",
        media_type="text/plain",
    )

    assert len(record.sha256) == 64
    assert len(record.sha1) == 40
    assert record.source_url == "submitted://sample"
    assert "go1_cloudsail_known_ioc" in record.backdoor_markers
    assert record.bytes_seen > 0


def test_wayback_provenance_fields() -> None:
    capture = WaybackCapture(
        timestamp="20250102030405",
        original_url="https://example.com/a.txt",
        mimetype="text/plain",
        statuscode="200",
        digest="ABCDEF",
    )
    record = analyze_artifact_bytes(
        b"heartbeat zzMAILBOX_AUTH1",
        source_url=capture.replay_url,
        source_kind="wayback",
        wayback_capture=capture,
    )

    assert record.wayback_timestamp == "20250102030405"
    assert record.wayback_original_url == "https://example.com/a.txt"
    assert record.wayback_digest == "ABCDEF"


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/a",
        "http://127.0.0.1/a",
        "http://10.0.0.1/a",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "https://user:pass@example.com/a",
        "https://example.com/update?id=1",
        "https://example.com/a?delete=1",
    ],
)
def test_url_ssrf_and_mutation_rejections(url: str) -> None:
    with pytest.raises((PermissionError, ValueError)):
        validate_readonly_url(url)


def test_redirect_destination_revalidation_rejects_private() -> None:
    with pytest.raises(PermissionError):
        validate_readonly_url("http://127.0.0.1/private", allowed_hosts={"127.0.0.1"})


def test_public_resolution_required(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.2.3.4", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(PermissionError):
        validate_readonly_url("https://public-name.example/a")
