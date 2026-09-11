import pytest

from roguewatch.collectors.public_http import PublicHttpCollector


def test_collector_rejects_non_allowlisted_host():
    collector = PublicHttpCollector(allowed_hosts={"example.com"})
    with pytest.raises(PermissionError):
        collector._validate_url("https://not-example.com/a")


def test_collector_rejects_authenticated_url():
    collector = PublicHttpCollector(allowed_hosts={"example.com"})
    with pytest.raises(PermissionError):
        collector._validate_url("https://user:pass@example.com/a")
