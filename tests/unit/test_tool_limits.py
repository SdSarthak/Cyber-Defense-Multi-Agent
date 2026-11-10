"""NVD throttling/caching, scan target restrictions, address classification."""
import json
import time
from unittest.mock import patch

import pytest

from core.config import settings
from core.tools import threat_tools
from tests.unit.test_threat_tools import _FakeResponse, _ainvoke, _nvd_payload


class _CountingSession:
    def __init__(self, response, log, headers=None):
        self._response, self._log, self.headers = response, log, headers or {}

    def get(self, url, params=None, timeout=None):
        self._log.append(self.headers)
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _patch(response, log):
    return patch.object(
        threat_tools.aiohttp, "ClientSession",
        lambda *a, **k: _CountingSession(response, log, k.get("headers")),
    )


async def test_successful_lookups_are_cached(fake_cache):
    calls: list = []
    payload = _nvd_payload({"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]})
    with _patch(_FakeResponse(payload=payload), calls):
        first = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        second = await _ainvoke(threat_tools.get_nvd_cve, cve_id="cve-2021-44228")
    assert first == second
    assert len(calls) == 1


async def test_errors_are_not_cached(fake_cache):
    calls: list = []
    with _patch(_FakeResponse(status=403), calls):
        await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
    assert len(calls) == 2


async def test_api_key_is_sent_when_configured(fake_cache, monkeypatch):
    monkeypatch.setattr(settings, "nvd_api_key", "k-123")
    calls: list = []
    with _patch(_FakeResponse(payload=_nvd_payload({})), calls):
        await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
    assert calls[0] == {"apiKey": "k-123"}


async def test_limiter_spaces_requests_beyond_the_quota(monkeypatch):
    monkeypatch.setattr(threat_tools, "NVD_WINDOW_SECONDS", 0.3)
    limiter = threat_tools._NvdLimiter()
    started = time.monotonic()
    for _ in range(limiter.limit() + 1):  # 5 free, the sixth must wait for the window
        await limiter.acquire()
    assert time.monotonic() - started >= 0.25


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "224.0.0.1", "0.0.0.0",
])
async def test_scanner_refuses_special_addresses(ip):
    out = await _ainvoke(threat_tools.scan_asset_ports, ip=ip)
    assert out["error"].startswith("scan refused")


async def test_scanner_honours_the_allow_list(monkeypatch):
    monkeypatch.setattr(settings, "scan_allowed_networks", "10.0.0.0/8, bogus")
    out = await _ainvoke(threat_tools.scan_asset_ports, ip="192.168.1.10")
    assert "outside SCAN_ALLOWED_NETWORKS" in out["error"]
    assert threat_tools._scan_refusal("10.1.2.3") is None


@pytest.mark.parametrize("ip,private", [
    ("10.0.0.1", True), ("100.64.0.9", True), ("fd00::1", True), ("fe80::1", True),
    ("::ffff:10.0.0.1", True), ("198.51.100.23", False), ("8.8.8.8", False),
])
def test_private_address_classification(ip, private):
    assert threat_tools._is_private(ip) is private
