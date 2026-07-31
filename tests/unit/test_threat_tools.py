"""
Tests for the threat-intel tools.

These are the only code paths in the project that talk to the outside world, so the
failure modes that matter are the ones the network produces: throttling, HTML error
pages, partially-populated records and nulls where a string was expected.
"""
import asyncio
import json
from unittest.mock import patch

import pytest

from core.tools import threat_tools


async def _ainvoke(tool, **kwargs):
    """Invoke a LangChain @tool and decode its JSON string result."""
    return json.loads(await tool.ainvoke(kwargs))


# ── score_ioc ─────────────────────────────────────────────────────────────────

class TestScoreIoc:
    async def test_public_ip_scores_above_zero(self):
        out = await _ainvoke(threat_tools.score_ioc, ioc="185.220.101.45")
        assert out["type"] == "ip"
        assert out["risk_score"] == 10

    async def test_private_ip_is_flagged_and_unscored(self):
        out = await _ainvoke(threat_tools.score_ioc, ioc="10.0.1.50")
        assert out["type"] == "ip"
        assert "private_ip" in out["flags"]
        assert out["risk_score"] == 0

    async def test_free_tld_phishing_domain_stacks_flags(self):
        out = await _ainvoke(threat_tools.score_ioc, ioc="secure-login-verify.tk")
        assert out["type"] == "domain"
        assert {"free_tld", "phishing_keyword"} <= set(out["flags"])
        assert out["risk_score"] >= 70

    async def test_score_is_capped_at_100(self):
        out = await _ainvoke(
            threat_tools.score_ioc,
            ioc="secure-login-verify-account-paypal-microsoft-update.tk",
        )
        assert out["risk_score"] == 100

    @pytest.mark.parametrize("digest_len", [32, 40, 64])
    async def test_hex_digests_are_recognised_as_hashes(self, digest_len):
        out = await _ainvoke(threat_tools.score_ioc, ioc="a" * digest_len)
        assert out["type"] == "hash"
        assert out["risk_score"] == 50

    async def test_hex_string_of_the_wrong_length_is_not_a_hash(self):
        out = await _ainvoke(threat_tools.score_ioc, ioc="abc123")
        assert out["type"] == "unknown"

    async def test_empty_ioc_does_not_masquerade_as_a_hash(self):
        """`all(...)` over an empty string is True — the emptiness check must come first."""
        out = await _ainvoke(threat_tools.score_ioc, ioc="   ")
        assert out["type"] == "unknown"
        assert out["risk_score"] == 0
        assert "empty" in out["flags"]

    async def test_ioc_is_whitespace_normalised(self):
        out = await _ainvoke(threat_tools.score_ioc, ioc="  185.220.101.45  ")
        assert out["ioc"] == "185.220.101.45"
        assert out["type"] == "ip"


# ── get_nvd_cve ───────────────────────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status=200, payload=None, raise_json=None):
        self.status = status
        self._payload = payload
        self._raise_json = raise_json

    async def json(self, content_type=None):
        if self._raise_json is not None:
            raise self._raise_json
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, response):
        self._response = response
        self.closed = False

    def get(self, url, params=None, timeout=None):
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        self.closed = True
        return False


def _nvd_payload(metrics: dict, descriptions=None, cve_id="CVE-2021-44228"):
    return {
        "vulnerabilities": [{
            "cve": {
                "id": cve_id,
                "descriptions": descriptions if descriptions is not None else [
                    {"lang": "es", "value": "descripcion"},
                    {"lang": "en", "value": "Log4Shell remote code execution"},
                ],
                "metrics": metrics,
                "published": "2021-12-10T10:15:09.143",
            }
        }]
    }


def _patch_session(response):
    return patch.object(
        threat_tools.aiohttp, "ClientSession", lambda *a, **k: _FakeSession(response)
    )


class TestNvdLookup:
    async def test_cvss_v31_is_read(self):
        payload = _nvd_payload({"cvssMetricV31": [
            {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL", "vectorString": "AV:N"}}
        ]})
        with _patch_session(_FakeResponse(payload=payload)):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert out["cvss_score"] == 10.0
        assert out["severity"] == "CRITICAL"

    async def test_cvss_v30_only_record_is_still_scored(self):
        """
        The regression: only cvssMetricV31 was consulted, so a CVE carrying a 3.0
        score reported `cvss_score: null` and the vuln agent treated a critical as
        unscored.
        """
        payload = _nvd_payload({"cvssMetricV30": [
            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "AV:N"}}
        ]})
        with _patch_session(_FakeResponse(payload=payload)):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2017-0144")
        assert out["cvss_score"] == 9.8
        assert out["severity"] == "CRITICAL"

    async def test_cvss_v2_severity_is_read_off_the_wrapping_entry(self):
        payload = _nvd_payload({"cvssMetricV2": [
            {"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L"}}
        ]})
        with _patch_session(_FakeResponse(payload=payload)):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2014-0160")
        assert out["cvss_score"] == 7.5
        assert out["severity"] == "HIGH"

    async def test_empty_metric_list_does_not_raise(self):
        """`metrics.get("cvssMetricV31", [{}])[0]` raised IndexError on an empty list."""
        payload = _nvd_payload({"cvssMetricV31": [], "cvssMetricV2": []})
        with _patch_session(_FakeResponse(payload=payload)):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2020-0001")
        assert out["cvss_score"] is None
        assert "error" not in out
        assert out["description"]

    async def test_english_description_is_preferred(self):
        with _patch_session(_FakeResponse(payload=_nvd_payload({}))):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert out["description"] == "Log4Shell remote code execution"

    async def test_missing_descriptions_are_tolerated(self):
        with _patch_session(_FakeResponse(payload=_nvd_payload({}, descriptions=[]))):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert out["description"] == ""

    async def test_rate_limit_is_reported_as_such(self):
        with _patch_session(_FakeResponse(status=429)):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert "rate limit" in out["error"].lower()
        assert out["status"] == 429

    async def test_server_error_is_reported_with_its_status(self):
        with _patch_session(_FakeResponse(status=503)):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert out["status"] == 503

    async def test_html_error_body_is_not_a_stack_trace(self):
        response = _FakeResponse(raise_json=ValueError("Attempt to decode JSON with unexpected mimetype"))
        with _patch_session(response):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert out["error"] == "NVD returned a non-JSON body"

    async def test_unknown_cve_returns_not_found(self):
        with _patch_session(_FakeResponse(payload={"vulnerabilities": []})):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-1999-9999")
        assert out["error"] == "CVE not found"

    async def test_timeout_is_reported_without_raising(self):
        with patch.object(
            threat_tools.aiohttp, "ClientSession",
            lambda *a, **k: (_ for _ in ()).throw(asyncio.TimeoutError()),
        ):
            out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="CVE-2021-44228")
        assert "timed out" in out["error"]

    async def test_blank_cve_id_short_circuits(self):
        out = await _ainvoke(threat_tools.get_nvd_cve, cve_id="  ")
        assert out["error"] == "no CVE id supplied"


# ── enrich_ip ─────────────────────────────────────────────────────────────────

class TestEnrichIp:
    async def test_private_ip_skips_the_network_call(self):
        with patch.object(threat_tools, "_rdap_lookup", side_effect=AssertionError("called")):
            out = await _ainvoke(threat_tools.enrich_ip, ip="192.168.1.10")
        assert out["type"] == "private"
        assert out["risk_score"] == 0

    async def test_non_ip_input_is_refused_before_lookup(self):
        with patch.object(threat_tools, "_rdap_lookup", side_effect=AssertionError("called")):
            out = await _ainvoke(threat_tools.enrich_ip, ip="not-an-ip")
        assert out["error"] == "not an IP address"

    async def test_null_org_description_does_not_zero_the_score(self):
        """
        RDAP records carry explicit nulls. `None.upper()` used to throw the whole
        enrichment into the error branch and report risk_score 0 for a host sitting
        in a suspicious ASN.
        """
        record = {"asn": "AS60068", "asn_description": None, "asn_country_code": None,
                  "network": None}
        with patch.object(threat_tools, "_rdap_lookup", return_value=record):
            out = await _ainvoke(threat_tools.enrich_ip, ip="185.220.101.45")
        assert "error" not in out
        assert out["suspicious_asn"] is True
        assert out["risk_score"] == 60

    async def test_risk_factors_accumulate(self):
        record = {"asn": "AS60068", "asn_description": "BULLETPROOF HOSTING LLC",
                  "asn_country_code": "RU", "network": {"cidr": "185.220.0.0/16"}}
        with patch.object(threat_tools, "_rdap_lookup", return_value=record):
            out = await _ainvoke(threat_tools.enrich_ip, ip="185.220.101.45")
        assert out["risk_score"] == 100
        assert out["network"] == "185.220.0.0/16"

    async def test_slow_rdap_lookup_is_abandoned_not_awaited_forever(self):
        """ipwhois sleeps for up to two minutes on RDAP rate limiting, inside a
        pooled worker thread. The tool must give up long before that."""
        def _hang(ip):
            import time
            time.sleep(5)
            return {}

        with patch.object(threat_tools, "RDAP_TOTAL_TIMEOUT", 0.05), \
             patch.object(threat_tools, "_rdap_lookup", _hang):
            out = await _ainvoke(threat_tools.enrich_ip, ip="185.220.101.45")
        assert out["error"] == "RDAP lookup timed out"
        assert out["risk_score"] == 0

    async def test_lookup_failure_is_returned_not_raised(self):
        with patch.object(threat_tools, "_rdap_lookup", side_effect=RuntimeError("rdap down")):
            out = await _ainvoke(threat_tools.enrich_ip, ip="185.220.101.45")
        assert out["error"] == "rdap down"
        assert out["risk_score"] == 0

    async def test_malformed_rdap_response_is_rejected(self):
        with patch.object(threat_tools, "_rdap_lookup", return_value="nonsense"):
            out = await _ainvoke(threat_tools.enrich_ip, ip="185.220.101.45")
        assert out["error"] == "malformed RDAP response"


# ── scan_asset_ports ──────────────────────────────────────────────────────────

class TestScanAssetPorts:
    async def test_hostname_target_is_refused(self):
        out = await _ainvoke(threat_tools.scan_asset_ports, ip="attacker.example.com")
        assert out["error"] == "not an IP address"
        assert out["risk_level"] == "unknown"

    async def test_all_ports_closed_is_low_risk(self):
        async def _refused(host, port):
            raise ConnectionRefusedError

        with patch.object(threat_tools.asyncio, "open_connection", _refused):
            out = await _ainvoke(threat_tools.scan_asset_ports, ip="10.0.1.50")
        assert out["open_ports"] == []
        assert out["risk_level"] == "low"

    async def test_open_port_is_recorded_even_if_teardown_fails(self):
        """The hit used to be appended *after* `wait_closed()`, so a socket that
        errored on close reported a live service as closed."""
        class _Writer:
            def close(self):
                pass

            async def wait_closed(self):
                raise OSError("connection reset during close")

        async def _accept(host, port):
            if port != 22:
                raise ConnectionRefusedError
            return object(), _Writer()

        with patch.object(threat_tools.asyncio, "open_connection", _accept):
            out = await _ainvoke(threat_tools.scan_asset_ports, ip="10.0.1.50")
        assert out["open_ports"] == [22]
        assert out["exposed_services"] == ["SSH"]
        assert out["risk_level"] == "high"
