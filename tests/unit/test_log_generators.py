"""Unit tests for the SIEM log generators."""
import pytest
from simulation.log_generators.generators import (
    make_normal_auth_log, make_brute_force_log, make_web_log,
    make_port_scan_log, make_data_exfil_log, make_c2_beacon_log,
    generate_batch,
)

REQUIRED_FIELDS = {"id", "timestamp", "source", "log_level", "message", "parsed_fields"}


def _assert_log(log: dict):
    for field in REQUIRED_FIELDS:
        assert field in log, f"Missing field: {field}"
    assert isinstance(log["parsed_fields"], dict)
    assert log["message"]


class TestNormalLogGenerators:
    def test_auth_log_structure(self):
        log = make_normal_auth_log()
        _assert_log(log)
        assert log["source"] == "sshd"

    def test_auth_log_unique_ids(self):
        ids = {make_normal_auth_log()["id"] for _ in range(100)}
        assert len(ids) == 100

    def test_web_log_normal(self):
        log = make_web_log(attack=False)
        _assert_log(log)
        assert log["source"] == "nginx"
        assert log["parsed_fields"]["attack"] is False

    def test_web_log_attack(self):
        log = make_web_log(attack=True)
        _assert_log(log)
        assert log["parsed_fields"]["attack"] is True
        assert any(kw in log["message"].lower() for kw in ["union", "script", "passwd", "or '1'"])


class TestAttackLogGenerators:
    def test_brute_force_structure(self):
        log = make_brute_force_log()
        _assert_log(log)
        assert "failed password" in log["message"].lower()
        assert log["parsed_fields"]["attack_type"] == "brute_force"

    def test_brute_force_specific_ip(self):
        log = make_brute_force_log(target_ip="10.10.10.1")
        assert "10.10.10.1" in log["message"]

    def test_port_scan_structure(self):
        log = make_port_scan_log()
        _assert_log(log)
        assert log["parsed_fields"]["attack_type"] == "port_scan"
        assert log["parsed_fields"]["ports_scanned"] >= 50

    def test_data_exfil_structure(self):
        log = make_data_exfil_log()
        _assert_log(log)
        assert log["log_level"] == "CRITICAL"
        assert log["parsed_fields"]["attack_type"] == "data_exfiltration"
        assert log["parsed_fields"]["size_mb"] >= 50

    def test_c2_beacon_structure(self):
        log = make_c2_beacon_log()
        _assert_log(log)
        assert log["log_level"] == "CRITICAL"
        assert log["parsed_fields"]["attack_type"] == "c2_beacon"
        assert log["parsed_fields"]["interval_s"] in [30, 60, 120, 300]


class TestBatchGeneration:
    def test_batch_size(self):
        batch = generate_batch(size=50, attack_probability=0.0)
        assert len(batch) == 50

    def test_batch_all_have_required_fields(self):
        batch = generate_batch(size=100, attack_probability=0.1)
        for log in batch:
            _assert_log(log)

    def test_zero_attack_probability(self):
        batch = generate_batch(size=200, attack_probability=0.0)
        attack_types = [
            l["parsed_fields"].get("attack_type")
            for l in batch
            if "attack_type" in l.get("parsed_fields", {})
        ]
        assert len(attack_types) == 0

    def test_full_attack_probability(self):
        batch = generate_batch(size=100, attack_probability=1.0)
        attack_types = [
            l["parsed_fields"].get("attack_type")
            for l in batch
            if "attack_type" in l.get("parsed_fields", {})
        ]
        assert len(attack_types) == 100

    @pytest.mark.parametrize("size", [1, 10, 100, 500, 1000])
    def test_various_batch_sizes(self, size):
        batch = generate_batch(size=size, attack_probability=0.1)
        assert len(batch) == size

    def test_attack_ratio_approximate(self):
        batch = generate_batch(size=1000, attack_probability=0.2)
        attacks = sum(1 for l in batch if l.get("parsed_fields", {}).get("attack_type"))
        # Allow ±10% variance
        assert 100 <= attacks <= 300
