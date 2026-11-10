"""Unit tests for Settings configuration."""
import os
import pytest
from unittest.mock import patch


def test_default_settings():
    from core.config import Settings
    s = Settings(_env_file=None)
    assert s.gemini_model == "gemini-2.5-flash"
    assert s.gemini_embedding_model == "models/gemini-embedding-001"
    assert s.postgres_port == 5432
    assert s.redis_port == 6379
    assert s.containment_require_approval is True
    assert s.simulation_inject_escalations is False


@pytest.mark.parametrize("key", ["", "supersecretkey_change_in_production", "short-key"])
def test_known_or_short_signing_key_is_replaced(key):
    """A repo-default key lets anyone mint an admin token; it must never sign one."""
    from core.config import Settings, harden
    s = harden(Settings(_env_file=None, api_secret_key=key, allow_insecure_defaults=False))
    assert s.api_secret_key != key
    assert len(s.api_secret_key) >= 32


def test_strong_signing_key_is_kept():
    from core.config import Settings, harden
    key = "k" * 48
    s = harden(Settings(_env_file=None, api_secret_key=key))
    assert s.api_secret_key == key


def test_insecure_defaults_flag_keeps_the_demo_key():
    from core.config import Settings, harden
    s = harden(Settings(_env_file=None, api_secret_key="", allow_insecure_defaults=True))
    assert s.api_secret_key == "supersecretkey_change_in_production"


@pytest.mark.parametrize("password,weak", [
    ("", True), ("admin123", True), ("change_me_admin_password", True), ("short", True),
    ("a-real-passphrase", False),
])
def test_password_strength_check(password, weak):
    from core.config import Settings
    assert Settings(_env_file=None).insecure_password(password) is weak


def test_postgres_url_format():
    from core.config import Settings
    s = Settings(postgres_user="user", postgres_password="pass",
                 postgres_host="db", postgres_port=5432, postgres_db="mydb")
    assert "postgresql+asyncpg://user:pass@db:5432/mydb" == s.postgres_url


def test_postgres_url_sync_format():
    from core.config import Settings
    s = Settings(postgres_user="u", postgres_password="p",
                 postgres_host="h", postgres_port=5432, postgres_db="d")
    assert s.postgres_url_sync.startswith("postgresql://")


def test_redis_url_without_password():
    from core.config import Settings
    s = Settings(redis_host="localhost", redis_port=6379, redis_db=0, redis_password="")
    assert s.redis_url == "redis://localhost:6379/0"


def test_redis_url_with_password():
    from core.config import Settings
    s = Settings(redis_host="localhost", redis_port=6379, redis_db=0, redis_password="secret")
    assert ":secret@" in s.redis_url


def test_cors_origins_list():
    from core.config import Settings
    s = Settings(cors_origins="http://localhost:3000,http://localhost:3001")
    assert s.cors_origins_list == ["http://localhost:3000", "http://localhost:3001"]


def test_cors_single_origin():
    from core.config import Settings
    s = Settings(cors_origins="http://app.example.com")
    assert s.cors_origins_list == ["http://app.example.com"]


def test_elasticsearch_url():
    from core.config import Settings
    s = Settings(elasticsearch_host="es-host", elasticsearch_port=9200)
    assert s.elasticsearch_url == "http://es-host:9200"


@pytest.mark.parametrize("prob", [0.0, 0.05, 0.5, 1.0])
def test_simulation_attack_probability_range(prob):
    from core.config import Settings
    s = Settings(simulation_attack_probability=prob)
    assert 0.0 <= s.simulation_attack_probability <= 1.0
