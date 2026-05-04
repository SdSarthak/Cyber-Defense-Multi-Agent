"""Unit tests for Settings configuration."""
import os
import pytest
from unittest.mock import patch


def test_default_settings():
    from core.config import Settings
    s = Settings()
    assert s.gemini_model == "gemini-2.5-flash"
    assert s.postgres_port == 5432
    assert s.redis_port == 6379
    assert s.agent_max_iterations == 10


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
