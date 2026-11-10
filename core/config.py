import secrets
from functools import lru_cache

import structlog
from pydantic_settings import BaseSettings, SettingsConfigDict

log = structlog.get_logger()

# Values that ship in this repository (config defaults and .env.example). Anyone who
# has read the repo knows them, so they must never be what protects a running server.
KNOWN_DEFAULT_SECRETS = frozenset({
    "",
    "supersecretkey_change_in_production",
    "change_me",
    "changeme",
    "secret",
})
KNOWN_DEFAULT_PASSWORDS = frozenset({
    "",
    "admin",
    "admin123",
    "analyst",
    "analyst123",
    "password",
    "change_me_admin_password",
    "change_me_analyst_password",
})
MIN_SECRET_LENGTH = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Google AI Studio
    google_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    # text-embedding-004 was shut down on 2026-01-14; keep the model configurable so
    # the next retirement is an .env change rather than a code change.
    gemini_embedding_model: str = "models/gemini-embedding-001"
    # Shared across every agent in the process so a burst of work queues instead of
    # tripping 429s. Set to 0 to disable.
    llm_requests_per_minute: float = 10.0
    llm_max_retries: int = 2

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "cyberdefense"
    postgres_user: str = "cyberdefense"
    postgres_password: str = "strongpassword123"
    # Apply Alembic migrations on API startup. Alembic is the only schema source.
    run_migrations_on_startup: bool = True

    @property
    def postgres_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_url_sync(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    # Redis
    redis_host: str = "localhost"
    redis_port: int = 6379
    redis_password: str = ""
    redis_db: int = 0
    redis_socket_timeout: float = 5.0

    @property
    def redis_url(self) -> str:
        if self.redis_password:
            return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/{self.redis_db}"
        return f"redis://{self.redis_host}:{self.redis_port}/{self.redis_db}"

    # Elasticsearch
    elasticsearch_host: str = "localhost"
    elasticsearch_port: int = 9200
    elasticsearch_user: str = "elastic"
    elasticsearch_password: str = "elastic123"
    elasticsearch_enabled: bool = True
    elasticsearch_log_index: str = "cyberdefense-logs"

    @property
    def elasticsearch_url(self) -> str:
        return f"http://{self.elasticsearch_host}:{self.elasticsearch_port}"

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8001
    chroma_collection_threats: str = "threat_intel"
    chroma_collection_vulns: str = "vulnerability_kb"
    chroma_collection_compliance: str = "compliance_policies"
    rag_enabled: bool = True
    # After a retrieval failure, skip RAG for this long instead of retrying every call.
    rag_retry_after_seconds: int = 60

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: str = ""
    api_algorithm: str = "HS256"
    api_access_token_expire_minutes: int = 60
    cors_origins: str = "http://localhost:3000"

    # The /ws socket accepts privileged override commands, so it authenticates the
    # same JWT the REST API does. Disable only for a local, single-user demo.
    websocket_auth_required: bool = True

    # Per-user ceiling on state-changing (non-GET) API calls, which mostly fan out to
    # LLM work. 0 disables the limit.
    api_write_rate_limit_per_minute: int = 30
    # Failed logins allowed per (username, client IP) before a temporary lockout.
    login_max_failures: int = 5
    login_lockout_seconds: int = 900

    # Lets the shipped demo passwords / signing key work. Never enable off-host.
    allow_insecure_defaults: bool = False

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    # Demo credentials — set real values in .env, or wire a real user store
    admin_username: str = "admin"
    admin_password: str = ""
    analyst_username: str = "analyst"
    analyst_password: str = ""

    # Agent Config
    agent_timeout_seconds: int = 120
    # The supervisor waits on routing, every dispatched agent and a follow-up report,
    # so it needs a larger budget than any single agent.
    supervisor_timeout_seconds: int = 420
    log_analysis_batch_size: int = 100
    # "always": every batch goes to the LLM. "on_hits": only batches where the
    # deterministic detector found something suspicious (saves quota). "off": regex only.
    log_analysis_llm_mode: str = "always"

    # Scheduled vulnerability scans. Nothing runs unless targets or CVEs are configured.
    vuln_scan_interval: int = 3600
    vuln_scan_targets: str = ""        # comma-separated IPs
    vuln_watchlist_cves: str = ""      # comma-separated CVE ids
    # When set, scan_asset_ports only probes addresses inside these CIDRs.
    scan_allowed_networks: str = ""
    # NVD: 5 requests / 30s without a key, 50 with one (free at nvd.nist.gov).
    nvd_api_key: str = ""
    nvd_cache_ttl_seconds: int = 86400

    # Persistence
    enable_persistence: bool = True

    # Escalation handling
    escalation_auto_response: bool = True
    escalation_cooldown_seconds: int = 60
    # A lower threat level only replaces a higher one after the higher one has stood
    # this long; raising the level always applies immediately.
    threat_level_hold_seconds: int = 900

    # Containment. "simulate" records what would run; "webhook" POSTs each approved
    # action to containment_webhook_url (a SOAR / firewall automation endpoint).
    containment_mode: str = "simulate"
    containment_webhook_url: str = ""
    containment_webhook_timeout_seconds: float = 10.0
    # Automated containment waits for an admin to approve it unless this is false.
    containment_require_approval: bool = True

    # Simulation
    simulation_mode: bool = True
    simulation_log_rate: int = 1
    simulation_attack_probability: float = 0.05
    simulation_consumer_enabled: bool = True
    simulation_batch_size: int = 100
    simulation_analysis_interval_seconds: int = 60
    # Queued logs older than this are dropped (and counted) instead of analysed late.
    simulation_max_lag_seconds: int = 600
    # Publish escalations straight from the simulator. Off by default so incidents only
    # appear when the detection agents actually catch the injected attack.
    simulation_inject_escalations: bool = False

    # ── Helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def split_csv(value: str) -> list[str]:
        return [v.strip() for v in (value or "").split(",") if v.strip()]

    def insecure_secret_key(self) -> bool:
        key = self.api_secret_key or ""
        return key.lower() in KNOWN_DEFAULT_SECRETS or len(key) < MIN_SECRET_LENGTH

    def insecure_password(self, password: str) -> bool:
        return (password or "").lower() in KNOWN_DEFAULT_PASSWORDS or len(password or "") < 8


def harden(s: Settings) -> Settings:
    """
    Make sure a repo-default signing key never signs a real token.

    A known key lets anyone mint an admin JWT. Instead of refusing to start, swap in a
    random per-process key: tokens stop surviving a restart, which is the right
    trade for a misconfigured deployment. `allow_insecure_defaults` keeps the old
    behaviour for local demos.
    """
    if s.allow_insecure_defaults:
        if not s.api_secret_key:
            s.api_secret_key = "supersecretkey_change_in_production"
        return s
    if s.insecure_secret_key():
        if s.api_secret_key:
            log.warning(
                "config.insecure_secret_key",
                detail="API_SECRET_KEY is a known default or shorter than 32 chars; "
                       "using a random per-process key (tokens will not survive restarts)",
            )
        s.api_secret_key = secrets.token_urlsafe(48)
    return s


@lru_cache
def get_settings() -> Settings:
    return harden(Settings())


settings = get_settings()
