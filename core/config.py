from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Google AI Studio
    google_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"

    # PostgreSQL
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "cyberdefense"
    postgres_user: str = "cyberdefense"
    postgres_password: str = "strongpassword123"

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

    @property
    def elasticsearch_url(self) -> str:
        return f"http://{self.elasticsearch_host}:{self.elasticsearch_port}"

    # ChromaDB
    chroma_host: str = "localhost"
    chroma_port: int = 8001
    chroma_collection_threats: str = "threat_intel"
    chroma_collection_vulns: str = "vulnerability_kb"
    chroma_collection_compliance: str = "compliance_policies"

    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_secret_key: str = "supersecretkey_change_in_production"
    api_algorithm: str = "HS256"
    api_access_token_expire_minutes: int = 60
    cors_origins: str = "http://localhost:3000"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    # Threat Intel APIs
    shodan_api_key: str = ""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    otxalienvault_api_key: str = ""

    # Agent Config
    agent_max_iterations: int = 10
    agent_timeout_seconds: int = 120
    threat_detection_interval: int = 30
    log_analysis_batch_size: int = 100
    vuln_scan_interval: int = 3600

    # Simulation
    simulation_mode: bool = True
    simulation_log_rate: int = 10
    simulation_attack_probability: float = 0.05


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
