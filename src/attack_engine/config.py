"""Central configuration.

Everything the engine needs to run is expressed here so that no component
reaches into ``os.environ`` on its own. Settings load from environment
variables (prefix ``AE_``) and an optional ``.env`` file. The defaults are
chosen so the whole system runs *in-process with zero external services* —
this is a hard requirement for the test suite.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    DEV = "dev"
    TEST = "test"
    PROD = "prod"


class AuditBackend(str, Enum):
    MEMORY = "memory"
    SQLITE = "sqlite"
    POSTGRES = "postgres"


class EventBusBackend(str, Enum):
    MEMORY = "memory"
    REDIS = "redis"


class GraphBackendKind(str, Enum):
    NETWORKX = "networkx"
    NEO4J = "neo4j"


class SandboxBackend(str, Enum):
    #: Ephemeral, network-scoped container per tool invocation (production).
    DOCKER = "docker"
    #: Run the tool directly on the host. NO isolation — dev/CI convenience only.
    LOCAL = "local"
    #: Never executes anything; returns a canned failure. Used in unit tests.
    NOOP = "noop"


class Settings(BaseSettings):
    """Process-wide settings. Construct via :func:`get_settings`."""

    model_config = SettingsConfigDict(
        env_prefix="AE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
        populate_by_name=True,  # allow field-name init even when an alias is set
    )

    env: Environment = Environment.DEV

    # --- logging ---
    log_level: str = "INFO"
    log_json: bool = False

    # --- audit log (governance) ---
    audit_backend: AuditBackend = AuditBackend.SQLITE
    audit_sqlite_path: Path = Path("./data/audit.db")
    audit_postgres_dsn: SecretStr | None = None

    # --- knowledge graph backend ---
    graph_backend: GraphBackendKind = GraphBackendKind.NETWORKX
    neo4j_url: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr | None = None
    neo4j_database: str = "default"

    # --- event bus (blackboard) ---
    eventbus_backend: EventBusBackend = EventBusBackend.MEMORY
    eventbus_redis_url: str = "redis://localhost:6379/0"
    eventbus_stream_prefix: str = "ae:events"

    # --- tool sandbox ---
    sandbox_backend: SandboxBackend = SandboxBackend.DOCKER
    sandbox_default_timeout_sec: int = 300
    sandbox_image_prefix: str = "attack-engine/tool"
    #: Docker network tool containers join. Empty ⇒ a per-engagement default.
    #: Point this at the range's network (``attack-engine-range_range_net``) so
    #: sandboxed tools can reach the lab targets by their in-scope IPs.
    sandbox_network: str = ""
    #: Read-only source (docker volume name or host path) holding a pre-seeded
    #: nuclei-templates tree, mounted into every nuclei run so scans never phone
    #: home. Seed once with ``nuclei -update-templates``. Empty ⇒ no mount (the
    #: image/default dir is used, which needs internet on first run).
    nuclei_templates_source: str = "ae-nuclei-templates"

    # --- BYOM model gateway (Fireworks AI open-source models via LiteLLM) ---
    fireworks_api_key: SecretStr | None = Field(default=None, alias="FIREWORKS_API_KEY")
    anthropic_api_key: SecretStr | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    model_frontier: str = "fireworks_ai/accounts/fireworks/models/llama-v3p1-70b-instruct"
    model_local: str = "fireworks_ai/accounts/fireworks/models/llama-v3p1-8b-instruct"
    #: When true, the gateway never calls a network provider; a deterministic
    #: mock backs every completion. Default for tests.
    model_mock: bool = False
    model_timeout_sec: int = 120
    model_max_retries: int = 2

    def is_prod(self) -> bool:
        return self.env is Environment.PROD


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton (cached)."""

    return Settings()


def reset_settings_cache() -> None:
    """Clear the cached settings. Tests use this after mutating the env."""

    get_settings.cache_clear()
