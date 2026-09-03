import os
import subprocess
import shutil
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8080
    node_id: str = "gateway-node-01"


class LoggingConfig(BaseModel):
    dir: str = "logs"
    audit_file: str = "audit.log"
    console_file: str = "console.log"
    service_file: str = "service.log"
    heartbeat_file: str = "heartbeat.log"
    level: str = "INFO"



class IdentityConfig(BaseModel):
    header_user: str = "X-Remote-User"
    header_first_name: str = "X-First-Name"
    header_last_name: str = "X-Last-Name"
    header_email: str = "X-Email"
    header_groups: str = "X-Remote-Groups"
    group_prefix: str = "DAI_"
    admin_groups: list[str] = Field(default_factory=lambda: ["DAI_ADMIN", "GATEWAY_ADMIN", "ADMIN"])


class AuthConfig(BaseModel):
    eval_roles: list[str] = Field(default_factory=lambda: ["DEV", "APS"])


class ClassificationConfig(BaseModel):
    default_provider: str = "tags"
    allowed_tags: Dict[str, list[str]] = Field(default_factory=dict)


class MockAdapterConfig(BaseModel):
    simulate_delay_seconds: float = 0.1


class DigitalAIAdapterConfig(BaseModel):
    url: str = "https://digitalai.company.internal"
    trigger_path: str = "/api/v1/releases/trigger"
    status_path: str = "/api/v1/releases/executions"


class AdaptersConfig(BaseModel):
    active: str = "mock"
    timeout_seconds: int = 30
    mock: MockAdapterConfig = Field(default_factory=MockAdapterConfig)
    digitalai: DigitalAIAdapterConfig = Field(default_factory=DigitalAIAdapterConfig)


class DatabaseConfig(BaseModel):
    host: str = "localhost"
    port: int = 5432
    name: str = "gateway_db"
    user: str = "gateway_user"
    password: str = "gateway_password"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 1800
    table_creations: bool = True


class HousekeepingConfig(BaseModel):
    enabled: bool = True
    retention_days: int = 30
    max_log_size_mb: float = 50.0
    max_disk_usage_percent: float = 85.0
    auto_rotate_logs: bool = True
    purge_db: bool = False


class GatewayConfig(BaseModel):
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    housekeeping: HousekeepingConfig = Field(default_factory=HousekeepingConfig)


class ConfigValidationError(Exception):
    """Raised when application configuration is invalid or missing required keys."""
    pass


class CredentialResolver:
    """Credential provider resolving service account credentials via `getCred` CLI/binary with fallback."""

    def __init__(self, executable_path: Optional[str] = None):
        self.executable_path = executable_path or shutil.which("getCred")

    def resolve(self, credential_key: str) -> str:
        """Resolves secret credential key via getCred executable or environment fallback."""
        if not credential_key:
            raise ValueError("Credential key cannot be empty")

        if self.executable_path and os.path.exists(self.executable_path):
            try:
                res = subprocess.run(
                    [self.executable_path, credential_key],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=True,
                )
                return res.stdout.strip()
            except Exception as exc:
                raise RuntimeError(f"Failed to resolve credential '{credential_key}' via getCred: {exc}")

        # Fallback for dev/test when getCred CLI is not installed on OS
        env_val = os.environ.get(f"CRED_{credential_key.upper()}")
        if env_val:
            return env_val

        # Simulated fallback for mock environment
        return f"mock_secret_for_{credential_key}"


def load_config(config_path: Optional[str] = None) -> GatewayConfig:
    """Loads and validates YAML configuration from disk."""
    if not config_path:
        base_dir = Path(__file__).resolve().parent.parent
        config_path = str(base_dir / "config" / "gateway.yaml")

    path = Path(config_path)
    if not path.exists():
        raise ConfigValidationError(f"Configuration file not found at: {config_path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
    except Exception as e:
        raise ConfigValidationError(f"Failed to parse YAML configuration: {e}")

    try:
        validated_config = GatewayConfig(**raw_data)
        return validated_config
    except Exception as e:
        raise ConfigValidationError(f"Configuration validation failed: {e}")
