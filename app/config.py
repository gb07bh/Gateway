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
    source: str = "ldap"  # "ldap" or "mock"
    header_user: str = "X-Remote-User"
    header_first_name: str = "X-First-Name"
    header_last_name: str = "X-Last-Name"
    header_email: str = "X-Email"
    header_groups: Optional[str] = "X-Remote-Groups"
    group_prefix: str = "DAI_"
    ldap_config_path: str = "config/ldap.yaml"
    admin_groups: list[str] = Field(default_factory=lambda: ["DAI_ADMIN", "GATEWAY_ADMIN", "ADMIN"])


class LDAPSyncConfig(BaseModel):
    interval_minutes: int = 15
    page_size: int = 500
    timeout_seconds: int = 10
    jit_fallback_enabled: bool = True
    incremental: bool = False
    prune_missing_users: bool = False


class LDAPConfig(BaseModel):
    enabled: bool = True
    server_uri: str = "ldaps://ad.company.internal:636"
    base_dn: str = "DC=company,DC=internal"
    user_search_base: str = "OU=Users,DC=company,DC=internal"
    group_search_base: str = "OU=Groups,DC=company,DC=internal"
    group_prefix: str = "DAI_"
    group_cn_attr: str = "cn"
    group_member_attr: str = "member"
    group_filter_template: str = "(&(objectClass=group)({group_cn_attr}={group_prefix}*))"
    user_uid_attr: str = "sAMAccountName"
    user_mail_attr: str = "mail"
    user_display_name_attr: str = "displayName"
    user_first_name_attr: str = "givenName"
    user_last_name_attr: str = "sn"
    nested_groups_enabled: bool = False
    bind_cred_key: str = "gateway_ldap_bind_account"
    mock_mode: bool = False
    sync: LDAPSyncConfig = Field(default_factory=LDAPSyncConfig)


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
    mode: str = "production"
    server: ServerConfig = Field(default_factory=ServerConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    identity: IdentityConfig = Field(default_factory=IdentityConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    classification: ClassificationConfig = Field(default_factory=ClassificationConfig)
    adapters: AdaptersConfig = Field(default_factory=AdaptersConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    housekeeping: HousekeepingConfig = Field(default_factory=HousekeepingConfig)
    ldap: Optional[LDAPConfig] = None

    @property
    def is_local_mode(self) -> bool:
        """Returns True if Gateway is configured for local standalone mock mode."""
        return (self.mode or "").strip().lower() == "local"


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


def load_ldap_config(config_path: Optional[str] = None) -> LDAPConfig:
    """Loads and validates LDAP YAML configuration from disk."""
    if not config_path:
        base_dir = Path(__file__).resolve().parent.parent
        config_path = str(base_dir / "config" / "ldap.yaml")

    path = Path(config_path)
    if not path.is_absolute():
        base_dir = Path(__file__).resolve().parent.parent
        path = base_dir / path

    if not path.exists():
        # Fallback to default LDAP configuration if file does not exist yet
        return LDAPConfig()

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}
    except Exception as e:
        raise ConfigValidationError(f"Failed to parse LDAP YAML configuration: {e}")

    ldap_data = raw_data.get("ldap", raw_data)
    try:
        return LDAPConfig(**ldap_data)
    except Exception as e:
        raise ConfigValidationError(f"LDAP configuration validation failed: {e}")


def save_ldap_config(config_path: Optional[str], update_dict: Dict[str, Any]) -> LDAPConfig:
    """Safely updates non-secret LDAP configuration settings in ldap.yaml."""
    if not config_path:
        base_dir = Path(__file__).resolve().parent.parent
        config_path = str(base_dir / "config" / "ldap.yaml")

    path = Path(config_path)
    if not path.is_absolute():
        base_dir = Path(__file__).resolve().parent.parent
        path = base_dir / path

    raw_data = {}
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            raw_data = yaml.safe_load(f) or {}

    current_ldap = raw_data.get("ldap", {})
    if not isinstance(current_ldap, dict):
        current_ldap = {}

    # Disallow injecting raw secret values into YAML
    disallowed_keys = {"password", "secret", "bind_password", "token"}
    for k in disallowed_keys:
        update_dict.pop(k, None)

    # Deep merge update_dict into current_ldap
    for k, v in update_dict.items():
        if isinstance(v, dict) and isinstance(current_ldap.get(k), dict):
            current_ldap[k].update(v)
        else:
            current_ldap[k] = v

    raw_data["ldap"] = current_ldap

    # Validate before saving
    validated = LDAPConfig(**current_ldap)

    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(raw_data, f, default_flow_style=False, sort_keys=False)

    return validated


def load_config(config_path: Optional[str] = None) -> GatewayConfig:
    """Loads and validates YAML configuration from disk."""
    if not config_path:
        base_dir = Path(__file__).resolve().parent.parent
        primary_path = base_dir / "config" / "gateway.yaml"
        fallback_path = base_dir / "config" / "gateway.yml"
        if primary_path.exists():
            config_path = str(primary_path)
        elif fallback_path.exists():
            config_path = str(fallback_path)
        else:
            config_path = str(primary_path)

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
        # Load LDAP config if enabled or specified
        ldap_path = getattr(validated_config.identity, "ldap_config_path", "config/ldap.yaml")
        try:
            validated_config.ldap = load_ldap_config(ldap_path)
        except Exception:
            validated_config.ldap = LDAPConfig()
        return validated_config
    except Exception as e:
        raise ConfigValidationError(f"Configuration validation failed: {e}")
