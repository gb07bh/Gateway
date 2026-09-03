import os
from typing import Dict, Any, Optional
from sqlalchemy import create_engine, text, Column, String, DateTime, Text, Boolean, Integer, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime, timezone
from app.config import DatabaseConfig

Base = declarative_base()


class DatabaseConnectionError(Exception):
    """Raised when PostgreSQL database engine initialization or connection fails."""
    pass


class AuditLogRecord(Base):
    """PostgreSQL persistent audit table model."""
    __tablename__ = "gateway_audit_logs"

    id = Column(String(64), primary_key=True)
    request_id = Column(String(64), nullable=False, index=True)
    human_uid = Column(String(128), nullable=False, index=True)
    action = Column(String(64), nullable=False)
    project = Column(String(128), nullable=False)
    release = Column(String(128), nullable=False)
    service_account = Column(String(128), nullable=False)
    downstream_execution_id = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False)
    reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ExecutionRecord(Base):
    """PostgreSQL persistent execution record model."""
    __tablename__ = "gateway_execution_records"

    execution_id = Column(String(128), primary_key=True)
    request_id = Column(String(64), nullable=False, index=True)
    project_name = Column(String(128), nullable=False)
    release_name = Column(String(128), nullable=False)
    service_account = Column(String(128), nullable=False)
    triggered_by_user = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class GatewayUser(Base):
    """PostgreSQL persistent user directory mirror model."""
    __tablename__ = "gateway_users"

    uid = Column(String(128), primary_key=True)
    display_name = Column(String(256), nullable=True)
    first_name = Column(String(128), nullable=True)
    last_name = Column(String(128), nullable=True)
    email = Column(String(256), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    last_synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class GatewayLdapGroup(Base):
    """PostgreSQL persistent LDAP group directory model."""
    __tablename__ = "gateway_ldap_groups"

    group_name = Column(String(256), primary_key=True)  # e.g., DAI_ProjectA_DEV
    group_dn = Column(String(512), nullable=True)
    project_name = Column(String(128), nullable=False, index=True)
    role_name = Column(String(64), nullable=False, index=True)
    last_synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class GatewayUserGroupMembership(Base):
    """PostgreSQL persistent user-to-group membership mapping model."""
    __tablename__ = "gateway_user_group_membership"

    user_uid = Column(String(128), ForeignKey("gateway_users.uid", ondelete="CASCADE"), primary_key=True)
    group_name = Column(String(256), ForeignKey("gateway_ldap_groups.group_name", ondelete="CASCADE"), primary_key=True)
    synced_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class GatewayLdapSyncStatus(Base):
    """PostgreSQL persistent log of LDAP sync execution runs."""
    __tablename__ = "gateway_ldap_sync_status"

    id = Column(Integer, primary_key=True, autoincrement=True)
    status = Column(String(32), nullable=False)  # SUCCESS, FAILED, RUNNING
    started_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime(timezone=True), nullable=True)
    users_synced = Column(Integer, default=0)
    groups_synced = Column(Integer, default=0)
    highest_usn = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)


class DatabaseManager:
    """Manages PostgreSQL database engine, connection pooling, and sessions. No SQLite fallback permitted."""

    def __init__(self, config: DatabaseConfig, lazy_connect: bool = True):
        self.config = config
        self.lazy_connect = lazy_connect
        self.engine = self._create_engine_instance()
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def _create_engine_instance(self):
        db_url = f"postgresql://{self.config.user}:{self.config.password}@{self.config.host}:{self.config.port}/{self.config.name}"
        
        try:
            engine = create_engine(
                db_url,
                pool_size=self.config.pool_size,
                max_overflow=self.config.max_overflow,
                pool_timeout=self.config.pool_timeout,
                pool_recycle=self.config.pool_recycle,
                pool_pre_ping=True,
                connect_args={"connect_timeout": 3},
            )
            if not self.lazy_connect:
                with engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
            return engine
        except Exception as exc:
            raise DatabaseConnectionError(
                f"Failed to connect to PostgreSQL database '{self.config.name}' at {self.config.host}:{self.config.port}: {exc}"
            )

    def get_session(self):
        """Returns a new SQLAlchemy session."""
        return self.SessionLocal()

    def _ensure_database_exists(self) -> bool:
        """Attempts to create the target PostgreSQL database if it does not exist when table_creations is enabled."""
        if not getattr(self.config, "table_creations", True):
            return False

        maintenance_db = os.environ.get("POSTGRES_MAINTENANCE_DB", "postgres")
        maint_url = f"postgresql://{self.config.user}:{self.config.password}@{self.config.host}:{self.config.port}/{maintenance_db}"

        try:
            maint_engine = create_engine(
                maint_url,
                isolation_level="AUTOCOMMIT",
                connect_args={"connect_timeout": 3},
            )
            with maint_engine.connect() as conn:
                result = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :dbname"),
                    {"dbname": self.config.name},
                )
                if not result.scalar():
                    conn.execute(text(f'CREATE DATABASE "{self.config.name}"'))
                    maint_engine.dispose()
                    return True
            maint_engine.dispose()
        except Exception:
            # If user lacks CREATEDB privilege or maintenance DB is inaccessible, defer to standard engine connection
            pass
        return False

    def create_tables(self) -> bool:
        """Automatically creates database and tables if config.table_creations is enabled."""
        if getattr(self.config, "table_creations", True):
            self._ensure_database_exists()
            Base.metadata.create_all(bind=self.engine)
            return True
        return False

    def check_health(self) -> Dict[str, Any]:
        """Checks PostgreSQL database connectivity health."""
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return {
                "status": "HEALTHY",
                "engine": "postgresql",
                "host": self.config.host,
                "port": self.config.port,
                "database": self.config.name,
                "pool_size": self.config.pool_size,
            }
        except Exception as e:
            return {
                "status": "UNHEALTHY",
                "engine": "postgresql",
                "error": str(e),
            }
