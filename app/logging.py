import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union, List
from flask import Flask, g, request

SENSITIVE_KEYWORDS = [
    "secret", "pass", "password", "token", "cred", "credential",
    "key", "auth", "authorization", "cookie", "bearer", "private"
]


def sanitize_value(key: str, value: Any) -> Any:
    """Recursively redacts values for keys matching sensitive keywords."""
    if any(s in key.lower() for s in SENSITIVE_KEYWORDS):
        return "***REDACTED***"

    if isinstance(value, dict):
        return {k: sanitize_value(k, v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_value(key, item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for structured log outputs."""

    def __init__(self, log_type: str = "service", node_id: str = "gateway-node-01", is_debug: bool = False):
        super().__init__()
        self.log_type = log_type
        self.node_id = node_id
        self.is_debug = is_debug

    def format(self, record: logging.LogRecord) -> str:
        levelname = record.levelname
        # When Gateway logging level is DEBUG, emit log records with level DEBUG instead of INFO
        if self.is_debug and levelname in ("INFO", "DEBUG"):
            levelname = "DEBUG"

        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": levelname,
            "node_id": self.node_id,
            "log_type": self.log_type,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Inject correlation trace_id / request_id across all loggers
        trace_id = getattr(record, "trace_id", None) or getattr(record, "request_id", None)
        if not trace_id and hasattr(record, "context") and isinstance(record.context, dict):
            trace_id = record.context.get("trace_id") or record.context.get("request_id")
        if not trace_id and Flask and g:
            try:
                trace_id = g.get("trace_id") or g.get("request_id")
            except Exception:
                pass

        if trace_id:
            log_entry["trace_id"] = trace_id
            log_entry["request_id"] = trace_id

        # Merge additional context passed via extra dict with recursive secret redaction
        if hasattr(record, "context") and isinstance(record.context, dict):
            sanitized_context = {
                k: sanitize_value(k, v) for k, v in record.context.items()
            }
            log_entry.update(sanitized_context)

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)


class GatewayLoggers:
    """Container for Gateway structured loggers with dedicated loggers per service component."""

    def __init__(self, log_dir: str, node_id: str = "gateway-node-01", level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.node_id = node_id
        self.level_str = level.upper()
        self.log_level = getattr(logging, self.level_str, logging.INFO)
        self.is_debug = self.level_str == "DEBUG"

        # Core system loggers
        self.audit_logger = self._create_logger("gateway.audit", self.log_dir / "audit.log", "audit", self.log_level)
        self.console_logger = self._create_logger("gateway.console", self.log_dir / "console.log", "console", self.log_level)
        self.service_logger = self._create_logger("gateway.service", self.log_dir / "service.log", "service", self.log_level)

        # Dedicated per-service component loggers
        self.db_logger = self.get_logger("database", log_type="database")
        self.auth_logger = self.get_logger("auth", log_type="auth")
        self.identity_logger = self.get_logger("identity", log_type="identity")
        self.adapter_logger = self.get_logger("adapter", log_type="adapter")
        self.housekeeping_logger = self.get_logger("housekeeping", log_type="housekeeping")
        self.heartbeat_logger = self.get_logger("heartbeat", log_type="heartbeat")
        self.ldap_logger = self.get_logger("ldap", log_type="ldap")

        # Also mirror gateway.ldap into service.log for unified service observability
        svc_handler_ldap = logging.FileHandler(self.log_dir / "service.log", encoding="utf-8")
        svc_handler_ldap.setFormatter(JsonFormatter(log_type="service", node_id=self.node_id, is_debug=self.is_debug))
        self.ldap_logger.addHandler(svc_handler_ldap)


        # Route SQLAlchemy DB queries (DDL create_tables, DML insert/update/select) into database.log and service.log when level is DEBUG
        if self.is_debug:
            sql_logger = logging.getLogger("sqlalchemy.engine")
            sql_logger.setLevel(logging.INFO)
            # Remove any existing unformatted handlers to attach clean JSON handlers
            sql_logger.handlers = []

            db_handler = logging.FileHandler(self.log_dir / "database.log", encoding="utf-8")
            db_handler.setFormatter(JsonFormatter(log_type="database", node_id=self.node_id, is_debug=True))
            sql_logger.addHandler(db_handler)

            svc_handler = logging.FileHandler(self.log_dir / "service.log", encoding="utf-8")
            svc_handler.setFormatter(JsonFormatter(log_type="service", node_id=self.node_id, is_debug=True))
            sql_logger.addHandler(svc_handler)

    def get_logger(self, service_name: str, log_type: str = "service") -> logging.Logger:
        """Returns or creates a dedicated logger for a specific service component (e.g., 'database', 'auth')."""
        logger_name = service_name if service_name.startswith("gateway.") else f"gateway.{service_name}"
        file_name = f"{service_name.replace('gateway.', '')}.log" if service_name not in ("gateway.service", "gateway.audit", "gateway.console") else "service.log"
        return self._create_logger(logger_name, self.log_dir / file_name, log_type, self.log_level)

    def _create_logger(self, name: str, file_path: Path, log_type: str, level: int) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False

        if not logger.handlers:
            handler = logging.FileHandler(file_path, encoding="utf-8")
            handler.setFormatter(JsonFormatter(log_type=log_type, node_id=self.node_id, is_debug=self.is_debug))
            logger.addHandler(handler)

            # Also stream console logger to stdout
            if log_type == "console":
                stream_handler = logging.StreamHandler()
                stream_handler.setFormatter(JsonFormatter(log_type=log_type, node_id=self.node_id, is_debug=self.is_debug))
                logger.addHandler(stream_handler)
        else:
            for h in logger.handlers:
                h.setFormatter(JsonFormatter(log_type=log_type, node_id=self.node_id, is_debug=self.is_debug))

        return logger


def setup_request_correlation(app: Flask, loggers: GatewayLoggers):
    """Flask request middleware for request trace & correlation ID generation and console logging."""

    @app.before_request
    def before_request():
        # Capture header or generate unique UUID trace correlation ID
        correlation_id = (
            request.headers.get("X-Trace-ID")
            or request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        g.trace_id = correlation_id
        g.request_id = correlation_id
        g.start_time = datetime.now(timezone.utc)

    @app.after_request
    def after_request(response):
        duration_ms = 0.0
        if hasattr(g, "start_time"):
            duration_ms = (datetime.now(timezone.utc) - g.start_time).total_seconds() * 1000.0

        trace_id = getattr(g, "trace_id", "")
        response.headers["X-Trace-ID"] = trace_id
        response.headers["X-Request-ID"] = trace_id

        user = getattr(g, "username", "anonymous")
        loggers.console_logger.info(
            f"{request.method} {request.path} {response.status_code} - {duration_ms:.2f}ms",
            extra={
                "context": {
                    "method": request.method,
                    "path": request.path,
                    "status_code": response.status_code,
                    "duration_ms": round(duration_ms, 2),
                    "user": user,
                    "remote_addr": request.remote_addr,
                }
            },
        )
        return response
