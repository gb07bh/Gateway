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

    def __init__(self, log_type: str = "service", node_id: str = "gateway-node-01"):
        super().__init__()
        self.log_type = log_type
        self.node_id = node_id

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "node_id": self.node_id,
            "log_type": self.log_type,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Inject correlation request_id if available
        request_id = getattr(record, "request_id", None)
        if not request_id and Flask and g and g.get("request_id"):
            request_id = g.get("request_id")
        if request_id:
            log_entry["request_id"] = request_id

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
    """Container for the 3 Gateway structured loggers."""

    def __init__(self, log_dir: str, node_id: str = "gateway-node-01", level: str = "INFO"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.node_id = node_id
        log_level = getattr(logging, level.upper(), logging.INFO)

        self.audit_logger = self._create_logger("gateway.audit", self.log_dir / "audit.log", "audit", log_level)
        self.console_logger = self._create_logger("gateway.console", self.log_dir / "console.log", "console", log_level)
        self.service_logger = self._create_logger("gateway.service", self.log_dir / "service.log", "service", log_level)

        # Route SQLAlchemy DB queries (DDL create_tables, DML insert/update/select) into service.log when level is DEBUG
        if level.upper() == "DEBUG":
            sql_logger = logging.getLogger("sqlalchemy.engine")
            sql_logger.setLevel(logging.INFO)
            if not sql_logger.handlers:
                handler = logging.FileHandler(self.log_dir / "service.log", encoding="utf-8")
                handler.setFormatter(JsonFormatter(log_type="service", node_id=self.node_id))
                sql_logger.addHandler(handler)

    def _create_logger(self, name: str, file_path: Path, log_type: str, level: int) -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        logger.propagate = False

        if not logger.handlers:
            handler = logging.FileHandler(file_path, encoding="utf-8")
            handler.setFormatter(JsonFormatter(log_type=log_type, node_id=self.node_id))
            logger.addHandler(handler)

            # Also stream console logger to stdout
            if log_type == "console":
                stream_handler = logging.StreamHandler()
                stream_handler.setFormatter(JsonFormatter(log_type=log_type, node_id=self.node_id))
                logger.addHandler(stream_handler)

        return logger


def setup_request_correlation(app: Flask, loggers: GatewayLoggers):
    """Flask request middleware for request correlation ID generation and console logging."""

    @app.before_request
    def before_request():
        # Capture header or generate unique UUID request correlation ID
        correlation_id = request.headers.get("X-Correlation-ID") or request.headers.get("X-Request-ID") or str(uuid.uuid4())
        g.request_id = correlation_id
        g.start_time = datetime.now(timezone.utc)

    @app.after_request
    def after_request(response):
        duration_ms = 0.0
        if hasattr(g, "start_time"):
            duration_ms = (datetime.now(timezone.utc) - g.start_time).total_seconds() * 1000.0

        response.headers["X-Request-ID"] = getattr(g, "request_id", "")

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
