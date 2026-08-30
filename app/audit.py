import logging
from typing import Any, Dict, Optional
from flask import g
from app.models import UserIdentity, ReleaseExecutionResult


class AuditLogger:
    """Helper capturing business and security events into structured audit.log."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_execution_event(
        self,
        user: UserIdentity,
        action: str,
        result: ReleaseExecutionResult,
        status: str = "SUCCESS",
        reason: Optional[str] = None,
    ) -> None:
        """Records an execution trigger event into audit.log."""
        audit_entry = {
            "human_uid": user.username,
            "display_name": user.display_name,
            "action": action,
            "project": result.project_name,
            "release": result.release_name,
            "service_account": result.service_account,
            "request_id": result.request_id,
            "downstream_execution_id": result.execution_id,
            "status": status,
            "message": result.message,
            "reason": reason or "Execution authorized and triggered",
        }

        self.logger.info(
            f"AUDIT EXECUTION {action} by {user.username} on {result.project_name}:{result.release_name} - {status}",
            extra={"context": audit_entry},
        )

    def log_security_event(
        self,
        user: UserIdentity,
        action: str,
        project: str,
        status: str,
        reason: str,
    ) -> None:
        """Records security/authorization decisions (including authorization failures)."""
        request_id = getattr(g, "request_id", "N/A")
        audit_entry = {
            "human_uid": user.username if user else "anonymous",
            "action": action,
            "project": project,
            "request_id": request_id,
            "status": status,
            "reason": reason,
        }

        self.logger.warning(
            f"AUDIT SECURITY {action} by {audit_entry['human_uid']} - {status}: {reason}",
            extra={"context": audit_entry},
        )
