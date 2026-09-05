import json
import uuid
import logging
from typing import Any, Dict, Optional
from flask import g
from app.models import UserIdentity, ReleaseExecutionResult
from app.database import DatabaseManager, AuditLogRecord, ExecutionRecord


class AuditLogger:
    """Helper capturing business and security events into structured audit.log and PostgreSQL persistent database."""

    def __init__(
        self,
        logger: logging.Logger,
        db_manager: Optional[DatabaseManager] = None,
        db_logger: Optional[logging.Logger] = None,
    ):
        self.logger = logger
        self.db_manager = db_manager
        self.db_logger = db_logger

    def log_execution_event(
        self,
        user: UserIdentity,
        action: str,
        result: ReleaseExecutionResult,
        status: str = "SUCCESS",
        reason: Optional[str] = None,
    ) -> None:
        """Records an execution trigger event into audit.log and persists records into PostgreSQL."""
        trace_id = getattr(g, "trace_id", None) or getattr(g, "request_id", None) or result.request_id
        audit_entry = {
            "human_uid": user.username,
            "display_name": user.display_name,
            "action": action,
            "project": result.project_name,
            "release": result.release_name,
            "service_account": result.service_account,
            "trace_id": trace_id,
            "request_id": trace_id,
            "downstream_execution_id": result.execution_id,
            "status": status,
            "message": result.message,
            "reason": reason or "Execution authorized and triggered",
        }

        self.logger.info(
            f"AUDIT EXECUTION {action} by {user.username} on {result.project_name}:{result.release_name} - {status}",
            extra={"context": audit_entry},
        )

        # Persist audit record and execution record into PostgreSQL database (skipped in local mock mode)
        if self.db_manager and not getattr(self.db_manager, "is_mock", False):
            session = self.db_manager.get_session()
            try:
                audit_record = AuditLogRecord(
                    id=f"aud-{uuid.uuid4()}",
                    request_id=trace_id,
                    human_uid=user.username,
                    action=action,
                    project=result.project_name,
                    release=result.release_name,
                    service_account=result.service_account,
                    downstream_execution_id=result.execution_id,
                    status=status,
                    reason=reason or "Execution authorized and triggered",
                )
                session.add(audit_record)

                exec_record = ExecutionRecord(
                    execution_id=result.execution_id,
                    request_id=trace_id,
                    project_name=result.project_name,
                    release_name=result.release_name,
                    service_account=result.service_account,
                    triggered_by_user=user.username,
                    status=result.status,
                    details_json=json.dumps(result.details) if result.details else None,
                )
                session.merge(exec_record)
                session.commit()

                if self.db_logger:
                    self.db_logger.debug(
                        f"Persisted AuditLogRecord and ExecutionRecord '{result.execution_id}' into PostgreSQL",
                        extra={"context": {"trace_id": trace_id, "execution_id": result.execution_id, "status": result.status}},
                    )
            except Exception as ex:
                session.rollback()
                if self.db_logger:
                    self.db_logger.warning(f"Failed to persist audit/execution record to database: {ex}", extra={"context": {"trace_id": trace_id}})
            finally:
                session.close()

    def log_security_event(
        self,
        user: UserIdentity,
        action: str,
        project: str,
        status: str,
        reason: str,
    ) -> None:
        """Records security/authorization decisions into audit.log and PostgreSQL."""
        trace_id = getattr(g, "trace_id", None) or getattr(g, "request_id", "N/A")
        audit_entry = {
            "human_uid": user.username if user else "anonymous",
            "action": action,
            "project": project,
            "trace_id": trace_id,
            "request_id": trace_id,
            "status": status,
            "reason": reason,
        }

        self.logger.warning(
            f"AUDIT SECURITY {action} by {audit_entry['human_uid']} - {status}: {reason}",
            extra={"context": audit_entry},
        )

        if self.db_manager and not getattr(self.db_manager, "is_mock", False):
            session = self.db_manager.get_session()
            try:
                audit_record = AuditLogRecord(
                    id=f"aud-{uuid.uuid4()}",
                    request_id=trace_id,
                    human_uid=user.username if user else "anonymous",
                    action=action,
                    project=project,
                    release="N/A",
                    service_account="N/A",
                    downstream_execution_id=None,
                    status=status,
                    reason=reason,
                )
                session.add(audit_record)
                session.commit()
            except Exception:
                session.rollback()
            finally:
                session.close()
