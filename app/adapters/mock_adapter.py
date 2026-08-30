import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.adapters.base import BaseAdapter, AdapterError
from app.models import ReleaseExecutionRequest, ReleaseExecutionResult, UserIdentity
from app.config import MockAdapterConfig


class MockAdapter(BaseAdapter):
    """Mock implementation of downstream adapter for testing without external systems."""

    _executions_store: Dict[str, ReleaseExecutionResult] = {}

    def __init__(self, config: Optional[MockAdapterConfig] = None):
        self.config = config or MockAdapterConfig()

    def trigger_release(
        self,
        request: ReleaseExecutionRequest,
        service_account_cred: str,
        user: UserIdentity,
        request_id: str,
    ) -> ReleaseExecutionResult:
        """Simulates triggering a downstream release pipeline."""
        if self.config.simulate_delay_seconds > 0:
            time.sleep(self.config.simulate_delay_seconds)

        # Generate mock downstream execution ID
        execution_id = f"MOCK-EXEC-{uuid.uuid4().hex[:8].upper()}"
        service_account = f"{request.project_name}_{request.execution_role}_sa".lower()

        comment_context = f"Triggered by Gateway user '{user.username}' (ReqID: {request_id})"

        result = ReleaseExecutionResult(
            execution_id=execution_id,
            status="IN_PROGRESS",
            project_name=request.project_name,
            release_name=request.release_name,
            service_account=service_account,
            triggered_by_user=user.username,
            request_id=request_id,
            message=f"Mock release execution successfully triggered. {comment_context}",
            details={
                "classification_tag": request.classification_tag,
                "downstream_provider": "MockEngine",
                "execution_comment": comment_context,
            },
        )

        MockAdapter._executions_store[execution_id] = result
        return result

    def get_execution_status(self, execution_id: str) -> ReleaseExecutionResult:
        """Retrieves or simulates progress for a mock execution."""
        if execution_id not in MockAdapter._executions_store:
            raise AdapterError(f"Mock execution ID '{execution_id}' not found")

        record = MockAdapter._executions_store[execution_id]
        # Transition IN_PROGRESS -> COMPLETED on status checks
        if record.status == "IN_PROGRESS":
            record.status = "COMPLETED"
            record.message = "Mock release execution completed successfully"

        return record

    def check_health(self) -> Dict[str, Any]:
        """Returns mock adapter readiness status."""
        return {
            "status": "HEALTHY",
            "adapter": "MockAdapter",
            "active_mock_executions": len(MockAdapter._executions_store),
        }
