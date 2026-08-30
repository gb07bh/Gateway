from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from app.models import ReleaseExecutionRequest, ReleaseExecutionResult, UserIdentity


class AdapterError(Exception):
    """Base exception for downstream adapter failures."""
    pass


class AdapterConnectionError(AdapterError):
    """Raised when downstream service is unreachable."""
    pass


class AdapterTimeoutError(AdapterError):
    """Raised when downstream call times out."""
    pass


class BaseAdapter(ABC):
    """Abstract base class contract for all downstream release system adapters."""

    @abstractmethod
    def trigger_release(
        self,
        request: ReleaseExecutionRequest,
        service_account_cred: str,
        user: UserIdentity,
        request_id: str,
    ) -> ReleaseExecutionResult:
        """Triggers release pipeline downstream and returns normalized execution result."""
        pass

    @abstractmethod
    def get_execution_status(self, execution_id: str) -> ReleaseExecutionResult:
        """Retrieves status for an active or completed execution."""
        pass

    @abstractmethod
    def check_health(self) -> Dict[str, Any]:
        """Verifies downstream adapter connectivity and health."""
        pass
