import httpx
from typing import Any, Dict, Optional
from app.adapters.base import BaseAdapter, AdapterError, AdapterConnectionError, AdapterTimeoutError
from app.models import ReleaseExecutionRequest, ReleaseExecutionResult, UserIdentity
from app.config import DigitalAIAdapterConfig


class DigitalAIAdapter(BaseAdapter):
    """
    Production/Pseudo Digital.ai Release REST API adapter.
    Uses AccessToken (Bearer token) authentication and injects SSO user trigger comment.
    """

    def __init__(self, config: Optional[DigitalAIAdapterConfig] = None, timeout_seconds: int = 30):
        self.config = config or DigitalAIAdapterConfig()
        self.timeout_seconds = timeout_seconds

    def trigger_release(
        self,
        request: ReleaseExecutionRequest,
        service_account_cred: str,
        user: UserIdentity,
        request_id: str,
    ) -> ReleaseExecutionResult:
        """Triggers release pipeline execution via Digital.ai REST API."""
        url = f"{self.config.url.rstrip('/')}{self.config.trigger_path}"

        headers = {
            "Authorization": f"Bearer {service_account_cred}",
            "X-Correlation-ID": request_id,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # Mandatory comment formatting with SSO human identity
        execution_comment = f"Triggered by user {user.username}"

        payload = {
            "releaseTitle": request.release_name,
            "project": request.project_name,
            "executionRole": request.execution_role,
            "tags": [request.classification_tag],
            "comment": execution_comment,
            "parameters": request.parameters,
        }

        try:
            with httpx.Client(timeout=float(self.timeout_seconds)) as client:
                response = client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json() or {}

                execution_id = data.get("id") or data.get("execution_id") or f"DAI-EXEC-{request_id[:8]}"
                status = data.get("status") or "IN_PROGRESS"
                service_account = f"{request.project_name}_{request.execution_role}_sa".lower()

                return ReleaseExecutionResult(
                    execution_id=execution_id,
                    status=status,
                    project_name=request.project_name,
                    release_name=request.release_name,
                    service_account=service_account,
                    triggered_by_user=user.username,
                    request_id=request_id,
                    message=f"Digital.ai release execution successfully triggered. {execution_comment}",
                    details={
                        "digitalai_url": url,
                        "comment": execution_comment,
                        "raw_response": data,
                    },
                )
        except httpx.TimeoutException as te:
            raise AdapterTimeoutError(f"Timeout calling Digital.ai endpoint at {url}: {te}")
        except httpx.HTTPStatusError as hse:
            raise AdapterError(
                f"Digital.ai API returned HTTP error status {hse.response.status_code}: {hse.response.text}"
            )
        except httpx.RequestError as re:
            raise AdapterConnectionError(f"Failed to connect to Digital.ai API at {url}: {re}")

    def get_execution_status(self, execution_id: str) -> ReleaseExecutionResult:
        """Retrieves release execution status from Digital.ai endpoint."""
        url = f"{self.config.url.rstrip('/')}{self.config.status_path}/{execution_id}"
        headers = {"Accept": "application/json"}

        try:
            with httpx.Client(timeout=float(self.timeout_seconds)) as client:
                response = client.get(url, headers=headers)
                response.raise_for_status()
                data = response.json() or {}

                return ReleaseExecutionResult(
                    execution_id=execution_id,
                    status=data.get("status", "COMPLETED"),
                    project_name=data.get("project_name", "Unknown"),
                    release_name=data.get("release_name", "Unknown"),
                    service_account=data.get("service_account", "unknown_sa"),
                    triggered_by_user=data.get("triggered_by_user", "unknown"),
                    request_id=data.get("request_id", "N/A"),
                    message=data.get("message", "Digital.ai status retrieved"),
                    details=data,
                )
        except httpx.TimeoutException as te:
            raise AdapterTimeoutError(f"Timeout checking status at {url}: {te}")
        except httpx.RequestError as re:
            raise AdapterConnectionError(f"Failed to connect to Digital.ai status API at {url}: {re}")

    def check_health(self) -> Dict[str, Any]:
        """Checks Digital.ai endpoint reachability."""
        health_url = f"{self.config.url.rstrip('/')}/api/v1/health"
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(health_url)
                is_healthy = response.status_code < 500
                return {
                    "status": "HEALTHY" if is_healthy else "UNHEALTHY",
                    "adapter": "DigitalAIAdapter",
                    "url": self.config.url,
                    "http_status": response.status_code,
                }
        except Exception as e:
            return {
                "status": "UNHEALTHY",
                "adapter": "DigitalAIAdapter",
                "url": self.config.url,
                "error": str(e),
            }
