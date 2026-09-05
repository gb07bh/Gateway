from functools import wraps
from typing import Dict, List, Optional, Tuple
from flask import abort, request, jsonify, current_app
from app.models import UserIdentity, ReleaseExecutionRequest
from app.config import AuthConfig, ClassificationConfig
from app.identity import get_current_user


def admin_required(f):
    """
    Decorator enforcing that the requesting user possesses administrative entitlements
    (is_admin == True). Rejects unauthorized requests with HTTP 403 Forbidden
    and logs a security audit event.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user or not getattr(user, "is_admin", False):
            # Log security audit event if AUDIT_LOGGER is configured
            audit_logger = current_app.config.get("AUDIT_LOGGER") if current_app else None
            if audit_logger:
                username = user.username if user else "anonymous"
                audit_logger.log_security_event(
                    user=user,
                    action="ADMIN_ACCESS_DENIED",
                    project="SYSTEM",
                    status="DENIED",
                    reason=f"Unauthorized non-admin access attempt to '{request.path}' by user '{username}'",
                )

            if request.path.startswith("/api/") or request.is_json:
                return jsonify({
                    "error": "Forbidden",
                    "message": "Administrator privileges required to access this endpoint."
                }), 403

            abort(403, description="Administrator privileges required to access this resource.")

        return f(*args, **kwargs)
    return decorated_function


class AuthorizationError(Exception):
    """Raised when execution authorization fails server-side."""
    pass


class ReleaseClassificationError(Exception):
    """Raised when release classification cannot be validated (fails closed)."""
    pass


class AuthorizationEvaluator:
    """Evaluates project execution authorization and release classification server-side."""

    def __init__(self, auth_config: AuthConfig, class_config: ClassificationConfig):
        self.auth_config = auth_config
        self.class_config = class_config

    def evaluate_execution_request(
        self, user: UserIdentity, request: ReleaseExecutionRequest
    ) -> Tuple[bool, str, str]:
        """
        Evaluates authorization and release classification.
        Returns (is_authorized, service_account_name, reason).
        Fails closed on missing permissions or unclassified tags.
        """
        role = request.execution_role.upper()
        project = request.project_name

        # 1. Validate requested role is evaluated by Gateway (DEV or APS)
        if role not in self.auth_config.eval_roles:
            raise AuthorizationError(
                f"Role '{role}' is not an authorized Gateway execution role. Evaluated roles: {self.auth_config.eval_roles}"
            )

        # 2. Server-side role check
        if not user.has_role(project, role):
            raise AuthorizationError(
                f"User '{user.username}' lacks required role '{role}' for project '{project}'"
            )

        # 3. Release classification evaluation (fail closed)
        self._validate_release_classification(role, request.classification_tag)

        # 4. Resolve service account name
        service_account = f"{project}_{role}_sa".lower()

        return True, service_account, "Authorization and classification verified"

    def _validate_release_classification(self, role: str, tag: str) -> None:
        """Validates release classification tag against allowed configuration per role."""
        if not tag or not tag.strip():
            raise ReleaseClassificationError("Release classification tag is missing or empty (fails closed)")

        clean_tag = tag.strip().lower()
        allowed_tags = self.class_config.allowed_tags.get(role, [])

        if not allowed_tags:
            # Default fallbacks if allowed_tags mapping empty in yaml
            allowed_tags = ["dev", "development", "sandbox"] if role == "DEV" else ["aps", "prod", "production", "release"]

        if clean_tag not in [t.lower() for t in allowed_tags]:
            raise ReleaseClassificationError(
                f"Release classification tag '{tag}' is not authorized for role '{role}'. Allowed tags: {allowed_tags}"
            )
