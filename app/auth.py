from typing import Dict, List, Optional, Tuple
from app.models import UserIdentity, ReleaseExecutionRequest
from app.config import AuthConfig, ClassificationConfig


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
