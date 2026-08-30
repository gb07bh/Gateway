from datetime import datetime, timezone
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class ProjectRole:
    project_name: str
    roles: List[str]  # e.g., ["DEV", "APS", "AUDIT", "DESIGNER"]


@dataclass
class UserIdentity:
    username: str
    display_name: str
    raw_groups: List[str]
    projects: Dict[str, List[str]] = field(default_factory=dict)  # {"ProjectA": ["DEV", "APS"]}

    def has_role(self, project_name: str, role_name: str) -> bool:
        """Returns True if the user holds the specified role in project_name."""
        project_roles = self.projects.get(project_name, [])
        return role_name.upper() in [r.upper() for r in project_roles]

    def get_projects_by_role(self, role_name: str) -> List[str]:
        """Returns all project names where the user holds role_name."""
        target_role = role_name.upper()
        return [
            proj for proj, roles in self.projects.items()
            if target_role in [r.upper() for r in roles]
        ]


@dataclass
class ReleaseExecutionRequest:
    project_name: str
    release_name: str
    execution_role: str  # DEV or APS
    classification_tag: str
    parameters: Dict[str, str] = field(default_factory=dict)


@dataclass
class ReleaseExecutionResult:
    execution_id: str
    status: str  # PENDING, IN_PROGRESS, COMPLETED, FAILED
    project_name: str
    release_name: str
    service_account: str
    triggered_by_user: str
    request_id: str
    message: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, str] = field(default_factory=dict)
