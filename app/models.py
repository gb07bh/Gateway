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
    is_admin: bool = False
    uid: str = ""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None

    def __post_init__(self):
        if not self.uid:
            self.uid = self.username

    @property
    def full_name(self) -> str:
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}".strip()
        if self.first_name:
            return self.first_name
        return self.display_name or self.username

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
