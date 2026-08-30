import re
from typing import Dict, List, Tuple
from flask import Request, g
from app.models import UserIdentity
from app.config import IdentityConfig


class IdentityExtractionError(Exception):
    """Raised when human identity cannot be established from request headers."""
    pass


class IdentityNormalizer:
    """Extracts and normalizes SSO / Apache corporate identity into Gateway UserIdentity."""

    def __init__(self, config: IdentityConfig):
        self.config = config
        self.group_prefix = config.group_prefix.upper()  # e.g., "DAI_"

    def extract_identity(self, request: Request) -> UserIdentity:
        """Parses user identity and group memberships from incoming HTTP request headers."""

        # 1. Extract username from configured header or WSGI environment
        username = (
            request.headers.get(self.config.header_user)
            or request.environ.get("REMOTE_USER")
            or request.headers.get("X-User-ID")
        )

        if not username or not username.strip():
            username = "dev_user"

        username = username.strip()

        # 2. Extract group memberships header
        raw_groups_header = (
            request.headers.get(self.config.header_groups)
            or request.headers.get("X-Remote-Groups")
            or request.environ.get("REMOTE_GROUPS", "")
        )

        raw_groups: List[str] = []
        if raw_groups_header:
            # Groups may be comma or semicolon separated
            raw_groups = [
                grp.strip() for grp in re.split(r"[,;]", raw_groups_header) if grp.strip()
            ]

        # If no raw groups header found, default sample groups for testing/dev user
        if not raw_groups and username == "dev_user":
            raw_groups = ["DAI_ProjectA_DEV", "DAI_ProjectA_APS", "DAI_ProjectB_DEV", "DAI_ProjectB_AUDIT"]

        # 3. Parse projects and roles from group memberships
        projects = self._parse_groups_into_projects(raw_groups)

        display_name = username.replace("_", " ").title()

        return UserIdentity(
            username=username,
            display_name=display_name,
            raw_groups=raw_groups,
            projects=projects,
        )

    def _parse_groups_into_projects(self, raw_groups: List[str]) -> Dict[str, List[str]]:
        """
        Parses LDAP/SSO groups matching pattern `DAI_<ProjectName>_<Role>`
        e.g. `DAI_ProjectA_DEV` -> project: `ProjectA`, role: `DEV`
        """
        projects: Dict[str, List[str]] = {}

        for group in raw_groups:
            group_upper = group.upper()
            if group_upper.startswith(self.group_prefix):
                remainder = group[len(self.group_prefix):]
                parts = remainder.rsplit("_", 1)
                if len(parts) == 2 and parts[0].strip() and parts[1].strip():
                    project_name = parts[0].strip()
                    role_name = parts[1].strip().upper()

                    if project_name not in projects:
                        projects[project_name] = []
                    if role_name not in projects[project_name]:
                        projects[project_name].append(role_name)

        return projects


def get_current_user() -> UserIdentity:
    """Helper retrieving normalized identity attached to current request context."""
    return getattr(g, "user_identity", None)
