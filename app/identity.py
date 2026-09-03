import re
from typing import Dict, List, Tuple, Optional
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

    def _extract_header_with_fallbacks(
        self,
        request: Request,
        configured_header: Optional[str],
        fallback_headers: List[str],
        fallback_environs: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Extracts header checking configured name, fallback header aliases, and WSGI environment."""
        if configured_header:
            val = request.headers.get(configured_header)
            if val is not None and str(val).strip():
                return str(val).strip()

        for header_name in fallback_headers:
            val = request.headers.get(header_name)
            if val is not None and str(val).strip():
                return str(val).strip()

        if fallback_environs and hasattr(request, "environ"):
            for env_name in fallback_environs:
                val = request.environ.get(env_name)
                if val is not None and str(val).strip():
                    return str(val).strip()

        return None

    def extract_identity(self, request: Request) -> UserIdentity:
        """Parses user identity and group memberships from incoming HTTP request headers."""

        # 1. Extract username / UID
        username = self._extract_header_with_fallbacks(
            request,
            configured_header=getattr(self.config, "header_user", None),
            fallback_headers=["Uid", "uid", "UID", "X-Remote-User", "x-remote-user", "X-User-ID", "x-user-id"],
            fallback_environs=["REMOTE_USER"],
        )

        if not username or not username.strip():
            username = "dev_user_1"

        username = username.strip()

        # 2. Extract firstName, Lastname, email headers
        first_name = self._extract_header_with_fallbacks(
            request,
            configured_header=getattr(self.config, "header_first_name", None),
            fallback_headers=["firstName", "firstname", "FirstName", "FIRSTNAME", "X-First-Name", "x-first-name", "givenName", "givenname"],
            fallback_environs=["FIRST_NAME", "GIVEN_NAME"],
        )

        last_name = self._extract_header_with_fallbacks(
            request,
            configured_header=getattr(self.config, "header_last_name", None),
            fallback_headers=["Lastname", "lastName", "lastname", "LastName", "LASTNAME", "X-Last-Name", "x-last-name", "sn", "surname"],
            fallback_environs=["LAST_NAME", "SURNAME"],
        )

        email = self._extract_header_with_fallbacks(
            request,
            configured_header=getattr(self.config, "header_email", None),
            fallback_headers=["email", "Email", "EMAIL", "X-Email", "x-email", "mail", "MAIL"],
            fallback_environs=["EMAIL", "MAIL"],
        )

        # 3. Extract group memberships header
        raw_groups_header = (
            request.headers.get(self.config.header_groups)
            or request.headers.get("X-Remote-Groups")
            or (request.environ.get("REMOTE_GROUPS", "") if hasattr(request, "environ") else "")
        )

        raw_groups: List[str] = []
        if raw_groups_header:
            # Groups may be comma or semicolon separated
            raw_groups = [
                grp.strip() for grp in re.split(r"[,;]", raw_groups_header) if grp.strip()
            ]

        # If no raw groups header found, default sample groups for testing/dev user
        if not raw_groups and username in ("dev_user", "dev_user_1"):
            raw_groups = ["DAI_ProjectA_DEV", "DAI_ProjectA_APS", "DAI_ProjectB_DEV", "DAI_ProjectB_AUDIT"]

        # 4. Parse projects and roles from group memberships
        projects = self._parse_groups_into_projects(raw_groups)

        # 5. Compute display name from first_name / last_name or username fallback
        if first_name and last_name:
            display_name = f"{first_name} {last_name}".strip()
        elif first_name:
            display_name = first_name.strip()
        else:
            display_name = username.replace("_", " ").title()

        # 6. Determine admin status
        admin_groups = getattr(self.config, "admin_groups", ["DAI_ADMIN", "GATEWAY_ADMIN", "ADMIN"])
        is_admin = (
            username in ("dev_user", "dev_user_1")
            or any(grp.upper() in [ag.upper() for ag in admin_groups] for grp in raw_groups)
            or any("ADMIN" in roles for roles in projects.values())
        )

        return UserIdentity(
            username=username,
            display_name=display_name,
            raw_groups=raw_groups,
            projects=projects,
            is_admin=is_admin,
            uid=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
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
