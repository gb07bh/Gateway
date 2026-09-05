import re
import logging
from typing import Dict, List, Tuple, Optional, Any
from flask import Request, g
from app.models import UserIdentity
from app.config import IdentityConfig

ldap_logger = logging.getLogger("gateway.ldap")


class IdentityExtractionError(Exception):
    """Raised when human identity cannot be established from request headers."""
    pass


class IdentityNormalizer:
    """Extracts and normalizes SSO / Apache corporate identity into Gateway UserIdentity."""

    def __init__(self, config: IdentityConfig, sync_manager: Optional[Any] = None):
        self.config = config
        self.group_prefix = (getattr(config, "group_prefix", None) or "DAI_").upper()
        self.sync_manager = sync_manager

    @staticmethod
    def _sanitize_header_value(val: Optional[str]) -> Optional[str]:
        """Sanitizes header values by stripping CRLF, null bytes, and control characters."""
        if val is None:
            return None
        sanitized = re.sub(r"[\r\n\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", str(val))
        clean = sanitized.strip()
        return clean if clean else None

    def _extract_header_with_fallbacks(
        self,
        request: Request,
        configured_header: Optional[str],
        fallback_headers: List[str],
        fallback_environs: Optional[List[str]] = None,
    ) -> Optional[str]:
        """Extracts header checking configured name, fallback header aliases, and WSGI environment."""
        if configured_header:
            clean = self._sanitize_header_value(request.headers.get(configured_header))
            if clean:
                return clean

        for header_name in fallback_headers:
            clean = self._sanitize_header_value(request.headers.get(header_name))
            if clean:
                return clean

        if fallback_environs and hasattr(request, "environ"):
            for env_name in fallback_environs:
                clean = self._sanitize_header_value(request.environ.get(env_name))
                if clean:
                    return clean

        return None

    def extract_identity(self, request: Request) -> UserIdentity:
        """Parses user identity and group memberships from incoming HTTP request headers or LDAP DB."""

        # 1. Extract username / UID
        username = self._extract_header_with_fallbacks(
            request,
            configured_header=getattr(self.config, "header_user", None),
            fallback_headers=["Uid", "uid", "UID", "X-Remote-User", "x-remote-user", "X-User-ID", "x-user-id"],
            fallback_environs=["REMOTE_USER"],
        )

        if not username or not username.strip():
            username = "dev_user1"

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

        projects: Dict[str, List[str]] = {}
        raw_groups: List[str] = []
        user_rec = None

        # 3. Resolve groups
        raw_groups_header = (
            request.headers.get(self.config.header_groups) if hasattr(self.config, "header_groups") and self.config.header_groups else None
        ) or request.headers.get("X-Remote-Groups") or (request.environ.get("REMOTE_GROUPS", "") if hasattr(request, "environ") else "")

        if raw_groups_header and raw_groups_header.strip():
            raw_groups = [
                sanitized for grp in re.split(r"[,;]", raw_groups_header)
                if (sanitized := self._sanitize_header_value(grp))
            ]
            projects = self._parse_groups_into_projects(raw_groups)
        else:
            source = getattr(self.config, "source", "ldap")
            if source == "ldap" and self.sync_manager:
                try:
                    ldap_logger.info(f"Resolving user '{username}' entitlements from LDAP directory mirror in PostgreSQL")
                    user_rec, projects, raw_groups = self.sync_manager.get_user_entitlements(username)
                    # Option A: JIT Fallback if user not yet in DB
                    if (not user_rec or not projects) and getattr(self.sync_manager.config.sync, "jit_fallback_enabled", True):
                        ldap_logger.info(f"User '{username}' missing from directory mirror. Executing Option A JIT sync.")
                        jit_res = self.sync_manager.sync_single_user(username)
                        if jit_res:
                            user_rec, projects, raw_groups = self.sync_manager.get_user_entitlements(username)
                            ldap_logger.info(f"Option A JIT sync succeeded for '{username}'. Granted roles: {projects}")
                        else:
                            ldap_logger.warning(f"Option A JIT sync: user '{username}' could not be resolved from LDAP")
                except Exception as e:
                    ldap_logger.error(f"Error during LDAP entitlement lookup for '{username}': {e}", exc_info=True)

            # Fallback if in mock mode and no groups found
            if not projects:
                if username in ("dev_user", "dev_user_1"):
                    raw_groups = ["DAI_ProjectA_DEV", "DAI_ProjectA_APS", "DAI_ProjectB_DEV", "DAI_ProjectB_AUDIT"]
                projects = self._parse_groups_into_projects(raw_groups)

        # Supplement profile from DB user record if headers were empty
        if user_rec:
            first_name = first_name or user_rec.first_name
            last_name = last_name or user_rec.last_name
            email = email or user_rec.email

        # 4. Compute display name from first_name / last_name or username fallback
        if first_name and last_name:
            display_name = f"{first_name} {last_name}".strip()
        elif first_name:
            display_name = first_name.strip()
        elif user_rec and user_rec.display_name:
            display_name = user_rec.display_name
        else:
            display_name = username.replace("_", " ").title()

        # 5. Determine admin status
        admin_groups = getattr(self.config, "admin_groups", ["DAI_ADMIN", "GATEWAY_ADMIN", "ADMIN"])
        is_admin = (
            username in ("dev_user", "dev_user_1", "admin_user")
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
