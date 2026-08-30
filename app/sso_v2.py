import re
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional
from app.config import IdentityConfig, load_config
from app.models import UserIdentity


@dataclass
class SSOInspectionResultV2:
    """Detailed inspection report capturing all SSO header and session attributes."""
    username: str
    display_name: str
    raw_groups: List[str] = field(default_factory=list)
    projects: Dict[str, List[str]] = field(default_factory=dict)
    captured_identity_headers: Dict[str, str] = field(default_factory=dict)
    captured_session: Dict[str, Any] = field(default_factory=dict)
    all_headers: Dict[str, str] = field(default_factory=dict)
    all_session_keys: List[str] = field(default_factory=list)
    is_dev_fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def format_cli_report(self) -> str:
        """Formats the inspection result as a readable CLI text report."""
        lines = [
            "==================================================================",
            "                   SSO V2 IDENTITY INSPECTION REPORT               ",
            "==================================================================",
            f" Username               : {self.username}",
            f" Display Name           : {self.display_name}",
            f" Dev Fallback Applied   : {self.is_dev_fallback}",
            "------------------------------------------------------------------",
            " [CAPTURED IDENTITY HEADERS]",
        ]

        if self.captured_identity_headers:
            for k, v in self.captured_identity_headers.items():
                lines.append(f"   - {k}: {v}")
        else:
            lines.append("   (None detected)")

        lines.extend([
            "------------------------------------------------------------------",
            " [CAPTURED SESSION VALUES]",
        ])
        if self.captured_session:
            for k, v in self.captured_session.items():
                lines.append(f"   - {k}: {v}")
        else:
            lines.append("   (None detected)")

        lines.extend([
            "------------------------------------------------------------------",
            " [RAW GROUP MEMBERSHIPS]",
        ])
        if self.raw_groups:
            for grp in self.raw_groups:
                lines.append(f"   - {grp}")
        else:
            lines.append("   (No groups extracted)")

        lines.extend([
            "------------------------------------------------------------------",
            " [PARSED PROJECTS & ROLES]",
        ])
        if self.projects:
            for proj, roles in self.projects.items():
                lines.append(f"   - Project: {proj} -> Roles: {', '.join(roles)}")
        else:
            lines.append("   (No project mappings resolved)")

        lines.extend([
            "------------------------------------------------------------------",
            f" Total HTTP Headers Received : {len(self.all_headers)}",
            f" Total Session Keys Received : {len(self.all_session_keys)}",
            "==================================================================",
        ])

        return "\n".join(lines)


class SSOInspectorV2:
    """
    Enhanced SSO V2 Identity Inspector & Normalizer.
    Inspects incoming HTTP headers and session state, capturing all identity-related
    attributes without dropping unparsed data.
    """

    KNOWN_IDENTITY_HEADER_PATTERNS = [
        r"^x-remote-",
        r"^x-user-",
        r"^x-authenticated-",
        r"^remote-",
        r"^authorization$",
        r"^cookie$",
        r"^sso-",
        r"^saml-",
        r"^oidc-",
    ]

    def __init__(self, config: Optional[IdentityConfig] = None):
        if config is None:
            # Fallback to default load if config is not passed
            try:
                config = load_config().identity
            except Exception:
                config = IdentityConfig()
        self.config = config
        self.group_prefix = config.group_prefix.upper()

    def inspect(
        self,
        headers: Optional[Dict[str, str]] = None,
        session: Optional[Dict[str, Any]] = None,
        request: Optional[Any] = None
    ) -> SSOInspectionResultV2:
        """
        Inspects headers and session inputs, capturing all identity attributes.
        Supports dictionary inputs or Flask request objects.
        """
        headers_dict: Dict[str, str] = {}
        session_dict: Dict[str, Any] = {}

        # 1. Extract headers from request object or passed dictionary
        if request is not None:
            if hasattr(request, "headers"):
                headers_dict = dict(request.headers)
            if hasattr(request, "environ"):
                for k, v in request.environ.items():
                    if isinstance(v, str):
                        headers_dict[k] = v

        if headers:
            headers_dict.update(headers)

        if session:
            session_dict.update(session)

        # 2. Capture relevant security/identity headers
        captured_headers = self._capture_identity_headers(headers_dict)

        # 3. Extract username (checking header_user, REMOTE_USER, session user/email, or dev_user fallback)
        username = (
            headers_dict.get(self.config.header_user)
            or headers_dict.get(self.config.header_user.lower())
            or headers_dict.get("REMOTE_USER")
            or headers_dict.get("X-User-ID")
            or headers_dict.get("x-user-id")
            or session_dict.get("username")
            or session_dict.get("user")
            or session_dict.get("email")
        )

        is_dev_fallback = False
        if not username or not str(username).strip():
            username = "dev_user"
            is_dev_fallback = True

        username = str(username).strip()

        # 4. Extract raw groups header or session groups
        raw_groups_header = (
            headers_dict.get(self.config.header_groups)
            or headers_dict.get(self.config.header_groups.lower())
            or headers_dict.get("X-Remote-Groups")
            or headers_dict.get("x-remote-groups")
            or headers_dict.get("REMOTE_GROUPS", "")
        )

        raw_groups: List[str] = []
        if raw_groups_header:
            raw_groups = [grp.strip() for grp in re.split(r"[,;]", str(raw_groups_header)) if grp.strip()]
        elif "groups" in session_dict and isinstance(session_dict["groups"], list):
            raw_groups = [str(g).strip() for g in session_dict["groups"]]
        elif "roles" in session_dict and isinstance(session_dict["roles"], list):
            raw_groups = [str(r).strip() for r in session_dict["roles"]]

        # Default sample groups for dev_user fallback if none provided
        if not raw_groups and username == "dev_user":
            raw_groups = ["DAI_ProjectA_DEV", "DAI_ProjectA_APS", "DAI_ProjectB_DEV", "DAI_ProjectB_AUDIT"]

        # 5. Parse projects and roles
        projects = self._parse_groups_into_projects(raw_groups)
        display_name = username.replace("_", " ").replace(".", " ").title()

        return SSOInspectionResultV2(
            username=username,
            display_name=display_name,
            raw_groups=raw_groups,
            projects=projects,
            captured_identity_headers=captured_headers,
            captured_session=session_dict,
            all_headers=headers_dict,
            all_session_keys=list(session_dict.keys()),
            is_dev_fallback=is_dev_fallback,
        )

    def _capture_identity_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Filters all headers matching known SSO and identity patterns."""
        captured = {}
        for key, val in headers.items():
            key_lower = key.lower()
            for pattern in self.KNOWN_IDENTITY_HEADER_PATTERNS:
                if re.search(pattern, key_lower):
                    captured[key] = val
                    break
        return captured

    def _parse_groups_into_projects(self, raw_groups: List[str]) -> Dict[str, List[str]]:
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
