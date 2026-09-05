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
    uid: str = ""
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    is_admin: bool = False

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

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["full_name"] = self.full_name
        return data

    def format_cli_report(self) -> str:
        """Formats the inspection result as a readable CLI text report."""
        lines = [
            "==================================================================",
            "                   SSO V2 IDENTITY INSPECTION REPORT               ",
            "==================================================================",
            f" Username               : {self.username}",
            f" UID                    : {self.uid}",
            f" Full Name              : {self.full_name}",
            f" Display Name           : {self.display_name}",
            f" First Name             : {self.first_name or '(None)'}",
            f" Last Name              : {self.last_name or '(None)'}",
            f" Email                  : {self.email or '(None)'}",
        ]
        if self.is_admin:
            lines.append(" Admin Status           : ADMIN")
        lines.extend([
            f" Dev Fallback Applied   : {self.is_dev_fallback}",
            "------------------------------------------------------------------",
            " [CAPTURED IDENTITY HEADERS]",
        ])

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
        r"^uid$",
        r"^firstname$",
        r"^lastname$",
        r"^first[_-]name$",
        r"^last[_-]name$",
        r"^email$",
        r"^mail$",
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

    def _lookup_header_or_source(self, keys: List[Optional[str]], source: Dict[str, Any]) -> Optional[str]:
        """Case-insensitive search across a dictionary for candidate keys."""
        lower_source = {str(k).lower(): str(v).strip() for k, v in source.items() if v is not None}
        for k in keys:
            if k and k.lower() in lower_source and lower_source[k.lower()]:
                return lower_source[k.lower()]
        return None

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

        # 3. Extract username / UID
        user_candidates = [
            getattr(self.config, "header_user", None),
            "Uid",
            "uid",
            "REMOTE_USER",
            "X-User-ID",
            "x-user-id",
        ]
        username = (
            self._lookup_header_or_source(user_candidates, headers_dict)
            or session_dict.get("username")
            or session_dict.get("user")
            or session_dict.get("email")
        )

        is_dev_fallback = False
        if not username or not str(username).strip():
            username = "dev_user"
            is_dev_fallback = True

        username = str(username).strip()

        # 4. Extract firstName, Lastname, email
        first_name_candidates = [
            getattr(self.config, "header_first_name", None),
            "firstName",
            "firstname",
            "first_name",
            "X-First-Name",
            "x-first-name",
            "givenName",
            "given_name",
        ]
        first_name = (
            self._lookup_header_or_source(first_name_candidates, headers_dict)
            or session_dict.get("first_name")
            or session_dict.get("firstName")
        )

        last_name_candidates = [
            getattr(self.config, "header_last_name", None),
            "Lastname",
            "lastName",
            "lastname",
            "last_name",
            "X-Last-Name",
            "x-last-name",
            "sn",
            "surname",
        ]
        last_name = (
            self._lookup_header_or_source(last_name_candidates, headers_dict)
            or session_dict.get("last_name")
            or session_dict.get("lastName")
        )

        email_candidates = [
            getattr(self.config, "header_email", None),
            "email",
            "Email",
            "mail",
            "X-Email",
            "x-email",
        ]
        email = (
            self._lookup_header_or_source(email_candidates, headers_dict)
            or session_dict.get("email")
            or session_dict.get("mail")
        )

        # 5. Extract raw groups header or session groups
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

        # 6. Parse projects and roles
        projects = self._parse_groups_into_projects(raw_groups)

        # 7. Format display name
        if first_name and last_name:
            display_name = f"{first_name} {last_name}".strip()
        elif first_name:
            display_name = first_name.strip()
        else:
            display_name = username.replace("_", " ").replace(".", " ").title()

        # 8. Determine admin status
        admin_groups = getattr(self.config, "admin_groups", ["DAI_ADMIN", "GATEWAY_ADMIN", "ADMIN"])
        is_admin = (
            username in ("dev_user", "dev_user_1", "admin_user")
            or any(grp.upper() in [ag.upper() for ag in admin_groups] for grp in raw_groups)
            or any("ADMIN" in roles for roles in projects.values())
        )

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
            uid=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            is_admin=is_admin,
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
