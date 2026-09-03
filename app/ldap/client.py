import re
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from app.config import LDAPConfig, CredentialResolver

logger = logging.getLogger("gateway.ldap")


class LdapClientError(Exception):
    """Raised when LDAP connection, bind, or search operation fails."""
    pass


@dataclass
class LdapGroupEntry:
    group_name: str
    group_dn: str
    project_name: str
    role_name: str
    members: List[str] = field(default_factory=list)  # List of member UIDs


@dataclass
class LdapUserEntry:
    uid: str
    display_name: str
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    groups: List[str] = field(default_factory=list)


class LdapClient:
    """Client for querying corporate LDAP/Active Directory with paging, SSL, and mock support."""

    def __init__(self, config: LDAPConfig, credential_resolver: Optional[CredentialResolver] = None):
        self.config = config
        self.credential_resolver = credential_resolver or CredentialResolver()
        self.mock_mode = getattr(config, "mock_mode", False)

    def _parse_dn_for_uid(self, dn_or_val: str) -> str:
        """Extracts username/UID from an LDAP distinguished name (e.g. CN=alice_smith,OU=Users...) or raw UID."""
        if not dn_or_val:
            return ""
        # If it looks like a DN (contains =), extract the leftmost RDN value
        if "=" in dn_or_val:
            first_rdn = dn_or_val.split(",", 1)[0]
            if "=" in first_rdn:
                return first_rdn.split("=", 1)[1].strip()
        return dn_or_val.strip()

    def parse_group_name(self, group_name: str) -> Optional[Tuple[str, str]]:
        """
        Parses group matching pattern <prefix><ProjectName>_<Role>
        e.g., 'DAI_ProjectA_DEV' -> ('ProjectA', 'DEV')
        """
        if not group_name:
            return None
        prefix = self.config.group_prefix
        if not group_name.upper().startswith(prefix.upper()):
            return None

        remainder = group_name[len(prefix):]
        parts = remainder.rsplit("_", 1)
        if len(parts) == 2 and parts[0].strip() and parts[1].strip():
            return parts[0].strip(), parts[1].strip().upper()
        return None

    def test_connection(self) -> Dict[str, Any]:
        """Tests connectivity and bind credentials to the LDAP server."""
        logger.info(f"Initiating LDAP connection test to {self.config.server_uri} (mock_mode={self.mock_mode})")
        if self.mock_mode:
            logger.info("Mock LDAP connection test passed successfully")
            return {
                "status": "SUCCESS",
                "mode": "MOCK",
                "server_uri": self.config.server_uri,
                "message": "Mock LDAP connection verified successfully",
            }

        try:
            from ldap3 import Server, Connection, ALL, Tls
            import ssl

            use_ssl = self.config.server_uri.lower().startswith("ldaps://")
            tls_config = Tls(validate=ssl.CERT_NONE) if use_ssl else None
            server = Server(
                self.config.server_uri,
                get_info=ALL,
                use_ssl=use_ssl,
                tls=tls_config,
                connect_timeout=self.config.sync.timeout_seconds,
            )

            bind_password = self.credential_resolver.resolve(self.config.bind_cred_key)
            conn = Connection(
                server,
                user=self.config.bind_cred_key,
                password=bind_password,
                auto_bind=True,
                receive_timeout=self.config.sync.timeout_seconds,
            )

            # Test search 1 entry on base DN
            conn.search(
                search_base=self.config.base_dn,
                search_filter="(objectClass=*)",
                size_limit=1,
            )
            conn.unbind()

            msg = f"Successfully connected and bound to {self.config.server_uri}"
            logger.info(msg)
            return {
                "status": "SUCCESS",
                "mode": "LIVE",
                "server_uri": self.config.server_uri,
                "message": msg,
            }
        except Exception as e:
            err_msg = f"LDAP connection test failed for {self.config.server_uri}: {e}"
            logger.error(err_msg, exc_info=True)
            raise LdapClientError(err_msg)

    def fetch_groups_and_members(self) -> List[LdapGroupEntry]:
        """Fetches all LDAP groups matching configured filter and extracts member UIDs."""
        if self.mock_mode:
            logger.info("Fetching LDAP directory groups in MOCK mode")
            groups = self._get_mock_groups()
            logger.info(f"Discovered {len(groups)} mock LDAP groups matching prefix '{self.config.group_prefix}'")
            return groups

        try:
            from ldap3 import Server, Connection, ALL, Tls
            import ssl

            use_ssl = self.config.server_uri.lower().startswith("ldaps://")
            tls_config = Tls(validate=ssl.CERT_NONE) if use_ssl else None
            server = Server(
                self.config.server_uri,
                get_info=ALL,
                use_ssl=use_ssl,
                tls=tls_config,
                connect_timeout=self.config.sync.timeout_seconds,
            )

            bind_password = self.credential_resolver.resolve(self.config.bind_cred_key)
            conn = Connection(
                server,
                user=self.config.bind_cred_key,
                password=bind_password,
                auto_bind=True,
                receive_timeout=self.config.sync.timeout_seconds,
            )

            # Build group search filter
            filter_template = self.config.group_filter_template
            search_filter = filter_template.format(
                group_cn_attr=self.config.group_cn_attr,
                group_prefix=self.config.group_prefix,
            )

            group_search_base = self.config.group_search_base or self.config.base_dn
            attributes = [self.config.group_cn_attr, self.config.group_member_attr]

            logger.info(
                f"Executing LDAP paged search: base='{group_search_base}', filter='{search_filter}', page_size={self.config.sync.page_size}"
            )
            entries = conn.extend.standard.paged_search(
                search_base=group_search_base,
                search_filter=search_filter,
                attributes=attributes,
                paged_size=self.config.sync.page_size,
                generator=False,
            )

            results: List[LdapGroupEntry] = []
            total_members_count = 0
            for entry in entries:
                if entry.get("type") != "searchResEntry":
                    continue
                attrs = entry.get("attributes", {})
                raw_cn = attrs.get(self.config.group_cn_attr)
                group_name = raw_cn[0] if isinstance(raw_cn, list) and raw_cn else str(raw_cn or "")
                group_dn = entry.get("dn", "")

                parsed = self.parse_group_name(group_name)
                if not parsed:
                    continue
                project_name, role_name = parsed

                raw_members = attrs.get(self.config.group_member_attr, [])
                if not isinstance(raw_members, list):
                    raw_members = [raw_members] if raw_members else []

                member_uids = [self._parse_dn_for_uid(str(m)) for m in raw_members if m]
                total_members_count += len(member_uids)

                results.append(
                    LdapGroupEntry(
                        group_name=group_name,
                        group_dn=group_dn,
                        project_name=project_name,
                        role_name=role_name,
                        members=member_uids,
                    )
                )

            conn.unbind()
            logger.info(
                f"LDAP search completed: {len(results)} groups discovered with {total_members_count} total membership entries"
            )
            return results
        except Exception as e:
            err_msg = f"Failed to fetch groups from LDAP: {e}"
            logger.error(err_msg, exc_info=True)
            raise LdapClientError(err_msg)

    def fetch_user(self, uid: str) -> Optional[LdapUserEntry]:
        """Fetches metadata and direct groups for a specific user UID (used for Option A JIT)."""
        logger.info(f"Looking up single LDAP user UID '{uid}' (mock_mode={self.mock_mode})")
        if self.mock_mode:
            user = self._get_mock_user(uid)
            if user:
                logger.info(f"Mock LDAP user '{uid}' found: email='{user.email}', groups={user.groups}")
            else:
                logger.warning(f"Mock LDAP user '{uid}' not found")
            return user

        try:
            from ldap3 import Server, Connection, ALL, Tls
            import ssl

            use_ssl = self.config.server_uri.lower().startswith("ldaps://")
            tls_config = Tls(validate=ssl.CERT_NONE) if use_ssl else None
            server = Server(
                self.config.server_uri,
                get_info=ALL,
                use_ssl=use_ssl,
                tls=tls_config,
                connect_timeout=self.config.sync.timeout_seconds,
            )

            bind_password = self.credential_resolver.resolve(self.config.bind_cred_key)
            conn = Connection(
                server,
                user=self.config.bind_cred_key,
                password=bind_password,
                auto_bind=True,
                receive_timeout=self.config.sync.timeout_seconds,
            )

            user_filter = f"({self.config.user_uid_attr}={uid})"
            user_search_base = self.config.user_search_base or self.config.base_dn
            attrs = [
                self.config.user_uid_attr,
                self.config.user_mail_attr,
                self.config.user_display_name_attr,
                self.config.user_first_name_attr,
                self.config.user_last_name_attr,
                "memberOf",
            ]

            conn.search(
                search_base=user_search_base,
                search_filter=user_filter,
                attributes=attrs,
                size_limit=1,
            )

            if not conn.entries:
                conn.unbind()
                return None

            entry = conn.entries[0]
            mail = str(entry[self.config.user_mail_attr]) if self.config.user_mail_attr in entry else None
            display_name = str(entry[self.config.user_display_name_attr]) if self.config.user_display_name_attr in entry else uid
            first_name = str(entry[self.config.user_first_name_attr]) if self.config.user_first_name_attr in entry else None
            last_name = str(entry[self.config.user_last_name_attr]) if self.config.user_last_name_attr in entry else None

            # Extract memberOf groups matching prefix
            raw_groups = []
            if "memberOf" in entry:
                raw_groups = [self._parse_dn_for_uid(str(g)) for g in entry.memberOf]

            matching_groups = [g for g in raw_groups if g.upper().startswith(self.config.group_prefix.upper())]

            conn.unbind()
            return LdapUserEntry(
                uid=uid,
                display_name=display_name,
                email=mail,
                first_name=first_name,
                last_name=last_name,
                groups=matching_groups,
            )
        except Exception as e:
            raise LdapClientError(f"Failed to fetch user '{uid}' from LDAP: {e}")

    # --------------------------------------------------------------------------
    # MOCK DATA PROVIDER FOR TESTING / OFFLINE DEV
    # --------------------------------------------------------------------------
    def _get_mock_groups(self) -> List[LdapGroupEntry]:
        prefix = self.config.group_prefix
        return [
            LdapGroupEntry(
                group_name=f"{prefix}ProjectA_DEV",
                group_dn=f"CN={prefix}ProjectA_DEV,OU=Groups,{self.config.base_dn}",
                project_name="ProjectA",
                role_name="DEV",
                members=["dev_user", "dev_user_1", "alice_smith", "bob_dev"],
            ),
            LdapGroupEntry(
                group_name=f"{prefix}ProjectA_APS",
                group_dn=f"CN={prefix}ProjectA_APS,OU=Groups,{self.config.base_dn}",
                project_name="ProjectA",
                role_name="APS",
                members=["dev_user", "dev_user_1", "alice_smith", "prod_lead"],
            ),
            LdapGroupEntry(
                group_name=f"{prefix}ProjectB_DEV",
                group_dn=f"CN={prefix}ProjectB_DEV,OU=Groups,{self.config.base_dn}",
                project_name="ProjectB",
                role_name="DEV",
                members=["dev_user_1", "bob_dev"],
            ),
            LdapGroupEntry(
                group_name=f"{prefix}ProjectB_AUDIT",
                group_dn=f"CN={prefix}ProjectB_AUDIT,OU=Groups,{self.config.base_dn}",
                project_name="ProjectB",
                role_name="AUDIT",
                members=["dev_user_1", "auditor_jane"],
            ),
            LdapGroupEntry(
                group_name=f"{prefix}ADMIN",
                group_dn=f"CN={prefix}ADMIN,OU=Groups,{self.config.base_dn}",
                project_name="GATEWAY",
                role_name="ADMIN",
                members=["dev_user", "admin_user"],
            ),
        ]

    def _get_mock_user(self, uid: str) -> Optional[LdapUserEntry]:
        mock_directory = {
            "dev_user": LdapUserEntry(
                uid="dev_user",
                display_name="Dev User",
                email="dev.user@company.internal",
                first_name="Dev",
                last_name="User",
                groups=[f"{self.config.group_prefix}ProjectA_DEV", f"{self.config.group_prefix}ProjectA_APS", f"{self.config.group_prefix}ADMIN"],
            ),
            "dev_user_1": LdapUserEntry(
                uid="dev_user_1",
                display_name="Dev User 1",
                email="dev1@company.internal",
                first_name="Dev",
                last_name="One",
                groups=[f"{self.config.group_prefix}ProjectA_DEV", f"{self.config.group_prefix}ProjectA_APS", f"{self.config.group_prefix}ProjectB_DEV"],
            ),
            "alice_smith": LdapUserEntry(
                uid="alice_smith",
                display_name="Alice Smith",
                email="alice.smith@company.internal",
                first_name="Alice",
                last_name="Smith",
                groups=[f"{self.config.group_prefix}ProjectA_DEV", f"{self.config.group_prefix}ProjectA_APS"],
            ),
            "bob_dev": LdapUserEntry(
                uid="bob_dev",
                display_name="Bob Developer",
                email="bob.dev@company.internal",
                first_name="Bob",
                last_name="Dev",
                groups=[f"{self.config.group_prefix}ProjectA_DEV", f"{self.config.group_prefix}ProjectB_DEV"],
            ),
        }
        if uid in mock_directory:
            return mock_directory[uid]
        # Dynamic fallback for arbitrary test users
        clean_name = uid.replace("_", " ").title()
        return LdapUserEntry(
            uid=uid,
            display_name=clean_name,
            email=f"{uid}@company.internal",
            first_name=clean_name.split()[0],
            last_name=clean_name.split()[-1] if len(clean_name.split()) > 1 else "",
            groups=[f"{self.config.group_prefix}ProjectA_DEV"],
        )
