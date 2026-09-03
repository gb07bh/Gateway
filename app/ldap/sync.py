import time
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from sqlalchemy import text
from app.config import LDAPConfig, CredentialResolver
from app.database import (
    DatabaseManager,
    GatewayUser,
    GatewayLdapGroup,
    GatewayUserGroupMembership,
    GatewayLdapSyncStatus,
)
from app.ldap.client import LdapClient, LdapClientError, LdapGroupEntry, LdapUserEntry

logger = logging.getLogger("gateway.ldap")

# Unique advisory lock key for LDAP sync cluster coordination
LDAP_SYNC_ADVISORY_LOCK_ID = 551042


class LdapSyncLockError(Exception):
    """Raised when an advisory lock cannot be acquired because another sync is in progress."""
    pass


class LdapSyncManager:
    """Orchestrates LDAP directory synchronization into PostgreSQL with advisory locking and JIT fallback."""

    def __init__(
        self,
        config: LDAPConfig,
        db_manager: DatabaseManager,
        credential_resolver: Optional[CredentialResolver] = None,
    ):
        self.config = config
        self.db_manager = db_manager
        self.credential_resolver = credential_resolver or CredentialResolver()
        self.client = LdapClient(config, self.credential_resolver)

    def _acquire_lock(self, session) -> bool:
        """Attempts to acquire a PostgreSQL session-level advisory lock."""
        try:
            logger.info(f"Attempting to acquire PostgreSQL advisory lock for LDAP sync (lock_id={LDAP_SYNC_ADVISORY_LOCK_ID})")
            res = session.execute(
                text("SELECT pg_try_advisory_lock(:lock_id)"),
                {"lock_id": LDAP_SYNC_ADVISORY_LOCK_ID},
            ).scalar()
            acquired = bool(res)
            if acquired:
                logger.info("PostgreSQL advisory lock acquired successfully.")
            else:
                logger.warning("PostgreSQL advisory lock already held by another node/process. Skipping run.")
            return acquired
        except Exception as e:
            logger.warning(f"Could not check advisory lock (non-critical if DB mock): {e}")
            return True

    def _release_lock(self, session) -> None:
        """Releases the PostgreSQL advisory lock."""
        try:
            session.execute(
                text("SELECT pg_advisory_unlock(:lock_id)"),
                {"lock_id": LDAP_SYNC_ADVISORY_LOCK_ID},
            )
            logger.info("PostgreSQL advisory lock released.")
        except Exception as e:
            logger.debug(f"Advisory lock release note: {e}")

    def run_full_sync(self, dry_run: bool = False) -> Dict[str, Any]:
        """
        Executes full synchronization of LDAP groups and user memberships into PostgreSQL.
        Prevents duplicate runs across nodes using PostgreSQL advisory locks.
        """
        start_time = time.time()
        started_at = datetime.now(timezone.utc)
        logger.info(
            f"Starting LDAP synchronization (dry_run={dry_run}, server='{self.config.server_uri}', prefix='{self.config.group_prefix}', mock={getattr(self.config, 'mock_mode', False)})"
        )
        session = self.db_manager.get_session()

        # 1. Acquire advisory lock
        locked = self._acquire_lock(session)
        if not locked:
            session.close()
            msg = "Another LDAP sync worker is currently running. Skipping duplicate execution."
            logger.warning(msg)
            raise LdapSyncLockError(msg)

        status_record = None
        try:
            # 2. Record RUNNING sync status
            if not dry_run:
                status_record = GatewayLdapSyncStatus(
                    status="RUNNING",
                    started_at=started_at,
                )
                session.add(status_record)
                session.commit()
                logger.info(f"Recorded sync status 'RUNNING' with start time {started_at.isoformat()}")

            # 3. Fetch groups & members from LDAP
            groups = self.client.fetch_groups_and_members()
            synced_groups_count = len(groups)
            all_member_uids = set()

            if not dry_run:
                now_utc = datetime.now(timezone.utc)

                # 1. Collect all distinct member UIDs across all groups
                for grp in groups:
                    for uid in grp.members:
                        if uid:
                            all_member_uids.add(uid)

                logger.info(
                    f"Sync processing: found {synced_groups_count} groups with {len(all_member_uids)} unique member UIDs"
                )

                # 2. Upsert distinct users first
                logger.info(f"Upserting {len(all_member_uids)} user records into gateway_users")
                for uid in all_member_uids:
                    user_rec = session.query(GatewayUser).filter_by(uid=uid).first()
                    if not user_rec:
                        user_rec = GatewayUser(
                            uid=uid,
                            display_name=uid.replace("_", " ").title(),
                            is_active=True,
                            last_synced_at=now_utc,
                        )
                        session.add(user_rec)
                    else:
                        user_rec.is_active = True
                        user_rec.last_synced_at = now_utc

                session.flush()

                # 3. Upsert groups and memberships
                logger.info(f"Upserting {synced_groups_count} group definitions and user-group memberships into PostgreSQL")
                for grp in groups:
                    existing_group = session.query(GatewayLdapGroup).filter_by(group_name=grp.group_name).first()
                    if existing_group:
                        existing_group.group_dn = grp.group_dn
                        existing_group.project_name = grp.project_name
                        existing_group.role_name = grp.role_name
                        existing_group.last_synced_at = now_utc
                    else:
                        new_grp = GatewayLdapGroup(
                            group_name=grp.group_name,
                            group_dn=grp.group_dn,
                            project_name=grp.project_name,
                            role_name=grp.role_name,
                            last_synced_at=now_utc,
                        )
                        session.add(new_grp)

                    for uid in grp.members:
                        if not uid:
                            continue
                        membership = session.query(GatewayUserGroupMembership).filter_by(
                            user_uid=uid, group_name=grp.group_name
                        ).first()
                        if not membership:
                            membership = GatewayUserGroupMembership(
                                user_uid=uid,
                                group_name=grp.group_name,
                                synced_at=now_utc,
                            )
                            session.add(membership)
                        else:
                            membership.synced_at = now_utc

                # Complete status record
                duration = round(time.time() - start_time, 2)
                if status_record:
                    status_record.status = "SUCCESS"
                    status_record.completed_at = datetime.now(timezone.utc)
                    status_record.groups_synced = synced_groups_count
                    status_record.users_synced = len(all_member_uids)
                    session.commit()
                    logger.info(f"Recorded sync status 'SUCCESS' (duration={duration}s)")

            duration = round(time.time() - start_time, 2)
            logger.info(
                f"LDAP synchronization completed: {synced_groups_count} groups, {len(all_member_uids)} users in {duration}s"
            )

            return {
                "status": "SUCCESS",
                "dry_run": dry_run,
                "groups_synced": synced_groups_count,
                "users_synced": len(all_member_uids),
                "duration_seconds": duration,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as e:
            session.rollback()
            logger.error(f"LDAP synchronization failed: {e}", exc_info=True)
            if status_record and not dry_run:
                try:
                    status_record.status = "FAILED"
                    status_record.completed_at = datetime.now(timezone.utc)
                    status_record.error_message = str(e)
                    session.commit()
                except Exception:
                    pass
            raise e
        finally:
            self._release_lock(session)
            session.close()

    def sync_single_user(self, uid: str) -> Optional[Dict[str, List[str]]]:
        """
        Option A (JIT Fallback): Synchronizes a single user and their groups on the fly.
        Called when an authenticated SSO user is not yet present in PostgreSQL.
        Returns the resolved projects/roles dictionary: e.g. {"ProjectA": ["DEV"]}.
        """
        if not uid or not uid.strip():
            return None

        clean_uid = uid.strip()
        logger.info(f"Triggering JIT LDAP single-user sync for UID: '{clean_uid}'")

        user_entry = self.client.fetch_user(clean_uid)
        if not user_entry:
            logger.warning(f"JIT sync: User '{clean_uid}' not found in LDAP directory")
            return None

        session = self.db_manager.get_session()
        try:
            now_utc = datetime.now(timezone.utc)

            # 1. Upsert GatewayUser
            user_rec = session.query(GatewayUser).filter_by(uid=clean_uid).first()
            if not user_rec:
                user_rec = GatewayUser(
                    uid=clean_uid,
                    display_name=user_entry.display_name,
                    first_name=user_entry.first_name,
                    last_name=user_entry.last_name,
                    email=user_entry.email,
                    is_active=True,
                    last_synced_at=now_utc,
                )
                session.add(user_rec)
            else:
                user_rec.display_name = user_entry.display_name or user_rec.display_name
                user_rec.first_name = user_entry.first_name or user_rec.first_name
                user_rec.last_name = user_entry.last_name or user_rec.last_name
                user_rec.email = user_entry.email or user_rec.email
                user_rec.is_active = True
                user_rec.last_synced_at = now_utc

            # 2. Process groups
            projects: Dict[str, List[str]] = {}
            for group_name in user_entry.groups:
                parsed = self.client.parse_group_name(group_name)
                if not parsed:
                    continue
                proj, role = parsed
                if proj not in projects:
                    projects[proj] = []
                if role not in projects[proj]:
                    projects[proj].append(role)

                # Ensure group exists
                grp_rec = session.query(GatewayLdapGroup).filter_by(group_name=group_name).first()
                if not grp_rec:
                    grp_rec = GatewayLdapGroup(
                        group_name=group_name,
                        project_name=proj,
                        role_name=role,
                        last_synced_at=now_utc,
                    )
                    session.add(grp_rec)

                # Ensure membership
                m_rec = session.query(GatewayUserGroupMembership).filter_by(
                    user_uid=clean_uid, group_name=group_name
                ).first()
                if not m_rec:
                    m_rec = GatewayUserGroupMembership(
                        user_uid=clean_uid, group_name=group_name, synced_at=now_utc
                    )
                    session.add(m_rec)
                else:
                    m_rec.synced_at = now_utc

            session.commit()
            logger.info(f"JIT sync completed for user '{clean_uid}': resolved {len(projects)} projects")
            return projects

        except Exception as e:
            session.rollback()
            logger.error(f"JIT sync failed for user '{clean_uid}': {e}", exc_info=True)
            return None
        finally:
            session.close()

    def get_sync_status(self) -> Dict[str, Any]:
        """Returns the current LDAP synchronization status, metrics, and health."""
        session = self.db_manager.get_session()
        try:
            latest_run = (
                session.query(GatewayLdapSyncStatus)
                .order_by(GatewayLdapSyncStatus.id.desc())
                .first()
            )
            total_users = session.query(GatewayUser).filter_by(is_active=True).count()
            total_groups = session.query(GatewayLdapGroup).count()

            status_dict = {
                "enabled": self.config.enabled,
                "server_uri": self.config.server_uri,
                "mock_mode": getattr(self.config, "mock_mode", False),
                "total_active_users": total_users,
                "total_synced_groups": total_groups,
                "group_prefix": self.config.group_prefix,
                "sync_interval_minutes": self.config.sync.interval_minutes,
                "last_run": None,
            }

            if latest_run:
                status_dict["last_run"] = {
                    "id": latest_run.id,
                    "status": latest_run.status,
                    "started_at": latest_run.started_at.isoformat() if latest_run.started_at else None,
                    "completed_at": latest_run.completed_at.isoformat() if latest_run.completed_at else None,
                    "users_synced": latest_run.users_synced,
                    "groups_synced": latest_run.groups_synced,
                    "error_message": latest_run.error_message,
                }

            return status_dict
        finally:
            session.close()

    def get_user_entitlements(self, uid: str) -> Tuple[Optional[GatewayUser], Dict[str, List[str]], List[str]]:
        """
        Retrieves user profile and project role entitlements directly from the PostgreSQL cache.
        Returns: (user_record, {project_name: [roles]}, [raw_group_names])
        """
        session = self.db_manager.get_session()
        try:
            user_rec = session.query(GatewayUser).filter_by(uid=uid).first()
            if not user_rec:
                logger.info(f"Directory cache miss: User '{uid}' not yet persisted in gateway_users")
                return None, {}, []

            memberships = (
                session.query(GatewayUserGroupMembership, GatewayLdapGroup)
                .join(GatewayLdapGroup, GatewayUserGroupMembership.group_name == GatewayLdapGroup.group_name)
                .filter(GatewayUserGroupMembership.user_uid == uid)
                .all()
            )

            projects: Dict[str, List[str]] = {}
            raw_groups: List[str] = []

            for m, grp in memberships:
                raw_groups.append(grp.group_name)
                if grp.project_name not in projects:
                    projects[grp.project_name] = []
                if grp.role_name not in projects[grp.project_name]:
                    projects[grp.project_name].append(grp.role_name)

            logger.info(
                f"Directory cache hit: Resolved '{uid}' with {len(projects)} projects ({list(projects.keys())}) and {len(raw_groups)} groups"
            )
            return user_rec, projects, raw_groups
        finally:
            session.close()

    def test_connection(self) -> Dict[str, Any]:
        """Tests LDAP connection."""
        return self.client.test_connection()
