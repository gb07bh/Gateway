import json
import logging
from pathlib import Path
from flask import Blueprint, jsonify, request, current_app
from app.config import save_ldap_config
from app.ldap.sync import LdapSyncLockError
from app.database import GatewayUser, GatewayLdapGroup, GatewayUserGroupMembership

logger = logging.getLogger("gateway.ldap")
ldap_bp = Blueprint("ldap", __name__, url_prefix="/api/v1/ldap")


@ldap_bp.route("/status", methods=["GET"])
def get_ldap_status():
    """Returns current LDAP synchronization status, metrics, and health."""
    sync_manager = current_app.config.get("LDAP_SYNC_MANAGER")
    if not sync_manager:
        return jsonify({"status": "DISABLED", "message": "LDAP synchronization is not configured or disabled"}), 200
    status = sync_manager.get_sync_status()
    logger.debug(f"Retrieved LDAP sync status: {status.get('total_active_users', 0)} users, {status.get('total_synced_groups', 0)} groups")
    return jsonify(status)


@ldap_bp.route("/sync", methods=["POST"])
def trigger_ldap_sync():
    """Triggers an on-demand LDAP synchronization run."""
    sync_manager = current_app.config.get("LDAP_SYNC_MANAGER")
    if not sync_manager:
        logger.warning("Rejecting /sync: LDAP sync manager is not configured")
        return jsonify({"error": "LDAP synchronization is not configured"}), 503

    dry_run = request.args.get("dry_run", "false").lower() == "true"
    user_uid = request.args.get("user")

    if user_uid:
        logger.info(f"API request: Triggering single user JIT sync for '{user_uid}'")
        try:
            projects = sync_manager.sync_single_user(user_uid)
            if projects is not None:
                logger.info(f"API single-user sync for '{user_uid}' succeeded: {projects}")
                return jsonify({"status": "SUCCESS", "user": user_uid, "projects": projects})
            logger.warning(f"API single-user sync for '{user_uid}': user not found in LDAP")
            return jsonify({"error": f"User '{user_uid}' not found in LDAP"}), 404
        except Exception as e:
            logger.error(f"API single-user sync failed for '{user_uid}': {e}", exc_info=True)
            return jsonify({"error": f"Single user sync failed: {e}"}), 500

    logger.info(f"API request: Triggering full LDAP synchronization (dry_run={dry_run})")
    try:
        res = sync_manager.run_full_sync(dry_run=dry_run)
        logger.info(f"API full LDAP sync completed successfully: {res}")
        return jsonify(res), 200
    except LdapSyncLockError as le:
        logger.warning(f"API LDAP sync aborted due to active lock: {le}")
        return jsonify({"error": str(le)}), 409
    except Exception as e:
        logger.error(f"API LDAP sync failed with error: {e}", exc_info=True)
        return jsonify({"error": f"LDAP sync execution failed: {e}"}), 500


@ldap_bp.route("/test-connection", methods=["POST"])
def test_ldap_connection():
    """Validates LDAP connectivity and bind authentication."""
    sync_manager = current_app.config.get("LDAP_SYNC_MANAGER")
    if not sync_manager:
        logger.warning("Rejecting /test-connection: LDAP sync manager is not configured")
        return jsonify({"error": "LDAP synchronization is not configured"}), 503

    logger.info("API request: Validating LDAP server connectivity and bind credentials")
    try:
        res = sync_manager.test_connection()
        logger.info(f"API LDAP connection test result: {res}")
        return jsonify(res), 200
    except Exception as e:
        logger.error(f"API LDAP connection test failed: {e}", exc_info=True)
        return jsonify({"status": "ERROR", "error": str(e)}), 502


@ldap_bp.route("/users", methods=["GET"])
def list_synced_users():
    """Returns list of synced users and their project role assignments."""
    db_manager = current_app.config.get("DB_MANAGER")
    if not db_manager:
        return jsonify({"error": "Database manager not configured"}), 503

    query_str = request.args.get("q", "").strip().lower()
    project_filter = request.args.get("project", "").strip()

    session = db_manager.get_session()
    try:
        q = session.query(GatewayUser).filter_by(is_active=True)
        if query_str:
            q = q.filter(
                (GatewayUser.uid.ilike(f"%{query_str}%")) |
                (GatewayUser.display_name.ilike(f"%{query_str}%")) |
                (GatewayUser.email.ilike(f"%{query_str}%"))
            )

        users = q.order_by(GatewayUser.uid).limit(100).all()
        results = []
        for u in users:
            # Fetch user memberships
            memberships = (
                session.query(GatewayLdapGroup)
                .join(GatewayUserGroupMembership, GatewayUserGroupMembership.group_name == GatewayLdapGroup.group_name)
                .filter(GatewayUserGroupMembership.user_uid == u.uid)
                .all()
            )

            projects = {}
            for grp in memberships:
                if grp.project_name not in projects:
                    projects[grp.project_name] = []
                if grp.role_name not in projects[grp.project_name]:
                    projects[grp.project_name].append(grp.role_name)

            if project_filter and project_filter not in projects:
                continue

            results.append({
                "uid": u.uid,
                "display_name": u.display_name,
                "first_name": u.first_name,
                "last_name": u.last_name,
                "email": u.email,
                "is_active": u.is_active,
                "last_synced_at": u.last_synced_at.isoformat() if u.last_synced_at else None,
                "projects": projects,
            })

        return jsonify({"count": len(results), "users": results})
    finally:
        session.close()


@ldap_bp.route("/projects", methods=["GET"])
def list_synced_projects():
    """Returns list of distinct projects and member counts broken down by role."""
    db_manager = current_app.config.get("DB_MANAGER")
    if not db_manager:
        return jsonify({"error": "Database manager not configured"}), 503

    session = db_manager.get_session()
    try:
        groups = session.query(GatewayLdapGroup).order_by(GatewayLdapGroup.project_name, GatewayLdapGroup.role_name).all()
        projects = {}
        for g in groups:
            proj = g.project_name
            if proj not in projects:
                projects[proj] = {"project_name": proj, "roles": {}, "total_members": 0}

            member_count = (
                session.query(GatewayUserGroupMembership)
                .filter_by(group_name=g.group_name)
                .count()
            )
            projects[proj]["roles"][g.role_name] = member_count
            projects[proj]["total_members"] += member_count

        return jsonify({"count": len(projects), "projects": list(projects.values())})
    finally:
        session.close()


@ldap_bp.route("/config", methods=["POST"])
def update_ldap_configuration():
    """Safely updates non-secret LDAP configuration settings in ldap.yaml."""
    gw_config = current_app.config.get("GATEWAY_CONFIG")
    ldap_path = getattr(gw_config.identity, "ldap_config_path", "config/ldap.yaml") if gw_config else "config/ldap.yaml"

    update_payload = request.get_json() or {}
    logger.info(f"API request: Updating LDAP configuration settings for keys: {list(update_payload.keys())}")
    try:
        updated_config = save_ldap_config(ldap_path, update_payload)
        # Update current app sync manager with new config if present
        sync_manager = current_app.config.get("LDAP_SYNC_MANAGER")
        if sync_manager:
            sync_manager.config = updated_config
            sync_manager.client.config = updated_config

        logger.info(f"LDAP configuration updated successfully and reloaded into active sync manager (path='{ldap_path}')")
        return jsonify({
            "status": "SUCCESS",
            "message": "LDAP configuration updated successfully",
            "server_uri": updated_config.server_uri,
            "group_prefix": updated_config.group_prefix,
            "group_filter_template": updated_config.group_filter_template,
        }), 200
    except Exception as e:
        logger.error(f"Failed to update LDAP configuration: {e}", exc_info=True)
        return jsonify({"error": f"Failed to save LDAP configuration: {e}"}), 400


@ldap_bp.route("/logs", methods=["GET"])
def get_ldap_logs():
    """Returns recent log entries from logs/ldap.log for live administrator monitoring."""
    gw_config = current_app.config.get("GATEWAY_CONFIG")
    log_dir_str = gw_config.logging.dir if gw_config and hasattr(gw_config, "logging") else "logs"
    log_dir = Path(log_dir_str)
    if not log_dir.is_absolute():
        base_dir = Path(__file__).resolve().parent.parent.parent
        log_dir = base_dir / log_dir

    ldap_log_file = log_dir / "ldap.log"
    logs = []
    if ldap_log_file.exists():
        try:
            with open(ldap_log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # Return the last 50 lines reversed so newest is first
                for l in reversed(lines[-50:]):
                    l = l.strip()
                    if not l:
                        continue
                    try:
                        logs.append(json.loads(l))
                    except Exception:
                        logs.append({"timestamp": "", "level": "INFO", "message": l})
        except Exception as e:
            logger.error(f"Failed reading ldap.log: {e}")

    return jsonify({"count": len(logs), "logs": logs})
