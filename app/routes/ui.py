from flask import Blueprint, render_template, request, g, redirect, url_for
from app.identity import get_current_user

ui_bp = Blueprint("ui", __name__)


@ui_bp.route("/")
@ui_bp.route("/dashboard")
def dashboard():
    """Renders user dashboard displaying SSO identity details, projects, and roles."""
    user = get_current_user()
    return render_template("dashboard.html", user=user)


@ui_bp.route("/execution/<execution_id>")
def execution_detail(execution_id: str):
    """Renders release execution status page."""
    user = get_current_user()
    return render_template("execution.html", user=user, execution_id=execution_id)


@ui_bp.route("/monitoring")
def monitoring():
    """Renders real-time service health and heartbeat monitoring dashboard."""
    user = get_current_user()
    return render_template("monitoring.html", user=user)


@ui_bp.route("/sso-inspect")
def sso_inspect():
    """Renders SSO Header & Entitlement Inspection Console."""
    user = get_current_user()
    return render_template("sso_inspect.html", user=user)


@ui_bp.route("/docs")
@ui_bp.route("/swagger")
def swagger_docs():
    """Renders interactive Swagger UI and API request lookup page."""
    user = get_current_user()
    return render_template("swagger.html", user=user)


@ui_bp.route("/admin/ldap")
def ldap_admin():
    """Renders LDAP Directory Synchronization & Entitlements Management dashboard."""
    from flask import current_app
    from app.database import GatewayUser, GatewayLdapGroup, GatewayUserGroupMembership
    from app.config import LDAPConfig

    user = get_current_user()
    sync_manager = current_app.config.get("LDAP_SYNC_MANAGER")
    db_manager = current_app.config.get("DB_MANAGER")

    status = sync_manager.get_sync_status() if sync_manager else {
        "enabled": False,
        "total_active_users": 0,
        "total_synced_groups": 0,
        "group_prefix": "DAI_",
        "last_run": None,
        "server_uri": "N/A",
        "mock_mode": True,
    }

    ldap_cfg = sync_manager.config if sync_manager else LDAPConfig()

    users_list = []
    projects_list = []

    if db_manager:
        session = db_manager.get_session()
        try:
            db_users = session.query(GatewayUser).filter_by(is_active=True).order_by(GatewayUser.uid).limit(100).all()
            for u in db_users:
                memberships = (
                    session.query(GatewayLdapGroup)
                    .join(GatewayUserGroupMembership, GatewayUserGroupMembership.group_name == GatewayLdapGroup.group_name)
                    .filter(GatewayUserGroupMembership.user_uid == u.uid)
                    .all()
                )
                projs = {}
                for grp in memberships:
                    if grp.project_name not in projs:
                        projs[grp.project_name] = []
                    if grp.role_name not in projs[grp.project_name]:
                        projs[grp.project_name].append(grp.role_name)

                users_list.append({
                    "uid": u.uid,
                    "display_name": u.display_name or u.uid,
                    "email": u.email,
                    "is_active": u.is_active,
                    "projects": projs,
                })

            # Summarize projects
            db_groups = session.query(GatewayLdapGroup).order_by(GatewayLdapGroup.project_name).all()
            projs_map = {}
            for g in db_groups:
                if g.project_name not in projs_map:
                    projs_map[g.project_name] = {"project_name": g.project_name, "total_members": 0}
                m_count = session.query(GatewayUserGroupMembership).filter_by(group_name=g.group_name).count()
                projs_map[g.project_name]["total_members"] += m_count

            projects_list = list(projs_map.values())
        finally:
            session.close()

    return render_template(
        "ldap_admin.html",
        user=user,
        status=status,
        users=users_list,
        projects=projects_list,
        config=ldap_cfg,
    )

