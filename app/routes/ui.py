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

