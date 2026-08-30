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
