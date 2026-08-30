from flask import Blueprint, jsonify, request, g, current_app
from app.identity import get_current_user
from app.models import ReleaseExecutionRequest
from app.auth import AuthorizationError, ReleaseClassificationError
from app.adapters.base import AdapterError

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")
health_bp = Blueprint("health", __name__)


@api_bp.route("/user", methods=["GET"])
def get_user_profile():
    """Returns normalized identity of authenticated user."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Identity not established"}), 401

    return jsonify({
        "username": user.username,
        "display_name": user.display_name,
        "raw_groups": user.raw_groups,
        "projects": user.projects,
    })


@api_bp.route("/sso/inspect", methods=["GET", "POST"])
def inspect_sso_v2():
    """SSO V2 Inspection endpoint returning complete header & session identity details."""
    from app.sso_v2 import SSOInspectorV2
    config = current_app.config["GATEWAY_CONFIG"].identity if "GATEWAY_CONFIG" in current_app.config else None
    inspector = SSOInspectorV2(config)

    req_json = request.get_json(silent=True) or {}
    custom_headers = req_json.get("headers")
    custom_session = req_json.get("session")

    result = inspector.inspect(headers=custom_headers, session=custom_session, request=request)
    return jsonify(result.to_dict())



@api_bp.route("/execute", methods=["POST"])
def trigger_execution():
    """Triggers release pipeline execution after server-side auth & classification checks."""
    user = get_current_user()
    if not user:
        return jsonify({"error": "Identity not established"}), 401

    data = request.get_json() or {}
    project_name = data.get("project_name")
    release_name = data.get("release_name")
    execution_role = data.get("execution_role", "DEV")
    classification_tag = data.get("classification_tag", "")

    if not project_name or not release_name:
        return jsonify({"error": "project_name and release_name are required"}), 400

    req = ReleaseExecutionRequest(
        project_name=project_name,
        release_name=release_name,
        execution_role=execution_role,
        classification_tag=classification_tag,
    )

    auth_evaluator = current_app.config["AUTH_EVALUATOR"]
    audit_logger = current_app.config["AUDIT_LOGGER"]
    credential_resolver = current_app.config["CREDENTIAL_RESOLVER"]
    adapter = current_app.config["ACTIVE_ADAPTER"]
    request_id = getattr(g, "request_id", "N/A")

    # 1. Server-side authorization & fail-closed classification check
    try:
        is_auth, service_account, reason = auth_evaluator.evaluate_execution_request(user, req)
    except (AuthorizationError, ReleaseClassificationError) as e:
        audit_logger.log_security_event(
            user=user,
            action="TRIGGER_RELEASE",
            project=project_name,
            status="DENIED",
            reason=str(e),
        )
        return jsonify({"error": str(e)}), 403

    # 2. Resolve service account credential
    service_account_cred = credential_resolver.resolve(service_account)

    # 3. Trigger execution downstream via adapter
    try:
        result = adapter.trigger_release(
            request=req,
            service_account_cred=service_account_cred,
            user=user,
            request_id=request_id,
        )
    except AdapterError as ae:
        audit_logger.log_security_event(
            user=user,
            action="TRIGGER_RELEASE",
            project=project_name,
            status="ADAPTER_ERROR",
            reason=str(ae),
        )
        return jsonify({"error": f"Downstream adapter error: {ae}"}), 502

    # 4. Record successful audit event
    audit_logger.log_execution_event(
        user=user,
        action="TRIGGER_RELEASE",
        result=result,
        status="SUCCESS",
    )

    return jsonify({
        "execution_id": result.execution_id,
        "status": result.status,
        "project_name": result.project_name,
        "release_name": result.release_name,
        "service_account": result.service_account,
        "message": result.message,
        "request_id": result.request_id,
        "details": result.details,
    }), 202


@api_bp.route("/execution/<execution_id>", methods=["GET"])
def get_execution_status(execution_id: str):
    """Retrieves status of release execution."""
    adapter = current_app.config["ACTIVE_ADAPTER"]
    try:
        result = adapter.get_execution_status(execution_id)
        return jsonify({
            "execution_id": result.execution_id,
            "status": result.status,
            "project_name": result.project_name,
            "release_name": result.release_name,
            "service_account": result.service_account,
            "message": result.message,
            "created_at": result.created_at,
        })
    except AdapterError as ae:
        return jsonify({"error": str(ae)}), 404


@api_bp.route("/housekeeping/status", methods=["GET"])
def housekeeping_status():
    """Returns housekeeping status, disk health, and record metrics."""
    hk_manager = current_app.config.get("HOUSEKEEPING_MANAGER")
    if not hk_manager:
        return jsonify({"error": "Housekeeping manager not configured"}), 500
    return jsonify(hk_manager.get_status())


@api_bp.route("/housekeeping/run", methods=["POST"])
def run_housekeeping_task():
    """Triggers on-demand housekeeping cleanup."""
    hk_manager = current_app.config.get("HOUSEKEEPING_MANAGER")
    if not hk_manager:
        return jsonify({"error": "Housekeeping manager not configured"}), 500
    
    dry_run = request.args.get("dry_run", "false").lower() == "true"
    res = hk_manager.run_all(dry_run=dry_run)
    return jsonify(res)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """Application health endpoint."""
    return jsonify({
        "status": "UP",
        "service": "Gateway-DAI",
        "node_id": current_app.config.get("GATEWAY_CONFIG").server.node_id,
    })


@health_bp.route("/ready", methods=["GET"])
def readiness_check():
    """Readiness endpoint evaluating downstream dependencies and database health."""
    adapter = current_app.config["ACTIVE_ADAPTER"]
    adapter_health = adapter.check_health()
    
    db_manager = current_app.config.get("DB_MANAGER")
    db_health = db_manager.check_health() if db_manager else {"status": "NOT_CONFIGURED"}

    return jsonify({
        "status": "READY",
        "adapter_health": adapter_health,
        "database_health": db_health,
    })
