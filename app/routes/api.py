import json
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
    gw_config = current_app.config.get("GATEWAY_CONFIG")
    adapter = current_app.config["ACTIVE_ADAPTER"]
    adapter_health = adapter.check_health()
    
    db_manager = current_app.config.get("DB_MANAGER")
    db_health = db_manager.check_health() if db_manager else {"status": "NOT_CONFIGURED"}

    is_local = gw_config.is_local_mode if gw_config else False
    ready_status = "READY (MOCK)" if is_local else "READY"

    return jsonify({
        "status": ready_status,
        "mode": "local" if is_local else "production",
        "adapter_health": adapter_health,
        "database_health": db_health,
    })


@api_bp.route("/heartbeat", methods=["GET"])
def heartbeat():
    """Heartbeat endpoint for periodic 5s health monitoring."""
    from datetime import datetime, timezone
    gw_config = current_app.config.get("GATEWAY_CONFIG")
    is_local = gw_config.is_local_mode if gw_config else False

    adapter = current_app.config.get("ACTIVE_ADAPTER")
    adapter_status = "UP"
    if adapter:
        try:
            h = adapter.check_health()
            if isinstance(h, dict) and h.get("status") not in ["HEALTHY", "UP"]:
                adapter_status = "DEGRADED"
        except Exception:
            adapter_status = "DOWN"

    db_manager = current_app.config.get("DB_MANAGER")
    db_status = "UP (MOCK)" if is_local else "UP"
    if db_manager and not is_local:
        try:
            dh = db_manager.check_health()
            if isinstance(dh, dict) and dh.get("status") not in ["HEALTHY", "UP"]:
                db_status = "DEGRADED"
        except Exception:
            db_status = "DOWN"

    node_id = (gw_config.server.node_id if gw_config else "gateway-node-01") + (" (local-mock)" if is_local else "")

    status = "UP" if adapter_status == "UP" and (db_status in ["UP", "UP (MOCK)"]) else "DEGRADED"

    timestamp_str = datetime.now(timezone.utc).isoformat()


    # Log structured pulse event to logs/heartbeat.log
    try:
        loggers = current_app.config.get("LOGGERS")
        hb_logger = loggers.heartbeat_logger if loggers and hasattr(loggers, "heartbeat_logger") else logging.getLogger("gateway.heartbeat")
        hb_logger.info(
            f"Heartbeat pulse check: status={status}, node_id={node_id}",
            extra={
                "context": {
                    "event": "HEARTBEAT_PULSE",
                    "status": status,
                    "node_id": node_id,
                    "adapter_status": adapter_status,
                    "database_status": db_status,
                    "timestamp": timestamp_str,
                }
            }
        )
    except Exception:
        pass


    return jsonify({
        "status": status,
        "timestamp": timestamp_str,
        "node_id": node_id,
        "adapter_status": adapter_status,
        "database_status": db_status,
    })



@api_bp.route("/requests/<request_id>", methods=["GET"])
def get_request_by_id(request_id: str):
    """Retrieves request execution status and details strictly from the database."""
    db_manager = current_app.config.get("DB_MANAGER")
    if not db_manager:
        return jsonify({"error": "Database manager is not configured. Direct DB request lookup unavailable."}), 503

    try:
        from app.database import ExecutionRecord, AuditLogRecord
        session = db_manager.get_session()
        try:
            # 1. Query gateway_execution_records table by request_id or execution_id
            rec = session.query(ExecutionRecord).filter(
                (ExecutionRecord.request_id == request_id) | (ExecutionRecord.execution_id == request_id)
            ).first()
            if rec:
                details = json.loads(rec.details_json) if rec.details_json else {}
                return jsonify({
                    "execution_id": rec.execution_id,
                    "request_id": rec.request_id,
                    "status": rec.status,
                    "project_name": rec.project_name,
                    "release_name": rec.release_name,
                    "service_account": rec.service_account,
                    "triggered_by_user": rec.triggered_by_user,
                    "message": "Execution record retrieved from database",
                    "created_at": rec.created_at.isoformat() if rec.created_at else None,
                    "details": details,
                    "data_source": "POSTGRESQL_DB"
                })

            # 2. Query gateway_audit_logs table by request_id or downstream_execution_id
            audit_rec = session.query(AuditLogRecord).filter(
                (AuditLogRecord.request_id == request_id) | (AuditLogRecord.downstream_execution_id == request_id)
            ).first()
            if audit_rec:
                return jsonify({
                    "execution_id": audit_rec.downstream_execution_id or audit_rec.id,
                    "request_id": audit_rec.request_id,
                    "status": audit_rec.status,
                    "project_name": audit_rec.project,
                    "release_name": audit_rec.release,
                    "service_account": audit_rec.service_account,
                    "triggered_by_user": audit_rec.human_uid,
                    "message": "Audit record retrieved from database",
                    "created_at": audit_rec.created_at.isoformat() if audit_rec.created_at else None,
                    "details": {"action": audit_rec.action, "reason": audit_rec.reason},
                    "data_source": "POSTGRESQL_DB"
                })
        finally:
            session.close()
    except Exception as exc:
        return jsonify({"error": f"Database query error: {exc}"}), 500

    return jsonify({"error": f"Request with ID '{request_id}' not found in database"}), 404





@api_bp.route("/openapi.json", methods=["GET"])
def get_openapi_spec():
    """Returns OpenAPI 3.0 specification for API documentation & Swagger UI."""
    return jsonify({
        "openapi": "3.0.0",
        "info": {
            "title": "Digital.ai Release Gateway REST API",
            "version": "1.9.0",
            "description": "Secure middleware for Digital.ai release execution, SSO entitlements, and health monitoring."
        },
        "paths": {
            "/api/v1/user": {
                "get": {
                    "summary": "Get authenticated user profile and entitlements",
                    "responses": {"200": {"description": "User profile returned"}}
                }
            },
            "/api/v1/execute": {
                "post": {
                    "summary": "Trigger release pipeline execution",
                    "responses": {"202": {"description": "Execution triggered"}, "403": {"description": "Forbidden"}}
                }
            },
            "/api/v1/execution/{execution_id}": {
                "get": {
                    "summary": "Get execution status by Execution ID",
                    "parameters": [{"name": "execution_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Execution status returned"}, "404": {"description": "Not found"}}
                }
            },
            "/api/v1/requests/{request_id}": {
                "get": {
                    "summary": "Get request details strictly from PostgreSQL database (Single Source of Truth)",
                    "parameters": [{"name": "request_id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "Request details returned"}, "404": {"description": "Not found in database"}, "503": {"description": "Database unavailable"}}
                }
            },

            "/api/v1/heartbeat": {
                "get": {
                    "summary": "5s heartbeat monitoring status",
                    "responses": {"200": {"description": "Heartbeat metrics returned"}}
                }
            },
            "/health": {
                "get": {
                    "summary": "Basic health check endpoint",
                    "responses": {"200": {"description": "Gateway UP"}}
                }
            },
            "/ready": {
                "get": {
                    "summary": "Readiness check endpoint evaluating database and adapter health",
                    "responses": {"200": {"description": "Gateway READY"}}
                }
            },
            "/api/v1/sso/inspect": {
                "get": {
                    "summary": "Inspect incoming SSO HTTP headers and session identity",
                    "responses": {"200": {"description": "SSO identity details returned"}}
                }
            }
        }
    })

