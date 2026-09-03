from typing import Optional
from flask import Flask, g, request, jsonify
from app.config import load_config, CredentialResolver, GatewayConfig
from app.logging import GatewayLoggers, setup_request_correlation
from app.identity import IdentityNormalizer
from app.auth import AuthorizationEvaluator
from app.audit import AuditLogger
from app.adapters.factory import AdapterFactory
from app.database import DatabaseManager
from app.housekeeping import HousekeepingManager
from app.routes.ui import ui_bp
from app.routes.api import api_bp, health_bp
from app.routes.ldap_api import ldap_bp


def create_app(config_path: Optional[str] = None) -> Flask:
    """Gateway application factory."""
    app = Flask(__name__)

    # 1. Load & validate configuration
    config: GatewayConfig = load_config(config_path)
    app.config["GATEWAY_CONFIG"] = config

    # 2. Setup structured loggers & request correlation
    loggers = GatewayLoggers(
        log_dir=config.logging.dir,
        node_id=config.server.node_id,
        level=config.logging.level,
    )
    app.config["LOGGERS"] = loggers
    setup_request_correlation(app, loggers)

    # 3. Instantiate core components
    credential_resolver = CredentialResolver()
    app.config["CREDENTIAL_RESOLVER"] = credential_resolver

    db_manager = DatabaseManager(config.database, lazy_connect=True)
    if config.database.table_creations:
        try:
            db_manager.create_tables()
            loggers.db_logger.info("Database auto table creation verified (table_creations=true)")
        except Exception as e:
            loggers.db_logger.warning(f"Database auto table creation check deferred/warning: {e}")
    app.config["DB_MANAGER"] = db_manager

    # Instantiate LDAP sync manager if configured
    app.config["LDAP_LOGGER"] = loggers.ldap_logger
    ldap_sync_manager = None
    if getattr(config, "ldap", None) and getattr(config.ldap, "enabled", False):
        from app.ldap.sync import LdapSyncManager
        ldap_sync_manager = LdapSyncManager(config.ldap, db_manager, credential_resolver)
        mode = "mock" if getattr(config.ldap, "mock_mode", False) else "live"
        loggers.ldap_logger.info(
            f"LDAP sync engine initialized (mode={mode}, uri={config.ldap.server_uri}, prefix={config.ldap.group_prefix})"
        )
    else:
        loggers.ldap_logger.info("LDAP sync engine is disabled or not configured")
    app.config["LDAP_SYNC_MANAGER"] = ldap_sync_manager

    identity_normalizer = IdentityNormalizer(config.identity, sync_manager=ldap_sync_manager)
    app.config["IDENTITY_NORMALIZER"] = identity_normalizer

    auth_evaluator = AuthorizationEvaluator(config.auth, config.classification)
    app.config["AUTH_EVALUATOR"] = auth_evaluator

    active_adapter = AdapterFactory.create_adapter(config.adapters)
    app.config["ACTIVE_ADAPTER"] = active_adapter

    audit_logger = AuditLogger(loggers.audit_logger, db_manager=db_manager, db_logger=loggers.db_logger)
    app.config["AUDIT_LOGGER"] = audit_logger

    housekeeping_manager = HousekeepingManager(config.housekeeping, config.logging, db_manager=db_manager)
    app.config["HOUSEKEEPING_MANAGER"] = housekeeping_manager

    loggers.service_logger.info(
        f"Gateway service initialized on node '{config.server.node_id}' with adapter '{config.adapters.active}'"
    )

    # 4. Global identity extraction middleware
    @app.before_request
    def extract_identity_middleware():
        if request.endpoint and any(ep in request.endpoint for ep in ["health", "heartbeat", "ready"]):
            return


        user_identity = identity_normalizer.extract_identity(request)
        g.user_identity = user_identity
        g.username = user_identity.username

    # 5. Global safe error handlers
    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Resource not found"}), 404
        return "404 Not Found", 404

    @app.errorhandler(500)
    def handle_500(e):
        loggers.service_logger.error(f"Unhandled server error: {e}", exc_info=True)
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return "500 Internal Server Error", 500

    # 6. Register Blueprints
    app.register_blueprint(ui_bp)
    app.register_blueprint(api_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(ldap_bp)

    return app
