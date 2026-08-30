#!/usr/bin/env python3
"""
Phase 3 Gateway Validation CLI Runner
Executes comprehensive validation of Identity Normalization, Server-Side Authorization,
Fail-Closed Classification, Audit Logging, and Mock Adapter Execution without Digital.ai.
"""

import sys
import json
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import load_config
from app.logging import GatewayLoggers, sanitize_value
from app.identity import IdentityNormalizer
from app.auth import AuthorizationEvaluator, AuthorizationError, ReleaseClassificationError
from app.models import UserIdentity, ReleaseExecutionRequest
from app.adapters.mock_adapter import MockAdapter


def run_phase3_validation():
    print("==================================================================")
    print("       DIGITAL.AI RELEASE GATEWAY - PHASE 3 VALIDATION RUNNER     ")
    print("==================================================================")
    checks_passed = 0
    total_checks = 0

    def check(title: str, func):
        nonlocal checks_passed, total_checks
        total_checks += 1
        print(f"[{total_checks}] Testing {title}...", end=" ")
        try:
            func()
            print("[OK]")
            checks_passed += 1
        except Exception as e:
            print(f"[FAIL]: {e}")

    # Check 1: YAML Config Validation
    def check_config():
        config = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml"))
        assert config.server.port == 8080
        assert config.adapters.active == "mock"
    check("YAML Configuration Loading & Validation", check_config)

    # Check 2: Identity Normalization & Group Parsing
    def check_identity():
        config = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml")).identity
        normalizer = IdentityNormalizer(config)
        from flask import Flask, request
        app = Flask(__name__)
        with app.test_request_context(
            headers={
                "X-Remote-User": "val_user",
                "X-Remote-Groups": "DAI_Proj1_DEV, DAI_Proj1_APS, DAI_Proj2_AUDIT",
            }
        ):
            identity = normalizer.extract_identity(request)
            assert identity.username == "val_user"
            assert identity.has_role("Proj1", "DEV") is True
            assert identity.has_role("Proj1", "APS") is True
            assert identity.has_role("Proj2", "DEV") is False
    check("Identity Normalization & Group Parsing", check_identity)

    # Check 3: Server-Side Authorization Check
    def check_auth_success():
        cfg = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml"))
        evaluator = AuthorizationEvaluator(cfg.auth, cfg.classification)
        user = UserIdentity("user1", "User One", [], {"Proj1": ["DEV"]})
        req = ReleaseExecutionRequest("Proj1", "Rel1", "DEV", "dev")
        is_auth, sa, reason = evaluator.evaluate_execution_request(user, req)
        assert is_auth is True
        assert sa == "proj1_dev_sa"
    check("Server-Side Authorization & Service-Account Mapping", check_auth_success)

    # Check 4: Authorization Fail-Closed (Role Missing)
    def check_auth_denied():
        cfg = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml"))
        evaluator = AuthorizationEvaluator(cfg.auth, cfg.classification)
        user = UserIdentity("user1", "User One", [], {"Proj1": ["DEV"]})
        req = ReleaseExecutionRequest("Proj1", "Rel1", "APS", "prod")
        try:
            evaluator.evaluate_execution_request(user, req)
            raise AssertionError("Expected AuthorizationError not raised")
        except AuthorizationError:
            pass
    check("Server-Side Authorization Fails Closed (Role Missing)", check_auth_denied)

    # Check 5: Classification Fail-Closed (Invalid Tag)
    def check_classification_denied():
        cfg = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml"))
        evaluator = AuthorizationEvaluator(cfg.auth, cfg.classification)
        user = UserIdentity("user1", "User One", [], {"Proj1": ["DEV"]})
        req = ReleaseExecutionRequest("Proj1", "Rel1", "DEV", "unauthorized_tag")
        try:
            evaluator.evaluate_execution_request(user, req)
            raise AssertionError("Expected ReleaseClassificationError not raised")
        except ReleaseClassificationError:
            pass
    check("Release Classification Fails Closed (Invalid Tag)", check_classification_denied)

    # Check 6: Secret Redaction in Logging Context
    def check_secret_redaction():
        ctx = {"db_pass": "secret123", "token": "abc", "user": "admin"}
        sanitized = {k: sanitize_value(k, v) for k, v in ctx.items()}
        assert sanitized["db_pass"] == "***REDACTED***"
        assert sanitized["token"] == "***REDACTED***"
        assert sanitized["user"] == "admin"
    check("Structured Logging Secret Redaction", check_secret_redaction)

    # Check 7: Mock Adapter Trigger & Execution Lifecycle
    def check_mock_adapter():
        adapter = MockAdapter()
        user = UserIdentity("val_user", "Val User", [], {"Proj1": ["DEV"]})
        req = ReleaseExecutionRequest("Proj1", "Rel1", "DEV", "dev")
        result = adapter.trigger_release(req, "cred123", user, "REQ-VAL-01")
        assert result.status == "IN_PROGRESS"
        status_res = adapter.get_execution_status(result.execution_id)
        assert status_res.status == "COMPLETED"
    check("Mock Adapter Execution Lifecycle", check_mock_adapter)

    print("==================================================================")
    print(f"Validation Summary: {checks_passed}/{total_checks} Checks Passed.")
    print("==================================================================")

    if checks_passed == total_checks:
        print("[SUCCESS] PHASE 3 CORE VALIDATION PASSED FULLY INDEPENDENT OF DIGITAL.AI")
        return 0
    else:
        print("[FAILURE] PHASE 3 VALIDATION FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(run_phase3_validation())
