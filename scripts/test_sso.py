#!/usr/bin/env python3
"""
CLI Testing Utility for SSO V2 Identity Inspection
Allows passing headers, session dictionary, username, and groups to test and inspect SSO identity extraction.
"""

import sys
import json
import argparse
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.sso_v2 import SSOInspectorV2
from app.config import IdentityConfig, load_config


def main():
    parser = argparse.ArgumentParser(description="Digital.ai Release Gateway - SSO V2 Identity Inspection CLI Utility")
    parser.add_argument("-u", "--user", type=str, help="Username to test (sets X-Remote-User header)")
    parser.add_argument("-g", "--groups", type=str, help="Comma-separated group memberships (sets X-Remote-Groups header)")
    parser.add_argument("-H", "--header", action="append", help="Custom header in Key=Value format (e.g. -H X-Custom-User=jdoe)")
    parser.add_argument("-s", "--session", type=str, help="Session dictionary formatted as JSON string (e.g. '{\"email\":\"user@co.com\"}')")
    parser.add_argument("--json-input", type=str, help="Raw JSON payload containing headers and/or session dict")
    parser.add_argument("--json", action="store_true", help="Output result formatted as JSON instead of CLI text report")

    args = parser.parse_args()

    headers = {}
    session = {}

    # 1. Parse json-input if provided
    if args.json_input:
        try:
            payload = json.loads(args.json_input)
            if "headers" in payload and isinstance(payload["headers"], dict):
                headers.update(payload["headers"])
            if "session" in payload and isinstance(payload["session"], dict):
                session.update(payload["session"])
        except json.JSONDecodeError as e:
            print(f"Error parsing --json-input: {e}", file=sys.stderr)
            return 1

    # 2. Apply user and groups convenience options
    if args.user:
        headers["X-Remote-User"] = args.user
    if args.groups:
        headers["X-Remote-Groups"] = args.groups

    # 3. Parse custom --header parameters
    if args.header:
        for h_str in args.header:
            if "=" in h_str:
                k, v = h_str.split("=", 1)
                headers[k.strip()] = v.strip()
            else:
                headers[h_str.strip()] = ""

    # 4. Parse --session JSON string
    if args.session:
        try:
            session_data = json.loads(args.session)
            if isinstance(session_data, dict):
                session.update(session_data)
        except json.JSONDecodeError as e:
            print(f"Error parsing --session JSON: {e}", file=sys.stderr)
            return 1

    # 5. Run SSO V2 Inspection
    try:
        config = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml")).identity
    except Exception:
        config = IdentityConfig()

    inspector = SSOInspectorV2(config)
    result = inspector.inspect(headers=headers, session=session)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.format_cli_report())

    return 0


if __name__ == "__main__":
    sys.exit(main())
