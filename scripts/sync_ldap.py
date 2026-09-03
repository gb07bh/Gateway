#!/usr/bin/env python3
"""
Standalone LDAP Synchronization CLI Script
Can be run via cron, systemd timer, or manually by administrators.
"""

import sys
import json
import argparse
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import load_config, load_ldap_config, CredentialResolver
from app.database import DatabaseManager
from app.ldap.sync import LdapSyncManager
from app.logging import GatewayLoggers


def main():
    parser = argparse.ArgumentParser(description="Digital.ai Release Gateway - Standalone LDAP Synchronization CLI")
    parser.add_argument("--config", type=str, default=str(PROJECT_ROOT / "config" / "ldap.yaml"), help="Path to ldap.yaml")
    parser.add_argument("--gateway-config", type=str, default=str(PROJECT_ROOT / "config" / "gateway.yaml"), help="Path to gateway.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Simulate synchronization without persisting to PostgreSQL")
    parser.add_argument("--user", type=str, help="Synchronize a single user UID immediately (Option A JIT)")
    parser.add_argument("--test", action="store_true", help="Test LDAP connection and exit")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")

    args = parser.parse_args()

    # 1. Load configurations
    try:
        gw_config = load_config(args.gateway_config)
        ldap_config = load_ldap_config(args.config)
    except Exception as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 1

    # Initialize loggers so all sync records stream to logs/ldap.log and logs/service.log
    log_dir = PROJECT_ROOT / gw_config.logging.dir
    GatewayLoggers(str(log_dir), node_id=gw_config.server.node_id, level=gw_config.logging.level)

    # 2. Initialize Database and LDAP Sync Manager
    cred_resolver = CredentialResolver()
    db_manager = DatabaseManager(gw_config.database, lazy_connect=False)
    sync_manager = LdapSyncManager(ldap_config, db_manager, cred_resolver)

    # 3. Handle connection test
    if args.test:
        try:
            res = sync_manager.test_connection()
            if args.json:
                print(json.dumps(res, indent=2))
            else:
                print(f"[SUCCESS] LDAP Connection: {res.get('message', 'Connected')}")
            return 0
        except Exception as e:
            if args.json:
                print(json.dumps({"status": "ERROR", "error": str(e)}, indent=2))
            else:
                print(f"[ERROR] LDAP Connection failed: {e}", file=sys.stderr)
            return 1

    # 4. Handle single-user sync
    if args.user:
        try:
            projects = sync_manager.sync_single_user(args.user)
            if projects is not None:
                res = {"status": "SUCCESS", "uid": args.user, "projects": projects}
                if args.json:
                    print(json.dumps(res, indent=2))
                else:
                    print(f"[SUCCESS] User '{args.user}' synced successfully.")
                    for p, roles in projects.items():
                        print(f"  - Project: {p}, Roles: {', '.join(roles)}")
                return 0
            else:
                print(f"[WARNING] User '{args.user}' not found or had no matching groups.", file=sys.stderr)
                return 2
        except Exception as e:
            print(f"[ERROR] Single-user sync failed for '{args.user}': {e}", file=sys.stderr)
            return 1

    # 5. Handle full synchronization
    try:
        res = sync_manager.run_full_sync(dry_run=args.dry_run)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("==================================================================")
            print("             GATEWAY LDAP SYNCHRONIZATION SUMMARY                 ")
            print("==================================================================")
            print(f" Status               : {res.get('status')}")
            print(f" Dry Run              : {res.get('dry_run')}")
            print(f" Groups Synced        : {res.get('groups_synced')}")
            print(f" Users Synced         : {res.get('users_synced')}")
            print(f" Duration             : {res.get('duration_seconds')}s")
            print(f" Timestamp            : {res.get('timestamp')}")
            print("==================================================================")
        return 0
    except Exception as e:
        print(f"[ERROR] Full sync failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
