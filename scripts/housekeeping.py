#!/usr/bin/env python3
"""
Gateway Housekeeping & Maintenance CLI Utility
Performs automated log rotation, expired database record purging, stale lock cleanup, and disk health checks.
"""

import sys
import argparse
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.config import load_config
from app.database import DatabaseManager
from app.housekeeping import HousekeepingManager


def main():
    parser = argparse.ArgumentParser(description="Digital.ai Release Gateway Housekeeping & Maintenance Utility")
    parser.add_argument("--dry-run", action="store_true", help="Preview housekeeping operations without modifying files or database records")
    parser.add_argument("--retention-days", type=int, help="Override default retention days threshold")
    parser.add_argument("--status", action="store_true", help="Print current housekeeping and disk status report")
    parser.add_argument("--clean-logs", action="store_true", help="Execute log rotation and expired log purge only")
    parser.add_argument("--clean-db", action="store_true", help="Execute expired database records purge only")
    parser.add_argument("--clean-locks", action="store_true", help="Clean stale process locks only")
    
    args = parser.parse_args()

    # Load configuration
    config = load_config(str(PROJECT_ROOT / "config" / "gateway.yaml"))
    if args.retention_days:
        config.housekeeping.retention_days = args.retention_days

    db_manager = DatabaseManager(config.database, lazy_connect=True)
    manager = HousekeepingManager(config.housekeeping, config.logging, db_manager=db_manager, base_dir=PROJECT_ROOT)

    if args.status:
        status_info = manager.get_status()
        print(json.dumps(status_info, indent=2))
        return 0

    print("==================================================================")
    print("       DIGITAL.AI RELEASE GATEWAY - HOUSEKEEPING & MAINTENANCE     ")
    print("==================================================================")
    if args.dry_run:
        print(" [MODE]: DRY-RUN (No files or database records will be deleted)")

    if args.clean_logs:
        res = manager.rotate_and_clean_logs(dry_run=args.dry_run)
        print("[LOGS RESULT]:", json.dumps(res, indent=2))
    elif args.clean_db:
        res = manager.purge_expired_db_records(dry_run=args.dry_run, force=True)
        print("[DATABASE RESULT]:", json.dumps(res, indent=2))
    elif args.clean_locks:
        res = manager.clean_stale_locks(dry_run=args.dry_run)
        print("[LOCKS RESULT]:", json.dumps(res, indent=2))
    else:
        res = manager.run_all(dry_run=args.dry_run)
        print("[FULL HOUSEKEEPING RESULT]:", json.dumps(res, indent=2))

    print("==================================================================")
    print("[SUCCESS] Housekeeping task completed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
