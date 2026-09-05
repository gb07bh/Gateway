import os
import shutil
import zipfile
import shutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
from sqlalchemy import text
from app.config import HousekeepingConfig, LoggingConfig
from app.database import DatabaseManager, AuditLogRecord, ExecutionRecord


class HousekeepingManager:
    """Manages Gateway maintenance, log rotation, database purging, and disk health checks."""

    def __init__(
        self,
        hk_config: HousekeepingConfig,
        log_config: LoggingConfig,
        db_manager: Optional[DatabaseManager] = None,
        base_dir: Optional[Path] = None,
    ):
        self.config = hk_config
        self.log_config = log_config
        self.db_manager = db_manager
        self.base_dir = base_dir or Path(__file__).resolve().parent.parent
        self.log_dir = self.base_dir / log_config.dir
        self.run_dir = self.base_dir / "run"

    def get_status(self) -> Dict[str, Any]:
        """Returns housekeeping status, disk usage, log directory sizes, and retention settings."""
        disk_health = self.check_disk_health()
        log_files_status = self._get_log_files_info()
        db_records_status = self._get_db_records_info()

        return {
            "enabled": self.config.enabled,
            "retention_days": self.config.retention_days,
            "max_log_size_mb": self.config.max_log_size_mb,
            "disk_health": disk_health,
            "log_files": log_files_status,
            "db_records": db_records_status,
        }

    def check_disk_health(self) -> Dict[str, Any]:
        """Evaluates disk utilization on log partition."""
        try:
            total, used, free = shutil.disk_usage(self.log_dir if self.log_dir.exists() else self.base_dir)
            percent_used = round((used / total) * 100, 2)
            is_warning = percent_used > self.config.max_disk_usage_percent

            return {
                "total_gb": round(total / (1024 ** 3), 2),
                "used_gb": round(used / (1024 ** 3), 2),
                "free_gb": round(free / (1024 ** 3), 2),
                "percent_used": percent_used,
                "warning_threshold_percent": self.config.max_disk_usage_percent,
                "disk_warning": is_warning,
            }
        except Exception as e:
            return {"error": f"Failed to check disk health: {e}"}

    def rotate_and_clean_logs(self, dry_run: bool = False) -> Dict[str, Any]:
        """Rotates logs exceeding max size and purges log archives older than retention_days."""
        rotated_files = []
        purged_files = []
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.retention_days)

        if not self.log_dir.exists():
            return {"rotated": [], "purged": [], "status": "Log directory does not exist"}

        # 1. Rotate active logs exceeding max_log_size_mb
        max_bytes = self.config.max_log_size_mb * 1024 * 1024
        for log_filename in [self.log_config.audit_file, self.log_config.console_file, self.log_config.service_file]:
            log_path = self.log_dir / log_filename
            if log_path.exists() and log_path.stat().st_size >= max_bytes:
                timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                archive_name = f"{log_path.stem}_{timestamp}.zip"
                archive_path = self.log_dir / archive_name

                if not dry_run:
                    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zipf:
                        zipf.write(log_path, arcname=log_path.name)
                    # Truncate original log file
                    with open(log_path, "w", encoding="utf-8") as f:
                        f.write("")

                rotated_files.append(archive_name)

        # 2. Purge old log zip archives past retention_days
        for file in self.log_dir.glob("*.zip"):
            mtime = datetime.fromtimestamp(file.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff_date:
                if not dry_run:
                    file.unlink()
                purged_files.append(file.name)

        return {
            "dry_run": dry_run,
            "rotated": rotated_files,
            "purged": purged_files,
        }

    def purge_expired_db_records(self, dry_run: bool = False, force: bool = False) -> Dict[str, Any]:
        """Deletes audit logs and execution records older than retention_days if purge_db is enabled or forced."""
        if not self.db_manager or getattr(self.db_manager, "is_mock", False):
            return {"status": "Database disabled in local mock mode", "deleted_audit_records": 0, "deleted_execution_records": 0}

        if not force and not getattr(self.config, "purge_db", False):
            return {
                "status": "Database purge skipped (purge_db=false)",
                "deleted_audit_records": 0,
                "deleted_execution_records": 0,
            }

        cutoff_date = datetime.now(timezone.utc) - timedelta(days=self.config.retention_days)
        session = self.db_manager.get_session()

        try:
            audit_query = session.query(AuditLogRecord).filter(AuditLogRecord.created_at < cutoff_date)
            exec_query = session.query(ExecutionRecord).filter(ExecutionRecord.created_at < cutoff_date)

            deleted_audit_count = audit_query.count()
            deleted_exec_count = exec_query.count()

            if not dry_run:
                audit_query.delete(synchronize_session=False)
                exec_query.delete(synchronize_session=False)
                session.commit()

            return {
                "dry_run": dry_run,
                "deleted_audit_records": deleted_audit_count,
                "deleted_execution_records": deleted_exec_count,
                "cutoff_date": cutoff_date.isoformat(),
            }
        except Exception as e:
            session.rollback()
            return {"error": f"Database purge failed: {e}"}
        finally:
            session.close()

    def clean_stale_locks(self, dry_run: bool = False) -> Dict[str, Any]:
        """Cleans up unheld process lock files in run directory."""
        cleared_locks = []
        if not self.run_dir.exists():
            return {"cleared_locks": cleared_locks}

        for lock_file in self.run_dir.glob("*.lock"):
            # If pid file doesn't exist or lock is empty, mark stale
            pid_file = self.run_dir / "gateway.pid"
            if not pid_file.exists():
                if not dry_run:
                    try:
                        lock_file.unlink()
                    except Exception:
                        pass
                cleared_locks.append(lock_file.name)

        return {"dry_run": dry_run, "cleared_locks": cleared_locks}

    def run_all(self, dry_run: bool = False) -> Dict[str, Any]:
        """Executes full housekeeping maintenance cycle."""
        logs_res = self.rotate_and_clean_logs(dry_run=dry_run)
        db_res = self.purge_expired_db_records(dry_run=dry_run)
        locks_res = self.clean_stale_locks(dry_run=dry_run)
        disk_res = self.check_disk_health()

        return {
            "dry_run": dry_run,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "logs": logs_res,
            "database": db_res,
            "locks": locks_res,
            "disk": disk_res,
        }

    def _get_log_files_info(self) -> List[Dict[str, Any]]:
        info = []
        if self.log_dir.exists():
            for f in self.log_dir.iterdir():
                if f.is_file():
                    info.append({
                        "filename": f.name,
                        "size_bytes": f.stat().st_size,
                        "size_mb": round(f.stat().st_size / (1024 * 1024), 2),
                    })
        return info

    def _get_db_records_info(self) -> Dict[str, Any]:
        if not self.db_manager or getattr(self.db_manager, "is_mock", False):
            return {"status": "Database disabled in local mock mode", "audit_records": 0, "execution_records": 0}
        session = self.db_manager.get_session()
        try:
            audit_count = session.query(AuditLogRecord).count()
            exec_count = session.query(ExecutionRecord).count()
            return {"audit_records": audit_count, "execution_records": exec_count}
        except Exception:
            return {"audit_records": 0, "execution_records": 0}
        finally:
            session.close()
