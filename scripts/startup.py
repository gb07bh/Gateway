#!/usr/bin/env python3
"""
Cross-Platform Gateway Lifecycle Management Utility
Supports Windows and Linux environments for server startup, shutdown, status, health checks, and housekeeping.
"""

import sys
import os
import time
import signal
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app.utils.lock import FileLock

RUN_DIR = PROJECT_ROOT / "run"
LOGS_DIR = PROJECT_ROOT / "logs"
PID_FILE = RUN_DIR / "gateway.pid"
LOCK_FILE = RUN_DIR / "gateway.lock"
CONFIG_FILE = PROJECT_ROOT / "config" / "gateway.yaml"

IS_WINDOWS = sys.platform == "win32"


def is_pid_running(pid: int) -> bool:
    """Checks if a process with the given PID is currently active."""
    if pid <= 0:
        return False
    if IS_WINDOWS:
        try:
            # Use tasklist on Windows
            output = subprocess.check_output(
                ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                text=True,
                stderr=subprocess.DEVNULL
            )
            return str(pid) in output and "No tasks are running" not in output
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def validate_config() -> bool:
    """Validates the application configuration file."""
    print(f"Validating configuration at {CONFIG_FILE}...")
    try:
        from app.config import load_config
        load_config(str(CONFIG_FILE))
        print("Configuration valid.")
        return True
    except Exception as e:
        print(f"Configuration validation failed: {e}")
        return False


def get_server_config():
    """Loads server host and port from config/gateway.yaml."""
    try:
        from app.config import load_config
        cfg = load_config(str(CONFIG_FILE))
        return cfg.server.host, cfg.server.port
    except Exception:
        return "0.0.0.0", 5510


def start_app():
    """Starts the Gateway server in background."""
    if not validate_config():
        sys.exit(1)

    host, port = get_server_config()

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)

    lock = FileLock(LOCK_FILE)
    if not lock.acquire(blocking=False):
        print("Error: Another startup/operation is in progress or Gateway is running.")
        sys.exit(1)

    try:
        if PID_FILE.exists():
            try:
                pid = int(PID_FILE.read_text().strip())
                if is_pid_running(pid):
                    print(f"Gateway is already running (PID: {pid}).")
                    sys.exit(0)
            except ValueError:
                pass

        print(f"Starting Gateway server on {host}:{port}...")

        # Determine WSGI server based on OS and availability
        if not IS_WINDOWS:
            # Try gunicorn first on Linux
            try:
                subprocess.run(["gunicorn", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                cmd = [
                    "gunicorn",
                    "--workers", "4",
                    "--bind", f"{host}:{port}",
                    "--pid", str(PID_FILE),
                    "--daemon",
                    "app:create_app()"
                ]
                subprocess.run(cmd, cwd=str(PROJECT_ROOT), check=True)
                print("Gateway started successfully using Gunicorn.")
                return
            except (FileNotFoundError, subprocess.CalledProcessError):
                pass

        # Fallback / Windows: use waitress or python runner
        python_exe = sys.executable
        service_log = LOGS_DIR / "service.log"

        run_script = (
            "import sys\n"
            "from pathlib import Path\n"
            f"sys.path.insert(0, r'{PROJECT_ROOT}')\n"
            "from app import create_app\n"
            "app = create_app()\n"
            "try:\n"
            "    from waitress import serve\n"
            f"    serve(app, host='{host}', port={port})\n"
            "except ImportError:\n"
            f"    app.run(host='{host}', port={port}, debug=False)\n"
        )

        log_fd = open(service_log, "a", encoding="utf-8")
        
        if IS_WINDOWS:
            # DETACHED_PROCESS flag for Windows background process
            DETACHED_PROCESS = 0x00000008
            proc = subprocess.Popen(
                [python_exe, "-c", run_script],
                cwd=str(PROJECT_ROOT),
                stdout=log_fd,
                stderr=log_fd,
                creationflags=DETACHED_PROCESS
            )
        else:
            proc = subprocess.Popen(
                [python_exe, "-c", run_script],
                cwd=str(PROJECT_ROOT),
                stdout=log_fd,
                stderr=log_fd,
                start_new_session=True
            )

        PID_FILE.write_text(str(proc.pid))
        print(f"Gateway started successfully (PID: {proc.pid}).")

    finally:
        lock.release()


def stop_app():
    """Stops the running Gateway server."""
    if not PID_FILE.exists():
        print("Gateway is not running.")
        return

    try:
        pid = int(PID_FILE.read_text().strip())
    except ValueError:
        print("Invalid PID file.")
        PID_FILE.unlink(missing_ok=True)
        return

    if not is_pid_running(pid):
        print("Gateway is not running (stale PID file removed).")
        PID_FILE.unlink(missing_ok=True)
        return

    print(f"Stopping Gateway server (PID: {pid})...")
    if IS_WINDOWS:
        try:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"Failed to stop process {pid}: {e}")
    else:
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
            if is_pid_running(pid):
                os.kill(pid, signal.SIGKILL)
        except Exception as e:
            print(f"Failed to stop process {pid}: {e}")

    PID_FILE.unlink(missing_ok=True)
    print("Gateway stopped.")


def status_app():
    """Checks the status of the Gateway server."""
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text().strip())
            if is_pid_running(pid):
                print(f"Gateway is running (PID: {pid}).")
                sys.exit(0)
        except ValueError:
            pass

    print("Gateway is stopped.")
    sys.exit(1)


def health_app():
    """Performs a health check against the running server."""
    _, port = get_server_config()
    url = f"http://localhost:{port}/health"

    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=5) as response:
            if response.status == 200:
                print("Gateway is healthy.")
                sys.exit(0)
    except Exception as e:
        print(f"Health check failed: {e}")
        sys.exit(1)


def run_housekeeping():
    """Executes the housekeeping maintenance CLI script."""
    print("Running Gateway housekeeping routine...")
    housekeeping_script = PROJECT_ROOT / "scripts" / "housekeeping.py"
    res = subprocess.run([sys.executable, str(housekeeping_script)], cwd=str(PROJECT_ROOT))
    sys.exit(res.returncode)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} {{start|stop|restart|status|health|validate-config|housekeeping}}")
        sys.exit(1)

    command = sys.argv[1].lower()
    if command == "start":
        start_app()
    elif command == "stop":
        stop_app()
    elif command == "restart":
        stop_app()
        time.sleep(2)
        start_app()
    elif command == "status":
        status_app()
    elif command == "health":
        health_app()
    elif command == "validate-config":
        if validate_config():
            sys.exit(0)
        else:
            sys.exit(1)
    elif command == "housekeeping":
        run_housekeeping()
    else:
        print(f"Unknown command '{command}'. Usage: {sys.argv[0]} {{start|stop|restart|status|health|validate-config|housekeeping}}")
        sys.exit(1)


if __name__ == "__main__":
    main()
