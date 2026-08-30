#!/usr/bin/env bash
# Lifecycle script for Gateway Application
set -eo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# If running on Windows OS or flock/gunicorn is missing, delegate to cross-platform startup.py
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" || ! -x "$(command -v flock)" ]]; then
    python "${APP_DIR}/scripts/startup.py" "$@"
    exit $?
fi

PID_FILE="${APP_DIR}/run/gateway.pid"
LOCK_FILE="${APP_DIR}/run/gateway.lock"
CONFIG_FILE="${APP_DIR}/config/gateway.yaml"

mkdir -p "${APP_DIR}/run" "${APP_DIR}/logs"

validate_config() {
    echo "Validating configuration at ${CONFIG_FILE}..."
    python -c "from app.config import load_config; load_config('${CONFIG_FILE}'); print('Configuration valid.')"
}

start_app() {
    validate_config
    exec 200>"${LOCK_FILE}"
    if ! flock -n 200; then
        echo "Error: Another startup/operation is in progress or Gateway is running."
        exit 1
    fi

    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "Gateway is already running (PID: $(cat "${PID_FILE}"))."
        exit 0
    fi

    echo "Starting Gateway Gunicorn server..."
    cd "${APP_DIR}"
    gunicorn --workers 4 --bind 0.0.0.0:8080 --pid "${PID_FILE}" --daemon "app:create_app()"
    echo "Gateway started successfully."
}

stop_app() {
    if [ -f "${PID_FILE}" ]; then
        PID=$(cat "${PID_FILE}")
        echo "Stopping Gateway server (PID: ${PID})..."
        kill -15 "${PID}" || true
        rm -f "${PID_FILE}"
        echo "Gateway stopped."
    else
        echo "Gateway is not running."
    fi
}

status_app() {
    if [ -f "${PID_FILE}" ] && kill -0 "$(cat "${PID_FILE}")" 2>/dev/null; then
        echo "Gateway is running (PID: $(cat "${PID_FILE}"))."
    else
        echo "Gateway is stopped."
        exit 1
    fi
}

health_app() {
    curl -s http://localhost:8080/health || (echo "Health check failed" && exit 1)
}

run_housekeeping() {
    echo "Running Gateway housekeeping routine..."
    python "${APP_DIR}/scripts/housekeeping.py"
}

case "$1" in
    start)
        start_app
        ;;
    stop)
        stop_app
        ;;
    restart)
        stop_app
        sleep 2
        start_app
        ;;
    status)
        status_app
        ;;
    health)
        health_app
        ;;
    validate-config)
        validate_config
        ;;
    housekeeping)
        run_housekeeping
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|health|validate-config|housekeeping}"
        exit 1
        ;;
esac

