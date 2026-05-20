#!/usr/bin/with-contenv bashio

set -e

bashio::log.info "Starting ClamAV Antivirus Addon..."

# ── Read config ────────────────────────────────────────────────
export WEB_PORT
WEB_PORT=$(bashio::config 'web_port')

export SCAN_SCHEDULE
SCAN_SCHEDULE=$(bashio::config 'scan_schedule')

export SCAN_HOUR
SCAN_HOUR=$(bashio::config 'scan_hour')

export AUTO_QUARANTINE
AUTO_QUARANTINE=$(bashio::config 'auto_quarantine')

export MAX_FILE_SIZE_MB
MAX_FILE_SIZE_MB=$(bashio::config 'max_file_size_mb')

export NOTIFY_HA
NOTIFY_HA=$(bashio::config 'notify_ha')

export ADMIN_PASSWORD_ENABLED
ADMIN_PASSWORD_ENABLED=$(bashio::config 'admin_password_enabled')

export ADMIN_USERNAME
ADMIN_USERNAME=$(bashio::config 'admin_username')

export ADMIN_PASSWORD
ADMIN_PASSWORD=$(bashio::config 'admin_password')

# Build JSON array of scan paths from config
export SCAN_PATHS
SCAN_PATHS=$(bashio::config 'scan_paths' | python3 -c "
import sys, json
lines = sys.stdin.read().strip().splitlines()
paths = [l.strip().strip('\"') for l in lines if l.strip()]
print(json.dumps(paths))
")
bashio::log.info "Scan paths: ${SCAN_PATHS}"

# ── Update ClamAV max file size from config ────────────────────
MAX_BYTES=$(( MAX_FILE_SIZE_MB * 1024 * 1024 ))
sed -i "s/^MaxFileSize .*/MaxFileSize ${MAX_BYTES}/" /etc/clamav/clamd.conf
sed -i "s/^MaxScanSize .*/MaxScanSize $(( MAX_BYTES * 4 ))/" /etc/clamav/clamd.conf

# ── Persistent data dirs ───────────────────────────────────────
mkdir -p /data/quarantine /data/history

# Initialize history file if missing
[ -f /data/history/scans.json ] || echo '[]' > /data/history/scans.json

# ── Update virus signatures ────────────────────────────────────
bashio::log.info "Updating ClamAV virus signatures (freshclam)..."
freshclam --daemon=0 --quiet || bashio::log.warning "freshclam update failed (no internet?)"

# ── Start clamd daemon ─────────────────────────────────────────
bashio::log.info "Starting clamd daemon..."
mkdir -p /var/run/clamav /var/log/clamav
clamd &
CLAMD_PID=$!

# Wait for clamd socket to become ready (up to 60s)
bashio::log.info "Waiting for clamd to become ready..."
WAITED=0
while [ ! -S /var/run/clamav/clamd.sock ] && [ $WAITED -lt 60 ]; do
    sleep 2
    WAITED=$(( WAITED + 2 ))
done

if [ ! -S /var/run/clamav/clamd.sock ]; then
    bashio::log.warning "clamd socket not ready after 60s – TCP mode will be used"
fi
bashio::log.info "clamd ready"

# ── Start scheduled scan background daemon ────────────────────
bashio::log.info "Schedule: ${SCAN_SCHEDULE} (hour ${SCAN_HOUR})"
python3 /app/scheduler.py &

# ── Start Flask web GUI ────────────────────────────────────────
bashio::log.info "Starting Web GUI on port ${WEB_PORT}..."
exec python3 /app/app.py
