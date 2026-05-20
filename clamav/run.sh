#!/usr/bin/with-contenv bashio

set -e

bashio::log.info "Starting ClamAV Antivirus Addon..."

# ── Read config ────────────────────────────────────────────────
export WEB_PORT;               WEB_PORT=$(bashio::config 'web_port')
export SCAN_SCHEDULE;          SCAN_SCHEDULE=$(bashio::config 'scan_schedule')
export SCAN_HOUR;              SCAN_HOUR=$(bashio::config 'scan_hour')
export DAEMON_MODE;            DAEMON_MODE=$(bashio::config 'daemon_mode')
export AUTO_QUARANTINE;        AUTO_QUARANTINE=$(bashio::config 'auto_quarantine')
export MAX_FILE_SIZE_MB;       MAX_FILE_SIZE_MB=$(bashio::config 'max_file_size_mb')
export NOTIFY_HA;              NOTIFY_HA=$(bashio::config 'notify_ha')
export ADMIN_PASSWORD_ENABLED; ADMIN_PASSWORD_ENABLED=$(bashio::config 'admin_password_enabled')
export ADMIN_USERNAME;         ADMIN_USERNAME=$(bashio::config 'admin_username')
export ADMIN_PASSWORD;         ADMIN_PASSWORD=$(bashio::config 'admin_password')

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
# /var/run is tmpfs and is wiped on every restart, so recreate the socket dir.
mkdir -p /var/run/clamav /var/log/clamav /data/quarantine /data/history /data/clamav-db
chmod 755 /var/run/clamav /var/log/clamav /data/clamav-db
[ -f /data/history/scans.json ] || echo '[]' > /data/history/scans.json

# ── Update virus signatures ────────────────────────────────────
# DB is persisted to /data/clamav-db (see clamd.conf DatabaseDirectory).
# First start downloads ~300 MB; subsequent starts only fetch diffs.
if [ ! -f /data/clamav-db/main.cvd ] && [ ! -f /data/clamav-db/main.cld ]; then
    bashio::log.info "First start — downloading full ClamAV signature DB (~300 MB)..."
else
    bashio::log.info "Updating ClamAV virus signatures (freshclam)..."
fi

if ! freshclam --daemon=0; then
    bashio::log.warning "freshclam update failed (no internet?). Will use existing DB if present."
fi

# Ensure we have *some* DB before starting clamd, otherwise clamd refuses to start.
# Use find instead of `ls *.cvd *.cld` — when one of the globs has no matches
# bash passes it literally and ls returns non-zero even if the other glob did match.
DB_FILES=$(find /data/clamav-db -maxdepth 1 \( -name '*.cvd' -o -name '*.cld' \) 2>/dev/null | head -1)
if [ -z "$DB_FILES" ]; then
    bashio::log.fatal "No virus database found and freshclam failed. Cannot start clamd."
    bashio::log.fatal "Check internet connectivity and restart the addon."
    exit 1
fi

# ── Start clamd daemon (only in 'always' mode) ─────────────────
# In 'on_demand' mode we skip clamd entirely — scans use clamscan directly,
# which loads the DB from disk per scan and releases the RAM afterwards.
if [ "${DAEMON_MODE}" = "on_demand" ]; then
    bashio::log.info "Daemon mode: on_demand — clamd NOT started (saves ~1 GB RAM)"
    bashio::log.info "Each scan will load the signature DB on demand (+30-60s startup)"
else
    bashio::log.info "Daemon mode: always — starting clamd (loading signature DB, this takes 30–60s)..."
    clamd &
    CLAMD_PID=$!

    # Wait for clamd socket to become ready (up to 120s — DB load is slow)
    WAITED=0
    while [ ! -S /var/run/clamav/clamd.sock ] && [ $WAITED -lt 120 ]; do
        if ! kill -0 "$CLAMD_PID" 2>/dev/null; then
            bashio::log.fatal "clamd process died during startup. Last lines from clamav.log:"
            tail -n 30 /var/log/clamav/clamav.log 2>&1 || echo "(no log file)"
            exit 1
        fi
        sleep 2
        WAITED=$(( WAITED + 2 ))
        if [ $(( WAITED % 20 )) -eq 0 ]; then
            bashio::log.info "Still waiting for clamd... (${WAITED}s)"
        fi
    done

    if [ ! -S /var/run/clamav/clamd.sock ]; then
        bashio::log.fatal "clamd socket /var/run/clamav/clamd.sock did not appear within 120s."
        bashio::log.fatal "Last lines from clamav.log:"
        tail -n 30 /var/log/clamav/clamav.log 2>&1 || echo "(no log file)"
        exit 1
    fi
    bashio::log.info "clamd ready after ${WAITED}s"
fi

# ── Start scheduled scan background daemon ────────────────────
bashio::log.info "Schedule: ${SCAN_SCHEDULE} (hour ${SCAN_HOUR})"
python3 /app/scheduler.py &

# ── Start Flask web GUI ────────────────────────────────────────
bashio::log.info "Starting Web GUI on port ${WEB_PORT}..."
exec python3 /app/app.py
