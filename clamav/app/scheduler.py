"""Background scheduler: trigger ClamAV scans on the configured interval."""
import logging
import os
import time
from datetime import datetime

import scanner

log = logging.getLogger("scheduler")

SCAN_SCHEDULE = os.environ.get("SCAN_SCHEDULE", "daily")
SCAN_HOUR     = int(os.environ.get("SCAN_HOUR", "2"))

INTERVALS = {
    "hourly":  3600,
    "daily":   86400,
    "weekly":  604800,
}


def _seconds_until_next(hour: int) -> int:
    now = datetime.now()
    target = now.replace(hour=hour, minute=0, second=0, microsecond=0)
    if SCAN_SCHEDULE == "hourly":
        target = now.replace(minute=0, second=0, microsecond=0)
        secs = (target.timestamp() + 3600) - time.time()
    elif SCAN_SCHEDULE == "weekly":
        # next Monday at scan_hour
        days_ahead = (7 - now.weekday()) % 7 or 7
        from datetime import timedelta
        target = (now + timedelta(days=days_ahead)).replace(
            hour=hour, minute=0, second=0, microsecond=0
        )
        secs = target.timestamp() - time.time()
    else:  # daily
        if now.hour >= hour:
            from datetime import timedelta
            target = (now + timedelta(days=1)).replace(
                hour=hour, minute=0, second=0, microsecond=0
            )
        secs = target.timestamp() - time.time()
    return max(int(secs), 60)


if __name__ == "__main__":
    scanner.configure_logging()

    if SCAN_SCHEDULE == "disabled":
        log.info("Scheduled scans disabled.")
        while True:
            time.sleep(3600)

    log.info("Schedule: %s, hour: %s", SCAN_SCHEDULE, SCAN_HOUR)

    while True:
        wait = _seconds_until_next(SCAN_HOUR)
        log.info("Next scan in %ss (%s)", wait, SCAN_SCHEDULE)
        time.sleep(wait)
        log.info("Starting scheduled scan at %s", datetime.now().isoformat())
        try:
            result = scanner.run_scan(triggered_by="scheduled")
            log.info(
                "Done: %s, %s files, %s threats",
                result["status"],
                result["files_scanned"],
                result["infected_count"],
            )
        except Exception as e:
            log.error("Error: %s", e)
