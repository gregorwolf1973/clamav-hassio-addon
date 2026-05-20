"""ClamAV scan logic: run clamscan, parse results, quarantine, notify HA."""
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime

DATA_DIR      = "/data"
HISTORY_FILE  = f"{DATA_DIR}/history/scans.json"
QUARANTINE_DIR = f"{DATA_DIR}/quarantine"
MAX_HISTORY   = 50

SCAN_PATHS       = json.loads(os.environ.get("SCAN_PATHS", '["/share","/media"]'))
AUTO_QUARANTINE  = os.environ.get("AUTO_QUARANTINE", "true").lower() in ("true", "1")
MAX_FILE_SIZE_MB = int(os.environ.get("MAX_FILE_SIZE_MB", "100"))
NOTIFY_HA        = os.environ.get("NOTIFY_HA", "true").lower() in ("true", "1")

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

_scan_running = False
_scan_progress = {"status": "idle", "current_path": "", "files_scanned": 0}


def _notify_ha(message: str, title: str = "ClamAV Antivirus"):
    if not NOTIFY_HA or not SUPERVISOR_TOKEN:
        return
    try:
        import urllib.request
        payload = json.dumps({"message": message, "title": title}).encode()
        req = urllib.request.Request(
            "http://supervisor/core/api/services/persistent_notification/create",
            data=payload,
            headers={
                "Authorization": f"Bearer {SUPERVISOR_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _load_history():
    try:
        with open(HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_history(history):
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history[-MAX_HISTORY:], f, indent=2)


def _quarantine_file(infected_path: str) -> str:
    """Move infected file to quarantine dir, return new path."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    basename = os.path.basename(infected_path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(QUARANTINE_DIR, f"{ts}_{basename}")
    try:
        shutil.move(infected_path, dest)
        return dest
    except Exception as e:
        return f"QUARANTINE_FAILED: {e}"


def run_scan(paths=None, triggered_by="manual") -> dict:
    global _scan_running, _scan_progress

    if _scan_running:
        return {"error": "Scan already running"}

    _scan_running = True
    scan_paths = paths or SCAN_PATHS
    start_time = time.time()
    started_at = datetime.now().isoformat()

    _scan_progress = {"status": "running", "current_path": "", "files_scanned": 0}

    infected_files = []
    quarantined = []
    errors = []
    total_files = 0
    total_size = 0

    try:
        for path in scan_paths:
            if not os.path.exists(path):
                errors.append(f"Path not found: {path}")
                continue

            _scan_progress["current_path"] = path

            cmd = [
                "clamscan",
                "--recursive",
                "--no-summary",
                f"--max-filesize={MAX_FILE_SIZE_MB}M",
                f"--max-scansize={MAX_FILE_SIZE_MB * 4}M",
                "--stdout",
                path,
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3600,
                )
                output = result.stdout + result.stderr

                for line in output.splitlines():
                    # Count scanned files
                    if line.endswith(": OK"):
                        total_files += 1
                        _scan_progress["files_scanned"] = total_files
                    # Detect infected files: "path: VirusName FOUND"
                    m = re.match(r"^(.+): (.+) FOUND$", line)
                    if m:
                        fpath, virus = m.group(1), m.group(2)
                        total_files += 1
                        _scan_progress["files_scanned"] = total_files
                        entry = {"file": fpath, "virus": virus, "quarantined": None}
                        if AUTO_QUARANTINE:
                            dest = _quarantine_file(fpath)
                            entry["quarantined"] = dest
                            quarantined.append(dest)
                        infected_files.append(entry)

            except subprocess.TimeoutExpired:
                errors.append(f"Scan timeout for path: {path}")
            except Exception as e:
                errors.append(f"Scan error for {path}: {e}")

    finally:
        _scan_running = False
        _scan_progress = {"status": "idle", "current_path": "", "files_scanned": 0}

    duration = round(time.time() - start_time, 1)
    status = "clean" if not infected_files else "infected"

    scan_result = {
        "id": f"scan_{int(start_time)}",
        "started_at": started_at,
        "finished_at": datetime.now().isoformat(),
        "duration_s": duration,
        "triggered_by": triggered_by,
        "paths": scan_paths,
        "status": status,
        "files_scanned": total_files,
        "infected_count": len(infected_files),
        "infected": infected_files,
        "quarantined": quarantined,
        "errors": errors,
    }

    history = _load_history()
    history.append(scan_result)
    _save_history(history)

    if infected_files:
        names = ", ".join(e["virus"] for e in infected_files[:3])
        suffix = f" (+{len(infected_files)-3} more)" if len(infected_files) > 3 else ""
        _notify_ha(
            f"{len(infected_files)} infected file(s) found: {names}{suffix}. "
            + ("Files quarantined." if quarantined else "Manual action required."),
            title="ClamAV: Threat Detected!",
        )
    else:
        if triggered_by == "scheduled":
            _notify_ha(
                f"Scheduled scan completed: {total_files} files scanned, no threats found.",
                title="ClamAV: Scan Clean",
            )

    return scan_result


def get_progress():
    return dict(_scan_progress, running=_scan_running)


def update_signatures() -> dict:
    try:
        result = subprocess.run(
            ["freshclam", "--daemon=0"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        return {
            "success": result.returncode == 0,
            "output": (result.stdout + result.stderr).strip()[-2000:],
        }
    except Exception as e:
        return {"success": False, "output": str(e)}


def get_signature_info() -> dict:
    try:
        result = subprocess.run(
            ["sigtool", "--info", "/var/lib/clamav/main.cvd"],
            capture_output=True, text=True, timeout=10,
        )
        lines = result.stdout.splitlines()
        info = {}
        for line in lines:
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return info
    except Exception:
        pass
    # fallback: check mtime of db files
    db_dir = "/var/lib/clamav"
    try:
        files = [f for f in os.listdir(db_dir) if f.endswith((".cvd", ".cld"))]
        if files:
            newest = max(files, key=lambda f: os.path.getmtime(os.path.join(db_dir, f)))
            mtime = os.path.getmtime(os.path.join(db_dir, newest))
            return {"Build date": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")}
    except Exception:
        pass
    return {}


def list_quarantine() -> list:
    if not os.path.isdir(QUARANTINE_DIR):
        return []
    files = []
    for fname in sorted(os.listdir(QUARANTINE_DIR), reverse=True):
        fpath = os.path.join(QUARANTINE_DIR, fname)
        try:
            stat = os.stat(fpath)
            files.append({
                "name": fname,
                "path": fpath,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            })
        except Exception:
            pass
    return files


def delete_quarantine_file(filename: str) -> bool:
    safe = os.path.basename(filename)
    fpath = os.path.join(QUARANTINE_DIR, safe)
    if os.path.isfile(fpath):
        os.remove(fpath)
        return True
    return False
