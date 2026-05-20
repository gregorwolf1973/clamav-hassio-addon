"""ClamAV scan logic: run clamscan, parse results, quarantine, notify HA."""
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime

DATA_DIR          = "/data"
HISTORY_FILE      = f"{DATA_DIR}/history/scans.json"
QUARANTINE_DIR    = f"{DATA_DIR}/quarantine"
QUARANTINE_META   = f"{DATA_DIR}/quarantine_meta.json"
INCREMENTAL_DIR   = f"{DATA_DIR}/incremental"
MAX_HISTORY       = 50

SCAN_PATHS        = json.loads(os.environ.get("SCAN_PATHS", '["/share","/media"]'))
AUTO_QUARANTINE   = os.environ.get("AUTO_QUARANTINE", "true").lower() in ("true", "1")
MAX_FILE_SIZE_MB  = int(os.environ.get("MAX_FILE_SIZE_MB", "100"))
NOTIFY_HA         = os.environ.get("NOTIFY_HA", "true").lower() in ("true", "1")
DAEMON_MODE       = os.environ.get("DAEMON_MODE", "always")
SCAN_ARCHIVES     = os.environ.get("SCAN_ARCHIVES", "true").lower() in ("true", "1")
INCREMENTAL_SCAN  = os.environ.get("INCREMENTAL_SCAN", "false").lower() in ("true", "1")
EXCLUDE_PATTERNS  = json.loads(os.environ.get("EXCLUDE_PATTERNS", "[]"))
DB_DIR            = "/data/clamav-db"

SUPERVISOR_TOKEN = os.environ.get("SUPERVISOR_TOKEN", "")

_scan_running = False
_scan_progress = {
    "status": "idle",
    "current_path": "",
    "current_file": "",
    "files_scanned": 0,
    "bytes_scanned": 0,
    "phase": "",  # "discovering", "scanning", "finishing"
}


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


def _load_quarantine_meta() -> dict:
    """Load per-file quarantine metadata (original path, virus name, ts)."""
    try:
        with open(QUARANTINE_META) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_quarantine_meta(meta: dict):
    try:
        with open(QUARANTINE_META, "w") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass


def _quarantine_file(infected_path: str, virus: str = "") -> str:
    """Move infected file to quarantine dir, return new path. Tracks the
    original location in quarantine_meta.json so the file can be restored
    later (e.g. for false positives)."""
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    basename = os.path.basename(infected_path)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    qname = f"{ts}_{basename}"
    dest = os.path.join(QUARANTINE_DIR, qname)
    try:
        shutil.move(infected_path, dest)
        meta = _load_quarantine_meta()
        meta[qname] = {
            "original_path": infected_path,
            "virus": virus,
            "quarantined_at": datetime.now().isoformat(),
        }
        _save_quarantine_meta(meta)
        return dest
    except Exception as e:
        return f"QUARANTINE_FAILED: {e}"


def _path_marker(path: str) -> str:
    """Return the per-path marker file used to track 'last scan time' for
    incremental scans. One marker file per scan path, hashed to avoid
    issues with slashes/special chars in filenames."""
    import hashlib
    h = hashlib.sha1(path.encode()).hexdigest()[:16]
    return os.path.join(INCREMENTAL_DIR, f"{h}.last_scan")


def _find_changed_files(path: str, marker: str) -> list:
    """Return list of files under `path` modified after the marker's mtime.
    On first run (no marker), return None to indicate full scan needed."""
    if not os.path.exists(marker):
        return None
    ref_time = os.path.getmtime(marker)
    changed = []
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                if os.path.getmtime(fp) > ref_time:
                    changed.append(fp)
            except OSError:
                pass
    return changed


def _build_scan_cmd(target, is_file_list: bool = False) -> list:
    """Construct the clamscan/clamdscan command line based on current config."""
    if DAEMON_MODE == "on_demand":
        cmd = [
            "clamscan",
            "--no-summary",
            f"--database={DB_DIR}",
            f"--max-filesize={MAX_FILE_SIZE_MB}M",
            f"--max-scansize={MAX_FILE_SIZE_MB * 4}M",
            "--stdout",
        ]
        # Archive scanning toggle — clamscan accepts these per invocation
        if not SCAN_ARCHIVES:
            cmd += [
                "--scan-archive=no",
                "--scan-pdf=no",
                "--scan-ole2=no",
                "--scan-swf=no",
                "--scan-html=no",
            ]
        if is_file_list:
            cmd += [f"--file-list={target}"]
        else:
            cmd += ["--recursive", target]
    else:
        cmd = [
            "clamdscan",
            "--multiscan",
            "--fdpass",
            "--no-summary",
        ]
        # clamdscan's archive behavior is controlled by clamd.conf
        # (configured in run.sh at startup based on scan_archives option).
        if is_file_list:
            cmd += [f"--file-list={target}"]
        else:
            cmd += [target]

    # Exclude patterns: clamscan/clamdscan use regex on the full path.
    # --exclude matches files, --exclude-dir matches whole subtrees.
    for pat in EXCLUDE_PATTERNS:
        cmd.append(f"--exclude={pat}")
        cmd.append(f"--exclude-dir={pat}")

    return cmd


def run_scan(paths=None, triggered_by="manual") -> dict:
    global _scan_running, _scan_progress

    if _scan_running:
        return {"error": "Scan already running"}

    _scan_running = True
    scan_paths = paths or SCAN_PATHS
    start_time = time.time()
    started_at = datetime.now().isoformat()

    _scan_progress = {
        "status": "running",
        "current_path": "",
        "current_file": "",
        "files_scanned": 0,
        "bytes_scanned": 0,
        "phase": "starting",
    }

    infected_files = []
    quarantined = []
    errors = []
    total_files = 0
    total_bytes = 0
    incremental_used = False
    incremental_skipped = 0  # paths skipped because nothing changed

    os.makedirs(INCREMENTAL_DIR, exist_ok=True)

    try:
        for path in scan_paths:
            if not os.path.exists(path):
                errors.append(f"Path not found: {path}")
                continue

            _scan_progress["current_path"] = path
            _scan_progress["current_file"] = ""

            file_list_path = None
            target = path

            # ── Incremental scan: find only changed files ─────────────
            if INCREMENTAL_SCAN:
                _scan_progress["phase"] = "discovering"
                marker = _path_marker(path)
                changed = _find_changed_files(path, marker)
                if changed is None:
                    # First scan for this path → fall back to full recursive
                    pass
                elif not changed:
                    # Nothing changed since last scan
                    incremental_used = True
                    incremental_skipped += 1
                    # Touch marker anyway so next scan compares against now
                    open(marker, "a").close()
                    os.utime(marker, None)
                    continue
                else:
                    # Write file list to disk and pass via --file-list
                    incremental_used = True
                    file_list_path = os.path.join(
                        INCREMENTAL_DIR, f"scan_{int(start_time)}.list"
                    )
                    with open(file_list_path, "w") as f:
                        f.write("\n".join(changed))
                    target = file_list_path

            _scan_progress["phase"] = "scanning"
            cmd = _build_scan_cmd(target, is_file_list=(file_list_path is not None))

            try:
                # Stream output line by line so progress updates live.
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )

                start_path = time.time()
                for line in proc.stdout:
                    line = line.rstrip()
                    if not line:
                        continue
                    if time.time() - start_path > 3600:
                        proc.kill()
                        errors.append(f"Scan timeout for path: {path}")
                        break

                    if line.endswith(": OK"):
                        fpath = line[:-4]
                        total_files += 1
                        try:
                            total_bytes += os.path.getsize(fpath)
                        except OSError:
                            pass
                        _scan_progress["files_scanned"] = total_files
                        _scan_progress["bytes_scanned"] = total_bytes
                        _scan_progress["current_file"] = fpath
                        continue

                    m = re.match(r"^(.+): (.+) FOUND$", line)
                    if m:
                        fpath, virus = m.group(1), m.group(2)
                        total_files += 1
                        _scan_progress["files_scanned"] = total_files
                        _scan_progress["current_file"] = fpath
                        entry = {"file": fpath, "virus": virus, "quarantined": None}
                        if AUTO_QUARANTINE:
                            dest = _quarantine_file(fpath, virus=virus)
                            entry["quarantined"] = dest
                            quarantined.append(dest)
                        infected_files.append(entry)
                        continue

                    if "ERROR" in line:
                        errors.append(line[-200:])

                proc.wait(timeout=60)

            except Exception as e:
                errors.append(f"Scan error for {path}: {e}")
            finally:
                # Clean up temp file list
                if file_list_path and os.path.exists(file_list_path):
                    try:
                        os.remove(file_list_path)
                    except OSError:
                        pass

            # Update incremental marker on successful scan of this path
            if INCREMENTAL_SCAN:
                try:
                    marker = _path_marker(path)
                    open(marker, "a").close()
                    os.utime(marker, None)
                except OSError:
                    pass

        _scan_progress["phase"] = "finishing"

    finally:
        _scan_running = False
        _scan_progress = {
            "status": "idle",
            "current_path": "",
            "current_file": "",
            "files_scanned": 0,
            "bytes_scanned": 0,
            "phase": "",
        }

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
        "bytes_scanned": total_bytes,
        "infected_count": len(infected_files),
        "infected": infected_files,
        "quarantined": quarantined,
        "errors": errors,
        "incremental": incremental_used,
        "incremental_skipped_paths": incremental_skipped,
        "scan_archives": SCAN_ARCHIVES,
        "exclude_patterns": EXCLUDE_PATTERNS,
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


def _sigtool_info(db_path: str) -> dict:
    """Run `sigtool --info` on a single DB file and return parsed fields."""
    try:
        result = subprocess.run(
            ["sigtool", "--info", db_path],
            capture_output=True, text=True, timeout=10,
        )
        info = {}
        for line in result.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                # Skip the very long digital signature blob
                if k.lower().startswith("digital signature"):
                    continue
                info[k] = v
        return info
    except Exception:
        return {}


def get_signature_info() -> dict:
    """
    Return signature info for main, daily and bytecode databases.
    Each DB exists either as .cvd (signed, full) or .cld (incremental updates).
    Format: {"main": {...}, "daily": {...}, "bytecode": {...}, "last_update": "..."}
    """
    db_dir = "/data/clamav-db"
    result = {}

    for db_name in ("main", "daily", "bytecode"):
        # Prefer .cld (incremental, newer) over .cvd
        for ext in (".cld", ".cvd"):
            path = os.path.join(db_dir, db_name + ext)
            if os.path.exists(path):
                info = _sigtool_info(path)
                if info:
                    info["_file"] = db_name + ext
                    info["_mtime"] = datetime.fromtimestamp(
                        os.path.getmtime(path)
                    ).strftime("%Y-%m-%d %H:%M")
                    result[db_name] = info
                break

    # Newest mtime across all DB files = effective "last freshclam update"
    try:
        mtimes = []
        for f in os.listdir(db_dir):
            if f.endswith((".cvd", ".cld")):
                mtimes.append(os.path.getmtime(os.path.join(db_dir, f)))
        if mtimes:
            result["last_update"] = datetime.fromtimestamp(
                max(mtimes)
            ).strftime("%Y-%m-%d %H:%M")
    except Exception:
        pass

    return result


def list_quarantine() -> list:
    if not os.path.isdir(QUARANTINE_DIR):
        return []
    meta = _load_quarantine_meta()
    files = []
    for fname in sorted(os.listdir(QUARANTINE_DIR), reverse=True):
        fpath = os.path.join(QUARANTINE_DIR, fname)
        if not os.path.isfile(fpath):
            continue
        try:
            stat = os.stat(fpath)
            entry_meta = meta.get(fname, {})
            files.append({
                "name": fname,
                "path": fpath,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "original_path": entry_meta.get("original_path"),
                "virus": entry_meta.get("virus"),
                "restorable": bool(entry_meta.get("original_path")),
            })
        except Exception:
            pass
    return files


def delete_quarantine_file(filename: str) -> bool:
    safe = os.path.basename(filename)
    fpath = os.path.join(QUARANTINE_DIR, safe)
    if os.path.isfile(fpath):
        os.remove(fpath)
        meta = _load_quarantine_meta()
        if safe in meta:
            del meta[safe]
            _save_quarantine_meta(meta)
        return True
    return False


def restore_quarantine_file(filename: str) -> dict:
    """Move a quarantined file back to its original location.
    Refuses to overwrite existing files or restore when the original
    directory no longer exists. Returns {'success': bool, ...}."""
    safe = os.path.basename(filename)
    qpath = os.path.join(QUARANTINE_DIR, safe)

    if not os.path.isfile(qpath):
        return {"success": False, "error": "Quarantined file not found."}

    meta = _load_quarantine_meta()
    entry = meta.get(safe)
    if not entry or not entry.get("original_path"):
        return {
            "success": False,
            "error": (
                "Original location unknown for this file (no metadata). "
                "Restore manually from /data/quarantine if needed."
            ),
        }

    original = entry["original_path"]

    if os.path.exists(original):
        return {
            "success": False,
            "error": f"A file already exists at the original location: {original}",
        }

    original_dir = os.path.dirname(original)
    if not os.path.isdir(original_dir):
        return {
            "success": False,
            "error": f"Original directory no longer exists: {original_dir}",
        }

    try:
        shutil.move(qpath, original)
        del meta[safe]
        _save_quarantine_meta(meta)
        return {"success": True, "restored_to": original}
    except Exception as e:
        return {"success": False, "error": f"Move failed: {e}"}
