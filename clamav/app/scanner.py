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
OPTIONS_FILE      = f"{DATA_DIR}/options.json"
MAX_HISTORY       = 50
DB_DIR            = "/data/clamav-db"

SUPERVISOR_TOKEN  = os.environ.get("SUPERVISOR_TOKEN", "")

# Predefined exclude pattern groups, toggled via skip_images/videos/audio
# in the addon config. Case-insensitive via [aA] character classes since
# clamscan's POSIX regex has no inline /i flag.
PRESET_PATTERNS = {
    "images": [
        r"\.[jJ][pP][eE]?[gG]$",       # .jpg .jpeg
        r"\.[pP][nN][gG]$",
        r"\.[gG][iI][fF]$",
        r"\.[wW][eE][bB][pP]$",
        r"\.[hH][eE][iI][cC]$",
        r"\.[tT][iI][fF][fF]?$",       # .tif .tiff
        r"\.[bB][mM][pP]$",
        r"\.[rR][aA][wW]$",
        r"\.[cC][rR]2$",
        r"\.[nN][eE][fF]$",
        r"\.[aA][rR][wW]$",
        r"\.[dD][nN][gG]$",
        r"\.[sS][vV][gG]$",
    ],
    "videos": [
        r"\.[mM][pP]4$",
        r"\.[mM][kK][vV]$",
        r"\.[mM][oO][vV]$",
        r"\.[aA][vV][iI]$",
        r"\.[mM]4[vV]$",
        r"\.[wW][eE][bB][mM]$",
        r"\.[wW][mM][vV]$",
        r"\.[fF][lL][vV]$",
        r"\.3[gG][pP]$",
        r"\.[mM][tT][sS]$",
        r"\.[mM]2[tT][sS]$",
        r"\.[mM][pP][eE][gG]$",
        r"\.[mM][pP][gG]$",
    ],
    "audio": [
        r"\.[mM][pP]3$",
        r"\.[fF][lL][aA][cC]$",
        r"\.[wW][aA][vV]$",
        r"\.[mM]4[aA]$",
        r"\.[oO][gG][gG]$",
        r"\.[aA][aA][cC]$",
        r"\.[oO][pP][uU][sS]$",
        r"\.[wW][mM][aA]$",
        r"\.[aA][iI][fF][fF]?$",
    ],
}


def _normalize_pattern(pat: str) -> str:
    """Collapse `\\\\` → `\\` and `\\.` → `\\.` (no-op for the dot case;
    kept to make YAML-style examples also work when entered in the HA UI
    form). The UI form takes input verbatim, so a user copying
    `\\\\.jpg` from the YAML docs ends up with a literal double-backslash
    pattern that never matches anything on Linux paths. Treat any
    `\\\\` as `\\` so both forms work."""
    if pat is None:
        return ""
    return pat.replace("\\\\", "\\")


def _load_config() -> dict:
    """Read live HA addon options from /data/options.json.

    Done at every scan so that toggling options in the HA UI takes effect
    on the next scan without needing an addon restart. Falls back to env
    vars (set by run.sh at startup) if options.json is missing.

    NOTE: `daemon_mode` and `scan_archives` (in daemon mode) still require
    a restart because they affect /etc/clamav/clamd.conf which is written
    by run.sh at startup.
    """
    opts = {}
    try:
        with open(OPTIONS_FILE) as f:
            opts = json.load(f)
    except Exception:
        pass

    def _b(key, env_default):
        if key in opts:
            return bool(opts[key])
        return os.environ.get(env_default, "false").lower() in ("true", "1")

    def _i(key, env_default, fallback):
        if key in opts:
            try:
                return int(opts[key])
            except (TypeError, ValueError):
                pass
        try:
            return int(os.environ.get(env_default, str(fallback)))
        except ValueError:
            return fallback

    def _l(key, env_default):
        if key in opts and isinstance(opts[key], list):
            return [str(x) for x in opts[key]]
        try:
            return json.loads(os.environ.get(env_default, "[]"))
        except Exception:
            return []

    raw_excludes = _l("exclude_patterns", "EXCLUDE_PATTERNS")
    custom = [_normalize_pattern(p) for p in raw_excludes if p]

    # Expand preset toggles into regex patterns merged with the custom list.
    skip_images = _b("skip_images", "SKIP_IMAGES")
    skip_videos = _b("skip_videos", "SKIP_VIDEOS")
    skip_audio  = _b("skip_audio",  "SKIP_AUDIO")
    preset_patterns = []
    if skip_images: preset_patterns += PRESET_PATTERNS["images"]
    if skip_videos: preset_patterns += PRESET_PATTERNS["videos"]
    if skip_audio:  preset_patterns += PRESET_PATTERNS["audio"]

    return {
        "scan_paths":       _l("scan_paths",      "SCAN_PATHS") or ["/share", "/media"],
        "exclude_patterns": preset_patterns + custom,
        "exclude_custom":   custom,           # for diagnostics / UI
        "skip_images":      skip_images,
        "skip_videos":      skip_videos,
        "skip_audio":       skip_audio,
        "auto_quarantine":  _b("auto_quarantine", "AUTO_QUARANTINE"),
        "notify_ha":        _b("notify_ha",       "NOTIFY_HA"),
        "scan_archives":    _b("scan_archives",   "SCAN_ARCHIVES"),
        "incremental_scan": _b("incremental_scan","INCREMENTAL_SCAN"),
        "max_file_size_mb": _i("max_file_size_mb","MAX_FILE_SIZE_MB", 100),
        "daemon_mode":      opts.get("daemon_mode") or os.environ.get("DAEMON_MODE", "always"),
    }

_scan_running = False
_scan_progress = {
    "status": "idle",
    "current_path": "",
    "current_file": "",
    "files_scanned": 0,
    "bytes_scanned": 0,
    "phase": "",  # "discovering", "scanning", "finishing"
}


def _notify_ha(message: str, title: str = "ClamAV Antivirus", cfg: dict = None):
    cfg = cfg or _load_config()
    if not cfg["notify_ha"] or not SUPERVISOR_TOKEN:
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
    """Return list of files under `path` that appeared or changed after the
    marker's mtime. On first run (no marker), return None to signal that a
    full scan is needed.

    Uses max(mtime, ctime) so that files uploaded with a preserved old
    mtime (e.g. via HA file editor, SMB, cp -p, or extracted from an
    archive that kept timestamps) are still picked up — their ctime
    reflects when they appeared on this filesystem.
    """
    if not os.path.exists(marker):
        return None
    ref_time = os.path.getmtime(marker)
    changed = []
    for root, dirs, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            try:
                st = os.stat(fp)
                if max(st.st_mtime, st.st_ctime) > ref_time:
                    changed.append(fp)
            except OSError:
                pass
    return changed


def _build_scan_cmd(target, is_file_list: bool, cfg: dict) -> list:
    """Construct the clamscan/clamdscan command line from live config."""
    max_mb = cfg["max_file_size_mb"]
    if cfg["daemon_mode"] == "on_demand":
        cmd = [
            "clamscan",
            "--no-summary",
            f"--database={DB_DIR}",
            f"--max-filesize={max_mb}M",
            f"--max-scansize={max_mb * 4}M",
            "--stdout",
        ]
        if not cfg["scan_archives"]:
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
        cmd = ["clamdscan", "--multiscan", "--fdpass", "--no-summary"]
        # clamdscan's archive behavior is controlled by clamd.conf, written
        # by run.sh at startup. Changing scan_archives requires a restart
        # in daemon mode.
        if is_file_list:
            cmd += [f"--file-list={target}"]
        else:
            cmd += [target]

    for pat in cfg["exclude_patterns"]:
        cmd.append(f"--exclude={pat}")
        cmd.append(f"--exclude-dir={pat}")

    return cmd


def run_scan(paths=None, triggered_by="manual") -> dict:
    global _scan_running, _scan_progress

    if _scan_running:
        return {"error": "Scan already running"}

    cfg = _load_config()
    print(
        f"[scanner] cfg: incremental={cfg['incremental_scan']} "
        f"archives={cfg['scan_archives']} "
        f"quarantine={cfg['auto_quarantine']} "
        f"exclude={cfg['exclude_patterns']}",
        flush=True,
    )

    _scan_running = True
    scan_paths = paths or cfg["scan_paths"]
    start_time = time.time()
    started_at = datetime.now().isoformat()
    last_cmd = []
    output_tail = []  # last ~30 lines of clamscan output for diagnostics

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

            # Pre-flight file count so 0-files scans are unambiguous
            pre_count = 0
            try:
                for _r, _d, _fs in os.walk(path):
                    pre_count += len(_fs)
                    if pre_count > 5000:
                        break
            except OSError:
                pass
            print(
                f"[scanner] path={path} pre-scan file count: "
                f"{'>5000' if pre_count > 5000 else pre_count}",
                flush=True,
            )
            if pre_count == 0:
                errors.append(f"{path}: directory is empty (nothing to scan)")

            _scan_progress["current_path"] = path
            _scan_progress["current_file"] = ""

            file_list_path = None
            target = path

            # ── Incremental scan: find only changed files ─────────────
            if cfg["incremental_scan"]:
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
            cmd = _build_scan_cmd(target, is_file_list=(file_list_path is not None), cfg=cfg)
            last_cmd = cmd
            print(f"[scanner] run: {' '.join(cmd)}", flush=True)

            stderr_buf = []
            try:
                # Stream output line by line so progress updates live.
                # stderr kept separate so silent failures (no stdout but
                # an error on stderr) are visible in diagnostics.
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

                # Drain stderr concurrently so the pipe doesn't fill.
                import threading
                def _drain_stderr():
                    for ln in proc.stderr:
                        ln = ln.rstrip()
                        if ln:
                            stderr_buf.append(ln)
                t = threading.Thread(target=_drain_stderr, daemon=True)
                t.start()

                start_path = time.time()
                for line in proc.stdout:
                    line = line.rstrip()
                    if not line:
                        continue
                    output_tail.append(line)
                    if len(output_tail) > 30:
                        output_tail.pop(0)
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
                        if cfg["auto_quarantine"]:
                            dest = _quarantine_file(fpath, virus=virus)
                            entry["quarantined"] = dest
                            quarantined.append(dest)
                        infected_files.append(entry)
                        continue

                    if "ERROR" in line:
                        errors.append(line[-200:])

                proc.wait(timeout=60)
                t.join(timeout=5)

                # Surface stderr in diagnostics and exit-code in errors.
                if stderr_buf:
                    output_tail.extend(["[stderr]"] + stderr_buf[-15:])
                    output_tail[:] = output_tail[-30:]
                if proc.returncode not in (0, 1):  # 1 = virus found
                    errors.append(
                        f"{path}: clamscan exit code {proc.returncode}; "
                        f"see diagnostics for stderr"
                    )

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
            if cfg["incremental_scan"]:
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
        "scan_archives": cfg["scan_archives"],
        "exclude_patterns": cfg["exclude_patterns"],
        "scan_command": " ".join(last_cmd),
        "output_tail": output_tail[-30:],
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
            cfg=cfg,
        )
    else:
        if triggered_by == "scheduled":
            _notify_ha(
                f"Scheduled scan completed: {total_files} files scanned, no threats found.",
                title="ClamAV: Scan Clean",
                cfg=cfg,
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
