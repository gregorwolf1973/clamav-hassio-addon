# Changelog

## 1.0.6 - 2026-05-20

### Added (speed optimizations for large libraries)
- **`scan_archives` option** — toggle ZIP/PDF/Office/HTML unpacking.
  Disable for ~5–20× speedup on media libraries where archives are rare
  and large files dominate. Affects clamd.conf (always mode) and
  clamscan flags (on_demand mode).
- **`exclude_patterns` option** — list of regex patterns matched against
  full file paths. Files and directories matching any pattern are skipped.
  Big speedup when excluding videos/music.
- **`incremental_scan` option** — only scan files modified since the
  previous scan. First scan is full; subsequent scans skip unchanged
  files entirely. Marker files stored in `/data/incremental/`, one per
  scan path. Periodic full scan still recommended to re-check old files
  against newer virus signatures.

### UI improvements
- Live scan progress now shows the **current file being scanned** and
  total **MB throughput** (not just file count).
- Last-scan card shows badges for `incremental` and `no archives` mode.
- Scan history records bytes scanned and which optimizations were used.

## 1.0.5 - 2026-05-20

### Added
- **Restore button for quarantined files.** Each file's original path is now
  tracked in `/data/quarantine_meta.json` when it's quarantined. The web GUI
  shows the original location and a Restore button next to Delete. Useful
  for false positives — the file is moved back to where it came from.
- Quarantine table now shows the original path and detected virus name for
  each file.

### Safety guards on restore
- Refuses to overwrite a file that has appeared at the original location.
- Refuses to restore when the original directory no longer exists.
- Warns the user before restore that the file was flagged as infected.

## 1.0.4 - 2026-05-20

### Added
- New `daemon_mode` config option to trade RAM for speed:
  - `always` (default, previous behavior): clamd daemon stays running and
    keeps the ~1 GB signature DB in RAM permanently. Scans start instantly.
  - `on_demand`: no daemon; each scan invokes `clamscan` directly, which
    loads the DB fresh from disk per scan and releases the RAM afterwards.
    Idle RAM drops from ~1 GB to ~50 MB, but each scan has 30–60s extra
    startup time. Recommended for Raspberry Pi or low-RAM hardware that
    only scans once a day.

## 1.0.3 - 2026-05-20

### Fixed
- DB-existence check after freshclam wrongly reported "no database found"
  on first start. The check used `ls *.cvd *.cld` — when one of the globs
  has no matches (no .cld files on first install), bash passes the literal
  pattern to ls which returns non-zero and aborts startup. Replaced with
  `find`, which handles partial matches correctly.
- Removed deprecated `SafeBrowsing` option from `freshclam.conf` (warning
  spam in log).

## 1.0.2 - 2026-05-20

### Fixed
- **clamd daemon now actually starts.** The Alpine default `clamd.conf` and
  `freshclam.conf` ship with an `Example` line that prevents the daemon
  from starting. Both configs are now written from scratch with sane
  defaults — no more "Could not connect to clamd on LocalSocket" errors.
- Startup waits up to 120s for clamd (DB load can take 60s+) and shows
  the clamav log if the daemon dies, instead of silently continuing.
- `/var/run` is tmpfs (wiped on restart) — socket directory is now
  recreated in `run.sh` before clamd starts.

### Added
- Signature database is now persisted to `/data/clamav-db/` instead of
  the ephemeral `/var/lib/clamav`. Subsequent restarts only fetch
  incremental updates (~MB) instead of the full ~300 MB DB.
- Startup aborts with a clear error if no virus DB is available
  (instead of starting clamd into a broken state).

## 1.0.1 - 2026-05-20

### Fixed
- Live scan progress now updates in real time (was stuck at 0 because
  subprocess output was buffered until process completion)
- Switched scan engine from `clamscan` to `clamdscan` — uses the running
  ClamAV daemon instead of reloading the ~1 GB signature database for
  every scan. Scans are 10–50× faster and use far less RAM.

### Added
- Signature info now shows all three databases (main, daily, bytecode)
  with version, signature count and build time, plus the last freshclam
  update timestamp

## 1.0.0 - 2026-05-20

### Added
- Initial release
- ClamAV daemon (clamd) with freshclam signature updates
- Web GUI with dark/light theme, scan history, quarantine management
- Manual scan trigger via web UI
- Scheduled scans: hourly / daily / weekly with configurable hour
- Auto-quarantine of infected files
- Home Assistant persistent notifications on scan completion and threat detection
- Configurable scan paths (defaults: /share, /media)
- Password-protected web interface (optional)
- German and English translations for addon configuration
