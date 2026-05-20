# Changelog

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
