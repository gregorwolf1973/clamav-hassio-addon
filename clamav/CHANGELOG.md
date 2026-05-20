# Changelog

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
