# ClamAV Antivirus – Documentation

## Overview

This addon runs ClamAV inside a Home Assistant container and provides:

- **Virus scanning** of configured paths (default: `/share`, `/media`)
- **Scheduled scans** (hourly / daily / weekly)
- **Auto-quarantine** of infected files
- **HA notifications** on scan completion and when threats are detected
- **Web GUI** with scan history and quarantine management

## Installation

1. Add this repository to Home Assistant: `https://github.com/gregorwolf1973/clamav-hassio-addon`
2. Install **ClamAV Antivirus** from the addon store
3. Configure options (see below)
4. Start the addon

On first start, freshclam downloads the ClamAV signature database (~300 MB). This may take several minutes depending on your internet connection.

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `scan_paths` | `["/share", "/media"]` | Paths to scan |
| `scan_schedule` | `daily` | `disabled`, `hourly`, `daily`, `weekly` |
| `scan_hour` | `2` | Hour of day for daily/weekly scan (0–23) |
| `daemon_mode` | `always` | `always` (clamd permanent, ~1 GB RAM, fast scans) or `on_demand` (no daemon, ~50 MB RAM idle, +30–60s per scan). See below. |
| `auto_quarantine` | `true` | Move infected files to `/data/quarantine` automatically |
| `max_file_size_mb` | `100` | Skip files larger than this (MB) |
| `notify_ha` | `true` | Send HA persistent notifications |
| `web_port` | `8200` | Web GUI port |
| `admin_password_enabled` | `false` | Enable login for web GUI |

### Daemon Mode: RAM vs. Speed Trade-off

ClamAV's signature database is ~1 GB and must be loaded into RAM before any
scan. There are two strategies:

**`always` (default)** — The `clamd` daemon stays running 24/7 and keeps the
database memory-mapped permanently. Every scan is fast (no DB load time).
RAM cost: ~1 GB constantly used by clamd.

→ Choose this on machines with ≥ 4 GB RAM, or when scanning frequently.

**`on_demand`** — No daemon runs. Each scan starts `clamscan` which loads the
DB fresh from disk, scans, then frees the RAM. RAM cost: ~50 MB idle.
Scans are 30–60 seconds slower at start (SSD ~5–10s, SD card up to 60s).

→ Choose this on Raspberry Pi or low-RAM hardware, especially if you only
   scan once a day. Big RAM saving for minimal real-world cost.

Switching modes only requires a restart of the addon — the signature DB on
disk is identical for both modes.

## Scanning SimpleNAS / NotSoSimpleNas shares

Add the path where your NAS shares are mounted to `scan_paths`. Typically:

```yaml
scan_paths:
  - /share
  - /media
```

Both SimpleNAS addons map HA `share` and `media` volumes, which are the same volumes this addon accesses.

## Quarantine

Infected files are moved to `/data/quarantine/` inside the addon's persistent storage. They can be deleted individually via the web GUI. The quarantine directory is **not** accessible from other addons by default.

## Notes

- ClamAV's signature database is stored in `/var/lib/clamav/` (ephemeral, re-downloaded on each container start). Signatures are updated automatically before each start and can be updated manually via the web GUI.
- `armv7` support is best-effort; ClamAV may be slow on older ARM hardware.
- Large NAS libraries (100k+ files) may take 10–30 minutes to scan.
