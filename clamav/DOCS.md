# ClamAV Antivirus – Documentation

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/gregorwolf1973) [![Donate using Liberapay](https://liberapay.com/assets/widgets/donate.svg)](https://liberapay.com/Gregor_Wolf/donate)

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
| `scan_hour` | `2` | Hour of day for daily/weekly scan (0–23); weekly scans run on Mondays |
| `daemon_mode` | `always` | `always` (clamd permanent, ~1 GB RAM, fast scans) or `on_demand` (no daemon, ~50 MB RAM idle, +30–60s per scan). See below. |
| `scan_archives` | `true` | Scan inside archives (ZIP/PDF/Office). Turn off for 5–20× speedup on media. |
| `skip_images` | `true` | Skip common image formats (jpg, png, gif, webp, heic, tiff, bmp, raw, cr2, nef, arw, dng, svg). Case-insensitive. |
| `skip_videos` | `true` | Skip common video formats (mp4, mkv, mov, avi, m4v, webm, wmv, flv, 3gp, mts, m2ts, mpeg, mpg). Case-insensitive. |
| `skip_audio` | `true` | Skip common audio formats (mp3, flac, wav, m4a, ogg, aac, opus, wma, aiff). Case-insensitive. |
| `exclude_patterns` | `[]` | Additional custom regex patterns to skip, *on top of* the preset toggles above. |
| `incremental_scan` | `false` | Only scan files changed since last scan. Huge speedup for daily scheduled scans. |
| `auto_quarantine` | `true` | Move infected files to `/data/quarantine` automatically |
| `max_file_size_mb` | `100` | Skip files larger than this (MB) |
| `notify_ha` | `true` | Send HA persistent notifications |
| `log_level` | `info` | `trace`, `debug`, `info`, `notice`, `warning`, `error`, `fatal` — see below |
| `web_port` | `8200` | Port the web GUI listens on **inside the container**. Do not change — see below. |
| `admin_password_enabled` | `false` | Enable login for web GUI |
| `admin_username` | `admin` | Username for the web GUI login |
| `admin_password` | empty | Password for the web GUI login (only used when `admin_password_enabled` is on) |

### Logging (`log_level`)

`log_level` controls how much the addon logs:

- The startup script (`run.sh`) — bashio messages below the configured
  level are dropped.
- The web GUI, the scheduler and the scanner (Python logging). At
  `warning` and above the web GUI's per-request access lines disappear,
  at `debug`/`trace` you additionally get per-path file counts.
- `debug` and `trace` also switch `clamd` and `freshclam` to verbose
  logging (`LogVerbose yes`).

The level is applied at startup, so changing it requires an addon restart.

### Web GUI port (`web_port`)

The Home Assistant panel uses ingress, which is hard-wired to port `8200`
(`ingress_port` in `config.yaml`), and the web GUI port is *not* published
to the host. So `web_port` only changes the port the Flask app binds inside
the container — set it to anything other than `8200` and the panel (and any
other way of reaching the GUI) stops working. Leave it at `8200`.

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

### Speed optimizations for large libraries

A scan of `/media` with several hundred GB of files can easily take hours.
The default configuration is the safest but slowest. Recommended tuning
for typical home use:

**Media libraries (/media full of videos/music):**
```yaml
scan_archives: false              # videos rarely contain malware
skip_images: true                 # all common image formats (default)
skip_videos: true                 # all common video formats (default)
skip_audio:  true                 # all common audio formats (default)
exclude_patterns:
  - "/cache/"                     # add your own custom patterns here
incremental_scan: true            # only scan new/changed files
```

Since v1.0.10 the three `skip_*` toggles replace the previous lengthy
regex lists for media formats. They default to **ON**, are
case-insensitive (so `.JPG` and `.jpg` both match), and apply on top
of any custom `exclude_patterns`.

> **Note on regex syntax.** In the Home Assistant UI form, type patterns
> with a single backslash — `\.mp4$`, `/cache/` etc. The form takes the
> value verbatim. Since v1.0.9 the scanner also accepts the double-backslash
> form (`\\.mp4$`) that YAML escaping produces, so existing configs keep
> working.

With these settings a daily scan of a 500 GB media library typically
completes in seconds after the initial full scan.

**Document storage (/share with PDFs, Office docs, downloads):**
```yaml
scan_archives: true               # PDFs and Office files CAN contain malware
skip_images: false                # scan images too — paranoid but cheap
skip_videos: false
skip_audio:  false
exclude_patterns: []              # scan everything
incremental_scan: true            # still useful — most files are unchanged
```

### Options that take effect immediately vs. require restart

Since v1.0.8 the scanner re-reads its options at the start of every scan,
so toggling **incremental_scan**, **exclude_patterns**, **skip_images**,
**skip_videos**, **skip_audio**, **auto_quarantine** and **notify_ha**
in the HA UI applies on the next scan — no addon restart needed.

**max_file_size_mb** depends on the daemon mode: in `on_demand` mode it is
passed to `clamscan` per scan and applies immediately, but in `always`
mode the limit comes from `MaxFileSize`/`MaxScanSize` in `clamd.conf`,
which `run.sh` writes at startup — so there it takes an addon restart.

**Always need an addon restart**: `daemon_mode`, `log_level`, `web_port`,
the login options, and `scan_archives` in daemon mode (baked into
`clamd.conf` at startup).

### Incremental scan caveat

When `incremental_scan` is ON, a file that was already on disk during the
previous scan is **not re-checked**, even if newer virus signatures would
now detect it. Run a full scan (`incremental_scan: false`) periodically —
e.g. once a month — to catch this case. The next incremental scan after
that resumes from the full scan's timestamp.

## Scanning SimpleNAS / NotSoSimpleNas shares

Add the path where your NAS shares are mounted to `scan_paths`. Typically:

```yaml
scan_paths:
  - /share
  - /media
```

Both SimpleNAS addons map HA `share` and `media` volumes, which are the same volumes this addon accesses.

## Quarantine

Infected files are moved to `/data/quarantine/` inside the addon's persistent storage. They can be deleted or restored to their original location individually via the web GUI. The quarantine directory is **not** accessible from other addons by default.

## Notes

- ClamAV's signature database is stored persistently in `/data/clamav-db/` (full download on first start, only updates afterwards). Signatures are updated automatically before each start and can be updated manually via the web GUI.
- clamd also listens on TCP port `3310` (mapped to host port `3310`) so other add-ons such as Simple NAS can use it for scanning. This requires `daemon_mode: always`; disable the port in the add-on's network settings if nothing uses it.
- Images are built for `amd64`, `aarch64` and `armv7` (see `arch` in
  `config.yaml`). `armv7` support is best-effort: ClamAV's ~1 GB signature
  database is heavy for 32-bit ARM hardware, so use `daemon_mode: on_demand`
  there and expect slow scans.
- Large NAS libraries (100k+ files) may take 10–30 minutes to scan.
