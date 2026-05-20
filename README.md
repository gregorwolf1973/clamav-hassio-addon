# ClamAV Antivirus – Home Assistant Addon

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

ClamAV-based antivirus and antimalware scanner for Home Assistant with web GUI, scheduled scans, auto-quarantine and HA notifications.

## Features

- **ClamAV engine** – battle-tested open-source antivirus
- **Web GUI** – dark/light theme, scan history, quarantine manager
- **Scheduled scans** – hourly / daily / weekly with configurable time
- **Auto-quarantine** – infected files are moved automatically
- **HA notifications** – persistent notifications on threats or scan completion
- **SimpleNAS / NotSoSimpleNas compatible** – scans the same `/share` and `/media` volumes

## Installation

Add this repository URL to Home Assistant:

```
https://github.com/gregorwolf1973/clamav-hassio-addon
```

Then install **ClamAV Antivirus** from the addon store.

## Supported architectures

- `amd64`
- `aarch64`
- `armv7`
