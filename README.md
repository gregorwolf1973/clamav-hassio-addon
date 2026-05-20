# ClamAV Antivirus – Home Assistant Addon

<p align="center">
  <img src="clamav/logo.png" alt="ClamAV Antivirus" height="100">
</p>

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Buy me a coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/gregorwolf1973)

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

## Support

If you find this addon useful, you can [buy me a coffee](https://www.buymeacoffee.com/gregorwolf1973) ☕.
