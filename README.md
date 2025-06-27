# Guard: A Windows Scheduling & Filtering Utility

Guard is a Windows application designed to provide robust, scheduled filtering of internet content. It uses a combination of hosts file modifications and Windows Firewall rules to enforce restrictions based on user-defined rules and categories.

## Features

- **Scheduled Rules:** Create rules that are active only during specific times or on specific days of the week.
- **Category-Based Blocking:** Block entire categories of websites and services.
- **Resilient:** The application runs as a background service with a watchdog to ensure it remains active.
- **Secure:** Uses PIN protection for administrative actions and a secure uninstall process.
- **Time-Sync Verification:** Uses network time servers to prevent bypassing time-based rules by changing the system clock.
- **Auto-Update:** Can check for new versions and facilitate updates.

## Installation



1.  Download the latest installer from the [https://guard.alexweb.app/download](https://github.com/ganjie/Guard.alexweb.app_client/releases).
2.  Run the installer. The application requires administrator privileges to function.
3.  The Guard icon will appear in your system tray.

## Known Issues & Future Work

---
## Code Signing Policy

This project uses a free code signing certificate provided by [SignPath.io](https://signpath.io), with the certificate issued by the SignPath Foundation.

* **Committers and Reviewers**: [ganjie](https://github.com/ganjie)
* **Approvers**: [ganjie](https://github.com/ganjie)
* **Privacy Policy**: Please review the [Privacy Policy](PRIVACY.md) for details on how the application handles data.
