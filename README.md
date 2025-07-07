# Guard: A Windows Scheduling & Filtering Utility

Guard is a Windows application that provides centralized control over internet access for any assigned device, managed securely through your online account at Guard.AlexWeb.app. Its core functionality is the ability to receive and apply instructions from your account, which define:
- Rules: Flexible filters that can restrict access to specific websites or online resources according to a schedule you set (for example, only allowing access during homework hours).
- Categories: Predefined groups—such as gambling, adult content, or social media—which are blocked at all times when selected.

Once a device is assigned, Guard keeps all settings automatically synchronized with your account. The application enforces restrictions by managing the system hosts file and Windows firewall rules, ensuring that the selected resources are inaccessible as specified by your instructions.

Guard protects access to its admin panel, closing, and uninstallation with a PIN code. Its state is securely encrypted, and all configuration data received from HTTP requests is thoroughly sanitized. The application is resistant to tampering: it monitors and automatically restarts itself if terminated, prevents operation without the necessary system privileges, and periodically verifies the device’s clock using public time services to ensure accurate rule enforcement. These safeguards ensure that Guard’s restrictions remain active and reliable, providing robust control for both families and administrators.

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
