# Privacy Policy for Guard for Windows

Last updated: June 26, 2025

This Privacy Policy describes how "Guard for Windows" (the "Software") communicates with the `guard.alexweb.app` service to apply your account settings to your computer.

## How the Software Communicates with Our Server

The Software is designed to be a client for the `guard.alexweb.app` service. Its primary function is to periodically check with the server to see if any new instructions or rules need to be applied.

To do this, the Software sends requests to our secure server API. These requests contain the following information:

* **Device Identification**: To receive the correct rules for your machine, the Software identifies itself using the unique `AssignCode` and `DeviceId` that were generated for this specific device in your `guard.alexweb.app` account. The Software does not create this information; it receives it from the server upon initial setup.

* **Instruction Versioning**: The Software reports back the status of the instructions it currently has, such as the `version` number and `lastUpdate` timestamp it last received from the server. This allows the server to efficiently determine if newer instructions are available for download, saving bandwidth and resources. The `pinStatus` is also reported back for the same synchronization purpose.

* **System Time Information**: The Software sends your system's current timezone ID (e.g., "Pacific Standard Time") and calculated UTC offset to the server. This is the only piece of system-specific information collected, and it is essential for the server to provide rules that apply correctly according to your local time-based schedules.

* **Diagnostic Logs**: If the Software encounters repeated critical errors, it may send an error report to the server. This report is linked to your device ID so that the details can be displayed in the logs section of your `guard.alexweb.app` account, helping you and me diagnose technical issues.

## How This Information is Used

The data sent from the Software is used exclusively for the following purposes:

* **To Provide Core Functionality**: To verify which device is asking for instructions and to deliver the correct filtering rules, schedules, and categories you have configured in your `guard.alexweb.app` account.
* **To Maintain Security**: To validate PIN codes for administrative actions on the device.
* **To Improve the Software**: To identify and resolve technical issues and to ensure the resilience and stability of the application.

## Data Security

We are committed to ensuring that your information is secure. The connection between the Software and our server is encrypted. All application state data stored locally on your machine is encrypted using the Windows Data Protection API (DPAPI), which is tied to your Windows user account.

## Information Sharing

We do not sell, distribute, or lease your personal information to third parties. The information sent from the Software is used solely for the operation of the Guard for Windows service.

## Disabling the Software

You can disable all communication and system modifications by using the "Disable App" function in the application's tray menu, which requires your PIN. A full uninstallation will remove all application files and system changes.

## Changes to This Policy

We may update this privacy policy from time to time. We will notify you of any changes by posting the new policy on our website.

## Contact Us

If you have any questions about this Privacy Policy, please contact us via the support channels on `guard.alexweb.app`.