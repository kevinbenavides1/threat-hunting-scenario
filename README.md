# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/kevinbenavides1/threat-hunting-scenario/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "labuser" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-07-31T20:10:49.460574Z`. These events began at `2025-07-31T19:55:52.199366Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-07-31T19:55:52.199366Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```
<img width="1835" height="473" alt="Screenshot 2025-08-01 at 9 13 40 AM" src="https://github.com/user-attachments/assets/ada66db3-26f6-470b-9e2c-75e0ce65db9b" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". Based on the logs returned, at `2025-07-31T19:58:10.2430554Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where ProcessCommandLine contains  "tor-browser-windows-x86_64-portable-14.5.5.exe"
| where DeviceName == "threat-hunt-lab"
| project Timestamp, DeviceName, ActionType, FolderPath, SHA256, ProcessCommandLine, AccountName
```
<img width="1866" height="102" alt="Screenshot 2025-08-01 at 9 17 56 AM" src="https://github.com/user-attachments/assets/05cc552a-6e4d-4db1-9a88-cc2b4edd3bbc" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "labuser" actually opened the TOR browser. There was evidence that they did open it at `2025-07-31T19:58:42.3405446Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("firefox.exe", "tor.exe", "tor-browser.exe", "start-tor-browser.exe", "start-tor-browser.desktop", "torbrowser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessCommandLine, AccountName, SHA256
| order by Timestamp desc
```
<img width="1484" height="679" alt="Screenshot 2025-08-01 at 9 25 54 AM" src="https://github.com/user-attachments/assets/6bcd8522-e03b-49cd-8c1a-307e5356dc40" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-07-31T19:59:03.0974794Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `68.67.32.34` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessAccountName == "labuser"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath 
```

<img width="1986" height="365" alt="Screenshot 2025-08-01 at 9 32 56 AM" src="https://github.com/user-attachments/assets/79d27180-70ec-4bd5-985a-197bb513e295" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-07-31T19:58:10.2430554Z`
- **Event:** The user "labuser" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\labuser\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-07-31T19:58:10.2430554Z`
- **Event:** The user "labuser" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe  /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-07-31T19:59:03.0974794Z`
- **Event:** User "labuser" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-07-31T19:59:03.0974794Z`
- **Event:** A network connection to IP `68.67.32.34` on port `9001` by user "labuser" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\labuser\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-07-31T19:59:09.8595852Z` - Connected to `78.46.92.172` on port `9001`.
  - `2025-07-31T20:00:04.9857779Z` - Local connection to `64.65.1.210` on port `443`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-07-31T20:10:49.460574Z`
- **Event:** The user "labuser" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
