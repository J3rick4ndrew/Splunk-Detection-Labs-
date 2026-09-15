# Enterprise Splunk Detection Engineering & SOC Telemetry Labs

## Executive Summary
This repository documents an end-to-end security monitoring, detection engineering, and SOC operations lab built using Splunk Enterprise. Using simulated attack vectors ranging from network discovery and perimeter fuzzing to web application exploitation and endpoint malware behavior, high-fidelity Search Processing Language (SPL) queries were engineered and mapped to the MITRE ATT&CK framework. All telemetry is aggregated into a central Security Operations Center (SOC) dashboard.

---

## Lab Architecture & Ingestion Topology

```text
+-----------------------------------------------------------------------------------+
|                        Target Host: Windows Server 2022                           |
|                         Host: WIN-3MPUH9IFDVP-JERICK                              |
|                                                                                   |
|  +--------------------+  +--------------------+  +---------------+  +-----------+ |
|  | Windows Event Logs |  |   IIS Web Server   |  |  FTP / SSH    |  | Snort NIDS| |
|  | (Sec/Sys/App)      |  |   (W3C Logs)       |  |  (Auth Logs)  |  | alert.ids | |
|  +---------+----------+  +---------+----------+  +-------+-------+  +-----+-----+ |
|            |                       |                     |                |       |
|            +-----------------------+----------+----------+----------------+       |
|                                               |                                   |
|                                               v                                   |
|                              [Splunk Universal Forwarder]                         |
+-----------------------------------------------+-----------------------------------+
                                                |
                                                | Ingestion Stream (TCP Port 9997)
                                                v
+-----------------------------------------------------------------------------------+
|                           SIEM Indexing Engine                                    |
|                        Splunk Enterprise Instance                                 |
|                         Host Name: LAPTOP-V4CDGBGF                                |
+-----------------------------------------------------------------------------------+
```

### Infrastructure Specifications
* **SIEM Indexer / Search Head:** Splunk Enterprise running on Linux Mint (`LAPTOP-V4CDGBGF`) listening on TCP `9997`.
* **Monitored Target:** Windows Server (`WIN-3MPUH9IFDVP-JERICK`) hosting IIS Web Server, FTP, and OpenSSH.
* **Telemetry Agents:** Splunk Universal Forwarder (UF), Microsoft-Windows-Sysmon, and Snort NIDS.
* **Adversary Emulation:** Kali Linux (Nmap, Dirb, Metasploit Framework, Hydra/custom scripts).

---

## MITRE ATT&CK Detection Matrix

| Tactic | Technique | ID | Data Source | Primary Event ID / SourceType | Lab Directory |
|---|---|---|---|---|---|
| **Reconnaissance** | Active Scanning (Nmap) | T1595.001 | Snort NIDS | `sourcetype="ids"` | `02-Network-and-Perimeter-Detections` |
| **Initial Access** | Exploit Public-Facing App (SQLi) | T1190 | IIS W3C Logs | `sourcetype="iis"` | `03-Web-Application-Attacks` |
| **Initial Access** | External Remote Services (FTP) | T1133 | IIS FTP Logs | `sourcetype="iis"` (sc_status 530/230) | `04-Endpoint-and-Host-Attacks` |
| **Credential Access**| Brute Force (Web Login) | T1110.001 | IIS W3C Logs | `sourcetype="iis"` (`/Account/Login`) | `03-Web-Application-Attacks` |
| **Execution** | Command & Scripting Interpreter | T1059.001 | Sysmon | Event ID 1 (`cmd.exe` / `powershell.exe`) | `04-Endpoint-and-Host-Attacks` |
| **Execution** | Web Shell Execution | T1505.003 | IIS & Sysmon | Correlation: IIS + Sysmon Event ID 1 | `04-Endpoint-and-Host-Attacks` |
| **Defense Evasion** | Clear Windows Event Logs | T1070.001 | Windows Security | Event ID 1102 / 104 | `04-Endpoint-and-Host-Attacks` |
| **Defense Evasion** | Service Stop (EventLog) | T1562.001 | Windows System | Event ID 7036 / 7040 | `04-Endpoint-and-Host-Attacks` |
| **Impact** | Network Denial of Service (HTTP) | T1499.002 | IIS W3C Logs | `sourcetype="iis"` (GET Flood) | `03-Web-Application-Attacks` |
| **Impact** | Data Encrypted for Impact (Ransomware)| T1486 | Sysmon | Event ID 1 & 11 | `04-Endpoint-and-Host-Attacks` |

---

## Lab Modules Overview

### [Lab 01: Multi-Source Telemetry Ingestion & Forwarding Pipeline](./01-Environment-and-Data-Ingestion)
* Deployed Splunk Enterprise indexer and configured TCP receiving port `9997`.
* Installed Splunk Universal Forwarder on Windows Server endpoint.
* Established continuous ingestion pipelines for Windows Event Logs, OpenSSH operational logs, IIS W3C logs, and Snort alerts.

### [Lab 02: Network Reconnaissance & Perimeter Threat Detections](./02-Network-and-Perimeter-Detections)
* Engineered regex-based SPL detections for Nmap port/service scans and high-frequency ICMP sweeps.
* Analyzed perimeter firewall logs for port scanning, volumetric DoS patterns, and data exfiltration spikes.
* Implemented East-West internal lateral movement detection rules across RFC 1918 subnets.

### [Lab 03: Web Application Threat Detection (IIS W3C Logs)](./03-Web-Application-Attacks)
* Formulated detection analytics for SQL Injection (`UNION`, `SELECT`, `OR 1=1`) and Reflected XSS.
* Identified automated web fuzzing and directory traversal using `dirb`.
* Detected application-layer HTTP GET floods and broken access controls (unauthenticated admin exposure, directory listing).

### [Lab 04: Endpoint Threat Detection & Defense Evasion](./04-Endpoint-and-Host-Attacks)
* Constructed a multi-stage malware scoring model correlating process spawns, network callbacks, and file modifications.
* Correlated web-tier HTTP requests (`.aspx`) with host process creation (`w3wp.exe` $\rightarrow$ `cmd.exe`) to confirm web shell RCE.
* Monitored defense evasion indicators: Event log clearing (Event ID 1102/104) and user-initiated system shutdowns (Event ID 1074).

### [Lab 05: Enterprise SOC Dashboarding & Alert Auditing](./05-SOC-Dashboards)
* Assembled a central SOC dashboard integrating real-time panels for SQLi, XSS, Brute Force, and Access Control anomalies.
* Built alert distribution audit tables tracking fired alerts, severity ratings, and TTL lifecycles.
