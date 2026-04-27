# Azure Honeypot + SOC Lab

A cloud-based cybersecurity lab deploying a live honeypot on Microsoft Azure to attract and analyze real-world attack traffic. The environment is monitored using Microsoft Sentinel as the SIEM, with custom KQL detection rules, automated incident response via Logic Apps, and a SOC dashboard workbook for threat visualization.

> **Results:** 37,000+ brute force attempts detected within 24 hours from 11 unique attacker IPs across 5 countries (Ukraine, Romania, Russia, Germany, Mozambique).

---

## Screenshots

### Threat Map
![Threat Map](screenshots/HoneypotThreatMap_Screenshot.png)

### SOC Dashboard
![SOC Dashboard](screenshots/HoneypotSOC_Dashboard.png)

### Attacker IP Analysis
![Attacker IPs](screenshots/FailedIPAdressAttempts_Screenshot.png)

### Top 10 Attackers
![Top 10 Attackers](screenshots/Top10Attacks_Screenshot.png)

### Failed Login Volume
![Failed Logins](screenshots/FailedLogins_Screenshot.png)

---

## Architecture
Internet (Attacker Traffic)
↓
Honeypot VM (Windows Server 2025, RDP/SSH/HTTP exposed)
↓
Azure Monitor Agent + Data Collection Rule
↓
Log Analytics Workspace
↓
Microsoft Sentinel (SIEM)
├── KQL Scheduled Analytics Rules
├── Incident Creation + Alert Grouping
├── Logic App Playbook (Email Alerts)
├── Threat Map Workbook
└── SOC Dashboard Workbook

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Cloud Platform | Microsoft Azure |
| SIEM | Microsoft Sentinel |
| Log Storage | Log Analytics Workspace |
| Detection Language | KQL (Kusto Query Language) |
| Incident Response | Azure Logic Apps |
| Visualization | Azure Monitor Workbooks |
| VM OS | Windows Server 2025 Datacenter |
| Threat Intelligence | geo_info_from_ip_address, MITRE ATT&CK |

---

## Key Findings (24 Hours)

| Metric | Value |
|--------|-------|
| Total Failed Login Attempts | 37,451 |
| Unique Attacker IPs | 11 |
| Countries of Origin | 5 |
| Top Attacker | 92.63.197.69 (Ukraine) — 9,043 attempts |
| Attack Type | RDP/SSH Brute Force |
| MITRE ATT&CK Tactic | Credential Access — T1110 Brute Force |

### Attacker Origins
| Country | Attempts |
|---------|----------|
| 🇺🇦 Ukraine | 36,200 |
| 🇷🇴 Romania | 8 |
| 🇩🇪 Germany | 2 |
| 🇲🇿 Mozambique | 2 |
| 🇷🇺 Russia | 1 |

---

## Detection Rules

### Brute Force RDP Detection
Fires when 5+ failed logins occur from the same IP within 5 minutes.

```kql
Event
| where EventLog == "Security" and EventID == 4625
| extend IpAddress = extract("Source Network Address:\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)", 1, RenderedDescription)
| where isnotempty(IpAddress) and IpAddress != "-" and IpAddress != "::1"
| summarize FailCount = count() by IpAddress, bin(TimeGenerated, 5m)
| where FailCount >= 5
```

### Attacker IP Geolocation
```kql
Event
| where EventLog == "Security" and EventID == 4625
| extend IpAddress = extract("Source Network Address:\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)", 1, RenderedDescription)
| where isnotempty(IpAddress)
| summarize Attempts = count() by IpAddress
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| project IpAddress, Country, Attempts
| order by Attempts desc
```

---

## Setup Guide

### Prerequisites
- Microsoft Azure account (free tier works)
- Azure for Students subscription recommended

### Phase 1 — Honeypot + Threat Intelligence
1. Create Resource Group `honeypot-lab` in East US 2
2. Deploy Log Analytics Workspace `honeypot`
3. Enable Microsoft Sentinel on the workspace
4. Deploy Windows Server 2025 VM (Standard B1s)
5. Open inbound NSG rules for RDP (3389), SSH (22), HTTP (80)
6. Create Data Collection Rule with Windows Security Events
7. Build Threat Map workbook with geo IP visualization

### Phase 2 — SIEM + Threat Detection
1. Create KQL scheduled analytics rule for brute force detection
2. Map rule to MITRE ATT&CK Credential Access tactic
3. Build Logic App playbook for automated email alerts
4. Create SOC Dashboard workbook with:
   - Security event breakdown bar chart
   - Failed login attempts over time line chart
   - Top attacker IPs table
   - Successful logins table

---

## MITRE ATT&CK Coverage

| Tactic | Technique | ID |
|--------|-----------|-----|
| Credential Access | Brute Force | T1110 |
| Credential Access | Password Spraying | T1110.003 |
| Initial Access | External Remote Services | T1133 |

---

## Skills Demonstrated

- Microsoft Sentinel (SIEM) configuration and management
- KQL query authoring for threat detection
- Azure cloud infrastructure deployment
- Incident response automation with Logic Apps
- Threat intelligence and geolocation analysis
- MITRE ATT&CK framework mapping
- SOC dashboard development
