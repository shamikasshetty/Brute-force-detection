# T1110.001 — RDP Brute Force Attack & Detection
### Project 2 — ECORP SOC Home Lab

![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110.001-red)
![Splunk](https://img.shields.io/badge/SIEM-Splunk%20Enterprise%209.4.2-green)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)

---

## Overview

This project simulates a real RDP brute force 
credential attack against a Windows 11 target 
machine and detects it in Splunk SIEM using 
Windows Security Event logs. This is one of the 
most common initial access techniques used by 
ransomware groups and threat actors targeting 
enterprise environments.

---

## Lab Environment

| Component | Details |
|---|---|
| Attacker | Kali Linux — 10.0.3.12 (ATTACKLAN) |
| Target | Windows 11 — 10.0.1.2 (ECORP LAN) |
| Firewall | pfSense — 3-zone network segmentation |
| SIEM | Splunk Enterprise 9.4.2 — 10.0.1.50 |
| Endpoint Logging | Sysmon + Splunk Universal Forwarder |
| Log Pipeline | Windows Security EventLog → UF → Splunk |

---

## Attack Phase

### Tool — Hydra
Hydra is an open source parallelised login 
cracker used by penetration testers and red 
teams worldwide. It supports dozens of protocols 
including RDP, SSH, FTP, HTTP, and SMB.

### Attack Command
```bash
hydra -l targetuser -P passwords.txt \
rdp://10.0.1.2 -V -t 1
```

### Command Breakdown
| Flag | Meaning |
|---|---|
| `-l targetuser` | Single username to attack |
| `-P passwords.txt` | Password list file (13 common passwords) |
| `rdp://10.0.1.2` | Protocol and target IP |
| `-V` | Verbose — show every attempt |
| `-t 1` | Single thread (RDP stability) |

### Password List Used
password, password123, Password123, admin,

admin123, Welcome1, letmein, 123456, qwerty,

abc123, Password1, Summer2024, Winter2024

### Attack Results
- Target account: targetuser
- Protocol: RDP (port 3389)
- Total attempts: 13 passwords
- Logon Type generated: 3 (Network logon)
- Windows Event ID generated: 4625

---

## Detection Phase

### Log Source
Windows Security Event Log via Splunk 
Universal Forwarder

### Key Event ID
**4625 — An account failed to log on**

This event fires every time a logon attempt 
fails on Windows. Each Hydra password attempt 
generates exactly one 4625 event, creating a 
clear and detectable pattern in the SIEM.

### Evidence in Splunk
| Field | Value |
|---|---|
| EventCode | 4625 |
| Account_Name | targetuser |
| Workstation_Name | kali |
| Logon_Type | 3 (Network) |
| Total Events | 24 |

### SPL Detection Query
index=main sourcetype="WinEventLog:Security"

EventCode=4625

| stats count by Account_Name, Workstation_Name,

Logon_Type

| where count > 5

| sort -count

### Detection Logic Explained
This query groups all failed logon events by 
account name, source workstation, and logon 
type. The `where count > 5` threshold filters 
out genuine mistyped passwords (typically 1-2 
attempts) and flags sustained attack patterns. 
A threshold of 5 balances sensitivity against 
false positives in a real environment.

---

## Saved Splunk Alert

| Setting | Value |
|---|---|
| Alert Name | T1110.001 — RDP Brute Force Detection |
| Schedule | Every hour |
| Search window | Last 60 minutes |
| Trigger | Results > 0 |
| Severity | High |

---

## MITRE ATT&CK Mapping

| Technique | ID | Description |
|---|---|---|
| Brute Force | T1110 | Parent technique |
| Password Guessing | T1110.001 | Specific sub-technique |
| Valid Accounts | T1078 | If attack succeeds |

### Kill Chain Stage
**Initial Access** — attacker attempting to 
gain first foothold into the ECORP network 
through credential guessing against exposed 
RDP service.

---

## Key Findings

1. **RDP brute force is extremely noisy** — 
   every single attempt leaves an Event ID 4625, 
   making it one of the easiest attacks to detect 
   when Windows Security logs flow into a SIEM.

2. **Logon Type 3 is the signature** — network 
   logon failures (Type 3) from the same source 
   against the same account in rapid succession 
   is the definitive brute force pattern.

3. **Attacker workstation is visible** — the 
   Workstation_Name field clearly shows `kali` 
   as the source of the attack, giving defenders 
   an immediate pivot point for investigation.

4. **NLA must be disabled for logging** — 
   Windows 11 with Network Level Authentication 
   enabled pre-authenticates at the network layer, 
   preventing 4625 events from being generated. 
   Real enterprise environments should enable NLA 
   as a defence but must compensate with network-
   level detection at the firewall.

5. **Detection rule fires in real time** — 
   logs appeared in Splunk within minutes of the 
   attack starting, demonstrating the value of 
   endpoint log forwarding to a centralised SIEM.

---

## Defensive Recommendations

| Control | Description |
|---|---|
| Account lockout policy | Lock account after 5 failed attempts |
| MFA on RDP | Credential alone is not enough |
| NLA enabled | Pre-authenticate before RDP session |
| Network segmentation | pfSense blocks RDP from internet |
| Geo-blocking | Block RDP from unexpected countries |
| Privileged Access | Dedicated jump server for RDP access |

---

## Tools Used

| Tool | Purpose |
|---|---|
| Hydra | RDP credential brute force |
| Kali Linux | Attacker machine |
| Windows 11 | Target machine |
| Sysmon | Enhanced endpoint logging |
| Splunk UF | Log forwarding from Windows |
| Splunk Enterprise | SIEM — detection and alerting |
| pfSense | Network segmentation and logging |

---

## Screenshots

| Screenshot | Description |
|---|---|
| hydra-attack.png | Hydra running brute force from Kali |
| splunk-4625-events.png | Failed logon events in Splunk |
| detection-rule-results.png | SPL query showing targetuser |
| splunk-alert-saved.png | Saved scheduled alert |

---

## Author

**Shamika Shetty** — Security Analyst  
Austin, TX | shamikasshetty.github.io  
linkedin.com/in/shamika-shetty-1209
