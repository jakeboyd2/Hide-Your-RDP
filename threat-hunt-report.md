# Threat Hunt Report

## Introduction

**Hunter:** Jake Boyd  
**Date:** September 21, 2025  
**Environment/Dataset:** Cyber Range — Log Analytics Workspace (Microsoft Sentinel / MDE / Advanced Hunting)  
**Objective:** Investigate suspicious activity on a cloud VM (DeviceName contains `flare`), reconstruct the attack timeline, identify IOCs, and assess scope/impact.

---
## Summary

An external actor performed RDP password-guessing and successfully authenticated as ```slflare``` from ```159.26.106.84```. They executed ```msupdate.exe``` which ran a PowerShell script, created persistence via a scheduled task named ```MicrosoftUpdateSync```, added a Microsoft Defender exclusion for ```C:\Windows\Temp```, staged data into ```backup_sync.zip```, and attempted exfiltration to ```185.92.220.87:8081```.

---

## Key Findings

- **Initial access (RDP brute force):** `159.26.106.84`
- **Compromised account:** `slflare`
- **Executed binary:** `msupdate.exe`
- **Command line used:**
    
    `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1`
- **Persistence:** Scheduled Task `MicrosoftUpdateSync`
- **Defender modification:** Exclusion added: `C:\Windows\Temp`
- **Discovery command observed:** `"cmd.exe" /c systeminfo`
- **Data staged for exfil:** `backup_sync.zip`
- **C2 / Exfil destination:** `185.92.220.87`
- **Exfil endpoint and port:** `185.92.220.87:8081`

### Risk Assessment
**Risk Level:** High/Critical  
**Confidence Level:** High  
**Impact Assessment:** An external actor gained RDP access using the ```slflare``` account, established persistence and Defender exclusions, staged sensitive data, and attempted exfiltration to a remote server.  

---

## Artifacts & Evidence

### KQL Queries Used

#### Query 1: Failed logons (brute force patterns)
```kql
// This query finds all failed logons where the device name contains "flare" per the hint and looks in the given time range
// The "project" part of the query allows for a more precise view of relevant data lessening noise
DeviceLogonEvents
| where ActionType == "LogonFailed"
| where DeviceName contains "flare"
| where Timestamp  between (datetime(2025-09-16T00:00:00Z) .. datetime(2025-09-17T23:59:59Z))
| order by Timestamp desc
| project Timestamp, DeviceId, DeviceName, ActionType, LogonType, AccountName
```

**Results:** Clear indication of brute force attempts highlighted by the rapid rate (Timestamp) and varying account names (AccountName)  

<img width="972" height="676" alt="image" src="https://github.com/user-attachments/assets/9eb20b19-57ef-4b3b-ac85-6e3b80dbf12b" />

---

#### Query 2: Determine username (compromised account)
```kql
// This query finds the username that was used during the successful RDP login associated with the attacker's IP
DeviceLogonEvents
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where RemoteIP == "159.26.106.84"
| where Timestamp  between (datetime(2025-09-13T07:53:53.7612957Z) .. datetime(2025-09-17T23:59:59Z))
| order by Timestamp asc
| project Timestamp, DeviceId, DeviceName, ActionType, LogonType, AccountName
```

**Results:** One result showing ```slflare``` successful logon via RDP (RemoteInteractive)
<img width="1088" height="379" alt="image" src="https://github.com/user-attachments/assets/f184df5e-ab67-40b5-a32d-43707bfa358d" />

---

#### Query 3: Sentinel - Suspicious binary (executed binary name)
```kql
// This query shows processes invoked by the compromised account name
DeviceProcessEvents
| where AccountName == "slflare"
| where TimeGenerated between (datetime(2025-09-16T00:00:00Z) .. datetime(2025-09-20T23:59:59Z))
| where ProcessCommandLine contains "Bypass"
| project ProcessCommandLine 
```

**Results:** Command line execution artifact

<img width="923" height="273" alt="image" src="https://github.com/user-attachments/assets/0466a47e-62e8-4a15-93b8-13251230e9aa" />

---

#### Query 4: Persistence mechanism
```kql
// This query shows registry keys with the TaskCache subkey which stores metadata about scheduled tasks
DeviceRegistryEvents
| where PreviousRegistryKey startswith @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
| where DeviceName == "slflarewinsysmo"
| order by Timestamp desc
| project ActionType, PreviousRegistryKey
```

**Results:** Suspicious registry key deletion 
<img width="959" height="339" alt="image" src="https://github.com/user-attachments/assets/1f885fb5-ec60-4ac6-a6a1-7e1f9a67da3b" />

---

#### Query 5: Defense Evasion
```kql
// This query searches for all registry keys containing "Exclusions"
DeviceRegistryEvents
| where DeviceName == "slflarewinsysmo"
| where PreviousRegistryKey contains "Exclusions"
| order by Timestamp desc
```

**Results:** Folder path the attacker added to Windows Defender’s exclusions after establishing persistence: ```C:\Windows\Temp```
<img width="816" height="337" alt="image" src="https://github.com/user-attachments/assets/800b826a-3477-4dde-adb7-5eb7ab164cb6" />

---


#### Query 6: MDE - Discovery Command
```kql
// This query searches for common discovery commands
DeviceProcessEvents
| where AccountName == "slflare"
| where ProcessCommandLine has_any ("whoami", "hostname", "ipconfig /all", "net user", "net localgroup", "net group /domain", "net view", "net view /domain", "netstat -ano", "tasklist", "systeminfo", "wmic qfe", "wmic process list", "query user", "arp -a", "route print", "nslookup", "nltest /dclist:domain", "nltest /domain_trusts", "dsquery user", "dsquery computer")
| where Timestamp between (datetime(2025-09-14T07:53:53.7612957Z) .. datetime(2025-09-20T23:59:59Z))
| order by Timestamp desc
| project DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Results:** Command line system discovery artifact

<img width="951" height="647" alt="image" src="https://github.com/user-attachments/assets/0b24a74c-fe99-4bc3-98eb-4d56bb9edf9b" />

---

#### Query 7: MDE - Archive File
```kql
// This query finds files that have extensions indicating compression and are in non-standard directories
DeviceFileEvents
| where DeviceName == "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-14T07:53:53.7612957Z) .. datetime(2025-09-20T23:59:59Z))
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| order by Timestamp desc
| project DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
```

**Results:** Archive file the attacker created to prepare for exfiltration

<img width="830" height="626" alt="image" src="https://github.com/user-attachments/assets/cecc41cb-105e-43a7-8214-5e606efde112" />

---

#### Query 8: C2 Connection 
```kql
// This query looks for C2 activity
DeviceProcessEvents
| where AccountName == "slflare"
| where ProcessCommandLine has_any("curl", "IEX", "iex", "POST", "backup_sync.ps1")
| where Timestamp between (datetime(2025-09-14T22:20:17.3891515Z) .. datetime(2025-09-20T23:54:17.3891515Z))
| order by Timestamp desc
```

**Results:** C2 exfil artifacts found

<img width="1066" height="432" alt="image" src="https://github.com/user-attachments/assets/36d8aa64-6a4c-4a1a-9d6d-27e501f347e4" />


---

## IoCs (Indicators of Compromise)

### Network Indicators
- **IP Addresses:**
  - `159.26.106.84` - Initial access (RDP) brute force
  - `185.92.220.87:8081` - Exfil endpoint and port

### User Account Indicators
- **Compromised Accounts:**
  - `slflare` - Account compromised

- **Suspicious Account Activity:**
  - Multiple failed logins followed by successful login
  - Registry modifications/deletions
  - Processes launched from unusal paths
  - Windows Defender AV exclusions

---

## Recommendations / Next Steps

### Immediate Actions Required
1. Isolate `slflarewinsysmo` device.
2. Disable `slflare` account.
3. Block RDP from malicious IP `159.26.106.84` in NSG/Firewall.
4. Block outbound connections to `182.92.220.87:8081`.

### Short-term Remediation (1-7 days)
- Enforce password resets across privileged and high-value accounts.
- Disable direct RDP exposure to the internet or restrict it with VPN + MFA.
- Re-baseline and re-enable Microsoft Defender protections, ensuring exclusions are reviewed/removed.

### Medium-term Improvements (1-4 weeks)
- Implement network-level RDP restrictions: only via secure bastion or jump host.
- Enforce MFA on all remote access methods.
- Conduct user and admin training on password security and remote access risks.

### Long-term Strategic Changes (1-3 months)
- Phase out direct RDP — replace with secure remote management solutions (e.g., Azure Bastion, privileged access workstations).
- Implement Zero Trust principles for account and access management.
- Adopt strong authentication policies (MFA everywhere, passwordless where possible).
- Deploy DLP (Data Loss Prevention) controls to detect/prevent unauthorized exfiltration attempts.

---


### Tools and Techniques Used
- **SIEM Platform:** Microsoft Sentinel
- **Query Languages:** KQL
- **Data Sources:** Azure, Logs Analytics Workspace (LAW), Microsoft Defender for Endpoint (MDE)

---

### Contact Information
**Primary Analyst:**  
- **Name:** Jake Boyd
- **Email:** jbsec2@gmail.com


---

**Document Classification:** Internal  
**Last Updated:** September 25, 2025  
**Version:** 1.0
