# Threat Hunt Report

## Introduction

**Hunter:** Jake Boyd  
**Date:** September 21, 2025  
**Environment/Dataset:** Cyber Range — Log Analytics Workspace (Microsoft Sentinel / MDE / Advanced Hunting)  
**Objective:** Investigate suspicious activity on a cloud VM (DeviceName contains flare), reconstruct the attack timeline, identify IOCs, and assess scope/impact.

---
## TL;DR  

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

#### Query 3: Suspicious binary (executed binary name)
```kql
// This query shows processes invoked by the compromised account name
DeviceProcessEvents
| where AccountName == "slflare"
| where TimeGenerated between (datetime(2025-09-16T00:00:00Z) .. datetime(2025-09-20T23:59:59Z))
| where ProcessCommandLine contains "Bypass"
| project TimeGenerated, AccountName, ActionType, DeviceName, FolderPath, ProcessCommandLine 
```

**Results:** Command line execution artifact

<img width="1541" height="275" alt="image" src="https://github.com/user-attachments/assets/5e4728dc-73c4-41f4-9b1d-db57ba2448df" />

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

#### Query 6: Discovery Command
```kql
// This query searches for common discovery commands
DeviceProcessEvents
| where AccountName == "slflare"
| where ProcessCommandLine has_any ("whoami", "hostname", "ipconfig /all", "net user", "net localgroup", "net group /domain", "net view", "net view /domain", "netstat -ano", "tasklist", "systeminfo", "wmic qfe", "wmic process list", "query user", "arp -a", "route print", "nslookup", "nltest /dclist:domain", "nltest /domain_trusts", "dsquery user", "dsquery computer")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| where Timestamp between (datetime(2025-09-14T07:53:53.7612957Z) .. datetime(2025-09-20T23:59:59Z))
| order by Timestamp desc
```

**Results:** Command line system discovery artifact

<img width="1004" height="597" alt="image" src="https://github.com/user-attachments/assets/c003644a-85b6-40c8-bd23-c2559be8c75a" />

#### Query 7: Archive File
```kql
// This query finds files that have extensions indicating compression and are in non-standard directories
DeviceFileEvents
| where DeviceName == "slflarewinsysmo"
| where Timestamp between (datetime(2025-09-14T07:53:53.7612957Z) .. datetime(2025-09-20T23:59:59Z))
| where FileName endswith ".zip" or FileName endswith ".rar" or FileName endswith ".7z"
| where FolderPath has_any ("\\Temp\\", "\\AppData\\", "\\ProgramData\\")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine
| order by Timestamp desc
```

**Results:** Archive file the attacker created to prepare for exfiltration

<img width="1598" height="618" alt="image" src="https://github.com/user-attachments/assets/fcd708e1-0cac-47cb-b03a-73d20c397ef3" />

#### Query 8: C2 Connection
```kql
// 
```

**Results:** 

### Additional Evidence
- **Log Files:** [Specify relevant log sources]
- **Network Traffic:** [Describe network artifacts]
- **File System Artifacts:** [Document file-related evidence]
- **Registry Changes:** [Note any registry modifications]
- **Process Activity:** [Describe suspicious processes]

---

## Data Staging & Exfiltration

### Staging Activity
- **Staging Locations Identified:** [List locations where data was staged]
- **File Types Targeted:** [Specify types of files involved]
- **Staging Methods:** [Describe how data was staged]

### Exfiltration Analysis
- **Exfiltration Methods:** [Document how data left the environment]
- **Destination Analysis:** [Describe where data was sent]
- **Volume Assessment:** [Quantify amount of data involved]
- **Timeline:** [Provide timeline of exfiltration activity]

### Data Loss Assessment
- **Confirmed Data Loss:** [Yes/No and details]
- **Data Types Compromised:** [List types of sensitive data]
- **Business Impact:** [Assess impact to operations]

---

## IoCs (Indicators of Compromise)

### Network Indicators
- **IP Addresses:**
  - `[IP Address]` - [Description/Context]
  - `[IP Address]` - [Description/Context]

- **Domain Names:**
  - `[Domain]` - [Description/Context]
  - `[Domain]` - [Description/Context]

- **URLs:**
  - `[URL]` - [Description/Context]

### Host-Based Indicators
- **File Hashes:**
  - **MD5:** `[Hash]` - [Filename and context]
  - **SHA1:** `[Hash]` - [Filename and context]
  - **SHA256:** `[Hash]` - [Filename and context]

- **File Paths:**
  - `[File Path]` - [Description]

- **Registry Keys:**
  - `[Registry Key]` - [Description]

- **Service Names:**
  - `[Service Name]` - [Description]

### User Account Indicators
- **Compromised Accounts:**
  - `[Username]` - [Context and compromise details]

- **Suspicious Account Activity:**
  - [Description of suspicious activities]

---

## Recommendations / Next Steps

### Immediate Actions Required
1. [Action item 1 with urgency level]
2. [Action item 2 with urgency level]
3. [Action item 3 with urgency level]

### Short-term Remediation (1-7 days)
- [Remediation step 1]
- [Remediation step 2]
- [Remediation step 3]

### Medium-term Improvements (1-4 weeks)
- [Improvement 1]
- [Improvement 2]
- [Improvement 3]

### Long-term Strategic Changes (1-3 months)
- [Strategic change 1]
- [Strategic change 2]
- [Strategic change 3]

### Monitoring Enhancements
- [Monitoring improvement 1]
- [Monitoring improvement 2]

---

## Analyst Workflow

### Investigation Methodology
1. **Initial Detection:** [How the threat was first identified]
2. **Scope Definition:** [How the scope was determined]
3. **Data Collection:** [Sources and methods used]
4. **Analysis Process:** [Step-by-step analysis approach]
5. **Validation Steps:** [How findings were validated]

### Tools and Techniques Used
- **SIEM Platform:** [Platform name and version]
- **Query Languages:** KQL, SPL, etc.
- **Analysis Tools:** [Additional tools used]
- **Data Sources:** [List all data sources consulted]

### Time Investment
- **Total Investigation Time:** [Hours/Days]
- **Phase Breakdown:**
  - Initial triage: [Time]
  - Deep analysis: [Time]
  - Documentation: [Time]
  - Validation: [Time]

---

## Repro/How I Validated Findings

### Validation Methodology
[Describe your approach to validating the findings]

### Reproduction Steps
1. [Step 1 to reproduce findings]
2. [Step 2 to reproduce findings]
3. [Step 3 to reproduce findings]

### Cross-Validation
- **Alternative Data Sources:** [Other sources that confirm findings]
- **Independent Verification:** [How findings were independently verified]
- **False Positive Analysis:** [Steps taken to rule out false positives]

### Confidence Assessment
**Overall Confidence:** [High/Medium/Low]  
**Reasoning:** [Explain why you have this confidence level]

### Supporting Evidence
- [Evidence item 1]
- [Evidence item 2]
- [Evidence item 3]

---

## Attribution & Contact

### Threat Actor Assessment
- **Suspected Actor:** [If known or suspected]
- **TTPs (Tactics, Techniques, Procedures):** [MITRE ATT&CK mappings if applicable]
- **Attribution Confidence:** [Low/Medium/High]
- **Attribution Reasoning:** [Basis for attribution assessment]

### Contact Information
**Primary Analyst:**  
- **Name:** [Your name]
- **Email:** [Your email]
- **Phone:** [Your phone number]
- **Department/Team:** [Your team/department]

**Secondary Contact:**  
- **Name:** [Secondary contact name]
- **Email:** [Secondary email]
- **Role:** [Their role/responsibility]

### Stakeholder Notifications
- **CISO:** [Notification status and date]
- **IT Management:** [Notification status and date]
- **Legal Team:** [Notification status and date]
- **External Authorities:** [If applicable, notification details]

### Case References
- **Internal Case ID:** [Internal tracking reference]
- **External Case ID:** [If applicable, external case reference]
- **Related Incidents:** [Links to related incidents]

---

## Appendices

### Appendix A: Detailed Query Results
[Include detailed query outputs if needed]

### Appendix B: Timeline Analysis
[Detailed timeline if complex]

### Appendix C: Technical Details
[Additional technical information]

---

**Document Classification:** Internal 
**Last Updated:** September 24, 2025
**Version:** 1.0
