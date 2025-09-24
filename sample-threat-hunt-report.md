# Threat Hunt Report - Sample

## Introduction

**Hunter:** John Smith  
**Date:** 2025-09-21  
**Environment/Dataset:** Azure Cyber Range Environment - Windows Server 2019 VMs, Sentinel Logs  
**Objective:** Investigate suspected lateral movement and data exfiltration following initial compromise detection in VM-Web-01

---

## Key Findings

### Summary
Investigation revealed successful lateral movement from compromised web server (VM-Web-01) to domain controller (VM-DC-01) with evidence of credential harvesting and data staging activities. Attacker used legitimate administrative tools to avoid detection.

### Critical Observations
- Successful privilege escalation on VM-Web-01 using CVE-2023-XXXX
- Lateral movement to VM-DC-01 via RDP using harvested credentials
- Data staging in C:\Windows\Temp\ on multiple systems
- Exfiltration attempt to external IP 185.220.101.42

### Risk Assessment
**Risk Level:** High  
**Confidence Level:** High  
**Impact Assessment:** Potential access to sensitive customer data and domain admin credentials

---

## Artifacts & Evidence

### KQL Queries Used

#### Query 1: Initial Compromise Detection
```kql
// Detect suspicious PowerShell execution with network connections
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4688
| where Process contains "powershell.exe"
| where CommandLine contains "-enc" or CommandLine contains "IEX"
| where Computer == "VM-Web-01"
| project TimeGenerated, Account, Process, CommandLine, Computer
```

**Results:** Found 15 instances of encoded PowerShell commands executed by IIS service account

#### Query 2: Lateral Movement Analysis
```kql
// Track RDP connections between systems
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4624
| where LogonType == 10 // RDP logon
| where Account != "Administrator"
| summarize count() by Account, Computer, SourceNetworkAddress
| where count_ > 3
```

**Results:** Identified unusual RDP activity from VM-Web-01 to VM-DC-01 using service account

#### Query 3: Data Staging Detection
```kql
// Identify large file operations in temp directories
DeviceFileEvents
| where TimeGenerated > ago(7d)
| where FolderPath contains "\\Temp\\"
| where ActionType == "FileCreated"
| where FileSize > 1000000 // Files larger than 1MB
| summarize TotalSize=sum(FileSize), FileCount=count() by InitiatingProcessAccountName, DeviceName
```

**Results:** Found 250MB of data staged across 3 systems in temp directories

### Additional Evidence
- **Log Files:** Windows Security Events, IIS Access Logs, Sysmon Events
- **Network Traffic:** Unusual outbound HTTPS connections to 185.220.101.42
- **File System Artifacts:** Staged files in C:\Windows\Temp\update_pkg\
- **Registry Changes:** New service registered: "WindowsUpdateAgent"
- **Process Activity:** Suspicious rundll32.exe and regsvr32.exe execution

---

## IoCs (Indicators of Compromise)

### Network Indicators
- **IP Addresses:**
  - `185.220.101.42` - C2 server, hosting malicious payload
  - `192.168.1.100` - Internal pivot point (VM-Web-01)

- **Domain Names:**
  - `update-service.com` - Malicious domain used for C2
  - `cdn-updates.net` - Secondary C2 domain

### Host-Based Indicators
- **File Hashes:**
  - **SHA256:** `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6` - malicious.dll
  - **MD5:** `12345678901234567890123456789012` - dropper.exe

- **File Paths:**
  - `C:\Windows\Temp\update_pkg\` - Staging directory
  - `C:\Windows\System32\malicious.dll` - Persistent backdoor

- **Registry Keys:**
  - `HKLM\System\CurrentControlSet\Services\WindowsUpdateAgent` - Malicious service

### User Account Indicators
- **Compromised Accounts:**
  - `CYBERRANGE\svc-iis` - Web service account used for lateral movement

---

## Recommendations / Next Steps

### Immediate Actions Required
1. Isolate affected systems (VM-Web-01, VM-DC-01) - CRITICAL
2. Reset passwords for compromised service accounts - HIGH
3. Block outbound connections to 185.220.101.42 - HIGH

### Short-term Remediation (1-7 days)
- Patch CVE-2023-XXXX on all web servers
- Implement application whitelisting on critical servers
- Enhanced monitoring of PowerShell execution

### Long-term Strategic Changes (1-3 months)
- Implement zero-trust network segmentation
- Deploy endpoint detection and response (EDR) solutions
- Regular penetration testing of cyber range environment

---

## Analyst Workflow

### Investigation Methodology
1. **Initial Detection:** Automated alert from Sentinel for suspicious PowerShell activity
2. **Scope Definition:** Expanded to include all systems in same subnet
3. **Data Collection:** Gathered 7 days of security events, network logs, and file activity
4. **Analysis Process:** Timeline analysis followed by IOC pivoting
5. **Validation Steps:** Manual verification of findings on test system

### Tools and Techniques Used
- **SIEM Platform:** Microsoft Sentinel
- **Query Languages:** KQL (Kusto Query Language)
- **Analysis Tools:** PowerShell, Sysinternals Suite
- **Data Sources:** Windows Security Events, Sysmon, Network Flow Logs

---

## Attribution & Contact

### Threat Actor Assessment
- **Suspected Actor:** Unknown - Possibly APT29 based on TTPs
- **TTPs:** T1059.001 (PowerShell), T1021.001 (RDP), T1041 (Exfiltration)
- **Attribution Confidence:** Low
- **Attribution Reasoning:** Similar encoded PowerShell techniques observed in previous APT29 campaigns

### Contact Information
**Primary Analyst:**  
- **Name:** John Smith
- **Email:** john.smith@company.com
- **Phone:** +1-555-0123
- **Department/Team:** Cyber Security Operations Center

---

**Document Classification:** Internal  
**Last Updated:** 2025-09-21  
**Version:** 1.0