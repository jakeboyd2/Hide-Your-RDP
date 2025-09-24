# Threat Hunt Report

## Introduction

**Hunter:** [Your Name]  
**Date:** [Investigation Date - YYYY-MM-DD]  
**Environment/Dataset:** [Cyber Range Environment / Dataset Details]  
**Objective:** [Primary goal and scope of the threat hunt investigation]

---

## Key Findings

### Summary
[Provide a high-level summary of the most critical findings from your threat hunt]

### Critical Observations
- [Finding 1]
- [Finding 2]
- [Finding 3]

### Risk Assessment
**Risk Level:** [Low/Medium/High/Critical]  
**Confidence Level:** [Low/Medium/High]  
**Impact Assessment:** [Brief description of potential impact]

---

## Artifacts & Evidence

### KQL Queries Used

#### Query 1: [Query Purpose/Label]
```kql
// [Brief description of what this query accomplishes]
[Paste your KQL query here]
```

**Results:** [Summary of results or key observations]

#### Query 2: [Query Purpose/Label]
```kql
// [Brief description of what this query accomplishes]
[Paste your KQL query here]
```

**Results:** [Summary of results or key observations]

#### Query 3: [Query Purpose/Label]
```kql
// [Brief description of what this query accomplishes]
[Paste your KQL query here]
```

**Results:** [Summary of results or key observations]

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

**Document Classification:** [Internal/Confidential/Restricted]  
**Last Updated:** [Date]  
**Version:** [Version number]