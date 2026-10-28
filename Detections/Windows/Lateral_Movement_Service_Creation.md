# Detection Rule: Lateral Movement via Remote Service Creation

## Overview
Detects potential lateral movement where an adversary remotely installs a Windows service (Event ID 4697) on a target host to execute arbitrary payloads under system privileges using tools like PsExec or Impacket.

## MITRE ATT&CK Mapping
- **Tactic:** Lateral Movement (TA0008)
- **Technique:** Remote Services: Server Execution / SMB/Windows Admin Shares (T1021.002 / T1570)

## Splunk SPL Detection Query
```spl
index=windows EventCode=4697 
| stats count by host, ServiceName, ServiceFileName, SubjectUserName 
| sort - count
