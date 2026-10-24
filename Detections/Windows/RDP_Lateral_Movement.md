# Detection Rule: Lateral Movement via Remote Desktop (RDP Logon Type 10)

## Overview
Detects potential lateral movement where a user or compromised account establishes an interactive remote desktop connection (Logon Type 10) to a target endpoint or critical server.

## MITRE ATT&CK Mapping
- **Tactic:** Lateral Movement (TA0008)
- **Technique:** Remote Services: Remote Desktop Protocol (T1021.001)

## Splunk SPL Detection Query
```spl
index=windows EventCode=4624 LogonType=10 
| stats count by host, TargetUserName, IpAddress, LogonType
| sort - count
