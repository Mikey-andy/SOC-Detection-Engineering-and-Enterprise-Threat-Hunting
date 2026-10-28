# Detection Rule: Defense Evasion via Windows Event Log Clearing

## Overview
Detects potential defense evasion attempts where an adversary manually clears the Windows Security Event Log (Event ID 1102) to blind incident responders and erase forensic artifacts before or after executing malicious activity.

## MITRE ATT&CK Mapping
- **Tactic:** Defense Evasion (TA0005)
- **Technique:** Indicator Removal on Host: Clear Windows Event Logs (T1070.001)

## Splunk SPL Detection Query
```spl
index=windows EventCode=1102 
| table _time, host, SubjectUserName
