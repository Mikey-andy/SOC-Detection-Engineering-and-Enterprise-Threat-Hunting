# Detection Rule: LSASS Process Access & Credential Dumping (Sysmon)

## Overview
Detects potential credential dumping attempts where an unauthorized process opens a handle to the Local Security Authority Subsystem Service (`lsass.exe`) to extract plaintext passwords or hashes from memory.

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access (TA0006)
- **Technique:** OS Credential Dumping: LSASS Memory (T1003.001)

## Splunk SPL Detection Query
```spl
index=windows EventCode=10 TargetImage="*\\lsass.exe" 
| stats count as activity by SourceImage 
| sort - activity
