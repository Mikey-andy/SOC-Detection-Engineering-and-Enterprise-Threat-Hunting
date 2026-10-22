# Detection Rule: Web Server Process Execution & Scheduled Task Persistence

## Overview
Detects potential initial web server compromises via unauthorized command shell spawning (Event ID 4688) and adversary persistence established through Windows Scheduled Tasks (Event ID 4698).

## MITRE ATT&CK Mapping
- **Tactic:** Execution (TA0002) / Persistence (TA0003)
- **Technique:** Exploitation for Client Execution (T1203) / Scheduled Task/Job: Scheduled Task (T1053.005)

## Splunk SPL Detection Queries

### Query 1: Web Servers Spawning Command Shells (Event ID 4688)
```spl
index=windows EventCode=4688 
| search ParentProcessName="*\\w3wp*" OR ParentProcessName="*\\tomcat*" OR ParentProcessName="*\\httpd*"
| search NewProcessName="*\\cmd.exe" OR NewProcessName="*\\powershell.exe"
| table _time, host, Account_Name, ParentProcessName, NewProcessName, Process_Command_Line
