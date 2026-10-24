# Detection Rule: Privilege Escalation via Security Group Modification

## Overview
Detects potential privilege escalation or backdoor creation where a user account or built-in account (such as Guest) is added to a high-privilege local or Active Directory security group (e.g., Administrators or Domain Admins).

## MITRE ATT&CK Mapping
- **Tactic:** Privilege Escalation (TA0004)
- **Technique:** Account Manipulation: Local Groups / Domain Groups (T1098)

## Splunk SPL Detection Query
```spl
index=windows EventCode=4728 OR EventCode=4732 
| stats count by host, TargetUserName, MemberName, Caller_User_Name
| sort - count
