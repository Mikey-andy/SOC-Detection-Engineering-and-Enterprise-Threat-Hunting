# Detection Rule: Windows Authentication Brute-Force & Anomalous Logons

## Overview
Detects potential brute-force attacks and credential stuffing attempts against Windows Active Directory or local endpoints by tracking high volumes of failed logons (Event ID 4625) followed by a successful logon event (Event ID 4624).

## MITRE ATT&CK Mapping
- **Tactic:** Credential Access (TA0006) / Initial Access (TA0001)
- **Technique:** Brute Force: Password Guessing (T1110.001)

## Splunk SPL Detection Query
\`\`\`spl
index=windows (EventCode=4625 OR EventCode=4624) 
| stats count(eval(EventCode=4625)) as failed_attempts, count(eval(EventCode=4624)) as success_attempts by TargetUserName, host, Source_Network_Address
| where failed_attempts > 5 AND success_attempts > 0
| sort - failed_attempts
\`\`\`

## Analyst Investigation Checklist
1. Review the `Source_Network_Address` to determine if the traffic originates from an internal workstation, a VPN gateway, or an external IP address.
2. Check account lockout status in Active Directory for `TargetUserName`.
3. Correlate with firewall or VPN logs to verify if the source IP belongs to an authenticated remote worker or an unknown external actor.
