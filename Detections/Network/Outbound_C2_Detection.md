# Detection Rule: Suspicious Outbound Traffic & C2 Beaconing

## Overview
Detects internal workstations making outbound network connections to external public IP addresses on non-standard ports. Used to identify potential malware beaconing or command-and-control (C2) channels bypassing perimeter filters.

## MITRE ATT&CK Mapping
- **Tactic:** Command and Control (TA0011)
- **Technique:** Application Layer Protocol (T1071) / Non-Standard Port (T1571)

## Splunk SPL Detection Query
\`\`\`spl
index=network action=allowed dest_ip!=10.0.0.0/8 dest_ip!=192.168.0.0/16 
| stats count by src_ip, dest_ip, dest_port, app 
| where dest_port > 1024 AND dest_port != 443 AND dest_port != 80
| sort - count
\`\`\`

## Analyst Investigation Checklist
1. Verify if `dest_ip` is a known public cloud endpoint or an unrecognized external host (run threat intelligence lookups on VirusTotal/AbuseIPDB).
2. Pivot to endpoint telemetry (Sysmon Event ID 3 or Process Creation Event ID 4688) using `src_ip` to identify the process initiating the connection.
3. If suspicious, pull a Packet Capture (PCAP) and analyze the TCP handshake and payload bytes in Wireshark to inspect connection metadata.
