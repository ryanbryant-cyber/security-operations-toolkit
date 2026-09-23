# Microsoft Sentinel KQL Threat Hunting Lab

A hands-on cloud SIEM and threat-hunting project focused on using Kusto Query Language (KQL) to investigate synthetic Microsoft Sentinel-style security telemetry.

This project demonstrates how analysts can move from isolated security events to multi-source behavioral correlations involving identity, endpoint, privilege, and network activity.

## Project Workflow

Synthetic Sentinel-Style Logs  
↓  
KQL Threat Hunt  
↓  
Filtering and Summarization  
↓  
Cross-Source Correlation  
↓  
Behavioral Timeline  
↓  
Threat-Hunting Finding  
↓  
Analyst Investigation

## Data Sources

The lab uses four synthetic telemetry sources:

```text
sample-logs/
├── signin_logs.csv
├── process_events.csv
├── privileged_activity.csv
└── network_events.csv

These datasets model telemetry similar to:

- Microsoft Entra ID sign-in logs
- Windows process creation events
- Azure privileged-access activity
- Network security telemetry

All identities, systems, IP addresses, commands, and events are fictional or reserved for documentation and testing.

## Threat Hunts

The lab contains 10 KQL threat-hunting queries that progress from individual event searches to multi-source behavioral correlation.

### Hunt 01 — Repeated Failed Sign-ins

Identifies identities receiving three or more failed authentication attempts from the same source IP.

The synthetic dataset identified:

```text
finance.user@northstar.example
Source IP: 198.51.100.24
Failed attempts: 3
First failure: 12:17:41
Last failure: 12:18:13
