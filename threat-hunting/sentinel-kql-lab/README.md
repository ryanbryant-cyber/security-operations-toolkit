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


