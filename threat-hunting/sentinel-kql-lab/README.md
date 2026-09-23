# Microsoft Sentinel KQL Threat Hunting Lab

A hands-on cloud SIEM and threat-hunting project focused on using Kusto Query Language (KQL) to investigate synthetic Microsoft Sentinel-style security telemetry.

## Project Goals

This project will demonstrate how a security analyst can:

- Understand basic KQL syntax
- Search and filter security telemetry
- Analyze authentication activity
- Identify repeated failed sign-ins
- Investigate suspicious PowerShell execution
- Review privileged role changes
- Detect unusual account activity
- Correlate related security events
- Summarize findings for analyst review
- Develop reusable threat-hunting queries

## Planned Hunts

The initial version will include hunts for:

- Repeated failed authentication attempts
- Successful sign-in following multiple failures
- Dormant-account activity
- Suspicious PowerShell execution
- Privileged role assignment changes
- Unusual outbound network activity

## Project Workflow

Synthetic Sentinel-Style Logs  
↓  
KQL Query  
↓  
Filtering and Summarization  
↓  
Event Correlation  
↓  
Threat-Hunting Result  
↓  
Analyst Review  
↓  
Investigation Recommendation

## Planned Data Sources

The synthetic dataset will model telemetry similar to:

- Sign-in logs
- Windows security events
- Process creation events
- Azure activity logs
- Network security telemetry
- Identity and privileged-access events

## Safety

All users, IP addresses, systems, commands, identities, and events used in this project are fictional or reserved for documentation and testing.

No production Microsoft Sentinel workspace, real credentials, or private organizational data are included.

## Project Status

🚧 In Development
## Project Status

🚧 In Development
