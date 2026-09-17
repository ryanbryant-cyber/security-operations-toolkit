# Windows Sigma Detection Lab

A hands-on detection engineering project focused on writing, testing, validating, and correlating Sigma-style detections against fictional Windows security events.

This project demonstrates how individual Windows events can be converted into analyst-ready detections and higher-value behavioral findings.

## Project Workflow

Windows Event Data  
↓  
Sigma Detection Rules  
↓  
Field Normalization  
↓  
Event-Level Matching  
↓  
Detection Validation  
↓  
Behavioral Correlation  
↓  
Structured JSON Reports  
↓  
Analyst Investigation

## Detection Rules

The lab currently includes three Sigma-style detection rules.

### Failed Windows Logon

Detects:

```text
Windows Event ID 4625

