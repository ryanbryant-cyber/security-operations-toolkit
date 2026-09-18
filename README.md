# Security Operations Toolkit

Hands-on cybersecurity tools, scripts, detection logic, threat intelligence exercises, endpoint hunting, log analysis, and security automation projects.

This repository serves as a technical workspace for demonstrating practical cybersecurity analyst skills through reproducible tools, sample datasets, documented workflows, and structured security outputs.

## Projects

### Threat Intelligence

#### IOC Enrichment & Triage Tool

Python-based IOC triage utility that validates and normalizes indicators, correlates duplicate observations, applies transparent evidence-based priority scoring, generates analyst recommendations, and exports structured CSV and JSON reports.

**Skills:** Python | Threat Intelligence | IOC Analysis | Log Correlation | Security Automation | JSON | CSV

[View the IOC Enrichment & Triage Tool](threat-intelligence/ioc-triage-tool/)

### Detection Engineering

#### Windows Sigma Detection Lab

Hands-on detection engineering project that tests Sigma-style Windows detections against fictional event data, validates expected matches, measures false positives and false negatives, correlates repeated failed logons, and exports structured JSON findings.

**Skills:** Sigma | Detection Engineering | Windows Event IDs | MITRE ATT&CK | Python | YAML | JSON | Behavioral Correlation | Detection Testing

[View the Windows Sigma Detection Lab](detection-engineering/windows-sigma-lab/)

### Incident Response / DFIR

#### Windows DFIR Incident Timeline Lab

Multi-source Windows incident-response investigation that reconstructs a simulated compromise from authentication, process, file, network, service, and Defender evidence. The project includes timeline reconstruction, persistence analysis, attempted lateral-movement assessment, confidence-based findings, containment priorities, MITRE ATT&CK context, and a finalized investigation report.

**Skills:** DFIR | Incident Response | Windows Event Analysis | Timeline Reconstruction | PowerShell Analysis | Persistence Analysis | Lateral Movement | MITRE ATT&CK | Evidence Correlation | Containment Planning

[View the Windows DFIR Incident Timeline Lab](incident-response/windows-dfir-timeline-lab/)

### Malware Analysis

#### YARA File Detection Lab

Hands-on static file detection project that uses YARA rules to identify suspicious PowerShell strings, ransomware-style markers, network indicators, command-line utilities, and composite multi-indicator patterns across harmless synthetic files.

The project validates expected and actual matches, measures false positives and false negatives, and exports structured JSON detection results.

**Skills:** YARA | Static File Analysis | Malware Analysis | Detection Engineering | Signature Development | Python | JSON | Rule Tuning | False-Positive Analysis | Composite Detection Logic

[View the YARA File Detection Lab](malware-analysis/yara-file-detection-lab/)

## Repository Goals

This repository is designed to demonstrate hands-on cybersecurity skills including:

- Security operations
- Threat intelligence
- Detection engineering
- Incident response
- Endpoint hunting
- Log analysis
- Python security automation
- Cloud security
- Structured security reporting

Additional projects will be added as the toolkit expands.

## Safety

All sample data, indicators, logs, identities, domains, and scenarios used in this repository are fictional, sanitized, or reserved for documentation and testing purposes.

No production credentials, private organizational information, or sensitive data are included.
