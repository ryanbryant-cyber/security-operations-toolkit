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

### DevSecOps

#### Secrets & Configuration Exposure Scanner

Python-based application-security tool that scans a synthetic source-code repository for exposed credentials, insecure configuration values, API keys, tokens, database connection strings, private-key headers, and debug settings.

The project includes false-positive suppression, secret redaction, severity classification, remediation guidance, structured JSON/CSV reporting, and a real detection-gap tuning cycle after the initial scan missed JSON-formatted secrets.

**Skills:** DevSecOps | Application Security | Secrets Detection | Python | Regular Expressions | Secure Configuration Review | Credential Exposure Analysis | Secret Redaction | False-Positive Suppression | Rule Tuning | JSON | CSV

[View the Secrets & Configuration Exposure Scanner](devsecops/secrets-exposure-scanner/)

### Threat Hunting

#### Microsoft Sentinel KQL Threat Hunting Lab

Hands-on cloud SIEM threat-hunting project using Kusto Query Language (KQL) across synthetic Microsoft Sentinel-style telemetry.

The lab includes 10 hunts covering repeated failed sign-ins, successful authentication after failures, dormant-account activity, suspicious PowerShell execution, ungoverned privileged-role changes, multi-stage account correlation, and high-interest network activity.

The project correlates identity, endpoint, privilege, and network telemetry and includes an independent Python validation harness that confirmed all 10 expected hunt behaviors against the synthetic ground truth.

**Skills:** Microsoft Sentinel | KQL | Threat Hunting | SIEM Analysis | Microsoft Entra ID | PowerShell Detection | Privileged Access Monitoring | Behavioral Correlation | Multi-Source Log Analysis | Python Validation

[View the Microsoft Sentinel KQL Threat Hunting Lab](threat-hunting/sentinel-kql-lab/)

### Vulnerability Management

#### Vulnerability Prioritization Engine

Risk-based vulnerability-management project that demonstrates why remediation priority should not be determined by CVSS alone.

The project uses a transparent Python scoring engine to evaluate 10 synthetic vulnerability findings using technical severity, asset criticality, internet exposure, known exploitation, public exploit availability, patch availability, vulnerability age, and compensating controls.

The engine generates ranked remediation priorities, analyst-readable rationale, and structured JSON/CSV reports.

Key project outcomes:

- Prioritized 10 synthetic vulnerability findings
- Produced CRITICAL, HIGH, MODERATE, and LOW remediation classifications
- Demonstrated that a CVSS 7.5 internet-facing, known-exploited VPN vulnerability can outrank a CVSS 9.8 vulnerability on an isolated lab system
- Demonstrated that a CVSS 5.9 known-exploited, unpatched legacy vulnerability can become a HIGH-priority remediation item
- Generated structured CSV and JSON remediation reports
- Implemented an independent validation harness
- Passed 14 of 14 validation checks

**Skills:** Vulnerability Management | Risk-Based Prioritization | CVSS | Asset Criticality | Known Exploitation Analysis | Compensating Controls | Remediation Planning | Risk Scoring | Python | Security Automation | Validation Testing

[View the Vulnerability Prioritization Engine](vulnerability-management/vulnerability-prioritization-engine/)

### Security Hardening

#### Secure Baseline Audit Tool

Windows security-configuration assessment project focused on comparing observed workstation settings against a defined security baseline.

The project evaluates 15 synthetic Windows security controls across authentication, account security, network security, remote access, logging, patch management, endpoint protection, and privilege management.

The Python audit engine supports multiple comparison types, including exact matches, minimum and maximum thresholds, approved ranges, analyst-review conditions, and conditional requirements.

Key project outcomes:

- Evaluated 15 Windows security controls
- Produced 9 PASS results
- Identified 5 configuration failures
- Generated 1 analyst-review finding
- Identified weak password-length requirements
- Identified an ineffective account-lockout threshold
- Detected Remote Desktop enabled without Network Level Authentication
- Detected disabled PowerShell Script Block Logging
- Identified excessive local administrator membership
- Confirmed secure Windows Firewall, SMBv1, endpoint protection, and audit settings
- Generated structured CSV and JSON audit reports
- Implemented an independent validation harness
- Passed 20 of 20 validation checks

**Skills:** Security Configuration Auditing | Windows Security Hardening | Secure Baselines | Configuration Drift Analysis | Authentication Security | Windows Firewall | Remote Access Security | PowerShell Logging | Privilege Management | Remediation Planning | Python | Security Automation | Validation Testing

[View the Secure Baseline Audit Tool](security-hardening/secure-baseline-audit-tool/)

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
