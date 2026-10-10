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

### Email Security

#### Phishing Email Investigation Lab

SOC-focused email-security project centered on phishing triage, authentication analysis, IOC extraction, and evidence-based disposition.

The project evaluates three synthetic email cases representing malicious phishing, a suspicious invoice scenario, and a benign internal message.

The Python analysis engine reviews sender context, SPF, DKIM, DMARC, domain alignment, social-engineering indicators, URLs, attachments, and extracted investigation artifacts before assigning a BENIGN, SUSPICIOUS, or MALICIOUS disposition.

Key project outcomes:

- Analyzed 3 synthetic email investigations
- Produced 1 MALICIOUS, 1 SUSPICIOUS, and 1 BENIGN disposition
- Detected SPF, DKIM, and DMARC failures
- Identified display-name impersonation
- Detected Reply-To and Return-Path mismatches
- Identified credential-phishing indicators
- Detected suspicious HTML attachment behavior
- Extracted email addresses, domains, IP addresses, URLs, and SHA-256 hashes
- Separated extracted investigation artifacts from confirmed malicious indicators
- Generated analyst-readable assessments
- Produced structured CSV and JSON investigation reports
- Implemented an independent validation harness
- Passed 10 of 10 validation checks

**Skills:** Phishing Analysis | Email Security | SOC Triage | Email Header Analysis | SPF | DKIM | DMARC | Sender Impersonation Detection | Domain Alignment Analysis | Social Engineering Detection | IOC Extraction | URL Analysis | Attachment Analysis | Python | Security Automation | Validation Testing

[View the Phishing Email Investigation Lab](email-security/phishing-investigation-lab/)

### Incident Detection & Containment

#### Session Hijacking & DDoS Detection and Containment Lab

Defensive security-operations project focused on detecting suspected session hijacking and distributed denial-of-service behavior using synthetic session and web-traffic telemetry.

The project correlates authentication context, session reuse, source changes, sensitive activity, request-volume baselines, distributed traffic, HTTP errors, and service degradation before assigning severity and containment guidance.

Key project outcomes:

- Detected 1 suspected session-hijacking scenario
- Correlated 6 session behavioral indicators
- Identified source-IP and user-agent changes
- Detected missing MFA verification on the anomalous origin
- Identified sensitive actions from the anomalous session
- Detected concurrent reuse of the same session identifier
- Established a normal HTTP baseline of 86.67 requests/minute
- Detected 2 DDoS traffic surges
- Measured traffic at 23.54x and 26.08x normal baseline
- Identified distributed source activity and endpoint concentration
- Detected HTTP 429 and 503 service degradation
- Generated containment recommendations for both incident types
- Produced structured CSV and JSON investigation reports
- Implemented an independent validation harness
- Passed 10 of 10 validation checks

**Skills:** Session Security | Session Hijacking Detection | DDoS Detection | Web Log Analysis | Authentication Analysis | Behavioral Correlation | Traffic Baselining | HTTP Traffic Analysis | Incident Triage | Incident Containment | Risk Scoring | Python | Security Automation | Validation Testing

[View the Session Hijacking & DDoS Detection and Containment Lab](incident-detection/session-ddos-detection-lab/)

### Memory Forensics

#### Windows Memory Forensics Investigation Lab

DFIR-focused memory-forensics project centered on correlating synthetic Windows volatile-memory artifacts across processes, command lines, loaded modules, network connections, and executable memory regions.

The project reconstructs a suspicious Finance workstation process chain and demonstrates how multiple independent artifacts can raise investigation priority without overstating what the evidence proves.

Key project outcomes:

- Analyzed 5 synthetic forensic evidence sources
- Reconstructed a suspicious process chain involving Outlook, Word, PowerShell, rundll32, and cmd
- Identified encoded PowerShell execution and ExecutionPolicy Bypass
- Identified identity, network, and privileged-group discovery commands
- Detected an unsigned DLL loaded from a user-writable Temp directory
- Correlated outbound connections from PowerShell and rundll32
- Identified attempted internal SMB communication while preserving the distinction between `SYN_SENT` and a completed session
- Detected private RWX memory
- Detected private executable memory without a backing file
- Correlated 16 forensic indicators into a HIGH-priority investigation
- Reconstructed an analyst-readable incident timeline
- Preserved forensic uncertainty around malware, C2, process injection, and lateral movement
- Generated structured CSV and JSON findings
- Implemented an independent validation harness
- Passed 10 of 10 validation checks

**Skills:** Memory Forensics | DFIR | Windows Process Analysis | Process Tree Analysis | PowerShell Investigation | Command-Line Analysis | Loaded Module Analysis | Memory Region Analysis | Network Connection Analysis | Incident Reconstruction | Evidence Correlation | Python | Security Automation | Validation Testing

[View the Windows Memory Forensics Investigation Lab](memory-forensics/windows-memory-forensics-lab/)

### SOAR Automation

#### SOC Alert Enrichment & Response Automation Lab

Security-operations automation project focused on transforming noisy multi-source alerts into enriched, prioritized, analyst-ready incident cases.

The project processes synthetic alerts from identity, endpoint, network, threat-intelligence, privilege, and email-security sources, then applies business context, IOC enrichment, deduplication, correlation, priority scoring, response playbooks, and analyst approval boundaries.

Key project outcomes:

- Processed 11 synthetic raw security alerts
- Normalized and enriched alerts with user, asset, and IOC context
- Deduplicated overlapping PowerShell detections while preserving original alert IDs
- Reduced 11 raw alerts to 10 enriched alert records
- Correlated activity into 4 analyst-ready incident cases
- Preserved 8 original Finance source alerts inside one CRITICAL incident
- Routed the Finance case to SOC Tier 2 / Incident Response
- Correlated authentication, execution, network, threat-intelligence, privilege, and email evidence
- Added business context for high-value identities, asset criticality, and data sensitivity
- Demonstrated how trusted IOC enrichment can reduce unnecessary analyst noise
- Tuned trusted administrative traffic from MODERATE to LOW priority
- Separated safe automated actions from analyst-approved containment
- Generated response playbooks and escalation conditions
- Produced structured JSON and CSV case reports
- Preserved analyst guardrails and evidentiary uncertainty
- Implemented an independent validation harness
- Passed 12 of 12 validation checks

**Skills:** SOAR | SOC Automation | Alert Normalization | Alert Enrichment | Alert Deduplication | Behavioral Correlation | Incident Prioritization | Case Management | Threat Intelligence Enrichment | Response Playbooks | Human-in-the-Loop Response | Python | Security Automation | Validation Testing

[View the SOC Alert Enrichment & Response Automation Lab](soar-automation/soc-alert-response-lab/)

### Cloud Incident Response

#### Microsoft Entra ID Cloud Compromise Investigation & Response Lab

Cloud incident-response project focused on reconstructing suspicious identity activity across synthetic Microsoft Entra ID and Azure-style telemetry.

The project correlates authentication failures, successful sign-ins, Conditional Access results, MFA context, privileged-access changes, Microsoft 365 activity, Azure resource access, storage activity, and containment actions into separate analyst-facing incident timelines.

Key project outcomes:

- Investigated 2 separate synthetic cloud incidents
- Correlated repeated Finance sign-in failures with a successful external authentication
- Preserved MFA-success context instead of incorrectly claiming MFA bypass
- Identified unmanaged and noncompliant device activity
- Interpreted report-only Conditional Access failures correctly
- Detected undocumented cloud role additions and modifications
- Reviewed Microsoft 365, Azure Resource Manager, and Azure Storage activity
- Correlated 16 indicators into the Finance incident
- Correlated 10 indicators into a separate dormant-contractor incident
- Preserved Finance and contractor activity as separate incident scopes
- Distinguished incident activity from later containment actions
- Recorded session revocation, role removal, and account disablement as response activity
- Generated analyst-readable timelines and containment recommendations
- Produced structured JSON and CSV investigation reports
- Preserved uncertainty around credential theft, MFA bypass, data exfiltration, VM compromise, and persistence
- Implemented an independent validation harness
- Passed 13 of 13 validation checks

**Skills:** Microsoft Entra ID | Cloud Incident Response | Azure Security | Identity Security | Conditional Access Analysis | MFA Analysis | Privileged Access Monitoring | Microsoft 365 Investigation | Azure Resource Analysis | Azure Storage Analysis | Incident Reconstruction | Scope Assessment | Incident Containment | Python | Security Automation | Validation Testing

[View the Microsoft Entra ID Cloud Compromise Investigation & Response Lab](cloud-incident-response/entra-cloud-incident-lab/)

### Detection Coverage

#### MITRE ATT&CK Detection Coverage & Gap Analysis Tool

Detection-engineering project focused on evaluating the strength, maturity, redundancy, and gaps of a synthetic security detection program using the MITRE ATT&CK framework.

The project analyzes 25 synthetic detections across Sigma, KQL, Python analytics, YARA, memory forensics, email security, network monitoring, cloud identity, and DevSecOps sources, then measures how effectively those detections cover 25 priority ATT&CK techniques.

Key project outcomes:

- Analyzed 25 synthetic detections
- Evaluated 25 priority MITRE ATT&CK techniques
- Calculated technique-level and tactic-level coverage
- Identified 3 STRONG coverage areas
- Identified 15 MODERATE coverage areas
- Identified 1 LOW coverage area
- Identified 6 complete detection gaps
- Prioritized Critical, High, Moderate, and Review engineering work
- Identified OS Credential Dumping and Impair Defenses as CRITICAL coverage gaps
- Identified Remote Desktop Protocol, Scheduled Task, and Exfiltration to Cloud Storage as HIGH-priority gaps
- Demonstrated that detection count alone does not equal mature coverage
- Identified Cloud Accounts as LOW coverage because one mapped detection remains experimental and needs review
- Identified layered PowerShell and Brute Force coverage for redundancy / alert-overlap review
- Correctly handled multi-tactic ATT&CK mappings
- Generated structured technique, tactic, engineering-priority, and JSON reports
- Preserved detection-engineering guardrails around validation, telemetry independence, and false-positive impact
- Implemented an independent validation harness
- Passed 12 of 12 validation checks

**Skills:** MITRE ATT&CK | Detection Engineering | Detection Coverage Analysis | Detection Gap Analysis | SOC Engineering | Security Analytics | Detection Validation | Detection Tuning | Detection Redundancy Analysis | ATT&CK Mapping | Engineering Prioritization | Python | Security Automation | Validation Testing

[View the MITRE ATT&CK Detection Coverage & Gap Analysis Tool](detection-coverage/attack-coverage-analyzer/)

### Network Detection

#### DNS Tunneling Detection & Triage Lab

Defensive network-detection project focused on identifying DNS behavior that may indicate covert tunneling or command-and-control activity.

The project analyzes synthetic DNS telemetry from three workstations and compares normal DNS behavior against higher-interest patterns involving rapid query frequency, long changing subdomains, TXT record usage, high unique-subdomain ratios, and encoded-looking labels.

Key project outcomes:

- Analyzed 29 synthetic DNS events
- Evaluated 3 source hosts
- Evaluated 7 parent domains
- Analyzed 10 host/domain behavior groups
- Generated 1 analyst finding
- Identified 16 higher-interest DNS queries from `NFG-FIN-WS07`
- Detected 5 TXT queries
- Measured a 100% unique-subdomain ratio
- Measured a 100% encoded-looking subdomain ratio
- Measured a 4.0-second average query interval
- Correlated 6 independent DNS behavioral indicators
- Assigned a CRITICAL investigation priority
- Kept normal HR and Marketing DNS traffic out of the analyst queue
- Generated structured JSON and CSV reports
- Preserved uncertainty around DNS tunneling, command-and-control, and data exfiltration
- Implemented an independent validation harness
- Passed 10 of 10 validation checks

**Skills:** DNS Security | DNS Tunneling Detection | Network Security Monitoring | Behavioral Detection | Command-and-Control Analysis | DNS Query Analysis | TXT Record Analysis | Subdomain Analysis | Network Detection Engineering | SOC Triage | Risk Scoring | Python | Security Automation | Validation Testing

[View the DNS Tunneling Detection & Triage Lab](network-detection/dns-tunneling-detection-lab/)

### Forensic Operations

#### Digital Evidence Integrity & Chain-of-Custody Tool

DFIR operations project focused on preserving, documenting, and verifying the integrity of digital evidence collected during cybersecurity investigations.

The project registers synthetic forensic artifacts, assigns unique evidence IDs, records metadata, calculates SHA-256 hashes, maintains chain-of-custody records, and later verifies whether evidence remains unchanged, has been altered, or is missing.

Key project outcomes:

- Registered 6 synthetic forensic evidence artifacts
- Assigned unique evidence identifiers from `EV-001` through `EV-006`
- Captured evidence metadata including type, source, size, custodian, and registration timestamp
- Calculated SHA-256 hashes for all registered evidence
- Generated a structured evidence manifest
- Generated an analyst-facing evidence inventory
- Created 12 initial chain-of-custody records
- Preserved separate `Collected` and `Registered` custody actions
- Created a controlled verification copy while preserving the original evidence package
- Detected 1 intentionally altered artifact through SHA-256 mismatch
- Detected 1 intentionally missing evidence artifact
- Verified 4 unchanged evidence files
- Appended integrity-verification events to the chain-of-custody record
- Distinguished `VERIFIED`, `HASH MISMATCH`, and `MISSING` evidence states
- Confirmed the original registered evidence package remained unchanged
- Generated structured JSON and CSV integrity reports
- Implemented an independent validation harness
- Passed 11 of 11 validation checks

**Skills:** Digital Forensics | Evidence Integrity | Chain of Custody | DFIR Operations | SHA-256 Hashing | Forensic Documentation | Evidence Registration | Evidence Verification | Evidence Handling | File Metadata Analysis | Incident Documentation | Python | Security Automation | Validation Testing

[View the Digital Evidence Integrity & Chain-of-Custody Tool](forensic-operations/evidence-integrity-tool/)

### SOC Data Engineering

#### SOC Telemetry Normalization & Data Quality Pipeline

SOC engineering project focused on transforming heterogeneous security telemetry into a consistent, validated schema suitable for SIEM analysis, threat hunting, dashboards, and detection engineering.

The Python pipeline ingests synthetic telemetry from Windows Security, Microsoft Entra ID, Endpoint Detection, Firewall, and DNS sources, then performs schema mapping, field normalization, timestamp standardization, identity normalization, IP validation, severity normalization, duplicate detection, event-quality scoring, and source-level telemetry health analysis.

Key project outcomes:

- Ingested 25 synthetic security events from 5 telemetry sources
- Normalized vendor-specific schemas into 11 common SOC fields
- Standardized usernames, hostnames, timestamps, IP addresses, and severity values
- Distinguished required fields from source-specific optional fields
- Detected 1 duplicate Windows Security event
- Detected 1 Entra ID event with a missing required host
- Detected 1 Firewall event with an invalid IP address
- Detected 1 Firewall event with a missing event identifier
- Produced 21 clean analyst-ready normalized events
- Preserved duplicate and invalid telemetry in separate reports
- Calculated event-level data-quality scores
- Calculated source-level telemetry-health scores
- Produced an overall telemetry quality score of **92.96 — GOOD**
- Identified DNS and EDR telemetry as **EXCELLENT**
- Identified Firewall telemetry as the lowest-quality source at **81.7 — FAIR**
- Generated JSON and CSV outputs for analysis and reporting
- Implemented independent expected-result validation
- Passed **15 of 15 validation checks**

**Skills:** SOC Engineering | SIEM Data Engineering | Security Telemetry | Log Normalization | Schema Mapping | ETL | Data Quality | Event Validation | Duplicate Detection | Telemetry Health Monitoring | Python | JSON | CSV | Security Automation | Validation Testing

[View the SOC Telemetry Normalization & Data Quality Pipeline](soc-data-engineering/telemetry-normalization-pipeline/)

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
