# MITRE ATT&CK Detection Coverage & Gap Analysis Tool

A hands-on detection-engineering project focused on evaluating security detection coverage across MITRE ATT&CK tactics and techniques.

The project demonstrates how a security analyst or detection engineer can move beyond individual detection rules and evaluate the overall strength, redundancy, and visibility gaps of a detection program.

## Project Objective

Building individual detections is only one part of detection engineering.

A security team must also understand:

- Which attacker behaviors are currently detectable
- Which MITRE ATT&CK tactics have strong coverage
- Which techniques have limited or no coverage
- Which detections overlap
- Which detections have been validated
- Which data sources provide coverage
- Where additional engineering effort should be prioritized
- Whether duplicate alerting may create unnecessary SOC noise

This project will demonstrate how to:

- Maintain a structured detection catalog
- Map detections to MITRE ATT&CK tactics and techniques
- Normalize detection metadata
- Measure tactic-level coverage
- Measure technique-level coverage
- Identify detection redundancy
- Identify coverage gaps
- Evaluate validation status
- Compare coverage across security data sources
- Prioritize detection-engineering improvements
- Generate analyst-readable CSV and JSON reports
- Validate results against known synthetic ground truth

## Planned Detection Sources

The synthetic detection catalog will model rules and analytics such as:

```text
Sigma Rules
Microsoft Sentinel KQL Hunts
Authentication Detections
PowerShell Detections
Network Detections
Phishing Detections
Cloud Identity Detections
Session Security Detections
YARA Rules
Memory Forensics Indicators
```

## Detection Metadata

Each detection will include information such as:

```text
Detection ID
Detection Name
Detection Type
Platform
Data Source
MITRE ATT&CK Tactic
MITRE ATT&CK Technique
Technique ID
Severity
Confidence
Validation Status
Detection Status
False-Positive Notes
```

## Project Workflow

```text
Detection Catalog
        ↓
Metadata Normalization
        ↓
MITRE ATT&CK Mapping
        ↓
Tactic Coverage Analysis
        ↓
Technique Coverage Analysis
        ↓
Redundancy Review
        ↓
Coverage Gap Identification
        ↓
Gap Prioritization
        ↓
Engineering Recommendations
        ↓
CSV / JSON Reports
        ↓
Validation
```

## Planned Coverage Ratings

The project will classify coverage using levels such as:

```text
STRONG
MODERATE
LOW
GAP
```

Coverage strength will consider factors including:

- Number of detections
- Number of validated detections
- Number of independent data sources
- Detection diversity
- Technique importance
- Detection redundancy

## Planned Project Structure

```text
attack-coverage-analyzer/
├── README.md
├── analyze_coverage.py
├── validate_coverage.py
├── sample-data/
│   └── detection_catalog.csv
├── rules/
│   └── coverage_model.json
├── expected-results/
└── output/
```

## Planned Analyst Outputs

The final analysis will provide views such as:

```text
Tactic Coverage
Technique Coverage
Detection Redundancy
Coverage Gaps
Unvalidated Detections
High-Priority Engineering Recommendations
```

Example:

```text
Technique:
T1059.001 — PowerShell

Detections:
3

Validated:
3

Data Sources:
Windows Event Logs
Endpoint Detection
Microsoft Sentinel

Coverage:
STRONG

Recommendation:
Maintain coverage while reviewing duplicate alerting and correlation logic.
```

Another example:

```text
Technique:
Credential Access

Validated Detections:
1

Coverage:
LOW

Recommendation:
Develop additional credential-access detections using identity,
endpoint, and Windows authentication telemetry.
```

## Skills Demonstrated

- MITRE ATT&CK
- Detection Engineering
- Detection Coverage Analysis
- Detection Gap Analysis
- SOC Engineering
- Security Analytics
- Detection Tuning
- Detection Validation
- Data Source Analysis
- Risk Prioritization
- Python
- CSV Processing
- JSON Reporting
- Security Automation
- Validation Testing
- Analyst Reporting

## Safety

All detections, systems, users, alerts, ATT&CK mappings, and security scenarios used in this project are synthetic or created specifically for defensive training.

The project does not execute attacks, exploit systems, or interact with production infrastructure.

## Project Status

🚧 **In Development**
