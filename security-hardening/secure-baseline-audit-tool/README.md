# Secure Baseline Audit Tool

A hands-on security-hardening and configuration-assessment project focused on evaluating system settings against a defined security baseline.

The project demonstrates how security analysts can identify configuration weaknesses, classify findings by severity, provide remediation guidance, and produce structured audit reports.

## Project Objective

Secure systems depend on more than patching vulnerabilities.

Misconfigured security controls can increase organizational risk even when the underlying operating system and applications are fully patched.

This project will demonstrate how a security analyst can:

- Define a measurable security baseline
- Review system configuration data
- Compare observed settings with expected values
- Identify configuration drift
- Assign PASS, FAIL, and REVIEW results
- Classify failed controls by severity
- Provide remediation guidance
- Generate structured CSV and JSON reports
- Validate audit results against known ground truth

## Planned Security Controls

The initial baseline will evaluate controls such as:

- Password length requirements
- Password complexity
- Account lockout thresholds
- Guest account status
- Host firewall status
- Remote Desktop configuration
- SMBv1 status
- PowerShell logging
- Security audit logging
- Automatic security updates
- Endpoint protection
- Local administrator configuration

## Project Workflow

```text
Synthetic System Configuration
        ↓
Security Baseline
        ↓
Control Evaluation
        ↓
PASS / FAIL / REVIEW
        ↓
Severity Classification
        ↓
Remediation Guidance
        ↓
Structured Audit Reports
        ↓
Validation
```

## Planned Project Components

```text
secure-baseline-audit-tool/
├── README.md
├── audit_baseline.py
├── validate_audit.py
├── sample-data/
├── baseline/
├── expected-results/
└── output/
```

## Skills Demonstrated

- Security Configuration Auditing
- System Hardening
- Secure Baselines
- Configuration Drift Analysis
- Security Control Validation
- Remediation Planning
- Risk Classification
- Python
- CSV Processing
- JSON Processing
- Security Automation
- Validation Testing
- Analyst Reporting

## Safety

All systems, users, configurations, and security findings used in this project are synthetic and created specifically for testing and portfolio demonstration.

No production systems, credentials, or organizational configuration data are used.

## Project Status

🚧 **In Development**
