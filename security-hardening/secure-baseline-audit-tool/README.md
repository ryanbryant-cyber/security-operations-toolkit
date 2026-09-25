# Secure Baseline Audit Tool

A hands-on security-hardening and configuration-assessment project focused on evaluating Windows workstation settings against a defined security baseline.

The project demonstrates how a security analyst can identify configuration drift, classify findings as PASS, FAIL, or REVIEW, assign severity, provide remediation guidance, generate structured audit reports, and validate results against known ground truth.

## Project Objective

Secure configuration is an important layer of defense.

A system can be fully patched and still introduce unnecessary risk through weak password requirements, disabled logging, excessive administrative access, insecure remote-access settings, or other configuration weaknesses.

This project demonstrates a repeatable configuration-audit workflow:

```text
Synthetic Windows Configuration
        ↓
Defined Security Baseline
        ↓
Control Evaluation
        ↓
PASS / FAIL / REVIEW
        ↓
Severity Classification
        ↓
Remediation Guidance
        ↓
CSV / JSON Audit Reports
        ↓
Independent Validation
```

## Target System

The synthetic system evaluated in this project is:

```text
Hostname:          NFG-FIN-WS07
Operating System:  Windows 11 Enterprise
Business Function: Finance Workstation
Environment:       Production
Asset Criticality: High
```

The workstation contains a deliberate mixture of secure and insecure configuration settings so the audit engine can produce meaningful results.

## Data Source

The observed workstation configuration is stored in:

```text
sample-data/
└── windows_configuration.json
```

The snapshot contains security-relevant settings including:

- Password policy
- Account lockout
- Guest account status
- Windows Firewall
- Remote Desktop
- Network Level Authentication
- SMBv1
- PowerShell logging
- Process creation auditing
- Automatic security updates
- Endpoint protection
- Local administrator count

All system names and configuration data are synthetic.

## Security Baseline

The baseline is stored in:

```text
baseline/
└── windows_security_baseline.json
```

The baseline contains 15 measurable security controls.

### Control Categories

The project evaluates controls across:

```text
Authentication
Account Security
Network Security
Remote Access
Logging and Monitoring
Patch Management
Endpoint Security
Privilege Management
```

## Baseline Controls

| Control | Security Requirement | Severity |
|---|---|---|
| BASE-001 | Minimum Password Length | HIGH |
| BASE-002 | Password Complexity | MODERATE |
| BASE-003 | Account Lockout Threshold | HIGH |
| BASE-004 | Guest Account Disabled | HIGH |
| BASE-005 | Domain Firewall Enabled | HIGH |
| BASE-006 | Private Firewall Enabled | HIGH |
| BASE-007 | Public Firewall Enabled | HIGH |
| BASE-008 | Remote Desktop Exposure Review | MODERATE |
| BASE-009 | Remote Desktop Network Level Authentication | HIGH |
| BASE-010 | SMBv1 Disabled | HIGH |
| BASE-011 | PowerShell Script Block Logging | MODERATE |
| BASE-012 | Process Creation Auditing | MODERATE |
| BASE-013 | Automatic Security Updates | HIGH |
| BASE-014 | Endpoint Protection Enabled | HIGH |
| BASE-015 | Local Administrator Count | MODERATE |

## Audit Logic

The engine supports multiple evaluation operators rather than only simple Boolean checks.

```text
equals
minimum
maximum
range
review_if_true
conditional_equals
```

### `equals`

Checks whether the observed configuration exactly matches the required value.

Example:

```text
SMBv1 Enabled = False
```

### `minimum`

Checks whether a value meets or exceeds a minimum requirement.

Example:

```text
Minimum Password Length >= 14
```

### `maximum`

Checks whether a value stays within an approved upper limit.

Example:

```text
Local Administrator Count <= 2
```

### `range`

Checks whether a value falls within an approved range.

Example:

```text
Account Lockout Threshold = 1 through 5
```

### `review_if_true`

Flags enabled functionality for analyst review instead of automatically treating it as insecure.

Example:

```text
Remote Desktop Enabled = True
        ↓
REVIEW
```

Remote Desktop may have a legitimate business purpose, so the tool requires analyst review rather than automatically classifying it as a failure.

### `conditional_equals`

Applies a requirement only when another condition is true.

Example:

```text
IF Remote Desktop Enabled = True

THEN

Network Level Authentication = True
```

This allows the baseline to evaluate relationships between configuration settings.

## Audit Engine

The primary audit script is:

```text
audit_baseline.py
```

The script:

1. Loads the synthetic Windows configuration.
2. Loads the defined security baseline.
3. Evaluates each security control.
4. Applies the appropriate comparison operator.
5. Assigns PASS, FAIL, REVIEW, or NOT_APPLICABLE.
6. Preserves severity and remediation guidance.
7. Generates structured JSON and CSV reports.
8. Prints an analyst-readable terminal summary.

## Audit Results

The completed audit evaluated all 15 controls.

```text
Total Controls:  15
PASS:             9
FAIL:             5
REVIEW:           1
NOT APPLICABLE:   0
```

### Failed Controls

The tool identified five configuration weaknesses.

#### BASE-001 — Minimum Password Length

```text
Observed: 8
Required: >= 14
Status:   FAIL
Severity: HIGH
```

The observed password requirement falls below the defined baseline.

Recommended remediation:

Configure the minimum password length to at least 14 characters.

#### BASE-003 — Account Lockout Threshold

```text
Observed: 0
Required: 1 through 5
Status:   FAIL
Severity: HIGH
```

A value of zero does not satisfy the defined account-lockout baseline.

Recommended remediation:

Configure account lockout to trigger after no more than five invalid authentication attempts while avoiding a threshold of zero.

#### BASE-009 — Remote Desktop Network Level Authentication

```text
Remote Desktop: Enabled
NLA:            Disabled

Status:   FAIL
Severity: HIGH
```

Because Remote Desktop is enabled, the conditional baseline requires Network Level Authentication.

Recommended remediation:

Enable Network Level Authentication whenever Remote Desktop is enabled.

#### BASE-011 — PowerShell Script Block Logging

```text
Observed: Disabled
Required: Enabled
Status:   FAIL
Severity: MODERATE
```

Script Block Logging provides additional visibility into PowerShell activity.

Recommended remediation:

Enable PowerShell Script Block Logging through the appropriate Windows or Group Policy configuration.

#### BASE-015 — Local Administrator Count

```text
Observed: 4
Maximum:  2
Status:   FAIL
Severity: MODERATE
```

The workstation contains more local administrative accounts than permitted by the defined baseline.

Recommended remediation:

Review local administrator membership and reduce privileged access to the minimum required for business operations.

## Analyst Review Finding

### BASE-008 — Remote Desktop Exposure Review

```text
Remote Desktop: Enabled
Status:         REVIEW
Severity:       MODERATE
```

The tool does not automatically classify enabled Remote Desktop as a failure.

Instead, the analyst should confirm:

- whether RDP is required
- who is authorized to use it
- how access is restricted
- whether strong authentication is enforced
- whether the system is exposed beyond intended network boundaries

This demonstrates an important configuration-assessment principle:

> Not every potentially risky setting is automatically a misconfiguration.

Some settings require business and operational context.

## Passed Controls

The workstation successfully met several baseline requirements:

```text
PASS  BASE-002  Password Complexity
PASS  BASE-004  Guest Account Disabled
PASS  BASE-005  Domain Firewall Enabled
PASS  BASE-006  Private Firewall Enabled
PASS  BASE-007  Public Firewall Enabled
PASS  BASE-010  SMBv1 Disabled
PASS  BASE-012  Process Creation Auditing
PASS  BASE-013  Automatic Security Updates
PASS  BASE-014  Endpoint Protection Enabled
```

These results show that a security assessment should preserve both compliant and non-compliant findings rather than reporting only failures.

## Generated Reports

Running:

```bash
python3 audit_baseline.py
```

creates:

```text
output/
├── baseline_audit_results.csv
└── baseline_audit_results.json
```

The JSON report preserves the complete audit structure, including system information, baseline information, result summary, control status, severity, reasoning, and remediation guidance.

The CSV output provides a concise analyst-friendly view suitable for filtering, remediation tracking, or later reporting.

## Validation

The project includes an independent validator:

```text
validate_audit.py
```

Expected results are stored in:

```text
expected-results/
└── audit_expectations.json
```

The validator checks:

- audit summary totals
- all 15 control results
- expected control severity
- important behavioral relationships in the audit logic

## Behavioral Validation

Four additional tests verify important security-audit behavior.

### Remote Desktop Requires Review

```text
Remote Desktop Enabled
        ↓
REVIEW
```

The engine correctly requires analyst review rather than creating an automatic failure.

### Missing NLA Produces Failure

```text
Remote Desktop Enabled
+
Network Level Authentication Disabled
        ↓
FAIL
```

The conditional baseline correctly identifies the missing safeguard.

### Windows Firewall Profiles Pass

The synthetic workstation has all three firewall profiles enabled:

```text
Domain  → PASS
Private → PASS
Public  → PASS
```

### SMBv1 Disabled Passes

```text
SMBv1 Enabled = False
        ↓
PASS
```

The engine correctly recognizes the secure configuration.

## Validation Results

The final validation run produced:

```text
Summary check:  PASS
Checks run:     20
Checks passed:  20
Checks failed:  0
Overall:        PASS
```

The validation included:

```text
15 individual control checks
4 behavioral checks
1 summary validation
-------------------------
20 total checks
```

All expected results matched the synthetic ground truth.

The generated validation report is stored in:

```text
output/
└── baseline_audit_validation_results.json
```

## Project Structure

```text
secure-baseline-audit-tool/
├── README.md
├── audit_baseline.py
├── validate_audit.py
├── sample-data/
│   └── windows_configuration.json
├── baseline/
│   └── windows_security_baseline.json
├── expected-results/
│   └── audit_expectations.json
└── output/
    ├── baseline_audit_results.csv
    ├── baseline_audit_results.json
    └── baseline_audit_validation_results.json
```

## Skills Demonstrated

```text
Security Configuration Auditing
Windows Security Hardening
Secure Baseline Development
Configuration Drift Analysis
Security Control Validation
Authentication Security
Windows Firewall Assessment
Remote Access Security
PowerShell Logging
Windows Audit Policy
Privilege Management
Remediation Planning
Risk Classification
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

## Key Lessons

This project reinforced several important configuration-management concepts.

### Secure configuration is separate from vulnerability scanning

Vulnerability scanners typically focus heavily on software flaws and known vulnerabilities.

Configuration auditing evaluates whether security controls are implemented as intended.

Both contribute to system security.

### Context matters

Remote Desktop being enabled does not automatically mean the system is insecure.

Business need, access restrictions, authentication controls, and network exposure must also be considered.

### Conditional controls improve audit quality

Security controls often depend on one another.

For example:

```text
IF RDP is enabled
THEN NLA should be enabled
```

A useful configuration-audit engine must understand those relationships.

### Logging is a security control

PowerShell and process-creation logging may not directly prevent an attack, but they improve detection, investigation, and incident-response capability.

### Least privilege should be measurable

The local administrator count gives the audit engine a measurable way to evaluate whether privileged access may need review.

### Audit results should explain why a control failed

A useful security report should provide more than:

```text
FAIL
```

It should explain:

```text
What was observed
What was expected
Why the control matters
How the issue can be remediated
```

## Limitations

This project uses a custom educational Windows security baseline and synthetic system data.

It is not intended to represent a complete enterprise hardening standard.

The current implementation does not directly execute PowerShell, query Windows APIs, collect live Group Policy settings, or modify system configuration.

Future improvements could include:

- live Windows configuration collection
- PowerShell integration
- Group Policy assessment
- Microsoft Security Compliance Toolkit integration
- CIS Benchmark mapping
- NIST control mapping
- multiple endpoint support
- configuration-drift history
- compliance scoring
- exception management
- remediation tracking
- dashboard visualization
- automated ticket creation

## Safety

All systems, users, settings, organizations, and findings used in this project are synthetic and created specifically for testing and portfolio demonstration.

The project does not modify operating-system settings or interact with production systems.

## Project Status

✅ **Functional and Validated**

The current version successfully:

- evaluates 15 Windows security controls
- supports six audit operators
- identifies 5 failed controls
- identifies 9 passing controls
- generates 1 analyst-review finding
- provides severity and remediation guidance
- exports CSV and JSON reports
- validates every expected control result
- passes 20 of 20 validation checks
