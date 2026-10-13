# Detection-as-Code CI Validation Pipeline

A hands-on detection engineering and DevSecOps project focused on treating security detection rules as version-controlled code that must pass automated quality checks before being accepted into a detection repository.

The project demonstrates how a security team can validate Sigma-style detection rules for structural correctness, metadata quality, MITRE ATT&CK coverage, duplicate identifiers, approved severity values, and expected detection behavior.

## Project Objective

Detection rules are production security logic.

A poorly written rule can create problems such as:

- Broken SIEM deployments
- Missing detections
- Excessive false positives
- Incorrect ATT&CK coverage
- Duplicate rule identifiers
- Invalid metadata
- Inconsistent severity levels
- Rules that appear valid but fail to detect the activity they were designed for

This project applies software-development quality-control concepts to detection engineering.

The completed workflow will resemble:

```text
Detection Rules
      ↓
YAML Parsing
      ↓
Required Metadata Validation
      ↓
Rule ID Validation
      ↓
Duplicate ID Detection
      ↓
MITRE ATT&CK Mapping Validation
      ↓
Severity / Status Validation
      ↓
Detection Structure Validation
      ↓
Synthetic Event Testing
      ↓
PASS / FAIL / REVIEW
      ↓
Detection Quality Report
      ↓
CI Quality Gate
```

## Detection-as-Code Concept

Instead of manually reviewing every detection rule after it is deployed, the project will automatically validate rules before they are considered ready.

Conceptually:

```text
Analyst creates or modifies rule
            ↓
Git commit / pull request
            ↓
Automated validation
            ↓
      ┌─────────────┐
      │ Did it pass?│
      └─────────────┘
        ↓         ↓
       YES        NO
        ↓         ↓
    Accept      Block /
    change      Review
```

## Planned Detection Repository

The project will contain intentionally mixed rule quality.

Planned test set:

```text
6 valid detection rules
1 malformed YAML rule
1 rule missing ATT&CK mapping
1 duplicate rule ID
1 invalid severity / status rule
1 rule that fails its synthetic event test
```

This allows the pipeline to prove that it can distinguish:

```text
Valid rule
Structural failure
Metadata failure
Duplicate identity
Policy violation
Behavioral test failure
```

## Planned Rule Topics

Synthetic rules will cover activity such as:

- Suspicious PowerShell execution
- Repeated authentication failures
- Encoded PowerShell commands
- Rundll32 suspicious execution
- DNS TXT activity
- Administrative privilege assignment
- Remote service creation
- Credential-dumping indicators
- Suspicious scheduled task activity
- Cloud identity risk events

## Planned Validation Checks

The pipeline will validate:

```text
YAML syntax
Required fields
Rule UUID format
Duplicate rule IDs
Approved status values
Approved severity levels
Required logsource fields
Detection section presence
Condition presence
MITRE ATT&CK technique tags
Rule test-case presence
Expected synthetic detection behavior
```

## Planned Required Metadata

Each detection rule will be expected to contain fields such as:

```text
title
id
status
description
author
date
tags
logsource
detection
falsepositives
level
```

## Approved Severity Levels

The validation policy will initially allow:

```text
informational
low
medium
high
critical
```

## Approved Rule Status Values

The validation policy will initially allow:

```text
experimental
test
stable
```

## MITRE ATT&CK Mapping

Detection rules will use ATT&CK technique tags such as:

```text
attack.t1059.001
attack.t1110
attack.t1218.011
attack.t1053.005
```

The validator will confirm that rules expected to contain ATT&CK mappings include at least one properly formatted technique identifier.

## Synthetic Rule Testing

Structural validity alone does not prove that a detection works.

The project will therefore include synthetic test events.

Example:

```text
Synthetic PowerShell Event
        ↓
Detection Rule
        ↓
Expected Match: TRUE
        ↓
Actual Match: TRUE
        ↓
PASS
```

A rule may therefore:

```text
Pass YAML validation
Pass metadata validation
Pass ATT&CK validation
```

but still fail because:

```text
Expected detection result
        ≠
Actual detection result
```

This provides a stronger validation model than syntax checking alone.

## CI Quality Gate

The final project will include a GitHub Actions workflow located at the repository level:

```text
.github/workflows/detection-as-code-validation.yml
```

The workflow will automatically run when relevant detection files or validation code change.

Conceptually:

```text
Git push
   ↓
GitHub Actions
   ↓
Install dependencies
   ↓
Validate detection rules
   ↓
Run synthetic rule tests
   ↓
Generate validation result
   ↓
PASS or FAIL
```

A failed validation should prevent the rule set from being treated as deployment-ready.

## Planned Project Structure

```text
detection-as-code-ci-pipeline/
├── README.md
├── requirements.txt
├── validate_detections.py
├── run_rule_tests.py
├── detections/
├── tests/
├── config/
│   └── validation_policy.json
├── expected-results/
└── output/
```

The GitHub Actions workflow will later be placed at the repository root:

```text
security-operations-toolkit/
└── .github/
    └── workflows/
        └── detection-as-code-validation.yml
```

## Planned Outputs

The completed pipeline will generate:

```text
output/
├── rule_validation_results.json
├── rule_validation_summary.csv
├── rule_test_results.json
├── rule_test_summary.csv
└── detection_ci_report.json
```

## Skills Demonstrated

- Detection Engineering
- Detection-as-Code
- DevSecOps
- CI/CD Security
- Sigma
- YAML
- Python
- Git
- GitHub Actions
- MITRE ATT&CK
- Detection Testing
- Rule Validation
- Configuration Management
- Security Automation
- Quality Gates
- JSON Processing
- CSV Processing
- Validation Testing

## Safety

All detection rules, identities, hosts, events, IP addresses, and test data used in this project are synthetic.

The project does not deploy detection rules into a production SIEM or security platform.

## Project Status

🚧 **In Development**
