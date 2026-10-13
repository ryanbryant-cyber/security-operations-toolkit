# Detection-as-Code CI Validation Pipeline

A hands-on detection engineering and DevSecOps project focused on treating security detection rules as version-controlled code that must pass automated quality checks before being considered deployment-ready.

The project combines:

- Sigma-style YAML detection rules
- Python validation
- MITRE ATT&CK metadata checking
- Behavioral rule testing
- Known-bad negative test fixtures
- GitHub Actions
- Automated CI quality gates
- Structured validation reporting

The final pipeline verifies both sides of detection quality:

```text
Good rules
→ must pass

Known-bad rules
→ must fail in the expected way
```

This creates a repeatable Detection-as-Code workflow rather than relying only on manual rule review.

# Project Objective

Detection rules are production security logic.

A rule may look correct but still contain problems such as:

- Invalid YAML
- Missing required metadata
- Duplicate rule identifiers
- Invalid rule status
- Unsupported severity values
- Missing MITRE ATT&CK mappings
- Broken logsource configuration
- Missing detection conditions
- Incorrect behavioral logic
- Incomplete false-positive documentation

A detection may also pass every structural check and still fail to detect the activity it was designed for.

This project demonstrates how detection engineering can borrow quality-control concepts from software development and CI/CD.

# Final Workflow

```text
Detection Rule Change
        ↓
Git Commit / Push / Pull Request
        ↓
GitHub Actions
        ↓
Python Environment Setup
        ↓
Install PyYAML Dependency
        ↓
Static Detection Validation
        ↓
Behavioral Rule Testing
        ↓
Negative Fixture Validation
        ↓
Combined CI Quality Gate
        ↓
PASS / FAIL
        ↓
Validation Reports Uploaded
```

# Detection Repository Architecture

The project separates deployment-candidate detections from intentionally broken test fixtures.

```text
detection-as-code-ci-pipeline/
├── README.md
├── requirements.txt
├── validate_detections.py
├── run_rule_tests.py
├── validate_negative_fixtures.py
├── detections/
│   ├── 01_powershell_encoded_command.yml
│   ├── 02_windows_logon_failure.yml
│   ├── 03_rundll32_temp_dll.yml
│   ├── 04_dns_txt_activity.yml
│   ├── 05_privileged_logon.yml
│   └── 06_remote_service_creation.yml
├── tests/
│   ├── rule_tests.json
│   └── fixtures/
│       └── invalid-rules/
│           ├── 07_malformed_yaml.yml
│           ├── 08_missing_attack_mapping.yml
│           ├── 09_duplicate_rule_id.yml
│           ├── 10_invalid_metadata.yml
│           └── 11_behavioral_test_failure.yml
├── config/
│   └── validation_policy.json
├── expected-results/
│   └── invalid_fixture_expectations.json
└── output/
```

The GitHub Actions workflow is stored at the repository level:

```text
.github/
└── workflows/
    └── detection-as-code-validation.yml
```

# Deployment-Candidate Detection Rules

The final detection set contains six Sigma-style rules.

## 01 — Suspicious PowerShell Encoded Command

Detects PowerShell execution using encoded command-line arguments.

MITRE ATT&CK:

```text
T1059.001
PowerShell
```

Detection logic evaluates:

```text
powershell.exe
AND
EncodedCommand / -enc
```

## 02 — Windows Failed User Logon

Detects:

```text
Windows Event ID 4625
```

MITRE ATT&CK:

```text
T1110
Brute Force
```

## 03 — Rundll32 Loading DLL From Temporary Directory

Detects:

```text
rundll32.exe
AND
DLL path referencing Temp
```

MITRE ATT&CK:

```text
T1218.011
Rundll32
```

## 04 — DNS TXT Query Activity

Detects:

```text
DNS QueryType = TXT
```

MITRE ATT&CK:

```text
T1071.004
DNS
```

## 05 — Windows Special Privileges Assigned

Detects:

```text
Windows Event ID 4672
```

MITRE ATT&CK:

```text
T1078
Valid Accounts
```

## 06 — Windows Remote Service Creation

Detects:

```text
Windows Event ID 7045
```

MITRE ATT&CK:

```text
T1021.002
SMB / Windows Admin Shares
```

# Validation Policy

Detection quality requirements are stored in:

```text
config/validation_policy.json
```

The policy defines what the Python validator must enforce.

## Required Rule Fields

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

## Approved Rule Status Values

```text
experimental
test
stable
```

## Approved Severity Levels

```text
informational
low
medium
high
critical
```

## UUID Validation

Each rule must use a properly formatted UUID.

Example:

```text
7d3bf66a-38d8-4bb7-b7c9-9ac116b6ef11
```

The UUID provides a stable detection identity even if the rule title or logic changes.

## Duplicate Rule ID Detection

The validator tracks previously observed rule IDs.

Conceptually:

```text
Rule A
UUID = X

Rule B
UUID = X

        ↓

duplicate_rule_id
```

Duplicate detection prevents multiple rules from claiming the same identifier.

# MITRE ATT&CK Validation

The policy requires at least one properly formatted ATT&CK technique mapping.

Valid examples include:

```text
attack.t1110
attack.t1059.001
attack.t1218.011
```

The validator distinguishes tactic tags from technique identifiers.

For example:

```text
attack.execution
```

may provide useful tactic context but does not satisfy the required technique mapping by itself.

# Logsource Validation

Each rule must contain a usable `logsource` mapping.

At least one of the following must exist:

```text
product
service
category
```

This allows rules to support different telemetry models without requiring all three fields.

# Detection Condition Validation

Each detection must contain a usable:

```text
condition
```

Example:

```yaml
detection:
  selection:
    EventID: 4625

  condition: selection
```

Without a condition, the rule has no usable match logic.

# Documentation Quality Checks

The validator also evaluates documentation quality.

Review findings may include:

```text
short_title
short_description
limited_falsepositive_documentation
```

These findings can require analyst review without necessarily blocking CI.

This creates three possible states:

```text
PASS
REVIEW
FAIL
```

# Static Detection Validation

Static rule validation is performed by:

```text
validate_detections.py
```

The validator checks:

```text
YAML parsing
Required fields
UUID format
Duplicate UUIDs
Rule status
Severity level
Date format
MITRE ATT&CK mappings
Logsource structure
Detection condition
Rule documentation
False-positive documentation
```

# Final Static Validation Results

After separating known-bad fixtures from production candidate rules:

```text
Rules scanned: 6
PASS:          6
REVIEW:        0
FAIL:          0
Quality gate:  PASSED
```

All six deployment-candidate rules passed static validation.

# Behavioral Detection Testing

Structural validity does not prove that a detection works.

Behavioral testing is performed by:

```text
run_rule_tests.py
```

Synthetic events are defined in:

```text
tests/rule_tests.json
```

Each test includes:

```text
rule_id
description
event
expected_match
```

The testing engine compares expected detection behavior against actual rule behavior.

Conceptually:

```text
Synthetic Event
       ↓
Detection Logic
       ↓
Expected Match
       ↓
Actual Match
       ↓
PASS / FAIL
```

# Supported Behavioral Operations

The educational rule engine supports the operations required by the project rules:

```text
Exact match
contains
endswith
single selection
selection AND selection
```

Example Sigma-style modifier:

```yaml
CommandLine|contains:
  - '-EncodedCommand'
```

The Python engine separates:

```text
CommandLine
```

from:

```text
contains
```

and applies the correct comparison operation.

# Final Behavioral Test Results

The deployment-candidate rules produced:

```text
Tests run:     6
PASS:          6
FAIL:          0
SKIPPED:       0
Quality gate:  PASSED
```

Each test produced:

```text
Expected: True
Actual:   True
```

for the synthetic activity it was designed to detect.

# Negative Fixture Testing

A strong test suite should not only prove that good rules pass.

It should also prove that bad rules are rejected correctly.

Known-bad fixtures are stored in:

```text
tests/fixtures/invalid-rules/
```

Negative validation is performed by:

```text
validate_negative_fixtures.py
```

Expected failure behavior is stored in:

```text
expected-results/
└── invalid_fixture_expectations.json
```

# Known-Bad Test Fixtures

## 07 — Malformed YAML

The rule intentionally contains malformed YAML.

Expected result:

```text
yaml_parse_error
```

Static expectation:

```text
FAIL
```

Actual result:

```text
FAIL
```

Negative test:

```text
PASS
```

The fixture passes the test because the validator rejected it correctly.

## 08 — Missing ATT&CK Mapping

The rule contains a tactic tag but no valid technique identifier.

Expected finding:

```text
missing_attack_mapping
```

Static expectation:

```text
FAIL
```

Actual result:

```text
FAIL
```

Negative test:

```text
PASS
```

## 09 — Duplicate Rule ID

The fixture intentionally reuses the UUID belonging to the production remote-service detection.

Expected finding:

```text
duplicate_rule_id
```

Static expectation:

```text
FAIL
```

Actual result:

```text
FAIL
```

Negative test:

```text
PASS
```

## 10 — Invalid Metadata

The rule intentionally uses:

```text
status: production
level: severe
```

Neither value is permitted by policy.

Expected findings:

```text
invalid_status
invalid_level
```

Static expectation:

```text
FAIL
```

Actual result:

```text
FAIL
```

Negative test:

```text
PASS
```

## 11 — Behavioral Detection Failure

This fixture is intentionally different from the other negative tests.

Its YAML and metadata are valid.

Static expectation:

```text
PASS
```

Static result:

```text
PASS
```

However, the detection requires:

```text
CommandLine contains DownloadString
```

while the synthetic event contains:

```text
Invoke-WebRequest
```

The test intentionally states:

```text
Expected Match: True
```

but the detection engine evaluates:

```text
Actual Match: False
```

This demonstrates:

```text
Structurally valid
        ≠
Behaviorally correct
```

The negative fixture passes because the pipeline correctly proves the logic mismatch.

# Final Negative Fixture Results

The completed negative test suite produced:

```text
Fixtures checked: 5
PASS:             5
FAIL:             0
Quality gate:     PASSED
```

This confirms that every intentionally bad fixture behaved exactly as expected.

# GitHub Actions CI Pipeline

The automated workflow is:

```text
.github/workflows/detection-as-code-validation.yml
```

The workflow runs when relevant project files change through:

```text
push
pull_request
workflow_dispatch
```

The GitHub-hosted runner performs:

```text
Repository checkout
        ↓
Python 3.12 setup
        ↓
Dependency installation
        ↓
Static detection validation
        ↓
Behavioral detection testing
        ↓
Negative fixture validation
        ↓
Combined quality gate
        ↓
Validation artifact upload
```

# Combined CI Quality Gate

The final gate evaluates all three validation layers.

```text
STATIC VALIDATION
6 PASS
0 REVIEW
0 FAIL
PASSED

BEHAVIORAL TESTING
6 PASS
0 FAIL
0 SKIPPED
PASSED

NEGATIVE FIXTURE TESTING
5 PASS
0 FAIL
PASSED
```

Final CI result:

```text
FINAL CI DECISION
PASSED
```

The final GitHub Actions message confirms:

```text
Production rules passed static and behavioral validation,
and known-bad fixtures were rejected as expected.
```

# CI Failure Enforcement

Earlier in development, the repository intentionally contained the broken fixtures inside the deployment detection folder.

The pipeline correctly produced:

```text
Rules scanned: 11
PASS:          7
FAIL:          4
Quality gate:  FAILED
```

The workflow then terminated with:

```text
Process completed with exit code 1
```

This demonstrated that the CI quality gate could actively reject a noncompliant detection set.

After the repository architecture was corrected and the fixtures were separated from production candidate rules, the workflow successfully turned green.

This demonstrates both:

```text
CI rejection of bad detection changes
```

and:

```text
CI acceptance of validated detection changes
```

# Validation Reports

The GitHub Actions workflow generates and uploads structured validation artifacts.

Outputs include:

```text
rule_validation_results.json
rule_validation_summary.csv
rule_test_results.json
rule_test_summary.csv
negative_fixture_results.json
negative_fixture_summary.csv
```

The workflow uses:

```text
actions/upload-artifact
```

to preserve the reports after CI execution.

This provides evidence showing why a detection repository passed or failed validation.

# Detection-as-Code Principles Demonstrated

## Detection Rules Are Code

Security detections should be:

```text
Version controlled
Reviewed
Tested
Validated
Repeatable
Auditable
```

just like other production logic.

## Syntax Is Only the First Layer

A YAML file may parse successfully while still violating detection policy.

```text
Valid YAML
≠
Valid detection
```

## Metadata Matters

Stable UUIDs, consistent status values, severity levels, ATT&CK mappings, false-positive documentation, and logsource information improve detection maintainability.

## Static Validation Is Not Enough

A rule can pass:

```text
YAML validation
Metadata validation
ATT&CK validation
Policy validation
```

and still fail to match the activity it was designed to detect.

Behavioral testing addresses that gap.

## Positive and Negative Testing Serve Different Purposes

Positive tests ask:

```text
Do valid detections work?
```

Negative tests ask:

```text
Does the validator correctly reject bad detections?
```

Both are necessary for stronger quality assurance.

## Configuration Should Be Separate From Logic

Python defines:

```text
HOW validation works
```

while JSON configuration defines:

```text
WHAT policy should be enforced
```

This allows detection policy to evolve without completely rewriting the validation engine.

# Skills Demonstrated

```text
Detection Engineering
Detection-as-Code
DevSecOps
CI/CD Security
GitHub Actions
Sigma
YAML
Python
MITRE ATT&CK
Rule Validation
Detection Testing
Negative Testing
Quality Gates
Configuration-Driven Development
Regular Expressions
UUID Validation
Behavioral Testing
Synthetic Security Events
Git
JSON
CSV
Security Automation
Validation Reporting
```

# Technologies Used

```text
Python 3
PyYAML
YAML
JSON
CSV
Git
GitHub
GitHub Actions
MITRE ATT&CK
Sigma-style detection logic
```

# Project Guardrails

This project uses a custom educational evaluator for controlled Sigma-style rule testing.

It is not intended to reproduce the complete Sigma specification or replace production Sigma conversion backends.

The behavioral engine currently supports only the operators required by this project:

```text
Exact match
contains
endswith
AND conditions
```

Production detection repositories may require additional support for:

```text
OR logic
NOT conditions
wildcards
regular-expression modifiers
CIDR matching
numeric comparisons
aggregation
time windows
event correlation
backend-specific field mapping
SIEM-specific query generation
```

# Safety

All:

```text
Detection rules
Hostnames
Users
IP addresses
Domains
Events
Test data
Security scenarios
```

used in this project are synthetic.

No production SIEM, corporate telemetry, credentials, or organizational detection content is used.

# Project Status

✅ **Functional and CI Validated**

The final project successfully:

- maintains 6 deployment-candidate Sigma-style rules
- validates YAML structure
- enforces required metadata
- validates UUID formatting
- detects duplicate rule IDs
- validates rule status values
- validates severity levels
- validates date formatting
- requires MITRE ATT&CK technique mappings
- validates logsource structure
- validates detection conditions
- evaluates detection documentation
- performs synthetic behavioral testing
- validates 6 of 6 production rule behaviors
- maintains 5 known-bad negative fixtures
- confirms all 5 negative fixtures fail or behave exactly as expected
- detects structurally valid but behaviorally incorrect detection logic
- integrates validation into GitHub Actions
- automatically blocks noncompliant detection sets
- automatically accepts compliant detection sets
- uploads structured JSON and CSV validation reports
- completes the final combined CI quality gate successfully
