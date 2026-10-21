# API Security Assessment & Abuse Detection Lab

A hands-on application security and SOC analysis project focused on detecting suspicious and unauthorized behavior within synthetic REST API telemetry.

The project demonstrates how API request logs can be enriched with identity and authorization context, correlated across users, tokens, endpoints, objects, and source IP addresses, and analyzed for behaviors such as authentication abuse, unauthorized object access, token misuse, object enumeration, administrative endpoint misuse, and excessive request rates.

The final implementation uses Python for analysis and GitHub Actions for automated execution, independent validation, and CI quality-gate enforcement.

# Project Objective

Modern enterprise applications rely heavily on APIs.

Security teams may need to investigate:

- Authentication activity
- Token usage
- User identity
- User roles
- Object-level permissions
- Administrative API access
- Request volume
- Sequential resource access
- Authorization failures
- Sensitive business records
- Source-IP changes

A single API request often does not provide enough context to determine whether activity is suspicious.

This project demonstrates how multiple data sources can be correlated to create a more meaningful security assessment.

# Final Analysis Workflow

```text
Synthetic API Request Logs
        ↓
Identity Lookup
        ↓
Role Enrichment
        ↓
Expected Source-IP Enrichment
        ↓
Object Authorization Lookup
        ↓
Normalized API Events
        ↓
Authentication Analysis
        ↓
Object Authorization Analysis
        ↓
Token Reuse Analysis
        ↓
Object Enumeration Analysis
        ↓
Administrative Access Analysis
        ↓
Request-Rate Analysis
        ↓
Structured Findings
        ↓
Independent Validation
        ↓
GitHub Actions Quality Gate
        ↓
PASS
```

# Synthetic Environment

The lab represents a fictional enterprise environment named:

```text
Northstar Ridge
```

The API environment includes namespaces such as:

```text
/api/auth/
/api/users/
/api/accounts/
/api/invoices/
/api/admin/
/api/reports/
```

# Synthetic Identities

The lab includes five identities representing different enterprise roles:

```text
finance.user
Role: finance

contractor.user
Role: contractor

admin.user
Role: administrator

svc.reports
Role: service_account

alex.employee
Role: employee
```

Each identity includes additional context such as:

```text
Department
Account status
Expected source IP addresses
```

This allows the analysis engine to compare observed API activity against expected identity behavior.

# Authorization Ground Truth

Object-level permissions are defined separately from the API telemetry.

The project tracks authorization for:

```text
Accounts
Invoices
Reports
```

For example:

```text
finance.user
Authorized account:
1001

Authorized invoices:
INV-1001
INV-1002

Authorized report:
finance-summary
```

The contractor account is authorized for:

```text
Account:
3001
```

This allows Python to determine whether requested objects fall inside or outside a user's expected authorization scope.

# API Telemetry Dataset

The completed project processes:

```text
27 synthetic API requests
```

The dataset contains both normal and suspicious behavior.

## Normal Activity

Examples include:

```text
Finance user accessing an approved account
Finance user accessing approved invoices
Administrator accessing /api/admin/
Service account accessing its approved report
Employee accessing a public report
Normal authentication
```

## Controlled Suspicious Activity

The dataset intentionally includes:

```text
5 failed contractor authentication attempts
Successful contractor login after those failures
6 sequential account-object requests
Unauthorized account-object access
Unauthorized finance-report access
Non-admin access to /api/admin/users
Finance token reuse from a second source IP
9 contractor requests within 22 seconds
```

# Normalized API Event Schema

Raw requests are enriched and normalized into fields including:

```text
timestamp
request_id
source_ip
source_ip_expected
user
role
department
token_id
http_method
endpoint
resource_type
object_id
object_in_expected_scope
response_status
response_bytes
user_agent
authentication_result
authorization_result
```

This provides a consistent event format for downstream analysis.

# Security Enrichment

The project combines:

```text
API telemetry
+
Identity data
+
Expected source-IP data
+
Object authorization data
```

to produce enriched security events.

For example:

```text
Raw request:
contractor.user
GET /api/accounts/1001

Identity context:
role = contractor

Authorization context:
authorized account = 3001

Analysis:
requested object 1001
is outside expected scope
```

The enriched result can record:

```text
object_in_expected_scope = false
```

This demonstrates how separate data sources become more useful when correlated.

# Detection Policy

Analysis thresholds are stored in:

```text
config/detection_policy.json
```

This separates detection logic from organizational policy.

The Python engine defines:

```text
HOW detections operate
```

while JSON configuration defines:

```text
WHAT thresholds and policies apply
```

Configured areas include:

- Authentication failure threshold
- Failure-analysis window
- Success-after-failure window
- Unauthorized-object threshold
- Token reuse threshold
- Token reuse time window
- Sequential object threshold
- Administrative roles
- API request-rate threshold
- Severity assignments
- OWASP API mappings
- Analyst guardrails

# Finding API-001 — Repeated Authentication Failures

Severity:

```text
HIGH
```

User:

```text
contractor.user
```

Observed evidence:

```text
5 failed authentication attempts
within 48 seconds
```

followed by:

```text
Successful authentication
14 seconds after the final failure
```

Supporting requests:

```text
REQ-0011
REQ-0012
REQ-0013
REQ-0014
REQ-0015
REQ-0016
```

Total supporting evidence:

```text
6 requests
```

OWASP API Security mapping:

```text
API2:2023 Broken Authentication
```

Analyst assessment:

```text
Repeated authentication failures exceeded the configured threshold.
```

Guardrail:

> Repeated failed authentication followed by success may indicate credential guessing or user error. It does not prove credential compromise.

# Finding API-002 — Unauthorized Object Access Pattern

Severity:

```text
HIGH
```

User:

```text
contractor.user
```

The contractor is authorized for:

```text
Account 3001
```

but requests multiple other objects, including:

```text
1001
1002
1003
1004
1005
1006
finance-summary
```

The analysis engine identified:

```text
7 requests
```

outside the user's expected authorization scope.

The API returned denied authorization results for those requests.

OWASP API Security mapping:

```text
API1:2023 Broken Object Level Authorization
```

Analyst assessment:

```text
The user repeatedly requested protected objects outside the configured authorization scope.
```

Guardrail:

> Requests for unauthorized objects indicate attempted access outside the user's expected scope. Denied requests do not prove successful exploitation.

# Finding API-003 — Suspicious Token Reuse

Severity:

```text
HIGH
```

User:

```text
finance.user
```

Token:

```text
TOK-FIN-001
```

Observed source IPs:

```text
198.51.100.24
203.0.113.77
```

The Finance identity profile lists:

```text
198.51.100.24
```

as the expected source address.

The same token was later observed from:

```text
203.0.113.77
```

The analysis found:

```text
2 distinct source IP addresses
2 token-use events from an unexpected source IP
```

Total supporting requests:

```text
7
```

OWASP API Security mapping:

```text
API2:2023 Broken Authentication
```

Analyst assessment:

```text
The same authentication token was reused across multiple source addresses within the configured analysis window.
```

Guardrail:

> Use of the same token from multiple source IP addresses may indicate token sharing, network changes, proxy use, or token misuse. It does not prove token theft.

# Finding API-004 — Sequential Object Enumeration

Severity:

```text
HIGH
```

User:

```text
contractor.user
```

Supporting requests:

```text
REQ-0017
REQ-0018
REQ-0019
REQ-0020
REQ-0021
REQ-0022
```

Requested objects:

```text
1001
1002
1003
1004
1005
1006
```

Observed pattern:

```text
6 distinct account objects
Longest sequential run: 6
Time span: 10 seconds
```

OWASP API Security mappings:

```text
API1:2023 Broken Object Level Authorization
API9:2023 Improper Inventory Management
```

Analyst assessment:

```text
The request sequence shows rapid access to multiple sequential account identifiers.
```

Guardrail:

> Rapid sequential object requests may indicate automated enumeration or scripted access. The pattern alone does not prove exploitation.

# Finding API-005 — Unauthorized Administrative Endpoint Access

Severity:

```text
HIGH
```

User:

```text
contractor.user
```

Role:

```text
contractor
```

Observed request:

```text
POST /api/admin/users
```

Supporting request:

```text
REQ-0023
```

Response:

```text
403 Forbidden
```

The API policy permits administrative endpoint access only to:

```text
administrator
```

OWASP API Security mapping:

```text
API5:2023 Broken Function Level Authorization
```

Analyst assessment:

```text
A non-administrator attempted to access an administrative API function.
```

Guardrail:

> A non-administrator requesting an administrative endpoint represents unauthorized function access. A denied request does not prove administrative compromise.

# Finding API-006 — Excessive API Request Rate

Severity:

```text
MEDIUM
```

User:

```text
contractor.user
```

Configured threshold:

```text
8 requests
within
30 seconds
```

Observed activity:

```text
9 requests
within
22 seconds
```

The activity includes:

```text
Authentication
Account requests
Administrative endpoint request
Finance report request
```

OWASP API Security mapping:

```text
API4:2023 Unrestricted Resource Consumption
```

Analyst assessment:

```text
The user's API request rate exceeded the configured analysis threshold.
```

Guardrail:

> High request volume may represent automation, legitimate application behavior, or abuse. Rate alone does not establish malicious intent.

# Final Findings

The completed analysis generated:

```text
API-001 | HIGH   | Repeated Authentication Failures
API-002 | HIGH   | Unauthorized Object Access Pattern
API-003 | HIGH   | Suspicious Token Reuse
API-004 | HIGH   | Sequential Object Enumeration
API-005 | HIGH   | Unauthorized Administrative Endpoint Access
API-006 | MEDIUM | Excessive API Request Rate
```

Summary:

```text
Normalized API events: 27
Security findings:      6
```

# User Activity Correlation

The engine generates:

```text
output/user_activity_summary.json
```

The summary tracks activity such as:

```text
Request count
Failed authentication count
Authorization denied count
Unexpected source count
Out-of-scope object count
Distinct endpoints
```

For the contractor account, validation confirms:

```text
Requests:                     14
Failed authentications:        5
Authorization denials:         8
Out-of-scope object requests:  7
```

For the Finance account:

```text
Requests:                  7
Unexpected-source events:  2
```

# Token Activity Correlation

The engine also creates:

```text
output/token_activity_summary.json
```

For:

```text
TOK-FIN-001
```

the final analysis confirms:

```text
Requests:                  7
Distinct source IPs:       2
Unexpected-source events:  2
```

This provides supporting context for API-003.

# Generated Outputs

The analysis engine creates:

```text
output/
├── normalized_api_events.json
├── api_findings.json
├── api_findings_summary.csv
├── user_activity_summary.json
├── token_activity_summary.json
└── api_validation_results.json
```

## Normalized API Events

```text
normalized_api_events.json
```

Contains the complete enriched event dataset.

## Findings Report

```text
api_findings.json
```

Contains structured finding details including:

```text
Finding ID
Title
Severity
User
Source IPs
Affected endpoints
First seen
Last seen
Supporting request IDs
Observed indicators
Assessment
OWASP mapping
Analyst guardrail
```

## Findings CSV

```text
api_findings_summary.csv
```

Provides an analyst-friendly summary suitable for review or reporting.

## User Summary

```text
user_activity_summary.json
```

Aggregates activity by identity.

## Token Summary

```text
token_activity_summary.json
```

Aggregates activity by token identifier.

# Independent Validation

The analysis engine is independently validated using:

```text
validate_api_analysis.py
```

Expected ground truth is stored in:

```text
expected-results/
└── api_analysis_expectations.json
```

The validator does not simply check whether the Python program completed successfully.

It independently checks whether the results match the expected evidence.

# Validation Checks

The completed validation verifies:

```text
Normalized API event count
Security finding count
Finding metadata and severity
Critical finding evidence mapping
Unexpected-source enrichment
Object authorization enrichment
Contractor activity summary
Finance unexpected-source summary
Finance token reuse summary
Analyst guardrails present
Expected finding ID set
```

Final result:

```text
Checks run:     11
Checks passed:  11
Checks failed:  0
Overall:        PASS
```

# GitHub Actions Automation

Because the project is designed to be repeatable, analysis and validation are automated using:

```text
.github/workflows/api-security-analysis.yml
```

The workflow runs on:

```text
push
pull_request
workflow_dispatch
```

for relevant project changes.

The GitHub-hosted runner performs:

```text
Repository checkout
        ↓
Python 3.12 setup
        ↓
API security analysis
        ↓
Foundation verification
        ↓
Independent validation
        ↓
CI quality gate
        ↓
Report artifact upload
```

# CI Foundation Verification

Before the final validation stage, the workflow confirms:

```text
Normalized events:    27
Unexpected-source:     2
Out-of-scope objects:  7
```

Result:

```text
PASSED
```

# Final CI Quality Gate

The final GitHub Actions gate confirms:

```text
Security findings: 6
Validation checks: 11
Checks passed:     11
Checks failed:     0
Validation status: PASS
```

Final CI decision:

```text
PASSED
```

The quality gate confirms that:

```text
API security findings,
correlation results,
and supporting evidence
matched expected ground truth.
```

# Project Architecture

```text
api-security-abuse-detection-lab/
├── README.md
├── analyze_api_activity.py
├── validate_api_analysis.py
├── sample-data/
│   ├── api_requests.json
│   ├── users.json
│   └── authorized_objects.json
├── config/
│   └── detection_policy.json
├── expected-results/
│   └── api_analysis_expectations.json
└── output/
    ├── normalized_api_events.json
    ├── api_findings.json
    ├── api_findings_summary.csv
    ├── user_activity_summary.json
    ├── token_activity_summary.json
    └── api_validation_results.json
```

Repository-level automation:

```text
.github/
└── workflows/
    └── api-security-analysis.yml
```

# Detection Functions

The Python engine separates each detection category into its own function:

```text
detect_authentication_abuse()
detect_object_authorization()
detect_token_reuse()
detect_object_enumeration()
detect_administrative_access()
detect_rate_abuse()
```

A central function:

```text
generate_findings()
```

coordinates the individual detection modules.

This modular design makes the analyzer easier to:

```text
Test
Maintain
Extend
Troubleshoot
Explain
```

# Security Concepts Demonstrated

## Authentication Analysis

The project analyzes failure bursts and failure-to-success sequences.

## Authorization Analysis

The project distinguishes:

```text
Identity
Role
Object authorization
Function authorization
```

rather than treating all API access the same.

## Object-Level Authorization

Requests are compared against explicit object permissions.

This demonstrates analytical concepts related to:

```text
Broken Object Level Authorization
```

without claiming that denied requests represent successful exploitation.

## Function-Level Authorization

Administrative endpoint access is evaluated separately from object ownership.

This demonstrates the distinction between:

```text
Can this user access this object?
```

and:

```text
Can this user's role perform this function?
```

## Token Correlation

Token identifiers are correlated across:

```text
Users
Source IP addresses
Requests
Time
```

to identify potentially unusual reuse.

## Behavioral Analysis

The engine evaluates:

```text
Request timing
Request volume
Sequential object patterns
Authentication sequences
Authorization context
Token reuse
```

rather than relying on a single suspicious event.

# OWASP API Security Concepts

The final findings reference relevant OWASP API Security categories including:

```text
API1:2023 Broken Object Level Authorization

API2:2023 Broken Authentication

API4:2023 Unrestricted Resource Consumption

API5:2023 Broken Function Level Authorization

API9:2023 Improper Inventory Management
```

These mappings provide security context.

They do not mean the lab claims that every observed behavior confirms the presence of an exploitable vulnerability.

# Analyst Guardrails

A major goal of the project is avoiding unsupported conclusions.

The analyzer distinguishes:

```text
Observed suspicious behavior
```

from:

```text
Confirmed exploitation or compromise
```

Examples:

```text
Multiple token source IPs
≠
Confirmed stolen token
```

```text
Unauthorized object requests
≠
Confirmed BOLA exploitation
```

```text
High API request rate
≠
Confirmed malicious automation
```

```text
Failed logins followed by success
≠
Confirmed credential compromise
```

This reflects evidence-based incident analysis.

# Key Lessons

## Context Changes the Meaning of Telemetry

A request to:

```text
/api/accounts/1001
```

is not inherently suspicious.

Its meaning depends on:

```text
Who made the request?
What role do they have?
Which object are they authorized for?
What token did they use?
Where did the request originate?
What happened before and after it?
```

## Authentication and Authorization Are Different

Authentication answers:

```text
Who are you?
```

Authorization answers:

```text
What are you allowed to do?
```

The project evaluates both independently.

## Object and Function Authorization Are Different

A user may be authenticated while still lacking permission to:

```text
Access a particular account
```

or:

```text
Use an administrative function
```

These require different analytical checks.

## Correlation Produces Better Security Context

The project combines:

```text
API logs
+
User information
+
Expected source IPs
+
Authorization scope
+
Token activity
+
Timing
```

before generating findings.

## Detection Thresholds Should Be Configurable

Detection thresholds are stored outside the Python engine.

This allows policy changes without rewriting core analysis logic.

## Detection Results Require Guardrails

Security automation should help analysts identify evidence.

It should not automatically convert suspicious indicators into unsupported claims of compromise.

## Validation Matters

Successful Python execution does not prove analytical correctness.

The project independently validates:

```text
Counts
Users
Severity
Evidence IDs
Enrichment
Token behavior
User summaries
Finding IDs
Guardrails
```

before CI considers the project valid.

# Skills Demonstrated

```text
API Security
Application Security
REST API Analysis
HTTP Analysis
Authentication Analysis
Authorization Analysis
Object-Level Authorization
Function-Level Authorization
Token Analysis
Identity Correlation
Behavioral Detection
API Abuse Detection
OWASP API Security
SOC Analysis
Detection Engineering
Security Analytics
Python
JSON
CSV
Data Enrichment
Data Correlation
Configuration-Driven Development
Modular Programming
Validation Testing
GitHub Actions
CI/CD Security
Security Automation
Analyst Reporting
```

# Technologies Used

```text
Python 3
JSON
CSV
Git
GitHub
GitHub Actions
REST API concepts
HTTP concepts
OWASP API Security
```

# Project Guardrails

This project is an educational defensive analysis lab.

It does not:

```text
Attack a live API
Bypass authentication
Attempt exploitation
Use real access tokens
Use production identities
Use real organizational data
```

The project analyzes only controlled synthetic telemetry.

# Safety

All:

```text
Users
Tokens
IP addresses
Endpoints
Objects
Requests
Authentication events
Authorization events
Findings
```

used in this project are synthetic.

# Project Status

✅ **Functional and CI Validated**

The completed project successfully:

- processes 27 synthetic API requests
- enriches events with identity and role context
- compares source IPs against expected identity behavior
- correlates API objects with authorization scope
- identifies 7 out-of-scope object requests
- identifies 2 events from unexpected source IPs
- detects repeated authentication failures
- correlates successful authentication after failure bursts
- detects unauthorized object-access patterns
- detects suspicious token reuse
- detects rapid sequential object enumeration
- detects non-admin access to administrative API functions
- detects excessive API request rates
- generates 6 structured security findings
- maps findings to OWASP API Security concepts
- preserves analyst guardrails against unsupported conclusions
- generates JSON and CSV analysis outputs
- creates user-level activity summaries
- creates token-level activity summaries
- independently validates expected results
- passes 11 of 11 validation checks
- runs automatically through GitHub Actions
- enforces a CI quality gate
- uploads analysis reports as workflow artifacts
- completes the final CI quality gate successfully
