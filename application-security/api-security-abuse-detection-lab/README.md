# API Security Assessment & Abuse Detection Lab

A hands-on application security and SOC analysis project focused on detecting suspicious and unauthorized behavior within synthetic REST API telemetry.

The project demonstrates how API request logs can be analyzed for authorization violations, token misuse, enumeration, authentication abuse, rate anomalies, and suspicious administrative activity.

## Project Objective

Modern enterprise applications depend heavily on APIs.

Security teams may need to investigate activity involving:

- REST API requests
- Authentication tokens
- User identities
- Object identifiers
- Administrative endpoints
- Sensitive business records
- Repeated authentication failures
- Excessive request rates
- Suspicious access patterns

The goal of this project is to build a repeatable API security analysis workflow that distinguishes legitimate application usage from activity requiring analyst review.

## Planned Workflow

```text
Synthetic API Request Logs
        ↓
Request Parsing
        ↓
User / Token / IP Correlation
        ↓
Authentication Analysis
        ↓
Authorization Analysis
        ↓
Object Access Review
        ↓
Endpoint Enumeration Analysis
        ↓
Request-Rate Analysis
        ↓
Administrative API Review
        ↓
Risk Classification
        ↓
OWASP API Security Mapping
        ↓
Analyst Findings
        ↓
Independent Validation
```

## Planned Synthetic Environment

The lab will represent a fictional enterprise API environment for:

```text
Northstar Ridge
```

Planned API areas include:

```text
/api/auth/
/api/users/
/api/accounts/
/api/invoices/
/api/admin/
/api/reports/
```

Synthetic users will represent several authorization levels:

```text
Standard employee
Finance user
Contractor
Administrator
Service account
```

## Planned API Security Scenarios

The dataset will contain both normal and suspicious activity.

### Normal Activity

Examples:

```text
Authorized user accessing their own account
Finance user retrieving approved invoice records
Administrator performing expected account management
Service account accessing an approved application endpoint
Normal authentication and token use
```

### Suspicious Activity

The lab will include controlled examples of:

```text
Repeated authentication failures
Object access outside the user's authorization scope
Administrative endpoint access by a non-admin user
Token reuse from multiple source IP addresses
Rapid sequential object enumeration
Excessive API request rates
Sensitive endpoint access
Unusual HTTP methods
```

## Planned Detection Categories

The analysis engine will evaluate activity for:

### Authentication Abuse

Examples:

```text
Repeated failed logins
Failure-to-success sequences
High authentication request volume
```

### Broken Object-Level Authorization Indicators

Example:

```text
finance.user
        ↓
Authorized account:
1001

Requests:
1001
1002
1003
1004
```

Access to objects outside the user's expected scope may require investigation.

### Token Misuse Indicators

Examples:

```text
Same token
+
Multiple source IP addresses
+
Short time window
```

This does not automatically prove token theft, but it may justify analyst review.

### Endpoint Enumeration

Example:

```text
GET /api/accounts/1001
GET /api/accounts/1002
GET /api/accounts/1003
GET /api/accounts/1004
GET /api/accounts/1005
```

Rapid sequential requests may indicate object enumeration or automated discovery.

### Administrative API Abuse

Example:

```text
POST /api/admin/users
```

from a user without an administrative role.

### Rate Abuse

Example:

```text
120 API requests
within
60 seconds
```

The project will distinguish high request volume from confirmed malicious activity.

## Planned Normalized API Event Schema

Raw API events will be transformed into a consistent structure:

```text
timestamp
request_id
source_ip
user
role
token_id
http_method
endpoint
object_id
response_status
response_bytes
user_agent
authentication_result
authorization_result
```

## Planned Findings

The project will generate analyst findings such as:

```text
API-001 Repeated Authentication Failures

API-002 Unauthorized Object Access Pattern

API-003 Suspicious Token Reuse

API-004 Sequential Object Enumeration

API-005 Unauthorized Administrative Endpoint Access

API-006 Excessive API Request Rate
```

Each finding will contain:

```text
Finding ID
Severity
User
Source IP
Affected endpoint
Supporting events
Observed indicators
Analyst assessment
Security mapping
Guardrails
```

## OWASP API Security Mapping

Findings will be mapped where appropriate to relevant OWASP API Security concepts, including areas such as:

```text
Broken Object Level Authorization
Broken Authentication
Broken Function Level Authorization
Unrestricted Resource Consumption
Security Misconfiguration
Improper Inventory Management
```

The project will use OWASP categories as analytical context rather than claiming that every suspicious event proves a vulnerability.

## Planned Project Structure

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
└── output/
```

## Planned Outputs

The analysis engine will generate:

```text
output/
├── normalized_api_events.json
├── api_findings.json
├── api_findings_summary.csv
├── user_activity_summary.json
├── token_activity_summary.json
└── api_validation_results.json
```

## Analyst Guardrails

This project will distinguish:

```text
Observed activity
```

from:

```text
Confirmed compromise
```

For example:

```text
Token used from multiple IP addresses
```

does not automatically prove:

```text
Token theft
```

Likewise:

```text
Rapid object access
```

does not automatically prove:

```text
Successful exploitation
```

The lab will document what the evidence supports without overstating conclusions.

## Skills Demonstrated

- API Security
- Application Security
- REST API Analysis
- HTTP Analysis
- Authorization Analysis
- Authentication Analysis
- Identity Correlation
- Token Analysis
- API Abuse Detection
- OWASP API Security
- SOC Analysis
- Security Analytics
- Python
- JSON
- CSV
- Data Correlation
- Detection Engineering
- Validation Testing
- Analyst Reporting

## Safety

All:

```text
Users
Tokens
IP addresses
Endpoints
Objects
Request logs
Authentication events
Authorization decisions
```

used in this project are synthetic.

No production API, live credential, real access token, or external service is tested.

## Project Status

🚧 **In Development**
