# Microsoft Entra ID Cloud Compromise Investigation & Response Lab

A hands-on cloud incident-response project focused on investigating synthetic Microsoft Entra ID and Azure-style security telemetry after suspicious cloud activity has already occurred.

The project demonstrates how a security analyst can correlate authentication, Conditional Access, privileged-access, cloud-resource, and containment evidence to reconstruct a suspected cloud identity compromise while preserving evidentiary uncertainty.

## Project Objective

Cloud incident response requires more than identifying a suspicious sign-in.

Analysts must determine:

- Which identity was affected
- Where the authentication originated
- Whether authentication behavior changed
- Whether Conditional Access controls were satisfied
- Whether privilege changed
- Which cloud services and resources were accessed
- Whether additional identities were involved
- What containment actions occurred
- What the evidence confirms
- What remains an analyst hypothesis

This project demonstrates a repeatable cloud incident-response workflow:

```text
Synthetic Cloud Telemetry
        ↓
Identity Analysis
        ↓
Authentication Correlation
        ↓
Conditional Access Review
        ↓
Privilege Analysis
        ↓
Cloud Resource Review
        ↓
Scope Assessment
        ↓
Incident Timeline
        ↓
Containment Review
        ↓
Analyst Assessment
        ↓
Validation
```

# Investigation Scenario

The lab contains two separate synthetic cloud incidents.

## CLOUD-INC-001 — Finance Identity

The primary incident involves:

```text
User:
finance.user@northstar.example

Session:
SESSION-FIN-8842

Source:
198.51.100.24
```

The identity first generates repeated failed authentication attempts from an unfamiliar external source.

That activity is followed by a successful sign-in from the same source.

The resulting session then performs:

```text
Microsoft 365 activity
Finance SharePoint access
Azure VM activity
Azure Storage activity
Cloud role changes
```

The sequence becomes a high-priority cloud incident because multiple independent identity, privilege, and resource artifacts converge on the same session.

## CLOUD-INC-002 — Dormant Contractor Identity

A second incident involves:

```text
User:
dormant.contractor@northstar.example

Session:
SESSION-CONTRACT-4402

Source:
203.0.113.55
```

The identity is marked as dormant but generates:

```text
Successful cloud authentication
Unmanaged / noncompliant device context
Report-only MFA concern
Contributor role assignment
Azure resource activity
Microsoft 365 activity
```

This activity is treated as a separate incident rather than being merged with the Finance case.

# Evidence Sources

The project uses four synthetic cloud telemetry sources:

```text
sample-data/
├── signin_events.csv
├── conditional_access.csv
├── privileged_activity.csv
└── resource_activity.csv
```

These datasets model evidence similar to:

```text
Microsoft Entra ID sign-in logs
Conditional Access evaluations
Privileged Identity Management activity
Azure Resource Manager activity
Microsoft 365 activity
Azure Storage access
Cloud audit activity
```

All identities, IP addresses, resources, sessions, and cloud events are synthetic or documentation-reserved.

# Authentication Analysis

## Finance Baseline

The Finance identity begins with normal activity:

```text
12:02:18
Source: 10.10.20.17
Managed Device: Yes
Compliant Device: Yes
MFA: Satisfied
Risk: Low
Conditional Access: Success
```

This establishes a normal internal baseline.

## Repeated External Failures

The identity then generates three failed sign-ins from:

```text
198.51.100.24
```

at:

```text
12:17:41
12:17:55
12:18:13
```

All failures originate from:

```text
Unknown location
Unmanaged device
Noncompliant device
```

## Successful Authentication

At:

```text
12:18:44
```

the same identity successfully authenticates from:

```text
198.51.100.24
```

only:

```text
31 seconds
```

after the final failure.

The successful session becomes:

```text
SESSION-FIN-8842
```

The event is marked:

```text
Sign-in Risk: High
Conditional Access: reportOnlyFailure
MFA: Satisfied
```

This supports a higher-priority investigation.

However, it does not independently establish credential theft.

# Conditional Access Analysis

The Finance session triggers two important policy outcomes.

## MFA Policy

```text
Require MFA for Microsoft 365
Mode: Enabled
Result: Success
```

The evidence confirms:

```text
MFA was satisfied
```

Therefore, the project explicitly avoids claiming:

```text
MFA bypass confirmed
```

## Compliant Device Policy

```text
Require Compliant Device
Mode: Report-only
Result: reportOnlyFailure
```

The device was:

```text
Managed: No
Compliant: No
```

The report-only failure means the session would have failed that policy if it had been enforced.

It does not mean the sign-in was actively blocked.

This distinction is preserved throughout the investigation.

# Privileged Access Analysis

The Finance session later generates cloud role activity.

## Role Added

```text
12:21:18

Action:
Add Member

Role:
Virtual Machine User Login

Target:
NFG-FIN-VM01

Justification:
None

Ticket:
NONE
```

## Role Modified

```text
12:22:03

Action:
Role Assignment Modified

Role:
Virtual Machine User Login

Ticket:
NONE
```

These events are concerning because they:

```text
occur within the suspicious session
lack documented justification
lack associated ticketing
```

The project records them as suspicious privilege activity.

It does not automatically label them confirmed privilege escalation because the full authorization mechanism is not established.

# Cloud Resource Activity

The Finance session accesses several cloud services.

## Microsoft 365

```text
12:19:31
List Documents
Finance SharePoint Site
```

```text
12:20:07
Download Document
Finance_Q3_Forecast.xlsx
```

## Azure Resource Manager

```text
12:21:44
Read Configuration
NFG-FIN-VM01
```

```text
12:22:36
Request Login Access
NFG-FIN-VM01
```

## Azure Storage

```text
12:23:18
List Containers
nfgfinstorage
```

```text
12:24:02
Read Blob
finance-export-2026.csv
```

The same session therefore spans:

```text
Microsoft 365
Azure Resource Manager
Azure Storage
```

This substantially increases the scope of the incident.

# Finance Incident Timeline

The reconstructed sequence is:

```text
12:17:41
Failed external sign-in
        ↓
12:17:55
Second failed sign-in
        ↓
12:18:13
Third failed sign-in
        ↓
12:18:44
Successful external sign-in
SESSION-FIN-8842
        ↓
12:19:31
Finance SharePoint enumeration
        ↓
12:20:07
Finance document downloaded
        ↓
12:21:18
VM login role added
        ↓
12:21:44
VM configuration queried
        ↓
12:22:03
Role assignment modified
        ↓
12:22:36
VM login access requested
        ↓
12:23:18
Storage containers enumerated
        ↓
12:24:02
Finance blob accessed
        ↓
12:43:12
Finance sessions revoked
```

The final event is classified as:

```text
Response / Containment
```

rather than suspicious incident activity.

# Dormant Contractor Incident

The second incident follows a separate identity and session.

```text
User:
dormant.contractor@northstar.example

Session:
SESSION-CONTRACT-4402
```

The account successfully authenticates from:

```text
203.0.113.55
```

using:

```text
Single-factor authentication
Unmanaged device
Noncompliant device
Unknown location
High sign-in risk
```

A report-only MFA policy also records:

```text
reportOnlyFailure
```

The session then performs:

```text
SharePoint enumeration
Contributor role assignment
Azure resource configuration access
Deployment-setting enumeration
```

The role activity also lacks:

```text
Business justification
Change ticket
Incident ticket
```

This incident remains separate from the Finance case because it involves a different:

```text
Identity
Session
Source IP
Cloud resource scope
```

# Dormant Contractor Containment

Later administrator actions include:

```text
Remove Member
Contributor role removed
```

and:

```text
Disable Account
Dormant contractor identity disabled
```

These events are preserved as:

```text
Response / Containment
```

rather than being counted as suspicious activity.

# Cloud Response Rules

Detection and response logic is stored in:

```text
rules/
└── cloud_response_rules.json
```

The model scores several evidence categories.

## Authentication Indicators

```text
Repeated failed sign-ins               +15
Success after failures                 +20
High sign-in risk                      +10
Unmanaged device                        +8
Noncompliant device                     +8
Unfamiliar external source             +10
```

## Conditional Access Indicators

```text
Report-only policy failure              +8
MFA satisfied                           -5
```

The MFA reduction is intentional.

It prevents the analysis from incorrectly strengthening an MFA-bypass hypothesis when the telemetry shows MFA succeeded.

## Privileged Activity Indicators

```text
Role added without justification       +20
Role modified without ticket           +15
Privilege activity in suspicious session
                                        +10
```

Approved privileged workflows can reduce concern:

```text
Approved PIM-style workflow            -10
```

## Resource Indicators

```text
Sensitive cloud content accessed       +10
Cloud resource enumeration              +8
VM login access requested              +15
Multiple cloud services accessed       +10
```

## Scope Indicators

```text
Single identity across services         +8
Separate dormant identity activity     +10
```

The final score is capped at:

```text
100
```

# Priority Thresholds

```text
80–100 → CRITICAL
55–79  → HIGH
30–54  → MODERATE
0–29   → LOW
```

A score of 100 means maximum investigation priority within this custom educational model.

It does not mean compromise is proven with 100% certainty.

# Analysis Engine

The primary analyzer is:

```text
analyze_cloud_incident.py
```

The script:

1. Loads Entra-style sign-in telemetry.
2. Loads Conditional Access events.
3. Loads privileged-access activity.
4. Loads cloud-resource activity.
5. Identifies repeated failed sign-ins.
6. Correlates success after failures.
7. Reviews device-management context.
8. Reviews sign-in risk.
9. Evaluates Conditional Access results.
10. Preserves MFA-success context.
11. Reviews cloud role changes.
12. Detects missing justification and ticketing.
13. Reviews Microsoft 365 activity.
14. Reviews Azure Resource Manager activity.
15. Reviews Azure Storage activity.
16. Calculates cloud-service scope.
17. Separates multiple identities into separate incidents.
18. Separates incident activity from containment activity.
19. Generates incident timelines.
20. Assigns risk scores and priorities.
21. Produces containment recommendations.
22. Exports CSV and JSON investigation reports.

# Analysis Results

Running:

```bash
python3 analyze_cloud_incident.py
```

produced two incidents.

## CLOUD-INC-001

```text
User:
finance.user@northstar.example

Session:
SESSION-FIN-8842

Source:
198.51.100.24

Score:
100

Priority:
CRITICAL

Indicators:
16

Privilege Events:
2

Resource Events:
6
```

Cloud services:

```text
Azure Resource Manager
Azure Storage
Microsoft 365
```

## CLOUD-INC-002

```text
User:
dormant.contractor@northstar.example

Session:
SESSION-CONTRACT-4402

Source:
203.0.113.55

Score:
100

Priority:
CRITICAL

Indicators:
10

Privilege Events:
2

Resource Events:
3
```

Cloud services:

```text
Azure Resource Manager
Microsoft 365
```

Overall:

```text
Incidents: 2
CRITICAL:  2
HIGH:      0
MODERATE:  0
LOW:       0
```

# Finance Indicators

The Finance incident contains 16 correlated indicators:

```text
Repeated failed sign-ins
Success after repeated failures
High sign-in risk
Unmanaged device
Noncompliant device
Unfamiliar external source
Report-only policy failure
MFA satisfied
Role added without justification
Role modified without ticket
Role activity in suspicious session
Sensitive content accessed
Cloud resource enumeration
VM login access requested
Multiple cloud services accessed
Single identity active across multiple services
```

# Dormant Contractor Indicators

The contractor incident contains 10 indicators:

```text
High sign-in risk
Unmanaged device
Noncompliant device
Unfamiliar external source
Report-only policy failure
Role added without justification
Role modified without ticket
Role activity in suspicious session
Cloud resource enumeration
Single identity active across multiple services
```

# Analyst Assessment

The engine classifies both findings as:

```text
Suspected Cloud Identity Compromise
```

rather than:

```text
Confirmed Account Compromise
```

The Finance assessment states that multiple identity, Conditional Access, privileged-access, and resource artifacts converge on the same authenticated session.

The evidence supports investigation and containment.

However, the available telemetry does not independently prove:

```text
Credential theft
MFA bypass
Data exfiltration
Successful VM compromise
Persistence
```

This distinction is central to the project.

# Containment Recommendations

## Finance Identity

Recommended actions include:

```text
Revoke active sessions
Require MFA reauthentication
Review and remove unauthorized cloud roles
Review Microsoft 365 activity
Review Azure resource activity
Review Finance document and storage access
Review VM login activity
Preserve Entra ID and Azure audit logs
Reset credentials if additional evidence supports it
```

## Dormant Contractor Identity

Recommended actions include:

```text
Disable the dormant identity
Remove newly assigned roles
Revoke active sessions
Review accessed resources
Investigate why the dormant identity became active
Preserve Entra ID and Azure audit evidence
```

# Analyst Guardrails

The project includes explicit cloud IR guardrails.

```text
Do not classify repeated failed sign-ins followed
by success as confirmed credential theft without
additional evidence.
```

```text
Do not classify MFA as bypassed when telemetry
shows MFA was satisfied.
```

```text
Do not treat a report-only Conditional Access
failure as an actively blocked sign-in.
```

```text
Do not classify cloud role assignment as confirmed
privilege escalation unless the mechanism and
authorization context are established.
```

```text
Do not classify document or blob access as
confirmed data exfiltration without evidence that
data left the controlled environment.
```

```text
Do not classify a VM login access request as
successful VM compromise.
```

```text
Separate incident activity from later containment
and response actions.
```

These guardrails help preserve defensible incident-response language.

# Generated Reports

The analyzer produces:

```text
output/
├── cloud_incident_results.json
└── cloud_incident_summary.csv
```

The JSON report preserves:

- Incident metadata
- Session identity
- Source IP
- Risk score
- Incident priority
- Indicator evidence
- Cloud-service scope
- Resource scope
- Privileged activity
- Containment activity
- Timeline
- Analyst assessment
- Guardrails
- Response recommendations

The CSV report provides a concise analyst-facing case summary.

# Validation

The project includes:

```text
validate_findings.py
```

Expected ground truth is stored in:

```text
expected-results/
└── cloud_incident_expectations.json
```

The validator checks both technical results and investigation quality.

# Validation Checks

The completed validator confirms:

```text
Incident summary
CLOUD-INC-001
CLOUD-INC-002
Finance required indicators
Contractor required indicators
Authentication failure-to-success correlation
Conditional Access and MFA interpretation
Undocumented Finance role activity
Multi-service Finance resource scope
Separate Finance and contractor incidents
Containment separation
Evidentiary uncertainty
Cloud incident-response guardrails
```

Final validation:

```text
Checks run:     13
Checks passed:  13
Checks failed:  0
Overall:        PASS
```

The validation report is stored in:

```text
output/
└── cloud_incident_validation_results.json
```

# Project Structure

```text
entra-cloud-incident-lab/
├── README.md
├── analyze_cloud_incident.py
├── validate_findings.py
├── sample-data/
│   ├── signin_events.csv
│   ├── conditional_access.csv
│   ├── privileged_activity.csv
│   └── resource_activity.csv
├── rules/
│   └── cloud_response_rules.json
├── expected-results/
│   └── cloud_incident_expectations.json
└── output/
    ├── cloud_incident_results.json
    ├── cloud_incident_summary.csv
    └── cloud_incident_validation_results.json
```

# Skills Demonstrated

```text
Microsoft Entra ID
Cloud Incident Response
Azure Security
Identity Security
Conditional Access Analysis
MFA Analysis
Privileged Access Monitoring
Azure Resource Analysis
Microsoft 365 Investigation
Azure Storage Investigation
Cloud Audit Analysis
Incident Reconstruction
Scope Assessment
Incident Containment
Behavioral Correlation
Evidence Analysis
Incident Timeline Development
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## A suspicious sign-in is only the beginning

The Finance incident became significant because the identity later performed:

```text
Cloud role activity
Microsoft 365 access
Azure VM activity
Azure Storage activity
```

The broader sequence matters more than the sign-in alone.

## MFA success does not automatically make activity benign

MFA was satisfied during the Finance session.

That reduces support for an MFA-bypass hypothesis.

It does not erase the surrounding suspicious context.

## Conditional Access mode matters

A:

```text
reportOnlyFailure
```

does not mean access was blocked.

The policy was evaluating what would have happened if enforcement were enabled.

## Privilege changes require authorization context

A role assignment can be legitimate.

Missing justification and missing ticketing increase concern, especially when the activity occurs during a suspicious session.

## Resource access does not automatically equal exfiltration

The project confirms that documents and blobs were accessed.

It does not prove that data left the controlled environment.

## Incident scope must preserve identity boundaries

Finance activity and dormant-contractor activity occurred close together.

They remain separate incidents because they involve different identities, sessions, and resources.

## Response activity must not be mistaken for attacker activity

Actions such as:

```text
Revoke Sessions
Remove Member
Disable Account
```

occur later in the timeline as defensive containment.

# Limitations

This project uses synthetic Microsoft Entra ID and Azure-style telemetry.

It does not connect to a live Microsoft tenant.

The project does not:

- Use real credentials
- Query production Entra ID
- Modify real Conditional Access policies
- Assign real Azure roles
- Access live cloud resources
- Revoke real sessions
- Disable production accounts
- Prove credential theft
- Prove MFA bypass
- Prove data exfiltration
- Prove VM compromise

Future improvements could include:

- Microsoft Graph integration
- Microsoft Sentinel integration
- Defender for Cloud integration
- Defender for Identity integration
- Entra risky-user telemetry
- Live sign-in log ingestion
- PIM audit integration
- Azure Activity Log ingestion
- Microsoft 365 Unified Audit Log integration
- Impossible-travel analysis
- Token/session analysis
- GeoIP enrichment
- Cloud asset criticality
- Automated incident creation
- SOAR containment workflows
- Incident-response dashboarding

# Safety

All identities, resources, sessions, IP addresses, cloud events, and containment actions used in this project are synthetic.

No live Microsoft tenant, production Azure environment, or real organizational data is used.

The project is limited to defensive cloud investigation, correlation, containment planning, reporting, and validation.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- analyzes synthetic Entra ID sign-in activity
- correlates authentication failures with successful login
- evaluates Conditional Access evidence
- preserves MFA-success context
- evaluates unmanaged and noncompliant devices
- analyzes undocumented cloud role changes
- reviews Microsoft 365 activity
- reviews Azure Resource Manager activity
- reviews Azure Storage activity
- reconstructs two separate cloud incidents
- correlates 16 Finance indicators
- correlates 10 dormant-contractor indicators
- assigns CRITICAL priority to both incidents
- preserves containment actions separately
- maintains evidentiary uncertainty
- generates JSON and CSV reports
- validates all expected results
- passes 13 of 13 validation checks
