# SOC Alert Enrichment & Response Automation Lab

A hands-on Security Operations and SOAR-style automation project focused on transforming raw security alerts into enriched, prioritized, analyst-ready incident cases.

The project demonstrates how a SOC can normalize alerts from multiple security products, enrich them with user, asset, and IOC context, collapse duplicate detections, correlate related activity, assign incident priority, route cases to the appropriate analyst queue, and recommend response actions while preserving human approval boundaries.

## Project Objective

Security analysts rarely investigate one alert at a time.

A single incident may generate alerts from:

- Identity monitoring
- Endpoint detection
- Network monitoring
- Threat intelligence
- Email security
- Privilege monitoring

Individually, those alerts may provide only part of the story.

This project demonstrates how automation can convert a noisy multi-source alert stream into a smaller number of structured analyst cases.

## Project Workflow

```text
Raw Security Alerts
        ↓
Alert Normalization
        ↓
User / Asset / IOC Enrichment
        ↓
Alert Deduplication
        ↓
Cross-Alert Correlation
        ↓
Incident Creation
        ↓
Priority Scoring
        ↓
Playbook Selection
        ↓
Response Recommendations
        ↓
Analyst Approval Boundaries
        ↓
Case Routing
        ↓
Analyst-Ready Incident Report
        ↓
Validation
```

## Synthetic Alert Stream

The project begins with:

```text
11 raw security alerts
```

modeled after multiple security tools.

The alert categories include:

```text
Authentication
Execution
Network
Threat Intelligence
Privilege
Email
```

The synthetic dataset is stored in:

```text
sample-data/
└── alerts.json
```

## Alert Sources

The dataset contains alerts modeled after:

```text
Identity Monitor
Endpoint Detection
Network Monitor
Threat Intelligence
Privilege Monitor
Email Security
```

The alert stream contains both related and unrelated activity so the automation must decide:

```text
Which alerts belong together?
Which alerts are duplicates?
Which alerts provide enrichment?
Which alerts are unrelated noise?
```

# Enrichment Context

The automation enriches raw technical alerts with business and security context.

## User Context

Stored in:

```text
sample-data/
└── users.json
```

User enrichment includes:

- Department
- Job role
- Privilege level
- MFA enrollment
- Business impact
- High-value identity status
- Account status

## Asset Context

Stored in:

```text
sample-data/
└── assets.json
```

Asset enrichment includes:

- Asset type
- Department
- Business function
- Criticality
- Environment
- EDR management
- Data sensitivity
- Internet exposure

## Threat Intelligence Context

Stored in:

```text
sample-data/
└── ioc_context.json
```

IOC enrichment includes:

- Indicator type
- Reputation
- Confidence
- Known-malicious status
- Data source
- Recommended handling
- Analyst notes

This enrichment can either increase or reduce investigation priority.

For example:

```text
203.0.113.88
Reputation: High Interest
Known Malicious: True
```

raises concern when correlated with endpoint activity.

Meanwhile:

```text
198.51.100.15
Reputation: Trusted
Known Malicious: False
```

reduces unnecessary alert noise when seen in approved administrative traffic.

# Alert Normalization

The main engine first normalizes every alert into a consistent structure.

Each normalized alert preserves:

```text
Alert ID
Timestamp
Security Product
Category
Severity
User
Asset
Source IP
Destination IP
Indicator
Event Type
Description
Confidence
Status
User Context
Asset Context
IOC Context
```

This gives later correlation logic one consistent data model to work with.

# Alert Deduplication

The project includes duplicate-alert reduction.

Two alerts described the same underlying PowerShell activity:

```text
ALERT-003
Suspicious PowerShell
```

and:

```text
ALERT-004
PowerShell Encoded Command
```

Because they involved the same:

```text
User
Asset
Time window
Execution activity
```

they were collapsed into:

```text
Suspicious Encoded PowerShell Execution
```

The original alert IDs were preserved.

Result:

```text
11 raw alerts
        ↓
10 post-deduplication alerts
```

This reduces analyst noise without deleting evidence.

# Cross-Alert Correlation

Alerts are correlated only when they share meaningful context.

Correlation considers:

```text
User
Asset
Source IP
Indicator
Time window
```

The engine intentionally does not merge alerts solely because they occurred close together.

That allows related Finance alerts to form one incident while unrelated Marketing, HR, and administrative alerts remain separate.

# Primary Incident — Finance Compromise Sequence

The strongest correlated case became:

```text
Incident ID:       INC-001
Priority:          CRITICAL
Priority Score:    100
Affected User:     finance.user
Affected Asset:    NFG-FIN-WS07
Route:             SOC Tier 2 / Incident Response
Playbook:          Finance Compromise Sequence
```

The case contains:

```text
8 original source alerts
7 correlated alert records after deduplication
```

## Related Evidence

The Finance incident combines:

```text
Repeated authentication failures
Successful authentication after failures
Suspicious PowerShell execution
Encoded PowerShell activity
High-interest outbound network communication
Threat-intelligence IOC correlation
Privilege-related activity
Suspicious email attachment context
```

## Security Categories

The final incident contains:

```text
Authentication
Execution
Network
Threat Intelligence
Privilege
Email
```

## Security Products

The incident correlates evidence from:

```text
Identity Monitor
Endpoint Detection
Network Monitor
Threat Intelligence
Privilege Monitor
Email Security
```

This gives the analyst a much more complete incident narrative than any individual alert could provide.

# Business Context

The incident is enriched with:

```text
User:              finance.user
Department:        Finance
Role:              Financial Analyst
Business Impact:   High
High-Value User:   Yes
```

and:

```text
Asset:             NFG-FIN-WS07
Business Function: Financial Operations
Criticality:       High
Data Sensitivity:  High
Environment:       Production
```

The analyst also receives IOC context for:

```text
203.0.113.88
```

which is marked as a synthetic known-malicious/high-interest indicator.

# Incident Priority Scoring

The scoring model is stored in:

```text
rules/
└── response_rules.json
```

The priority model considers:

- Highest alert severity
- User business impact
- High-value identity status
- Privileged identity status
- Asset criticality
- Data sensitivity
- IOC reputation
- Number of alert categories
- Number of security products
- Authentication + execution correlation
- Execution + network correlation
- Identity + privilege correlation
- Number of related alerts

Priority thresholds:

```text
80+   → CRITICAL
55–79 → HIGH
30–54 → MODERATE
0–29  → LOW
```

The score represents incident priority within this custom educational workflow.

It is not a probability that compromise occurred.

# Analyst-Facing Cases

The final automation produced four analyst cases.

## INC-001 — Finance Compromise Sequence

```text
Priority:          CRITICAL
Score:             100
User:              finance.user
Asset:             NFG-FIN-WS07
Source Alerts:     8
Correlated Alerts: 7
Route:             SOC Tier 2 / Incident Response
```

## INC-002 — Marketing PowerShell Activity

```text
Priority:          LOW
Score:             3
User:              marketing.user
Asset:             NFG-MKT-WS08
Source Alerts:     1
Correlated Alerts: 1
Route:             SOC Tier 1 Monitoring
Playbook:          General Analyst Review
```

The activity remains low priority because no broader suspicious context is present.

## INC-003 — Low-Risk Authentication Noise

```text
Priority:          LOW
Score:             16
User:              alex.employee
Asset:             NFG-HR-WS03
Source Alerts:     1
Correlated Alerts: 1
Route:             SOC Tier 1 Monitoring
Playbook:          Low-Risk Authentication Noise
```

A single failed sign-in followed by successful authentication remains low priority in the absence of additional suspicious evidence.

## INC-004 — Trusted Administrative Traffic

```text
Priority:          LOW
Score:             29
User:              it.admin
Asset:             NFG-ADMIN-WS01
Source Alerts:     1
Correlated Alerts: 1
Route:             SOC Tier 1 Monitoring
Playbook:          Trusted Administrative Traffic
```

This case demonstrates how enrichment can reduce analyst noise.

The account and asset are highly sensitive:

```text
Privileged Identity
Critical Asset
High Data Sensitivity
```

but the destination:

```text
198.51.100.15
```

is identified as trusted.

The scoring model was tuned so the trusted IOC reduction changed this case from:

```text
MODERATE / 44
```

to:

```text
LOW / 29
```

without deleting the underlying alert.

This is an important lesson:

> Good enrichment should both raise important incidents and reduce explainable noise.

# Response Automation

The project separates response actions into three categories.

## Automated Safe Actions

Examples include:

```text
Create incident record
Attach related alert evidence
Enrich user context
Enrich asset context
Enrich IOC context
Tag affected user and asset
Collect related authentication logs
Collect related endpoint alerts
Collect related network alerts
Notify assigned SOC queue
```

These actions add information or organize the case without significantly disrupting users or systems.

## Analyst Approval Required

Potentially disruptive actions are not automatically executed.

Examples include:

```text
Revoke active user sessions
Require MFA reauthentication
Disable user account
Isolate endpoint
Block source or destination IP
Quarantine suspicious email
Remove privileged access
```

These remain human-approved decisions.

## Escalation Conditions

The Finance incident triggers several escalation conditions:

```text
High-value identity involved
High-value asset involved
Known malicious IOC correlated with endpoint activity
Authentication anomalies followed by suspicious execution
Suspicious execution followed by network activity
Privilege-related activity follows suspected compromise
```

# Finance Response Playbook

The selected playbook recommends:

```text
Revoke active sessions
Require MFA reauthentication
Preserve authentication and endpoint evidence
Review recent account activity
Review outbound network activity
Consider endpoint isolation if additional compromise evidence is confirmed
Escalate to SOC Tier 2
```

The important wording is:

```text
Consider endpoint isolation if additional compromise evidence is confirmed
```

rather than automatically isolating the system.

# Analyst Assessment

The generated Finance case explains that multiple related alerts were correlated across multiple security categories.

Business and threat enrichment increases the investigation priority.

However, the assessment also states that the evidence:

```text
does not independently establish the complete compromise mechanism
```

and does not assume every correlated alert is malicious.

This preserves the distinction between:

```text
Observed Evidence
```

and:

```text
Analyst Interpretation
```

# Analyst Guardrails

The project includes explicit safety and investigation guardrails.

```text
Do not merge alerts solely because they occur close together in time.
```

```text
Require shared user, asset, source, indicator, or behavioral context before correlation.
```

```text
Do not classify a trusted IOC as malicious without contradictory evidence.
```

```text
Do not automatically isolate a host or disable an account without analyst approval.
```

```text
Do not treat enrichment data as proof of compromise.
```

```text
Distinguish observed alert evidence from analyst interpretation.
```

# Analysis Engine

The primary automation script is:

```text
process_alerts.py
```

The engine:

1. Loads raw alerts.
2. Loads user context.
3. Loads asset context.
4. Loads IOC context.
5. Normalizes alerts.
6. Adds enrichment.
7. Deduplicates overlapping PowerShell detections.
8. Correlates related alerts using shared context.
9. Creates analyst incident cases.
10. Calculates incident priority.
11. Applies threat and business context.
12. Selects response playbooks.
13. Assigns SOC routing.
14. Identifies escalation conditions.
15. Separates safe automation from analyst-approved containment.
16. Generates analyst assessments.
17. Exports structured JSON and CSV reports.

# Processing Results

Running:

```bash
python3 process_alerts.py
```

produced:

```text
Raw alerts:             11
After deduplication:     10
Analyst incident cases:   4
```

Final analyst cases:

```text
INC-001 | CRITICAL | Score 100 | finance.user   | NFG-FIN-WS07
INC-002 | LOW      | Score   3 | marketing.user | NFG-MKT-WS08
INC-003 | LOW      | Score  16 | alex.employee  | NFG-HR-WS03
INC-004 | LOW      | Score  29 | it.admin       | NFG-ADMIN-WS01
```

# Generated Reports

The project creates:

```text
output/
├── normalized_enriched_alerts.json
├── analyst_incident_cases.json
└── analyst_incident_summary.csv
```

## Normalized Alert Report

Contains:

- Normalized alert data
- User enrichment
- Asset enrichment
- IOC enrichment
- Deduplication state
- Original source-alert IDs

## Analyst Incident Case Report

Contains:

- Incident ID
- Priority
- Priority score
- Routing
- Affected user
- Affected asset
- Business context
- IOC context
- Categories
- Security products
- Original alert IDs
- Deduplicated alert count
- Priority factors
- Evidence
- Response playbook
- Automated safe actions
- Analyst-approved response actions
- Escalation conditions
- Analyst assessment
- Guardrails

## CSV Summary

Provides a concise case queue suitable for analyst review.

# Validation

The project includes:

```text
validate_cases.py
```

Expected results are stored in:

```text
expected-results/
└── incident_expectations.json
```

The validator confirms both technical output and analyst-facing quality.

# Validation Checks

The completed validation verifies:

```text
Alert normalization and deduplication
Incident summary
INC-001
INC-002
INC-003
INC-004
PowerShell duplicate collapse
Finance business and threat enrichment
Cross-product incident correlation
Safe automation vs analyst-approved containment
Trusted administrative traffic tuning
Analyst guardrails and evidentiary uncertainty
```

Final validation:

```text
Checks run:     12
Checks passed:  12
Checks failed:  0
Overall:        PASS
```

The validation report is stored in:

```text
output/
└── incident_validation_results.json
```

# Project Structure

```text
soc-alert-response-lab/
├── README.md
├── process_alerts.py
├── validate_cases.py
├── sample-data/
│   ├── alerts.json
│   ├── users.json
│   ├── assets.json
│   └── ioc_context.json
├── rules/
│   └── response_rules.json
├── expected-results/
│   └── incident_expectations.json
└── output/
    ├── normalized_enriched_alerts.json
    ├── analyst_incident_cases.json
    ├── analyst_incident_summary.csv
    └── incident_validation_results.json
```

# Skills Demonstrated

```text
SOAR Concepts
SOC Automation
Alert Normalization
Alert Enrichment
Alert Deduplication
Cross-Alert Correlation
Incident Prioritization
Case Management
Analyst Workflow Design
Response Playbooks
Threat Intelligence Enrichment
Asset Context Enrichment
Identity Context Enrichment
Security Operations
Incident Triage
Human-in-the-Loop Response
Python
JSON Processing
CSV Reporting
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## More alerts do not necessarily mean more incidents

Eight original Finance alerts became:

```text
7 correlated records
1 analyst incident
```

because duplicate PowerShell detections were consolidated while preserving the original evidence.

## Context changes priority

A technical alert becomes more meaningful when the analyst also knows:

```text
Who is affected?
What asset is involved?
How important is the asset?
Is the IOC trusted or high-interest?
What other alerts occurred?
```

## Enrichment can reduce noise

The IT administrator case initially reached MODERATE because the identity and workstation were highly sensitive.

Trusted destination context reduced the case to LOW.

This prevented security sensitivity from creating unnecessary analyst workload.

## Automation should organize evidence, not replace judgment

The system can safely:

```text
Create cases
Collect logs
Add context
Route incidents
```

But disruptive containment remains analyst-approved.

## Correlation requires shared evidence

Time proximity alone is insufficient.

The system requires shared context such as:

```text
User
Asset
Source IP
Indicator
```

before treating alerts as related.

## A useful incident report explains why

The analyst should not receive only:

```text
CRITICAL
```

The case should explain:

```text
What happened
What evidence supports it
What business context matters
Why the priority changed
What response is recommended
What still requires human judgment
```

# Limitations

This project uses synthetic alerts, users, assets, indicators, and response rules.

It does not connect directly to a live SIEM, EDR, SOAR, identity platform, or ticketing system.

The project does not automatically execute disruptive containment actions.

Future improvements could include:

- Microsoft Sentinel integration
- Microsoft Defender integration
- Wazuh alert ingestion
- Splunk integration
- Real threat-intelligence enrichment
- ServiceNow incident creation
- Jira ticket creation
- Slack or Teams analyst notifications
- Automated evidence collection
- Case status tracking
- SLA monitoring
- Incident aging
- Escalation timers
- Analyst feedback loops
- Dynamic scoring adjustments
- SOAR playbook execution
- Dashboard visualization

# Safety

All alerts, users, systems, IP addresses, indicators, and incident scenarios used in this project are synthetic.

No production user accounts, endpoints, mailboxes, or infrastructure are modified.

Potentially disruptive actions are represented as analyst-approved recommendations rather than automatically executed.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- processes 11 synthetic raw alerts
- enriches alerts with user, asset, and IOC context
- deduplicates overlapping endpoint detections
- reduces 11 alerts to 10 enriched records
- correlates activity into 4 analyst incident cases
- preserves 8 original Finance source alerts
- produces 1 CRITICAL Finance incident
- keeps unrelated Marketing and HR activity LOW
- tunes trusted administrative traffic from MODERATE to LOW
- selects analyst-facing response playbooks
- separates safe automation from disruptive containment
- assigns SOC routing
- generates structured JSON and CSV reports
- preserves evidentiary uncertainty
- validates all expected outcomes
- passes 12 of 12 validation checks
