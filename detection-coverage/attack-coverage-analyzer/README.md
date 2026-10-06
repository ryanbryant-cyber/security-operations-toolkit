# MITRE ATT&CK Detection Coverage & Gap Analysis Tool

A hands-on detection-engineering project focused on evaluating the strength, diversity, validation state, redundancy, and gaps of a synthetic security detection program using the MITRE ATT&CK framework.

The project demonstrates how a security analyst or detection engineer can move beyond building individual rules and evaluate whether the overall detection program provides meaningful coverage across priority attacker behaviors.

## Project Objective

A detection program should answer more than:

```text
Do we have a rule for this?
```

A more useful assessment asks:

```text
Is the detection validated?
Does it use reliable telemetry?
Do multiple independent data sources provide visibility?
Are several analytics creating useful layered coverage or unnecessary noise?
Which important attacker behaviors have no detection at all?
```

This project demonstrates how to:

- Maintain a structured detection catalog
- Map detections to MITRE ATT&CK techniques and tactics
- Evaluate detection validation status
- Measure telemetry diversity
- Measure detection-method diversity
- Calculate technique-level coverage
- Calculate tactic-level coverage
- Identify detection gaps
- Identify weak or experimental coverage
- Review redundant detection overlap
- Prioritize detection-engineering work
- Generate structured JSON and CSV reports
- Validate expected results against synthetic ground truth

## Analysis Workflow

```text
Detection Catalog
        ↓
Metadata Normalization
        ↓
MITRE ATT&CK Mapping
        ↓
Technique Coverage Scoring
        ↓
Tactic Coverage Analysis
        ↓
Validation Review
        ↓
Redundancy Analysis
        ↓
Coverage Gap Identification
        ↓
Engineering Prioritization
        ↓
Detection Recommendations
        ↓
CSV / JSON Reporting
        ↓
Validation
```

# Detection Catalog

The project evaluates:

```text
25 synthetic detections
```

stored in:

```text
sample-data/
└── detection_catalog.csv
```

The catalog models detection content from:

```text
Sigma
KQL
Python behavioral analytics
YARA
Memory forensics
Email security
Network monitoring
Cloud identity
DevSecOps
```

Each detection contains:

```text
Detection ID
Detection Name
Detection Type
Project Source
Platform
Data Source
ATT&CK Tactic
ATT&CK Technique
Technique ID
Severity
Confidence
Validation Status
Detection Status
False-Positive Notes
```

# ATT&CK Coverage Model

Coverage logic is stored in:

```text
rules/
└── coverage_model.json
```

The analyzer evaluates detections against:

```text
25 priority MITRE ATT&CK techniques
```

across multiple tactics.

The model intentionally includes both:

```text
Existing detection coverage
```

and:

```text
Techniques with no current detection
```

so engineering gaps can be identified.

# Coverage Scoring

A technique does not receive strong coverage simply because one detection exists.

The scoring model evaluates several dimensions.

## Detection Presence

```text
At least one detection exists → +15
```

## Validated Detections

```text
+15 per validated detection
Maximum: 30 points
```

Validated rules contribute more confidence than experimental or unreviewed analytics.

## Data Source Diversity

```text
+10 per unique data source
Maximum: 20 points
```

Independent telemetry improves resilience.

For example:

```text
Windows Event Logs
Endpoint telemetry
Memory artifacts
Cloud identity logs
Network telemetry
```

can provide different perspectives on related behavior.

## Detection Type Diversity

```text
+5 per unique detection type
Maximum: 15 points
```

Examples include:

```text
Sigma
KQL
Python
YARA
```

## Active Detection Bonus

Active detections can contribute:

```text
Up to 10 points
```

Experimental detections receive less effective coverage.

## Detection Confidence

Average detection confidence contributes:

```text
Up to 10 points
```

## Review Penalty

```text
Needs Review → -10 per detection
Maximum penalty: -20
```

## Experimental Penalty

```text
Experimental → -10 per detection
Maximum penalty: -20
```

# Coverage Ratings

Final scores are classified as:

```text
75–100 → STRONG
50–74  → MODERATE
1–49   → LOW
0      → GAP
```

These thresholds are part of this custom educational detection-coverage model and are not presented as a universal industry standard.

# Overall Results

Running:

```bash
python3 analyze_coverage.py
```

produced:

```text
Detection catalog:      25
Priority techniques:    25

STRONG coverage:         3
MODERATE coverage:      15
LOW coverage:            1
Coverage GAPs:           6

Validated detections:   24
Needs review:            1
Experimental:            1

Redundancy reviews:      2
```

# Strong Coverage Areas

Three techniques reached STRONG coverage.

## T1059.001 — PowerShell

```text
Coverage Score: 99.17
Coverage Rating: STRONG
Detections: 3
Validated: 3
```

Detection sources include:

```text
Sigma
KQL
Python
```

with telemetry from multiple analysis approaches.

The three detections include:

```text
Suspicious Encoded PowerShell
Suspicious PowerShell Activity
Memory Correlated PowerShell Execution
```

This provides layered visibility.

However, because three separate detections cover the same technique, the analyzer also recommends reviewing alert overlap.

## T1110 — Brute Force

```text
Coverage Score: 93.83
Coverage Rating: STRONG
Detections: 3
Validated: 3
```

Coverage includes:

```text
Repeated Failed Windows Logons
Repeated Entra Sign-in Failures
Success After Repeated Sign-in Failures
```

This provides visibility across both Windows and cloud authentication telemetry.

The technique is also flagged for redundancy review because three analytics may create overlapping SOC alerts.

## T1071.001 — Web Protocols

```text
Coverage Score: 87.75
Coverage Rating: STRONG
Detections: 2
```

Coverage includes:

```text
PCAP / network evidence
Memory network artifacts
```

Because only two detections exist, this technique does not cross the configured redundancy-review threshold.

# Moderate Coverage

Fifteen techniques received MODERATE coverage.

These techniques have useful detection capability but may benefit from:

```text
Additional telemetry
Additional analytic diversity
Additional validation
Improved confidence
```

Examples include:

```text
Spearphishing Attachment
Spearphishing Link
Windows Service
Rundll32
Unsecured Credentials
Account Discovery
System Network Configuration Discovery
Cloud Service Discovery
SMB Windows Admin Shares
Data from Cloud Storage
Network Denial of Service
Application Exhaustion Flood
Data Encrypted for Impact
```

MODERATE coverage does not mean poor detection.

It means the current implementation has less diversity or depth than the strongest-covered techniques.

# Low Coverage Finding

## T1078.004 — Cloud Accounts

```text
Coverage Score: 43.25
Coverage Rating: LOW
Engineering Priority: REVIEW
Detections: 2
Validated: 1
Needs Review: 1
Experimental: 1
```

The technique technically has two detections:

```text
Suspicious Cloud Account Sign-in
Dormant Cloud Identity Activity
```

However, one detection is:

```text
Needs Review
Experimental
```

The model therefore does not interpret:

```text
2 detections exist
```

as:

```text
Strong operational coverage
```

This demonstrates an important detection-engineering principle:

> Detection quantity and detection maturity are not the same thing.

# Detection Coverage Gaps

The analyzer identified six priority techniques with no current detection coverage.

## CRITICAL Engineering Priorities

### T1003 — OS Credential Dumping

```text
Coverage: GAP
Coverage Score: 0
Technique Priority: Critical
Engineering Priority: CRITICAL
```

Recommendation:

Develop detection capability using appropriate endpoint, Windows security, memory, or identity telemetry.

### T1562.001 — Impair Defenses

```text
Coverage: GAP
Coverage Score: 0
Technique Priority: Critical
Engineering Priority: CRITICAL
```

This gap is especially important because activity that disables or weakens security controls can directly reduce the visibility of other detections.

# HIGH Engineering Priorities

## T1021.001 — Remote Desktop Protocol

```text
Coverage: GAP
Engineering Priority: HIGH
```

## T1053.005 — Scheduled Task

```text
Coverage: GAP
Engineering Priority: HIGH
```

## T1567.002 — Exfiltration to Cloud Storage

```text
Coverage: GAP
Engineering Priority: HIGH
```

These techniques are considered important but rank below the Critical-priority gaps.

# MODERATE Engineering Priority

## T1119 — Automated Collection

```text
Coverage: GAP
Technique Priority: Moderate
Engineering Priority: MODERATE
```

This gap should be addressed after higher-priority missing detection areas.

# Engineering Priority Results

The analyzer produced seven engineering-priority items:

```text
CRITICAL | T1003     | OS Credential Dumping
CRITICAL | T1562.001 | Impair Defenses

HIGH     | T1021.001 | Remote Desktop Protocol
HIGH     | T1053.005 | Scheduled Task
HIGH     | T1567.002 | Exfiltration to Cloud Storage

MODERATE | T1119     | Automated Collection

REVIEW   | T1078.004 | Cloud Accounts
```

This demonstrates that:

```text
Not every gap has equal urgency.
```

Technique importance and existing coverage strength both influence the remediation queue.

# Redundancy & Overlap Analysis

The project also evaluates detection overlap.

A technique enters redundancy review when:

```text
3 or more detections
```

are mapped to the same ATT&CK technique.

The analyzer then asks whether those detections provide:

```text
Independent telemetry
Different detection methods
Useful layered visibility
```

or whether they may create:

```text
Duplicate alerting
Analyst fatigue
Unnecessary SOC noise
```

## PowerShell Redundancy Review

```text
Technique:
T1059.001 — PowerShell

Detections:
3

Classification:
Layered Coverage - Review Alert Overlap
```

The detections use multiple approaches, so the recommendation is not to remove them automatically.

Instead:

```text
Maintain layered coverage
+
Review duplicate alert generation
```

## Brute Force Redundancy Review

```text
Technique:
T1110 — Brute Force

Detections:
3

Classification:
Layered Coverage - Review Alert Overlap
```

Coverage exists across different authentication contexts.

Again, overlap can be beneficial while still requiring tuning.

# Multi-Tactic ATT&CK Mapping

The analyzer correctly handles techniques associated with multiple tactics.

For example:

```text
T1543.003 — Windows Service
```

maps to:

```text
Persistence
Privilege Escalation
```

and:

```text
T1098 — Account Manipulation
```

also maps to:

```text
Persistence
Privilege Escalation
```

The analyzer splits those mappings rather than treating:

```text
Persistence|Privilege Escalation
```

as one artificial tactic.

This improves tactic-level reporting.

# Tactic Coverage Analysis

Technique results are aggregated into ATT&CK tactic views.

The project evaluates tactics including:

```text
Initial Access
Execution
Persistence
Privilege Escalation
Defense Evasion
Credential Access
Discovery
Lateral Movement
Collection
Command and Control
Exfiltration
Impact
```

Tactic strength is based on the average coverage score of priority techniques assigned to that tactic.

This provides a higher-level view of where the detection program is strongest or weakest.

# Detection Engineering Recommendations

Coverage recommendations depend on the final technique rating.

## STRONG

```text
Maintain current coverage.
Validate periodically.
Review overlapping detections for unnecessary duplicate alerting.
```

## MODERATE

```text
Maintain existing detections.
Improve coverage through additional telemetry,
analytic diversity, or validation.
```

## LOW

```text
Prioritize tuning and validation.
Add independent telemetry or detection logic before
treating the technique as reliably covered.
```

## GAP

```text
Develop new detection capability using appropriate
endpoint, identity, network, cloud, or application telemetry.
```

# Analysis Engine

The primary script is:

```text
analyze_coverage.py
```

The analyzer:

1. Loads the detection catalog.
2. Loads the ATT&CK coverage model.
3. Matches detections to priority techniques.
4. Separates multi-tactic mappings.
5. Counts validated detections.
6. Evaluates data-source diversity.
7. Evaluates detection-type diversity.
8. Calculates average confidence.
9. Applies experimental and review penalties.
10. Calculates technique coverage scores.
11. Assigns STRONG, MODERATE, LOW, or GAP.
12. Identifies coverage gaps.
13. Assigns engineering priority.
14. Identifies redundancy-review candidates.
15. Calculates tactic coverage.
16. Generates engineering recommendations.
17. Exports structured reports.

# Generated Reports

Running:

```bash
python3 analyze_coverage.py
```

creates:

```text
output/
├── attack_coverage_results.json
├── technique_coverage.csv
├── tactic_coverage.csv
└── engineering_priorities.csv
```

## ATT&CK Coverage JSON

Contains:

```text
Analysis summary
Technique coverage
Tactic coverage
Engineering priorities
Redundancy review
Scoring breakdowns
Detection mappings
Recommendations
Analyst guardrails
```

## Technique Coverage CSV

Provides a technique-level view containing:

```text
Technique
ATT&CK ID
Tactic
Priority
Detection count
Validated count
Data-source diversity
Detection-type diversity
Confidence
Coverage score
Coverage rating
Engineering priority
Recommendation
```

## Tactic Coverage CSV

Provides:

```text
Tactic
Priority technique count
Average coverage
Coverage rating
Strong technique count
Low technique count
Gap count
```

## Engineering Priorities CSV

Provides a concise detection-engineering backlog.

# Validation

The project includes:

```text
validate_coverage.py
```

Expected outcomes are stored in:

```text
expected-results/
└── coverage_expectations.json
```

The validation harness checks both numerical results and detection-engineering behavior.

# Validation Checks

The validator confirms:

```text
Coverage analysis summary
PowerShell STRONG coverage
Brute Force STRONG coverage
Web Protocols STRONG coverage
Exact expected coverage-gap set
Correct engineering-priority assignment
Experimental Cloud Accounts coverage remains LOW
PowerShell redundancy review
Brute Force redundancy review
Two-detection Web Protocol coverage does not trigger redundancy
Multi-tactic ATT&CK mappings are split correctly
Detection coverage analyst guardrails are preserved
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
└── attack_coverage_validation_results.json
```

# Analyst Guardrails

The project intentionally includes detection-program guardrails.

```text
Do not interpret detection count alone as strong coverage.
```

```text
Do not treat an unvalidated or experimental rule as
equivalent to a validated production detection.
```

```text
Do not assume multiple detections provide independent
coverage when they rely on the same telemetry and logic.
```

```text
Do not treat a MITRE ATT&CK mapping as proof that a
detection reliably identifies every implementation
of that technique.
```

```text
Do not classify a technique as fully covered solely
because one rule exists.
```

```text
Review false-positive behavior and analyst workload
when multiple detections overlap.
```

```text
Treat the coverage model as an engineering prioritization
aid rather than a universal measurement standard.
```

# Project Structure

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
│   └── coverage_expectations.json
└── output/
    ├── attack_coverage_results.json
    ├── technique_coverage.csv
    ├── tactic_coverage.csv
    ├── engineering_priorities.csv
    └── attack_coverage_validation_results.json
```

# Skills Demonstrated

```text
MITRE ATT&CK
Detection Engineering
Detection Coverage Analysis
Detection Gap Analysis
SOC Engineering
Security Analytics
Detection Program Assessment
Detection Validation
Detection Tuning
Data Source Analysis
Detection Redundancy Analysis
ATT&CK Technique Mapping
ATT&CK Tactic Mapping
Engineering Prioritization
Risk-Based Detection Planning
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## Detection count is not coverage quality

Two or three rules mapped to one technique do not automatically mean strong coverage.

Validation state, telemetry diversity, analytic diversity, and confidence all matter.

## Validation maturity matters

The Cloud Accounts example demonstrates that:

```text
2 detections
```

can still produce:

```text
LOW coverage
```

when one detection remains experimental and requires review.

## Detection gaps need prioritization

A missing Critical-priority technique should receive more attention than a missing Moderate-priority technique.

This turns ATT&CK coverage analysis into an engineering backlog rather than a simple checklist.

## Redundant detection can be good

Multiple detections may provide resilient layered coverage.

The correct question is not:

```text
Can we delete duplicate rules?
```

but:

```text
Do these analytics provide independent security value,
or do they only create duplicate analyst workload?
```

## ATT&CK mapping is not proof of detection quality

Mapping a rule to an ATT&CK technique documents intent.

It does not prove that the analytic detects every variation of that attacker behavior.

## Coverage should be measured continuously

As detections are:

```text
Added
Validated
Tuned
Retired
Replaced
```

coverage should be recalculated.

# Limitations

This project uses a synthetic detection catalog and custom educational coverage model.

It is not intended to represent a universal ATT&CK coverage methodology.

The model does not currently account for:

- Detection test frequency
- Production alert volumes
- Mean time to triage
- False-positive rates
- False-negative estimates
- Telemetry health
- Sensor outages
- Rule ownership
- Detection SLAs
- Detection version history
- ATT&CK technique prevalence
- Threat-intelligence relevance
- Organization-specific threat modeling

Future improvements could include:

- ATT&CK Navigator export
- Production detection ingestion
- Sigma metadata parsing
- Sentinel analytic-rule ingestion
- Wazuh rule ingestion
- Detection-as-code integration
- Threat-informed priority weighting
- Historical coverage trending
- Telemetry health scoring
- False-positive scoring
- Detection test dates
- Rule ownership tracking
- Dashboard visualization
- Detection engineering backlog generation

# Safety

All detection rules, systems, alerts, mappings, techniques, and security scenarios used in this project are synthetic or created for defensive training.

The project does not execute attacks, exploit systems, or interact with production infrastructure.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- analyzes 25 synthetic detections
- evaluates 25 priority ATT&CK techniques
- scores technique coverage
- calculates tactic coverage
- identifies 3 STRONG techniques
- identifies 15 MODERATE techniques
- identifies 1 LOW technique
- identifies 6 complete detection gaps
- assigns risk-based engineering priorities
- identifies 2 redundancy-review candidates
- evaluates detection validation maturity
- handles experimental detections
- handles multi-tactic ATT&CK mappings
- generates engineering recommendations
- exports JSON and CSV reports
- preserves detection-program guardrails
- validates all expected outcomes
- passes 12 of 12 validation checks
