# Microsoft Sentinel KQL Threat Hunting Lab

A hands-on cloud SIEM and threat-hunting project focused on using Kusto Query Language (KQL) to investigate synthetic Microsoft Sentinel-style security telemetry.

This project demonstrates how analysts can move from isolated security events to multi-source behavioral correlations involving identity, endpoint, privilege, and network activity.

## Project Workflow

Synthetic Sentinel-Style Logs  
↓  
KQL Threat Hunt  
↓  
Filtering and Summarization  
↓  
Cross-Source Correlation  
↓  
Behavioral Timeline  
↓  
Threat-Hunting Finding  
↓  
Analyst Investigation

## Data Sources

The lab uses four synthetic telemetry sources:

```text
sample-logs/
├── signin_logs.csv
├── process_events.csv
├── privileged_activity.csv
└── network_events.csv
```

These datasets model telemetry similar to:

- Microsoft Entra ID sign-in logs
- Windows process creation events
- Azure privileged-access activity
- Network security telemetry

All identities, systems, IP addresses, commands, and events are fictional or reserved for documentation and testing.

## Threat Hunts

The lab contains 10 KQL threat-hunting queries that progress from individual event searches to multi-source behavioral correlation.

### Hunt 01 — Repeated Failed Sign-ins

Identifies identities receiving three or more failed authentication attempts from the same source IP.

The synthetic dataset identified:

```text
finance.user@northstar.example
Source IP: 198.51.100.24
Failed attempts: 3
First failure: 12:17:41
Last failure: 12:18:13
```

KQL concepts practiced:

- `where`
- `summarize`
- `count()`
- `min()`
- `max()`
- `order by`

### Hunt 02 — Successful Sign-in After Repeated Failures

Correlates repeated authentication failures with a successful sign-in from the same identity and source IP within five minutes.

```text
3 failed attempts
        ↓
31 seconds
        ↓
Successful authentication
```

The query confirmed a successful sign-in for `finance.user@northstar.example` 31 seconds after the final failed attempt.

This pattern increases investigation priority but does not independently prove password guessing or credential theft.

### Hunt 03 — Dormant Account Activity

Identifies successful authentication by identities marked as dormant.

Synthetic result:

```text
Identity: dormant.contractor@northstar.example
Source IP: 203.0.113.55
Application: Microsoft 365
Conditional Access: notApplied
Device compliant: false
Account status: dormant
```

This creates a high-interest identity event because an account designated as dormant should not normally be generating new authentication activity.

### Hunt 04 — Suspicious PowerShell Activity

Searches Windows process telemetry for PowerShell containing higher-risk command-line characteristics such as:

```text
-EncodedCommand
-enc
-ExecutionPolicy Bypass
Invoke-WebRequest
DownloadString
```

The hunt identified activity associated with:

- `finance.user`
- `dormant.contractor`

Normal PowerShell activity such as `Get-Service` remained outside the suspicious result set.

### Hunt 05 — Dormant Sign-in to Suspicious PowerShell

Correlates a successful dormant-account sign-in with suspicious PowerShell activity by the same identity.

```text
12:31:07
Dormant contractor sign-in
        ↓
71 seconds
        ↓
12:32:18
Encoded PowerShell execution
```

This demonstrates cross-source correlation between identity and endpoint telemetry.

### Hunt 06 — Ungoverned Privileged Role Assignment

Searches privileged-access telemetry for successful role assignments or modifications that lack expected governance controls.

The hunt checks for missing:

- business justification
- change ticket
- incident ticket

The synthetic dataset identified two Contributor-related role changes involving the dormant contractor identity with no documented justification and `TicketNumber = NONE`.

### Hunt 07 — Dormant Account Multi-Stage Attack Chain

Correlates three stages of activity:

```text
Dormant account sign-in
        ↓
Encoded PowerShell
        ↓
Contributor role assignment
```

Synthetic sequence:

```text
12:31:07  Dormant contractor sign-in
12:32:18  Encoded PowerShell
12:33:04  Contributor role added
12:35:21  Contributor assignment modified
```

This hunt produced two correlation rows because two qualifying Contributor events occurred within the configured time window.

### Hunt 08 — Dormant Account Network Correlation

Extends the previous correlation with follow-on network activity.

```text
Identity sign-in
        ↓
Encoded PowerShell
        ↓
Contributor privilege
        ↓
Network communication
```

Observed activity included:

```text
12:33:29
Connection to internal Azure management gateway

12:36:12
Outbound connection to 203.0.113.91:8443
```

This hunt demonstrates correlation across four telemetry categories:

- identity
- endpoint
- privileged access
- network

### Hunt 09 — Finance Account Multi-Source Correlation

Reconstructs a separate investigation involving the Finance identity.

```text
12:17:41–12:18:13
Three failed sign-ins
        ↓
12:18:44
Successful sign-in
        ↓
12:19:11
whoami
        ↓
12:19:27
Encoded PowerShell
        ↓
12:20:14
Blocked SMB connection
        ↓
12:21:49
Outbound TCP/8443 connection
```

This hunt intentionally produced multiple correlation rows because several process events matched several later network events within the five-minute windows.

Expected result:

```text
11 correlation rows
```

This demonstrates an important SIEM concept:

> More joined rows do not necessarily represent more incidents.

Analysts must understand how query joins expand datasets before interpreting result counts.

### Hunt 10 — High-Priority Threat Hunting Summary

Combines the highest-interest findings into one analyst-oriented result set.

The summary includes:

- timestamp
- priority
- finding type
- identity
- device
- supporting evidence

Expected categories:

```text
Finance authentication finding:        1
Dormant multi-stage findings:          2
Suspicious PowerShell findings:        2
Privileged role findings:              2
High-interest network findings:        5
-----------------------------------------
Total expected rows:                  12
```

This provides a concise triage view while preserving access to the underlying events.

## Major Investigation Scenarios

### Finance Identity Scenario

The Finance investigation combined authentication, endpoint, and network telemetry.

Confirmed evidence:

- three authentication failures from the same external source
- successful authentication 31 seconds later
- identity and account discovery commands
- encoded PowerShell execution
- blocked SMB activity
- outbound connection to TCP/8443

Analyst assessment:

The sequence is consistent with a potentially compromised Finance identity followed by discovery and network activity.

The available telemetry does not establish:

- how credentials were obtained
- whether the SMB attempt represented malicious lateral movement
- whether another host was successfully compromised
- whether the TCP/8443 connection was command-and-control activity

### Dormant Contractor Scenario

The second scenario correlated activity from a dormant identity across four data sources.

```text
Dormant account sign-in
        ↓
Encoded PowerShell
        ↓
Contributor role assignment
        ↓
Internal management connection
        ↓
External TCP/8443 communication
```

This sequence substantially increases investigation priority because multiple individually suspicious events occurred under the same identity within minutes.

The correlation still does not independently establish malicious intent.

## Validation Methodology

Because this project does not use a live Microsoft Sentinel workspace, the KQL queries are not executed locally.

Instead, the project includes an independent Python validation harness:

```text
validate_hunts.py
```

The validator:

1. Loads the four synthetic CSV datasets.
2. Reconstructs the behavioral conditions represented by each hunt.
3. Loads the expected ground-truth findings.
4. Compares expected and actual row counts.
5. Validates key identity, timing, privilege, process, and network relationships.
6. Exports a structured JSON validation report.

Expected results are stored in:

```text
expected-results/
└── hunt_expectations.json
```

Generated validation results are stored in:

```text
output/
└── hunt_validation_results.json
```

## Validation Results

The final validation run produced:

```text
Hunts validated:   10
Hunts passed:      10
Hunts for review:  0
```

All expected row counts and core behavioral findings matched the synthetic ground truth.

This does not prove production KQL accuracy. It demonstrates that the synthetic source data contains the behaviors the designed queries are intended to identify.

## KQL Concepts Practiced

The project includes hands-on practice with:

```text
where
project
summarize
count()
min()
max()
let
join
extend
split()
datetime_diff()
isempty()
has_any()
in
in~
=~
union
order by
strcat()
iff()
```

## Project Structure

```text
sentinel-kql-lab/
├── README.md
├── validate_hunts.py
├── sample-logs/
│   ├── signin_logs.csv
│   ├── process_events.csv
│   ├── privileged_activity.csv
│   └── network_events.csv
├── queries/
│   ├── 01_repeated_failed_signins.kql
│   ├── 02_success_after_failed_signins.kql
│   ├── 03_dormant_account_activity.kql
│   ├── 04_suspicious_powershell_activity.kql
│   ├── 05_dormant_signin_to_powershell.kql
│   ├── 06_suspicious_privileged_role_assignment.kql
│   ├── 07_dormant_account_attack_chain.kql
│   ├── 08_dormant_account_network_correlation.kql
│   ├── 09_finance_account_correlation.kql
│   └── 10_high_priority_hunting_summary.kql
├── expected-results/
│   └── hunt_expectations.json
└── output/
    └── hunt_validation_results.json
```

## Skills Demonstrated

- Microsoft Sentinel
- Kusto Query Language (KQL)
- SIEM Threat Hunting
- Microsoft Entra ID Security
- Authentication Analysis
- Windows Process Analysis
- PowerShell Detection
- Privileged Access Monitoring
- Network Security Monitoring
- Behavioral Correlation
- Multi-Source Log Analysis
- Detection Logic
- Identity Normalization
- Incident Investigation
- Python Validation
- JSON / CSV Analysis

## Threat-Hunting Lessons

This project reinforced several important concepts:

- One event rarely tells the complete security story.
- Identity, endpoint, privilege, and network telemetry become significantly more useful when correlated.
- Repeated authentication failures followed by success warrant investigation but do not automatically prove credential compromise.
- Dormant identities should not normally generate new authentication and privilege activity.
- Encoded PowerShell is suspicious but can have legitimate uses.
- Privileged role changes should have appropriate governance context.
- KQL joins can multiply records and must be interpreted carefully.
- Detection logic should be validated against known data.
- Threat hunters must separate confirmed evidence from analyst hypotheses.

## Limitations

This project uses synthetic Microsoft Sentinel-style telemetry.

The KQL queries were designed for Sentinel-style data but were not executed against a live Microsoft Sentinel workspace.

The Python validator confirms the presence of the intended behaviors in the synthetic datasets; it is not a KQL execution engine.

Future improvements could include:

- testing queries in a live Microsoft Sentinel workspace
- Microsoft Defender integration
- additional Entra ID telemetry
- threat-intelligence enrichment
- reusable KQL functions
- watchlists
- scheduled analytics rules
- Sentinel workbooks
- incident creation
- SOAR playbooks
- larger synthetic datasets

## Safety

All identities, systems, IP addresses, commands, applications, and security events used in this project are fictional or reserved for documentation and testing purposes.

No production Microsoft Sentinel workspace, credentials, organizational data, or live malicious infrastructure are included.

## Project Status

✅ **Functional**

The current version successfully:

- models four Sentinel-style security data sources
- implements 10 KQL threat hunts
- correlates identity, endpoint, privilege, and network telemetry
- reconstructs two multi-stage investigation scenarios
- validates all 10 hunts against synthetic ground truth
- produces a structured validation report
