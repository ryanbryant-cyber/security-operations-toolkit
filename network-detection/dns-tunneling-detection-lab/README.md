# DNS Tunneling Detection & Triage Lab

A defensive network-security project focused on identifying DNS behavior that may indicate covert tunneling or command-and-control activity.

The project demonstrates how a security analyst can compare normal DNS behavior against higher-interest patterns involving long subdomains, frequent queries, TXT records, high subdomain diversity, and encoded-looking labels without overstating what DNS telemetry alone can prove.

## Project Objective

DNS is required for normal network operations, which makes it useful for both legitimate applications and attackers attempting to hide communications inside DNS traffic.

A single unusual DNS query does not prove tunneling.

This project demonstrates how to:

- Analyze synthetic DNS telemetry
- Establish normal DNS behavior
- Measure DNS query frequency
- Identify unusually long subdomains
- Review TXT record activity
- Measure unique-subdomain ratios
- Detect encoded-looking query patterns
- Correlate multiple DNS behaviors
- Assign investigation priority
- Generate analyst-readable findings
- Produce structured CSV and JSON reports
- Validate detections against synthetic ground truth

## Investigation Workflow

```text
Synthetic DNS Telemetry
        ↓
Query Normalization
        ↓
Behavioral Baseline
        ↓
Query Frequency Analysis
        ↓
Subdomain Length Analysis
        ↓
TXT Record Review
        ↓
Unique-Subdomain Analysis
        ↓
Encoded-Pattern Review
        ↓
Behavioral Correlation
        ↓
Risk Scoring
        ↓
Analyst Finding
        ↓
Validation
```

# Synthetic DNS Dataset

The project analyzes:

```text
29 synthetic DNS events
```

stored in:

```text
sample-data/
└── dns_queries.csv
```

The dataset contains traffic from:

```text
NFG-HR-WS03
NFG-FIN-WS07
NFG-MKT-WS08
```

and includes both routine DNS behavior and one intentionally higher-interest sequence.

# Normal DNS Behavior

The dataset includes routine lookups such as:

```text
login.microsoftonline.com
graph.microsoft.com
updates.microsoft.com
portal.office.com
time.windows.com
intranet.northstar.example
files.northstar.example
```

Normal behavior is characterized by:

```text
Low query frequency
Predictable hostnames
Common A record requests
Expected internal and Microsoft domains
Low subdomain diversity
```

These queries remain below the configured investigation thresholds.

# Higher-Interest Finance Activity

The primary finding involves:

```text
Host:
NFG-FIN-WS07

Source IP:
10.10.20.17

Parent Domain:
tunnel-demo.example
```

The host generated:

```text
16 DNS queries
```

within approximately one minute.

The observed subdomains resemble:

```text
a8f31d92b741c0e54f2a.tunnel-demo.example
b90e41c72f64aa130d9b.tunnel-demo.example
c71a80f924bc317e04d5.tunnel-demo.example
```

The labels:

```text
change repeatedly
are approximately 20 characters long
consist primarily of hexadecimal-looking characters
```

The sequence also includes multiple:

```text
TXT queries
```

# Behavioral Indicators

The detection engine identified six independent DNS behaviors.

## High Query Frequency

The Finance workstation generated:

```text
16 queries
```

with an average interval of:

```text
4.0 seconds
```

This exceeded the configured high-frequency threshold.

## Long Subdomain Labels

Most observed labels were at least:

```text
18 characters
```

long.

Long labels can occur in legitimate applications, so this indicator is not treated as malicious by itself.

## High Unique-Subdomain Ratio

The suspicious DNS sequence produced:

```text
100% unique subdomains
```

across the analyzed parent domain.

This indicates that nearly every DNS request used a different label.

## Multiple TXT Queries

The sequence contained:

```text
5 TXT queries
```

to the same parent domain.

TXT records can be legitimate, but repeated TXT activity adds investigative value when combined with other behaviors.

## Encoded-Looking Subdomains

The analyzer determined that:

```text
100%
```

of the suspicious subdomain labels matched the configured hexadecimal-looking pattern.

This provides a useful behavioral signal but does not prove that data was encoded or exfiltrated.

## Single Parent-Domain Concentration

All 16 higher-interest queries were concentrated on:

```text
tunnel-demo.example
```

This increased confidence that the behavior represented a distinct DNS communication pattern rather than normal browsing.

# Risk Scoring Model

Detection logic is stored in:

```text
rules/
└── dns_detection_rules.json
```

The scoring model uses:

```text
High query frequency               +20
Long subdomain labels              +15
High unique-subdomain ratio        +20
Multiple TXT queries               +15
Encoded-looking subdomains         +20
Single parent-domain concentration +10
```

Maximum score:

```text
100
```

# Priority Thresholds

```text
80–100 → CRITICAL
60–79  → HIGH
30–59  → MODERATE
0–29   → LOW
```

The score represents investigation priority within this custom educational model.

It does not represent a probability that DNS tunneling occurred.

# Analysis Engine

The primary script is:

```text
analyze_dns.py
```

The analyzer:

1. Loads synthetic DNS telemetry.
2. Loads the behavioral detection rules.
3. Groups events by source host, source IP, and parent domain.
4. Extracts subdomain labels.
5. Measures query volume.
6. Measures average query timing.
7. Counts TXT queries.
8. Measures unique-subdomain ratios.
9. Measures long-label frequency.
10. Detects hexadecimal-looking labels.
11. Calculates a risk score.
12. Assigns investigation priority.
13. Separates LOW-priority baseline traffic from analyst findings.
14. Generates response recommendations.
15. Produces structured CSV and JSON reports.

# Analysis Results

Running:

```bash
python3 analyze_dns.py
```

produced:

```text
DNS events:              29
Hosts analyzed:           3
Parent domains analyzed:  7
Behavior groups:         10
Findings:                 1
```

The primary finding was:

```text
Finding ID:
DNS-001

Finding Type:
Possible DNS Tunneling Activity

Host:
NFG-FIN-WS07

Source IP:
10.10.20.17

Parent Domain:
tunnel-demo.example

Queries:
16

TXT Queries:
5

Unique Subdomains:
100%

Encoded-Looking Labels:
100%

Average Query Interval:
4.0 seconds

Indicators:
6

Risk Score:
100

Priority:
CRITICAL
```

# Analyst Assessment

The correlated DNS behavior is consistent with a pattern that warrants investigation for possible DNS tunneling or covert communications.

The evidence includes:

```text
High-frequency DNS requests
Long changing subdomains
High subdomain diversity
TXT record usage
Hexadecimal-looking labels
Concentration on one parent domain
```

However, DNS telemetry alone does not establish:

```text
Command-and-control confirmed
Data exfiltration confirmed
Payload content
Transferred data contents
Attacker identity
Compromise mechanism
```

The finding therefore remains:

```text
Possible DNS Tunneling Activity
```

rather than a confirmed tunneling event.

# Normal Traffic Suppression

Only one analyst finding was generated.

Normal traffic from:

```text
NFG-HR-WS03
NFG-MKT-WS08
```

did not trigger higher-priority findings.

Normal Microsoft, Windows, Office, internal Northstar, and example.net queries remained in the baseline analysis.

This demonstrates an important detection-engineering principle:

> Useful detection logic should identify unusual behavior without promoting routine DNS activity into unnecessary analyst alerts.

# Recommended Analyst Actions

For a CRITICAL-priority finding, the project recommends:

```text
Preserve DNS resolver and endpoint telemetry
Review the affected host for suspicious processes
Investigate the parent domain using approved threat-intelligence sources
Correlate DNS events with EDR, proxy, and firewall telemetry
Review related network connections
Consider host restriction if additional compromise evidence is confirmed
Escalate to SOC Tier 2 or Incident Response
```

The tool does not automatically block the domain or isolate the workstation.

Containment decisions remain analyst-controlled.

# Generated Reports

The analyzer produces:

```text
output/
├── dns_detection_results.json
└── dns_detection_summary.csv
```

## JSON Report

The JSON output preserves:

```text
Analysis summary
Behavior groups
DNS metrics
Risk indicators
Risk score
Priority
Response recommendations
Analyst assessment
Analyst guardrails
```

## CSV Report

The CSV output provides a concise analyst-facing finding containing:

```text
Finding ID
Finding Type
Host
Source IP
Parent Domain
Query Count
TXT Query Count
Unique-Subdomain Ratio
Encoded-Subdomain Ratio
Average Query Interval
Risk Score
Priority
Indicator Count
Analyst Assessment
```

# Validation

The project includes an independent validation script:

```text
validate_detection.py
```

Expected ground truth is stored in:

```text
expected-results/
└── dns_detection_expectations.json
```

The validator checks both technical output and analyst-facing behavior.

# Validation Checks

The completed validation confirms:

```text
DNS analysis summary
Primary DNS tunneling finding
All six behavioral indicators
Multiple TXT query behavior
Unique and encoded subdomain behavior
Normal peer hosts remain out of the analyst queue
Only the higher-interest parent domain becomes a finding
Analyst assessment preserves uncertainty
Analyst guardrails remain present
Correlated behavior reaches CRITICAL priority
```

Final validation:

```text
Checks run:     10
Checks passed:  10
Checks failed:  0
Overall:        PASS
```

The validation report is stored in:

```text
output/
└── dns_detection_validation_results.json
```

# Analyst Guardrails

The project explicitly preserves several detection guardrails.

```text
Do not classify long DNS queries as tunneling
without additional behavioral evidence.
```

```text
Do not classify TXT record usage as malicious
by itself.
```

```text
Do not assume high subdomain diversity is malicious
because legitimate cloud and security applications
may generate changing hostnames.
```

```text
Do not classify hexadecimal-looking labels as encoded
exfiltration without supporting endpoint or network evidence.
```

```text
Treat the final score as investigation priority rather
than proof of command-and-control or data exfiltration.
```

```text
Distinguish observed DNS behavior from analyst hypotheses.
```

# Project Structure

```text
dns-tunneling-detection-lab/
├── README.md
├── analyze_dns.py
├── validate_detection.py
├── sample-data/
│   └── dns_queries.csv
├── rules/
│   └── dns_detection_rules.json
├── expected-results/
│   └── dns_detection_expectations.json
└── output/
    ├── dns_detection_results.json
    ├── dns_detection_summary.csv
    └── dns_detection_validation_results.json
```

# Skills Demonstrated

```text
DNS Security
DNS Tunneling Detection
Network Security Monitoring
Behavioral Detection
Command-and-Control Analysis
DNS Query Analysis
TXT Record Analysis
Subdomain Analysis
Network Detection Engineering
SOC Triage
Risk Scoring
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## One unusual DNS query is not enough

Long queries, TXT records, or changing subdomains can appear in legitimate software.

Confidence increases when multiple behaviors appear together.

## Query timing provides useful context

The suspicious sequence averaged:

```text
4 seconds between DNS queries
```

which differed significantly from the normal peer traffic.

## Unique-subdomain behavior can reveal automation

A 100% unique-subdomain ratio suggests generated or automated query behavior.

That remains an investigation signal rather than proof of malicious intent.

## TXT traffic should be interpreted carefully

TXT records support many legitimate technologies.

Repeated TXT activity becomes more meaningful when combined with frequency, length, and diversity anomalies.

## Encoded-looking data requires corroboration

Hexadecimal-looking labels may suggest encoded content.

DNS telemetry alone cannot determine the original information represented by those characters.

## Peer comparison helps reduce noise

Normal HR and Marketing workstations provided baseline context and did not become analyst findings.

# Limitations

This project uses synthetic DNS telemetry and a custom educational scoring model.

It does not establish a real DNS tunnel.

The project does not:

- Send real data through DNS
- Execute tunneling software
- Contact malicious infrastructure
- Resolve real attacker-controlled domains
- Decode actual exfiltrated information
- Prove command-and-control
- Prove data exfiltration

Future improvements could include:

- Real PCAP DNS parsing
- Zeek DNS log ingestion
- Suricata DNS telemetry
- Passive DNS enrichment
- Domain-age enrichment
- Shannon entropy scoring
- NXDOMAIN analysis
- DNS response-size analysis
- Query/response timing analysis
- Base32/Base64 pattern detection
- Endpoint process correlation
- SIEM integration
- Threat-intelligence enrichment
- ATT&CK mapping
- Detection dashboarding

# Safety

All DNS queries, parent domains, IP addresses, workstations, and behaviors used in this project are synthetic or documentation-reserved.

No live DNS tunneling, malicious infrastructure, or real data transfer was used.

The project is limited to defensive detection, triage, correlation, reporting, and validation.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- analyzes 29 synthetic DNS events
- analyzes 3 source hosts
- evaluates 7 parent domains
- analyzes 10 host/domain behavior groups
- generates 1 analyst finding
- detects 16 higher-interest DNS queries
- identifies 5 TXT requests
- identifies a 100% unique-subdomain ratio
- identifies a 100% encoded-looking subdomain ratio
- measures a 4.0-second average query interval
- correlates 6 DNS behavioral indicators
- assigns a CRITICAL investigation priority
- keeps normal peer traffic out of the analyst queue
- produces JSON and CSV findings
- preserves evidentiary uncertainty
- validates all expected results
- passes 10 of 10 validation checks
