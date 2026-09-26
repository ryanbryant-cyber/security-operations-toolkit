# Session Hijacking & DDoS Detection and Containment Lab

A defensive security-operations project focused on detecting suspected session hijacking and distributed denial-of-service activity using synthetic authentication, session, and web-traffic telemetry.

The project demonstrates how analysts can establish normal behavior, identify behavioral anomalies, correlate multiple indicators, classify findings by severity, and recommend containment actions without generating live attack traffic.

## Project Objective

Session hijacking and DDoS attacks produce very different technical behavior, but both require analysts to evaluate activity over time rather than relying on isolated events.

This project demonstrates how to:

- Establish normal session and traffic baselines
- Detect session reuse from unexpected origins
- Identify source-IP and user-agent changes
- Detect missing MFA context
- Correlate sensitive activity with anomalous sessions
- Identify concurrent session reuse
- Establish normal HTTP request volume
- Detect large traffic-volume deviations
- Identify distributed source activity
- Measure endpoint concentration
- Identify HTTP error increases
- Detect service-response degradation
- Assign risk scores and severity
- Recommend containment actions
- Generate structured investigation reports
- Validate findings against synthetic ground truth

## Project Workflow

```text
Synthetic Security Telemetry
        ↓
Establish Normal Behavior
        ↓
Behavioral Detection
        ↓
Cross-Event Correlation
        ↓
Risk Scoring
        ↓
Security Finding
        ↓
Severity Classification
        ↓
Containment Recommendation
        ↓
CSV / JSON Reporting
        ↓
Validation
```

# Scenario 1 — Suspected Session Hijacking

The first investigation models an authenticated Finance user whose session identifier later appears from a different source IP and user agent.

## Normal Session Context

The legitimate session begins with:

```text
User:        finance.user
Session ID:  SESSION-FIN-8842
Source IP:   10.10.20.17
User Agent:  Chrome-Windows
MFA:         Verified
```

The user accesses normal Finance resources from the original workstation.

## Anomalous Session Activity

The same session identifier later appears from:

```text
Source IP:   198.51.100.88
User Agent:  Firefox-Linux
MFA:         Not reverified
```

The anomalous origin performs activity involving:

```text
/finance/export-payments
/account/security
/finance/vendor-bank-details
```

The original workstation also continues using the same session identifier during the anomalous activity window.

## Session Hijacking Indicators

The detection engine identified six behavioral indicators:

```text
Source IP change
User-agent change
MFA not verified on anomalous origin
Rapid origin change
Sensitive action from anomalous origin
Concurrent origin reuse
```

The combined evidence produced:

```text
Finding ID:       HIJACK-FIN-8842
User:             finance.user
Risk Score:       100
Severity:         CRITICAL
Indicator Count:  6
```

The telemetry is consistent with suspected session hijacking.

However, the evidence does not establish how the session identifier was obtained.

## Session Containment Recommendations

Recommended containment actions include:

- Revoke the affected session identifier
- Require reauthentication with MFA
- Invalidate active authentication tokens where supported
- Review sensitive actions performed during the anomalous session
- Review recent authentication activity
- Temporarily restrict the account if additional compromise indicators are discovered

# Scenario 2 — Suspected DDoS Activity

The second investigation analyzes synthetic HTTP traffic against a public-facing service.

## Normal Traffic Baseline

The first three minutes were used to establish normal activity:

```text
13:20 → 91 requests/minute
13:21 → 82 requests/minute
13:22 → 87 requests/minute
```

Calculated baseline:

```text
86.67 requests/minute
```

Normal response times were approximately:

```text
118–149 ms
```

## Traffic Surge

At 13:23:

```text
Observed traffic: 2040 requests/minute
Baseline:         86.67 requests/minute
Increase:         23.54x
Distinct sources: 5
Target endpoint:  /login
Severity:         CRITICAL
```

At 13:24:

```text
Observed traffic: 2260 requests/minute
Baseline:         86.67 requests/minute
Increase:         26.08x
Distinct sources: 5
Target endpoint:  /login
Severity:         CRITICAL
```

## DDoS Behavioral Indicators

Both surge periods triggered six indicators:

```text
Traffic volume spike
Critical traffic volume spike
Distributed source activity
Endpoint concentration
Error response increase
Response-time degradation
```

The web service also showed:

```text
HTTP 429 Too Many Requests
HTTP 503 Service Unavailable
```

and substantial latency increases.

The combination of traffic volume, distributed sources, endpoint concentration, errors, and response degradation supports a suspected distributed denial-of-service event.

The telemetry alone does not establish the intent or ownership of every participating source.

## DDoS Containment Recommendations

Recommended defensive actions include:

- Apply or tighten rate limiting
- Use WAF or reverse-proxy controls to challenge abusive traffic
- Coordinate with hosting or network providers for upstream filtering
- Preserve network, web, and application logs
- Monitor service health and latency during containment
- Avoid overly broad blocking until legitimate traffic impact is understood

# Detection Rules

Detection logic is stored in:

```text
rules/
└── detection_rules.json
```

## Session Risk Model

Session findings consider:

```text
Source IP change                         +20
User-agent change                        +15
MFA not verified                         +10
Rapid origin change                      +15
Sensitive action from anomalous origin   +25
Concurrent origin reuse                  +20
```

Severity thresholds:

```text
80+   → CRITICAL
60–79 → HIGH
30–59 → MODERATE
0–29  → LOW
```

No single indicator automatically determines compromise.

The engine increases confidence when several behaviors occur together.

## DDoS Detection Model

The DDoS detector evaluates:

```text
Traffic volume
Baseline multiplier
Distributed source count
Endpoint concentration
HTTP error ratio
Response latency
```

Important thresholds include:

```text
Traffic >10x baseline        → Volume spike
Traffic >20x baseline        → Critical volume spike
5+ sources                   → Distributed activity
80%+ traffic to one endpoint → Endpoint concentration
50%+ monitored errors        → Error degradation
750+ ms response time        → Latency degradation
```

Risk weights:

```text
Traffic volume spike          +30
Critical volume spike         +15
Distributed source activity   +15
Endpoint concentration        +15
Error response increase       +15
Response-time degradation     +10
```

# Analysis Engine

The main detection script is:

```text
analyze_activity.py
```

The analyzer:

1. Loads session telemetry.
2. Loads web-traffic telemetry.
3. Loads the detection rules.
4. Groups activity by session identifier.
5. Establishes each session's original source context.
6. Detects origin and user-agent changes.
7. Detects rapid transitions.
8. Identifies anomalous sensitive actions.
9. Detects concurrent session reuse.
10. Calculates a session risk score.
11. Establishes the HTTP traffic baseline.
12. Calculates request-volume multipliers.
13. Measures source distribution.
14. Measures endpoint concentration.
15. Calculates error ratios.
16. Calculates weighted response latency.
17. Assigns risk scores and severity.
18. Attaches containment recommendations.
19. Generates CSV and JSON reports.

# Analysis Results

Running:

```bash
python3 analyze_activity.py
```

produced:

```text
SESSION ANALYSIS

HIJACK-FIN-8842
finance.user
Score: 100
Severity: CRITICAL
Indicators: 6
```

DDoS baseline:

```text
Baseline minute totals: 91, 82, 87
Average baseline: 86.67 requests/minute
```

DDoS findings:

```text
DDOS-2026-09-26T1323
2040 req/min
23.54x baseline
Score: 100
CRITICAL
```

```text
DDOS-2026-09-26T1324
2260 req/min
26.08x baseline
Score: 100
CRITICAL
```

Overall:

```text
Session findings: 1
DDoS findings:    2
Total findings:   3
```

# Generated Reports

The analyzer produces:

```text
output/
├── activity_analysis_results.json
└── security_findings.csv
```

The JSON report preserves detailed behavioral evidence, calculated metrics, severity, analyst assessment, and containment recommendations.

The CSV report provides a concise analyst-facing list of findings.

# Validation

The project includes an independent validator:

```text
validate_detections.py
```

Expected results are stored in:

```text
expected-results/
└── detection_expectations.json
```

The validator checks:

- Expected finding count
- Session finding identity
- Session risk score
- Session severity
- Session indicator count
- Anomalous source IP
- Anomalous user agent
- DDoS request volume
- DDoS baseline multiplier
- Distributed source count
- Target endpoint
- DDoS risk score
- DDoS severity
- Baseline calculation
- Required behavioral indicators
- Containment recommendations

# Behavioral Validation

The validation harness confirms that:

```text
All six session indicators are present
```

```text
finance.user is the only session-hijacking finding
```

```text
DDoS baseline equals 86.67 requests/minute
```

```text
Both DDoS findings contain all six behavioral indicators
```

```text
Both DDoS findings exceed 20x baseline
```

```text
Containment guidance exists for both incident types
```

# Validation Results

The completed validation produced:

```text
Summary check:  PASS
Checks run:     10
Checks passed:  10
Checks failed:  0
Overall:        PASS
```

All expected findings and behavioral relationships matched the synthetic ground truth.

The validation report is stored in:

```text
output/
└── activity_validation_results.json
```

# Project Structure

```text
session-ddos-detection-lab/
├── README.md
├── analyze_activity.py
├── validate_detections.py
├── sample-data/
│   ├── session_events.csv
│   └── web_traffic.csv
├── rules/
│   └── detection_rules.json
├── expected-results/
│   └── detection_expectations.json
└── output/
    ├── activity_analysis_results.json
    ├── security_findings.csv
    └── activity_validation_results.json
```

# Skills Demonstrated

```text
Session Security
Session Hijacking Detection
Web Log Analysis
Authentication Analysis
Behavioral Detection
Behavioral Correlation
DDoS Detection
Traffic Baselining
HTTP Traffic Analysis
Rate-Limit Analysis
Availability Monitoring
Incident Triage
Incident Containment
Risk Scoring
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## Session anomalies require context

A source-IP change by itself does not prove hijacking.

VPN changes, mobile networks, and legitimate routing changes can create similar behavior.

The Finance finding became higher confidence because multiple indicators occurred together.

## Sensitive activity increases investigative priority

The anomalous session did not only browse normal pages.

It accessed:

```text
Payment exports
Account security
Vendor banking details
```

That materially increased the investigation priority.

## Concurrent session reuse is a strong behavioral signal

The original workstation continued using the same session identifier while another origin used it.

This is more concerning than a simple one-time IP change.

## Traffic spikes alone do not prove DDoS

Legitimate events can produce sudden traffic increases.

Confidence increased because the lab also observed:

```text
Multiple sources
Endpoint concentration
429 responses
503 responses
Latency degradation
```

## Baselines make anomalies measurable

Rather than labeling traffic as "high," the detector calculated:

```text
23.54x baseline
26.08x baseline
```

This creates more defensible findings.

## Containment should preserve legitimate access where possible

Broad blocking can affect legitimate users.

Rate limiting, WAF controls, upstream filtering, and careful monitoring can provide more controlled mitigation.

# Limitations

This project uses synthetic telemetry and custom educational detection thresholds.

It does not perform live session interception, token theft, credential capture, or denial-of-service traffic generation.

The project does not automatically modify production firewalls, revoke real authentication tokens, or block network sources.

Future improvements could include:

- Microsoft Entra session telemetry
- Web server access-log ingestion
- Reverse-proxy log ingestion
- GeoIP enrichment
- User behavioral baselines
- Session-device fingerprinting
- JA3 / TLS fingerprint analysis
- SIEM integration
- WAF telemetry
- NetFlow integration
- Automated incident creation
- SOAR containment workflows
- Cloud-based DDoS telemetry
- Dashboard visualization

# Safety

All users, session identifiers, IP addresses, endpoints, systems, and traffic patterns used in this project are synthetic or documentation-reserved.

No live session hijacking or denial-of-service attack was performed.

The project is limited to defensive detection, analysis, validation, and containment planning.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- analyzes synthetic session telemetry
- analyzes synthetic HTTP traffic
- detects one suspected session-hijacking scenario
- correlates six session behavioral indicators
- establishes a normal traffic baseline
- detects two DDoS traffic surges
- measures traffic at 23.54x and 26.08x baseline
- correlates six DDoS behavioral indicators
- assigns CRITICAL severity to all three findings
- generates containment recommendations
- exports CSV and JSON reports
- validates expected results
- passes 10 of 10 validation checks
