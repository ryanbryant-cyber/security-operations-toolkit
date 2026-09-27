# Active Directory & Kerberos Authentication Detection Lab

A hands-on detection-engineering and identity-security project focused on analyzing synthetic Windows and Active Directory authentication telemetry.

The project demonstrates how a security analyst can distinguish routine authentication failures from higher-value behavioral patterns involving Windows logon failures, Kerberos ticket activity, pre-authentication failures, and successful authentication following repeated failures.

## Project Objective

Authentication environments naturally generate noise.

A single failed logon does not necessarily indicate malicious activity. Mistyped passwords, expired credentials, service accounts, stale sessions, and Kerberos pre-authentication behavior can all generate failed-authentication events.

This project will demonstrate how to:

- Analyze Windows authentication events
- Interpret Event ID 4625 failed logons
- Analyze Kerberos TGT requests using Event ID 4768
- Analyze Kerberos service ticket activity using Event ID 4769
- Investigate Kerberos pre-authentication failures using Event ID 4771
- Establish normal authentication behavior
- Identify repeated authentication failures
- Correlate failures with successful authentication
- Distinguish noisy authentication activity from higher-risk behavior
- Apply detection tuning
- Produce analyst-readable findings
- Generate structured CSV and JSON reports
- Validate detection results against synthetic ground truth

## Planned Detection Scenarios

The lab will include several authentication behaviors:

### Normal User Mistyped Password

A legitimate user generates a small number of failed logons before successfully authenticating.

Expected outcome:

```text
LOW / BASELINE AUTHENTICATION NOISE
```

### Kerberos Pre-Authentication Noise

A domain user or service generates repeated Event ID 4771 events associated with routine credential or ticket behavior.

Expected outcome:

```text
REVIEW / TUNED AUTHENTICATION NOISE
```

### Repeated Failures Followed by Success

An identity receives multiple failed authentication events from the same source followed by a successful authentication within a short time window.

Expected outcome:

```text
HIGHER-PRIORITY AUTHENTICATION FINDING
```

### Suspicious Kerberos Service-Ticket Activity

A synthetic identity requests multiple service tickets in a short period against higher-value services.

Expected outcome:

```text
SUSPICIOUS KERBEROS ACTIVITY
```

## Event IDs

The project will use synthetic events modeled after:

```text
4625 — An account failed to log on
4768 — A Kerberos authentication ticket (TGT) was requested
4769 — A Kerberos service ticket was requested
4771 — Kerberos pre-authentication failed
```

## Project Workflow

```text
Synthetic Windows / AD Telemetry
        ↓
Authentication Event Parsing
        ↓
Baseline Behavior
        ↓
Failure Detection
        ↓
Kerberos Analysis
        ↓
Cross-Event Correlation
        ↓
Detection Tuning
        ↓
Risk Classification
        ↓
Analyst Finding
        ↓
Validation
```

## Planned Project Structure

```text
ad-kerberos-detection-lab/
├── README.md
├── analyze_authentication.py
├── validate_detections.py
├── sample-data/
│   ├── windows_logons.csv
│   └── kerberos_events.csv
├── rules/
│   └── detection_rules.json
├── expected-results/
└── output/
```

## Skills Demonstrated

- Active Directory Security
- Kerberos Authentication
- Windows Event Analysis
- Authentication Detection
- Event ID 4625 Analysis
- Event ID 4768 Analysis
- Event ID 4769 Analysis
- Event ID 4771 Analysis
- Detection Engineering
- False-Positive Tuning
- Behavioral Correlation
- Identity Security
- SOC Triage
- Python
- CSV Processing
- JSON Reporting
- Validation Testing
- Analyst Reporting

## Safety

All users, systems, domains, IP addresses, authentication events, and Kerberos activity used in this project are synthetic.

The project does not perform password guessing, credential theft, Kerberos abuse, or attacks against live Active Directory infrastructure.

## Project Status

🚧 **In Development**
