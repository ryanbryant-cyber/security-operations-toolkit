# Microsoft Entra ID Cloud Compromise Investigation & Response Lab

A hands-on cloud incident-response project focused on investigating synthetic Microsoft Entra ID and Azure-style security telemetry after suspicious cloud activity has already occurred.

The project demonstrates how a security analyst can correlate identity, authentication, Conditional Access, privileged-access, and cloud-resource activity to determine what happened, assess scope, and recommend containment actions.

## Project Objective

Cloud incident response requires more than identifying a suspicious sign-in.

Analysts must determine:

- Which identity was affected
- Where the authentication originated
- Whether authentication behavior changed
- Whether Conditional Access controls were satisfied
- Whether privileges changed
- Which cloud resources were accessed
- Whether additional services were involved
- What evidence supports the incident timeline
- What containment actions are appropriate

This project will demonstrate how to:

- Analyze Microsoft Entra ID-style sign-in telemetry
- Correlate repeated authentication failures with later success
- Review Conditional Access results
- Identify unusual source changes
- Analyze privileged-role activity
- Review Azure resource access
- Reconstruct a cloud compromise timeline
- Distinguish confirmed evidence from analyst hypotheses
- Recommend session and identity containment
- Generate structured CSV and JSON reports
- Validate findings against synthetic ground truth

## Investigation Scenario

The synthetic investigation will follow a Finance identity through activity such as:

```text
Repeated Sign-in Failures
        ↓
Successful Authentication
        ↓
Unfamiliar External Source
        ↓
Conditional Access Concern
        ↓
Privileged Role Activity
        ↓
Sensitive Cloud Resource Access
        ↓
Incident Correlation
        ↓
Containment Recommendation
```

## Planned Evidence Sources

```text
Entra ID Sign-in Logs
Conditional Access Events
Privileged Identity Activity
Azure Resource Activity
Microsoft 365 Activity
Cloud Audit Events
```

## Planned Workflow

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
Incident Timeline
        ↓
Scope Assessment
        ↓
Containment Planning
        ↓
Validation
```

## Planned Project Structure

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
└── output/
```

## Skills Demonstrated

- Microsoft Entra ID
- Cloud Incident Response
- Azure Security
- Identity Security
- Conditional Access Analysis
- Privileged Access Monitoring
- Cloud Audit Analysis
- Incident Reconstruction
- Scope Assessment
- Incident Containment
- Behavioral Correlation
- Python
- CSV Processing
- JSON Reporting
- Validation Testing
- Analyst Reporting

## Safety

All identities, cloud resources, IP addresses, sign-ins, role assignments, and cloud events used in this project are synthetic.

The project does not interact with live Microsoft tenants, production Azure resources, real credentials, or real user accounts.

## Project Status

🚧 **In Development**
