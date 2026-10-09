# DNS Tunneling Detection & Triage Lab

A defensive network-security project focused on identifying DNS behavior that may indicate covert tunneling or command-and-control activity.

The project demonstrates how a security analyst can compare normal DNS behavior against higher-interest patterns involving long subdomains, frequent queries, TXT records, high subdomain diversity, and repeated communication with a single parent domain.

## Project Objective

DNS is required for normal network operations, which makes it useful for both legitimate applications and attackers attempting to hide communications inside DNS traffic.

A single unusual DNS query does not prove tunneling.

This project will demonstrate how to:

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

## Planned Investigation Scenario

The synthetic dataset will contain:

```text
Normal Workstation
        ↓
Routine DNS Queries
        ↓
Low Query Frequency
        ↓
Expected Domains
```

and:

```text
Higher-Interest Workstation
        ↓
Repeated Queries to One Parent Domain
        ↓
Long Changing Subdomains
        ↓
TXT Requests
        ↓
High Unique-Subdomain Ratio
        ↓
Possible DNS Tunneling Finding
```

## Project Workflow

```text
Synthetic DNS Telemetry
        ↓
Query Normalization
        ↓
Behavioral Baseline
        ↓
Query Length Analysis
        ↓
Frequency Analysis
        ↓
TXT Record Review
        ↓
Subdomain Diversity
        ↓
Behavioral Correlation
        ↓
Risk Scoring
        ↓
Analyst Finding
        ↓
Validation
```

## Planned Project Structure

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
└── output/
```

## Skills Demonstrated

- DNS Security
- DNS Tunneling Detection
- Network Security Monitoring
- Behavioral Detection
- Command-and-Control Analysis
- DNS Query Analysis
- SOC Triage
- Network Detection Engineering
- Python
- CSV Processing
- JSON Reporting
- Security Automation
- Validation Testing
- Analyst Reporting

## Safety

All DNS queries, domains, systems, IP addresses, and network activity used in this project are synthetic or documentation-reserved.

The project does not establish live DNS tunnels, transmit real data through DNS, or communicate with malicious infrastructure.

## Project Status

🚧 **In Development**
