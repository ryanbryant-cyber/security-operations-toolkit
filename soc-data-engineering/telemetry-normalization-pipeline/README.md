# SOC Telemetry Normalization & Data Quality Pipeline

A hands-on SOC engineering project focused on transforming security telemetry from multiple products into a consistent analyst-ready schema.

The project demonstrates how security teams can normalize heterogeneous log formats, validate required fields, identify malformed records, detect duplicates, measure telemetry quality, and produce structured datasets suitable for SIEM analysis and detection engineering.

## Project Objective

Enterprise security teams collect telemetry from many different systems.

Examples include:

- Windows Security Event Logs
- Microsoft Entra ID
- Endpoint Detection and Response
- Firewalls
- DNS resolvers
- Cloud services
- Email security platforms
- Network monitoring tools

Each product may describe the same concepts using different field names.

For example:

```text
Windows Security Event
Computer
TargetUserName
IpAddress
```

may represent the same concepts as:

```text
Microsoft Entra ID
DeviceName
UserPrincipalName
IPAddress
```

or:

```text
Endpoint Detection
host_name
user_name
remote_ip
```

A SOC needs consistent data before detections, hunts, dashboards, and investigations can reliably use it.

This project will demonstrate how to:

- Ingest security telemetry from multiple sources
- Identify source-specific schemas
- Normalize timestamps
- Standardize hostnames
- Standardize usernames
- Standardize IP address fields
- Normalize severity values
- Normalize event categories
- Preserve original event identifiers
- Detect duplicate records
- Identify missing required fields
- Detect malformed values
- Calculate data-quality metrics
- Generate source-specific quality scores
- Produce analyst-ready normalized datasets
- Validate results against synthetic ground truth

## Planned Normalized Schema

The pipeline will transform different log formats into a common structure:

```text
timestamp
event_source
event_category
host
user
source_ip
destination_ip
action
outcome
severity
raw_event_id
```

## Planned Telemetry Sources

The synthetic dataset will include telemetry modeled after:

```text
Windows Security Events
Microsoft Entra ID Sign-ins
Endpoint Detection
Firewall Logs
DNS Logs
```

## Data Quality Checks

The pipeline will evaluate issues such as:

```text
Missing timestamp
Malformed timestamp
Missing hostname
Invalid IP address
Unknown event source
Invalid severity
Missing event identifier
Duplicate event
Unmapped field
```

## Planned Workflow

```text
Raw Security Telemetry
        ↓
Source Identification
        ↓
Schema Mapping
        ↓
Field Normalization
        ↓
Timestamp Standardization
        ↓
Host / User / IP Normalization
        ↓
Required-Field Validation
        ↓
Duplicate Detection
        ↓
Quality Scoring
        ↓
Normalized SOC Dataset
        ↓
Telemetry Quality Report
        ↓
Validation
```

## Planned Project Structure

```text
telemetry-normalization-pipeline/
├── README.md
├── normalize_telemetry.py
├── validate_pipeline.py
├── sample-data/
│   ├── windows_events.json
│   ├── entra_signins.json
│   ├── edr_events.json
│   ├── firewall_events.json
│   └── dns_events.json
├── mappings/
│   └── schema_mappings.json
├── rules/
│   └── quality_rules.json
├── expected-results/
└── output/
```

## Planned Outputs

The completed project will generate:

```text
normalized_events.json
normalized_events.csv
invalid_events.json
duplicate_events.json
telemetry_quality_report.json
telemetry_quality_summary.csv
```

## Skills Demonstrated

- SOC Engineering
- SIEM Data Engineering
- Security Telemetry
- Log Normalization
- Schema Mapping
- ETL
- Data Quality
- Event Validation
- Duplicate Detection
- Security Analytics
- Detection Engineering Support
- Python
- JSON Processing
- CSV Processing
- Security Automation
- Validation Testing
- Analyst Reporting

## Safety

All telemetry, identities, systems, IP addresses, logs, and events used in this project are synthetic.

The project does not connect to production SIEM platforms or ingest real organizational security data.

## Project Status

🚧 **In Development**
