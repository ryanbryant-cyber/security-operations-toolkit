# SOC Telemetry Normalization & Data Quality Pipeline

A hands-on SOC engineering project focused on transforming heterogeneous security telemetry into a consistent, validated, analyst-ready schema.

The project demonstrates how enterprise security teams can ingest logs from multiple security products, normalize differences in field names and values, detect malformed or duplicate records, calculate telemetry-quality metrics, and generate clean datasets suitable for SIEM analysis, threat hunting, dashboards, and detection engineering.

## Project Objective

Enterprise SOCs collect security telemetry from many different technologies.

Examples include:

- Windows Security Events
- Microsoft Entra ID
- Endpoint Detection and Response
- Firewalls
- DNS infrastructure
- Cloud platforms
- Email security gateways
- Network monitoring systems

These platforms often describe the same concepts using different schemas.

For example:

```text
Windows Security:
Computer
TargetUserName
IpAddress

Microsoft Entra ID:
deviceName
userPrincipalName
ipAddress

Endpoint Detection:
host_name
user_name
local_ip
```

Although these fields represent similar concepts, their names and values are not standardized.

This project demonstrates a normalization workflow that converts them into a common SOC schema.

## Normalized SOC Schema

The final dataset uses:

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

This provides a predictable structure for downstream analytics.

## Pipeline Workflow

```text
Raw Security Telemetry
        ↓
Source Discovery
        ↓
Schema Mapping
        ↓
Field Extraction
        ↓
Timestamp Normalization
        ↓
Host / User Normalization
        ↓
IP Address Validation
        ↓
Severity Normalization
        ↓
Required-Field Validation
        ↓
Duplicate Detection
        ↓
Event Quality Scoring
        ↓
Valid / Duplicate / Invalid Separation
        ↓
Source-Level Quality Metrics
        ↓
Overall Telemetry Quality Report
        ↓
Independent Validation
```

# Synthetic Telemetry Sources

The project processes five synthetic security telemetry sources:

```text
Windows Security
Microsoft Entra ID
Endpoint Detection
Firewall
DNS Resolver
```

Each source contains:

```text
5 events
```

Total input:

```text
25 raw security events
```

## Intentional Data-Quality Conditions

The synthetic dataset includes known problems so that the pipeline can be tested against established ground truth.

### Windows Security

Contains:

```text
1 duplicate event
```

`WIN-1002` appears twice.

### Microsoft Entra ID

Contains:

```text
1 event with a missing hostname
```

`ENTRA-2005` cannot satisfy the required `host` field.

### Firewall

Contains:

```text
1 invalid IP address
1 missing event identifier
```

`FW-4004` contains:

```text
999.10.20.15
```

which is not a valid IPv4 address.

The fifth firewall event has no `log_id`.

### Endpoint Detection

All five synthetic EDR events are valid.

### DNS Resolver

All five synthetic DNS events are valid.

# Schema Mapping

Source-specific field mappings are stored in:

```text
mappings/schema_mappings.json
```

The mapping configuration allows different vendor fields to be translated into one normalized schema.

Example:

```text
Windows Computer
Entra deviceName
EDR host_name
Firewall device
DNS client_host

        ↓

       host
```

This separates source-specific field names from the normalization engine itself.

## Schema Normalization

For example:

```text
Computer → host
deviceName → host
host_name → host
device → host
client_host → host
```

## Value Normalization

The project also normalizes values inside those fields.

For example:

```text
Windows Warning
        ↓
Medium
```

Normalized severity values are:

```text
Informational
Low
Medium
High
Critical
```

# Data Quality Policy

Quality rules are stored in:

```text
rules/quality_rules.json
```

The configuration defines:

- Required fields
- Optional fields
- IP-address fields
- Duplicate identity fields
- Severity mappings
- Quality penalties
- Fatal issues
- Nonfatal issues
- Minimum and maximum quality scores

## Required Fields

```text
timestamp
event_source
event_category
host
source_ip
action
outcome
severity
raw_event_id
```

## Optional Fields

```text
user
destination_ip
```

Optional fields prevent telemetry from being rejected when information does not naturally apply to a particular source.

For example, synthetic DNS records do not contain user identity information.

# Quality Penalties

Each event begins with:

```text
100 points
```

Configured penalties include:

```text
Missing required field   -25
Invalid timestamp        -20
Invalid IP address       -20
Invalid severity         -15
Duplicate event          -10
Unknown event source     -40
```

The resulting event-quality score represents how complete and trustworthy the individual record is.

## Fatal Issues

The following prevent an event from entering the clean normalized dataset:

```text
missing_required_field
invalid_timestamp
invalid_ip_address
invalid_severity
unknown_event_source
```

## Nonfatal Issues

```text
duplicate_event
```

A duplicate may contain valid data, but the duplicate copy should not be counted twice in the clean telemetry dataset.

# Duplicate Detection

Duplicate identity is defined by:

```text
event_source + raw_event_id
```

This creates a composite identity.

For example:

```text
Windows Security + WIN-1002
```

is treated as a unique event identity.

When that combination appears again, the additional record is classified as:

```text
DUPLICATE
```

rather than added to the clean dataset.

# Normalization Engine

The main processing engine is:

```text
normalize_telemetry.py
```

The Python program performs:

- JSON ingestion
- Automatic telemetry-file discovery
- Schema lookup
- Field extraction
- String normalization
- Host normalization
- User normalization
- Timestamp normalization
- IP validation
- Severity normalization
- Required-field checking
- Event scoring
- Fatal/nonfatal issue classification
- Duplicate detection
- Source aggregation
- Overall quality scoring
- JSON report generation
- CSV report generation

# Dataset Separation

The pipeline does not silently discard problematic telemetry.

Instead, all 25 events are separated by status:

```text
25 Raw Events
      ↓
 ┌──────────────┬───────────────┬───────────────┐
 ↓              ↓               ↓
21 VALID      1 DUPLICATE     3 INVALID
 ↓              ↓               ↓
Clean          Duplicate       Invalid
Dataset        Report          Report
```

This preserves visibility into telemetry-quality problems while preventing bad records from contaminating the clean dataset.

# Pipeline Results

Final processing results:

```text
Raw events loaded:        25
Clean normalized events:  21
Duplicate events:          1
Invalid events:            3
```

## Event Quality

```text
Average event score:      96.8
Accepted event rate:      84.0%
Overall quality score:    92.96
Overall quality rating:   GOOD
```

# Source-Level Quality

The source-level scoring model combines:

```text
70% Average Event Quality
30% Accepted Event Rate
```

This prevents a source with several unusable events from appearing healthier simply because its remaining records have high individual scores.

Final source results:

```text
DNS Resolver
Quality Score: 100.0
Rating: EXCELLENT
Clean: 5
Duplicate: 0
Invalid: 0

Endpoint Detection
Quality Score: 100.0
Rating: EXCELLENT
Clean: 5
Duplicate: 0
Invalid: 0

Microsoft Entra ID
Quality Score: 90.5
Rating: GOOD
Clean: 4
Duplicate: 0
Invalid: 1

Firewall
Quality Score: 81.7
Rating: FAIR
Clean: 3
Duplicate: 0
Invalid: 2

Windows Security
Quality Score: 92.6
Rating: GOOD
Clean: 4
Duplicate: 1
Invalid: 0
```

The Firewall source produced the lowest telemetry-quality score because two of its five events were unusable.

# Detected Data Quality Issues

The pipeline correctly identified:

```text
duplicate_event             1
invalid_ip_address          1
missing_required_field      2
```

## Duplicate Event

```text
Windows Security
WIN-1002
```

The original event remains in the clean normalized dataset.

The repeated copy is stored separately as a duplicate.

## Missing Host

```text
Microsoft Entra ID
ENTRA-2005
```

The source event lacks a usable hostname and therefore fails a required-field check.

## Invalid IP Address

```text
Firewall
FW-4004

999.10.20.15
```

Python's IP-address validation rejects the malformed value.

## Missing Event Identifier

The fifth firewall record contains no event ID.

Because `raw_event_id` is required, the record is classified as invalid.

# Generated Outputs

The engine creates:

```text
output/
├── normalized_events.json
├── normalized_events.csv
├── invalid_events.json
├── duplicate_events.json
├── telemetry_quality_report.json
└── telemetry_quality_summary.csv
```

## Normalized Dataset

```text
normalized_events.json
normalized_events.csv
```

Contains only the 21 validated, nonduplicate events suitable for downstream analysis.

## Invalid Event Report

```text
invalid_events.json
```

Contains records that failed fatal data-quality requirements.

## Duplicate Report

```text
duplicate_events.json
```

Preserves duplicate telemetry separately rather than silently discarding it.

## Telemetry Quality Report

```text
telemetry_quality_report.json
```

Contains:

- Overall event counts
- Event quality averages
- Accepted event rate
- Overall quality score
- Quality label
- Issue counts
- Source-specific metrics

## Quality Summary

```text
telemetry_quality_summary.csv
```

Provides analyst-friendly source-level telemetry metrics.

# Independent Validation

A separate validation program is implemented in:

```text
validate_pipeline.py
```

Expected results are stored in:

```text
expected-results/pipeline_expectations.json
```

The validator independently confirms that the normalization engine produced the expected results.

## Validation Coverage

The validator checks:

```text
Overall event counts
Overall quality scoring
Quality issue counts
Source-level quality metrics
Normalized JSON count
Normalized CSV count
Duplicate identification
Duplicate exclusion from clean telemetry
Invalid event count
Entra missing-host detection
Firewall invalid-IP detection
Firewall missing-ID detection
Identity normalization
Hostname normalization
Severity normalization
Optional DNS user handling
```

Final validation:

```text
Checks run:     15
Checks passed:  15
Checks failed:  0
Overall:        PASS
```

# Example Identity Normalization

Microsoft Entra ID supplies:

```text
finance.user@northstar.example
```

The pipeline normalizes it to:

```text
finance.user
```

This provides a more consistent identity value for cross-source SOC analysis.

# Example Host Normalization

Source values are normalized into a standardized uppercase hostname format:

```text
NFG-FIN-WS07
```

This reduces inconsistencies caused by casing differences across telemetry products.

# Example Severity Normalization

Windows Security provides:

```text
Warning
```

The pipeline translates it to:

```text
Medium
```

allowing downstream tools to use one predictable severity vocabulary.

# Project Structure

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
│   └── pipeline_expectations.json
└── output/
    ├── normalized_events.json
    ├── normalized_events.csv
    ├── invalid_events.json
    ├── duplicate_events.json
    ├── telemetry_quality_report.json
    ├── telemetry_quality_summary.csv
    └── pipeline_validation_results.json
```

# Skills Demonstrated

```text
SOC Engineering
SIEM Data Engineering
Security Telemetry
Log Normalization
Schema Mapping
ETL
Data Quality Engineering
Event Validation
Duplicate Detection
Telemetry Health Monitoring
Security Analytics
Detection Engineering Support
Python
JSON Processing
CSV Processing
IP Address Validation
Configuration-Driven Development
Data Aggregation
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## Normalization Happens at Multiple Levels

Security telemetry may require both:

```text
Schema normalization
```

and:

```text
Value normalization
```

Field names and the data stored within those fields can both vary between technologies.

## Missing Does Not Always Mean Broken

An optional field may simply not apply to a particular telemetry source.

The pipeline distinguishes:

```text
Required but missing
```

from:

```text
Not expected for this source
```

## Valid Data Can Still Be Duplicate Data

A duplicate event may contain perfectly valid telemetry while still needing to be removed from the clean analytical dataset.

## Program Logic and Configuration Should Be Separated

Python controls how the pipeline works.

JSON configuration controls:

```text
Schema mappings
Severity translations
Quality policy
Penalty values
Required fields
Duplicate identity
```

This makes the pipeline easier to maintain and extend.

## Data Quality Directly Affects Detection Quality

A SIEM detection cannot reliably analyze information that never arrived, cannot be parsed, or was normalized incorrectly.

Telemetry quality is therefore part of detection engineering—not merely an ingestion concern.

## Successful Execution Does Not Prove Correctness

A Python program can run without errors and still produce incorrect results.

Independent validation provides stronger evidence that expected behavior occurred.

# Analyst Guardrails

This project demonstrates educational SOC data-engineering concepts using synthetic telemetry.

It does not claim to reproduce the complete ingestion architecture or schema model of any specific commercial SIEM.

Production environments may use technologies and standards such as:

- Microsoft Sentinel
- Splunk
- Elastic
- Wazuh
- OpenTelemetry
- Common Event Format
- Elastic Common Schema
- Open Cybersecurity Schema Framework

Actual normalization requirements depend on the organization's architecture, data sources, detection strategy, and compliance requirements.

# Safety

All:

```text
Users
Hosts
IP addresses
Domains
Logs
Events
Security findings
```

used in this project are synthetic.

No production security telemetry or organizational data is used.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- ingests 25 synthetic events
- processes 5 different security telemetry sources
- maps source-specific schemas
- normalizes hostnames
- normalizes usernames
- normalizes timestamps
- validates IP addresses
- normalizes severity values
- enforces required and optional fields
- detects duplicate telemetry
- separates valid, duplicate, and invalid records
- produces 21 clean normalized events
- detects 1 duplicate
- detects 3 invalid records
- calculates event-level quality scores
- calculates source-level quality scores
- calculates an overall telemetry-quality score
- produces JSON and CSV outputs
- independently validates expected behavior
- passes 15 of 15 validation checks
