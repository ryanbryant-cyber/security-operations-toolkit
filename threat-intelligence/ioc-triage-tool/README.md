# IOC Enrichment & Triage Tool

A Python-based cybersecurity analyst project designed to validate, normalize, correlate, score, and triage Indicators of Compromise (IOCs).

This project demonstrates a simple SOC-style workflow for turning raw security observations into structured analyst output.

## Project Workflow

Raw IOC Data  
↓  
IOC Type Detection  
↓  
Normalization  
↓  
Duplicate Correlation  
↓  
Evidence-Based Risk Scoring  
↓  
Analyst Priority Assignment  
↓  
Recommended Investigation Action  
↓  
CSV and JSON Report Export

## Supported Indicator Types

The current version supports:

- IPv4 addresses
- Domain names
- URLs
- MD5 hashes
- SHA-1 hashes
- SHA-256 hashes

## Key Features

- Loads IOC data from CSV
- Automatically detects IOC type
- Compares detected type with analyst-declared type
- Normalizes indicators into consistent formats
- Safely handles defanged URLs
- Correlates duplicate indicators across multiple sources
- Aggregates observed events and failed authentication attempts
- Assigns evidence-based triage scores
- Classifies indicators as:
  - LOW
  - MODERATE
  - HIGH
  - CRITICAL
- Generates analyst investigation recommendations
- Exports structured CSV and JSON reports

## Risk Scoring Model

The scoring model represents investigation priority, not confirmed maliciousness.

| Evidence | Score |
|---|---:|
| At least 1 observed event | +1 |
| 3 or more observed events | +1 |
| 5 or more observed events | +1 |
| At least 1 failed login | +2 |
| 3 or more failed logins | +1 |
| Duplicate IOC observation | +1 |
| IOC observed in multiple sources | +1 |

### Priority Levels

| Score | Priority |
|---|---|
| 0 | LOW |
| 1–2 | MODERATE |
| 3–5 | HIGH |
| 6+ | CRITICAL |

The tool does not automatically block or contain an indicator solely because of its score. Analyst validation is still required before restrictive action is taken.

## Sample Results

The included training dataset contains six IOC observations that correlate into five unique indicators.

Example:

```text
Indicator: 203.0.113.77
Type: ipv4
Occurrences: 2
Observed Events: 6
Failed Logins: 0
Sources: phishing-investigation, proxy-logs
Risk Score: 5
Priority: HIGH
