# Phishing Email Investigation Lab

A hands-on SOC email-security project focused on investigating synthetic phishing messages using email headers, authentication results, sender context, URLs, attachments, and extracted indicators of compromise.

The project demonstrates how a security analyst can move from a user-reported suspicious email to a documented triage decision supported by observable evidence.

## Project Objective

Phishing investigations require analysts to evaluate multiple pieces of evidence rather than relying on a single suspicious characteristic.

This project will demonstrate how to:

- Review email metadata and headers
- Evaluate sender and reply-to information
- Interpret SPF, DKIM, and DMARC results
- Identify suspicious domain characteristics
- Extract URLs and other indicators
- Review attachment metadata
- Separate confirmed evidence from analyst hypotheses
- Assign BENIGN, SUSPICIOUS, or MALICIOUS dispositions
- Generate structured JSON and CSV findings
- Produce an analyst-readable investigation summary
- Validate results against known synthetic ground truth

## Planned Investigation Areas

The lab will evaluate:

- From address
- Reply-To address
- Return-Path
- Sending IP
- Received headers
- Subject line
- SPF
- DKIM
- DMARC
- Display-name impersonation
- Domain mismatches
- Suspicious URLs
- Attachment metadata
- Urgency and social-engineering indicators
- Extracted IOCs

## Project Workflow

```text
Synthetic Email Evidence
        ↓
Header Analysis
        ↓
Authentication Review
        ↓
Sender / Domain Analysis
        ↓
URL & Attachment Review
        ↓
IOC Extraction
        ↓
Risk Scoring
        ↓
Disposition
        ↓
Analyst Findings
        ↓
Validation
```

## Planned Project Structure

```text
phishing-investigation-lab/
├── README.md
├── analyze_email.py
├── validate_analysis.py
├── sample-data/
├── rules/
├── expected-results/
└── output/
```

## Skills Demonstrated

- Phishing Analysis
- Email Security
- SOC Triage
- Email Header Analysis
- SPF Analysis
- DKIM Analysis
- DMARC Analysis
- IOC Extraction
- URL Analysis
- Social Engineering Detection
- Python
- JSON Processing
- CSV Reporting
- Security Automation
- Validation Testing
- Analyst Reporting

## Safety

All email messages, domains, IP addresses, URLs, attachments, identities, and organizations used in this project are synthetic or reserved for documentation and testing.

No live phishing infrastructure, real credentials, or malicious attachments are used.

## Project Status

🚧 **In Development**
