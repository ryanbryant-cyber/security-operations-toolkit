# Phishing Email Investigation Lab

A hands-on SOC email-security project focused on investigating synthetic suspicious messages using email authentication results, sender context, URLs, attachments, social-engineering indicators, IOC extraction, and risk-based triage.

The project demonstrates how a security analyst can move from a user-reported suspicious email to a documented disposition supported by observable evidence.

## Project Objective

Phishing investigations require analysts to evaluate multiple pieces of evidence rather than relying on one suspicious characteristic.

A message may contain urgency without being malicious. An external sender may be legitimate. Even extracted investigation artifacts such as IP addresses, domains, URLs, or hashes are not automatically malicious indicators.

This project demonstrates a repeatable email-investigation workflow:

```text
Synthetic Email Evidence
        ↓
Header & Authentication Review
        ↓
Sender / Domain Analysis
        ↓
URL & Attachment Review
        ↓
Social-Engineering Analysis
        ↓
IOC Extraction
        ↓
Risk Scoring
        ↓
BENIGN / SUSPICIOUS / MALICIOUS
        ↓
Analyst Assessment
        ↓
Validation
```

## Investigation Dataset

The project contains three synthetic email cases:

```text
sample-data/
└── email_cases.json
```

Each case contains evidence related to:

- Sender display name
- From address
- Reply-To address
- Return-Path
- Sending IP
- Message ID
- Subject
- SPF
- DKIM
- DMARC
- Sender familiarity
- Display-name impersonation
- Domain alignment
- Urgency
- Credential requests
- Financial requests
- Threatening language
- Security-alert themes
- URLs
- Attachments
- Attachment hashes

All identities, domains, IP addresses, URLs, hashes, and organizations are synthetic or reserved for documentation and testing.

## Email Cases

### EMAIL-001 — Credential Phishing Scenario

The first message impersonates organizational IT support and attempts to pressure a Finance user into verifying a Microsoft 365 account.

Key evidence includes:

```text
SPF:   FAIL
DKIM:  FAIL
DMARC: FAIL

Display-name impersonation:  Yes
Reply-To domain mismatch:     Yes
Return-Path mismatch:         Yes
Credential request:           Yes
Urgency language:             Yes
Threatening language:         Yes
Security-alert theme:         Yes
Suspicious URL domain:        Yes
HTML attachment:              Yes
External form:                Yes
```

Final analysis:

```text
Risk Score:      100
Disposition:     MALICIOUS
Risk Indicators: 14
Extracted IOCs:  10
```

The raw score exceeded the configured maximum because numerous independent indicators were present, so the engine capped the final score at 100.

### EMAIL-002 — Suspicious Invoice Scenario

The second message represents a more ambiguous external invoice email.

Authentication results were stronger:

```text
SPF:   PASS
DKIM:  PASS
DMARC: NONE
```

Sender and message context included:

```text
External sender
Unknown sender
Invoice theme
Financial request
Urgency language
Aligned sender / Reply-To domains
Aligned sender / Return-Path domains
URL domain aligned with sender
PDF attachment
```

Final analysis:

```text
Risk Score:      18
Disposition:     SUSPICIOUS
Risk Indicators: 4
Extracted IOCs:  6
```

The available evidence warrants additional investigation but does not independently establish that the message is malicious.

### EMAIL-003 — Benign Internal Message

The third message provides a clean comparison case involving a synthetic internal HR benefits message.

```text
SPF:   PASS
DKIM:  PASS
DMARC: PASS

Known sender
Internal sender
Aligned domains
No impersonation
No urgency
No credential request
No financial request
No suspicious attachment behavior
```

Final analysis:

```text
Risk Score:      0
Disposition:     BENIGN
Risk Indicators: 0
Extracted IOCs:  6
```

This case demonstrates an important investigation principle:

> An extracted IOC or artifact is not automatically malicious.

The benign message still contains addresses, domains, an IP address, a URL, and an attachment hash that may be useful during an investigation.

Those artifacts are preserved without being incorrectly treated as phishing evidence.

## Phishing Risk Model

The scoring model is stored in:

```text
rules/
└── phishing_risk_model.json
```

The model evaluates several categories of evidence.

## Authentication Indicators

```text
SPF failure       +10
DKIM failure       +8
DMARC failure     +15
DMARC none         +2
```

Authentication failures contribute to risk but are evaluated alongside other message characteristics.

## Sender Context

```text
External unknown sender       +5
Display-name impersonation   +15
Reply-To domain mismatch     +10
Return-Path domain mismatch   +8
```

Sender-context checks help identify impersonation and routing inconsistencies.

## Message Content Indicators

```text
Urgency language       +5
Credential request    +15
Financial request      +6
Threatening language   +5
Security-alert theme   +4
```

These signals help identify common social-engineering techniques.

A single indicator does not automatically make an email malicious.

## URL Indicators

```text
Sender-domain mismatch  +10
Non-HTTPS URL            +8
```

URL analysis considers whether message links align with sender context and whether encrypted transport is used.

## Attachment Indicators

```text
HTML attachment        +8
External form          +12
Macro-enabled file     +15
Executable attachment  +20
```

Higher-risk attachment behaviors receive greater weight.

## Disposition Thresholds

The custom educational model uses:

```text
40–100 → MALICIOUS
15–39  → SUSPICIOUS
0–14   → BENIGN
```

These thresholds are designed specifically for this synthetic lab and are not presented as a universal email-security standard.

## Analysis Engine

The primary analysis script is:

```text
analyze_email.py
```

The analyzer:

1. Loads the synthetic email dataset.
2. Loads the phishing-risk model.
3. Evaluates SPF, DKIM, and DMARC.
4. Reviews sender and domain context.
5. Detects impersonation and routing mismatches.
6. Evaluates message-content indicators.
7. Reviews URLs.
8. Reviews attachment characteristics.
9. Calculates a risk score.
10. Caps scores at the configured maximum.
11. Assigns a disposition.
12. Extracts investigation artifacts.
13. Generates an analyst assessment.
14. Produces CSV and JSON reports.

## IOC Extraction

The analyzer extracts investigation artifacts including:

```text
Email addresses
Domains
Sending IP addresses
URLs
SHA-256 attachment hashes
```

IOC extraction is intentionally separate from risk scoring.

This means an artifact can be preserved for investigation without being automatically labeled malicious.

For example:

```text
EMAIL-003

Risk Indicators: 0
Extracted IOCs:  6
Disposition:     BENIGN
```

This distinction helps avoid confusing:

```text
Observed Artifact
```

with:

```text
Confirmed Malicious Indicator
```

## Analysis Results

Running:

```bash
python3 analyze_email.py
```

produced:

```text
EMAIL-001 | Score: 100 | MALICIOUS  | Indicators: 14 | IOCs: 10
EMAIL-002 | Score:  18 | SUSPICIOUS | Indicators:  4 | IOCs:  6
EMAIL-003 | Score:   0 | BENIGN     | Indicators:  0 | IOCs:  6
```

Overall results:

```text
Total Cases: 3
MALICIOUS:   1
SUSPICIOUS:  1
BENIGN:      1
```

## Generated Reports

The analysis engine produces:

```text
output/
├── phishing_analysis_results.json
└── phishing_analysis_summary.csv
```

The JSON report preserves:

- Complete case metadata
- Authentication results
- Risk score
- Disposition
- Risk indicators
- Evidence supporting each indicator
- Extracted IOCs
- Analyst assessment

The CSV report provides a concise triage view suitable for filtering and analyst review.

## Analyst Assessment Principles

The project intentionally separates:

```text
Confirmed Evidence
```

from:

```text
Analyst Interpretation
```

For example, EMAIL-002 contains urgency and a financial theme, but its sender authentication and domain alignment are stronger than the confirmed phishing case.

The tool therefore assigns:

```text
SUSPICIOUS
```

instead of automatically labeling it:

```text
MALICIOUS
```

This supports a more defensible SOC investigation process.

## Validation

The project includes an independent validation script:

```text
validate_analysis.py
```

Expected results are stored in:

```text
expected-results/
└── phishing_expectations.json
```

The validator checks:

- Total case count
- Expected case distribution
- Risk score
- Disposition
- Risk-indicator count
- IOC count
- Important behavioral relationships

## Behavioral Validation

Six behavioral tests verify key investigation outcomes.

### Authentication Failures and Impersonation

The validator confirms that EMAIL-001 contains:

```text
SPF FAIL
DKIM FAIL
DMARC FAIL
Display-name impersonation
```

and receives:

```text
MALICIOUS
```

### Credential Request Detection

The validator confirms that the malicious phishing case contains a detected credential request.

### External HTML Form Detection

The validator confirms that EMAIL-001 contains both:

```text
HTML attachment
External form
```

### Suspicious Invoice Handling

The validator confirms that an authenticated but contextually risky invoice remains:

```text
SUSPICIOUS
```

rather than being automatically classified as malicious.

### Benign Internal Email

The validator confirms that EMAIL-003 has:

```text
SPF PASS
DKIM PASS
DMARC PASS
Risk Score 0
BENIGN disposition
```

### IOC and Risk Separation

The validator confirms that a benign message can contain extracted investigation artifacts while having:

```text
0 risk indicators
```

This verifies that artifact collection and malicious classification remain separate processes.

## Validation Results

The final validation run produced:

```text
Summary check:  PASS
Checks run:     10
Checks passed:  10
Checks failed:  0
Overall:        PASS
```

The validation included:

```text
3 case-level validation checks
6 behavioral checks
1 summary check
------------------------------
10 total checks
```

All expected results matched the synthetic ground truth.

The generated validation report is stored at:

```text
output/
└── phishing_validation_results.json
```

## Project Structure

```text
phishing-investigation-lab/
├── README.md
├── analyze_email.py
├── validate_analysis.py
├── sample-data/
│   └── email_cases.json
├── rules/
│   └── phishing_risk_model.json
├── expected-results/
│   └── phishing_expectations.json
└── output/
    ├── phishing_analysis_results.json
    ├── phishing_analysis_summary.csv
    └── phishing_validation_results.json
```

## Skills Demonstrated

```text
Phishing Analysis
Email Security
SOC Triage
Email Header Analysis
SPF Analysis
DKIM Analysis
DMARC Analysis
Sender Impersonation Detection
Domain Alignment Analysis
Social Engineering Detection
Credential Phishing Analysis
URL Analysis
Attachment Analysis
IOC Extraction
Risk-Based Triage
Python
JSON Processing
CSV Reporting
Security Automation
Validation Testing
Analyst Reporting
```

## Key Lessons

### Authentication results are evidence, not the entire investigation

SPF, DKIM, and DMARC provide important evidence about message authenticity and domain alignment.

However, analysts should evaluate those results together with sender context, message content, URLs, and attachments.

### Multiple independent indicators increase confidence

EMAIL-001 was not classified as malicious because of one failed authentication check.

Its final disposition resulted from a combination of:

```text
Authentication failures
Impersonation
Domain mismatches
Credential request
Urgency
Threatening language
Suspicious URL
HTML attachment
External form
```

### Authenticated email can still require investigation

EMAIL-002 passed SPF and DKIM but still received a SUSPICIOUS disposition because contextual indicators remained.

Authentication success does not automatically establish that an email is safe.

### Suspicious does not mean confirmed malicious

A suspicious disposition means the available evidence warrants additional investigation.

It should not be presented as proof of malicious intent.

### IOCs and evidence should be preserved independently

An IP address, URL, domain, email address, or hash may be useful during an investigation without being malicious.

Preserving those artifacts separately from risk indicators helps prevent overclassification.

### Automation should support analyst judgment

The scoring engine provides consistent triage, but its purpose is to support an analyst rather than replace investigation and business context.

## Limitations

This project uses synthetic email evidence and a custom educational scoring model.

It does not connect to a production mail platform or automatically query external reputation services.

The project does not execute attachments or visit URLs.

Future improvements could include:

- Raw `.eml` parsing
- Full Received-header chain analysis
- Microsoft 365 message-trace integration
- Microsoft Defender for Office 365 integration
- URL reputation enrichment
- Domain-age analysis
- WHOIS enrichment
- VirusTotal-style reputation enrichment
- Attachment metadata extraction
- Sandbox integration
- QR-code phishing detection
- Homoglyph / lookalike-domain detection
- Thread hijacking analysis
- Automated quarantine recommendations
- SIEM case creation
- SOAR response workflows

## Safety

All email messages, identities, domains, IP addresses, URLs, hashes, attachments, and organizations used in this project are synthetic or reserved for documentation and testing.

No live phishing infrastructure, real credentials, or malicious executable content are used.

The analyzer does not open links or execute attachments.

## Project Status

✅ **Functional and Validated**

The current version successfully:

- analyzes 3 synthetic email cases
- evaluates SPF, DKIM, and DMARC
- detects sender and domain inconsistencies
- evaluates social-engineering indicators
- analyzes URLs and attachments
- extracts investigation artifacts
- calculates contextual phishing risk
- assigns BENIGN, SUSPICIOUS, and MALICIOUS dispositions
- generates analyst assessments
- exports structured CSV and JSON reports
- validates all expected case outcomes
- passes 10 of 10 validation checks
