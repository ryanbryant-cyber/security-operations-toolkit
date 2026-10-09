# Digital Evidence Integrity & Chain-of-Custody Tool

A hands-on forensic-operations project focused on preserving, documenting, and verifying the integrity of digital evidence collected during cybersecurity investigations.

The project demonstrates how a security analyst can register evidence, capture file metadata, generate SHA-256 hashes, maintain chain-of-custody records, and later verify whether forensic artifacts remain unchanged.

## Project Objective

Incident-response findings are only as defensible as the evidence supporting them.

Security teams may collect artifacts such as:

- Event logs
- CSV exports
- JSON reports
- Packet captures
- Screenshots
- PowerShell transcripts
- Analyst notes
- Memory-forensics output

Those artifacts may later be reviewed, transferred, archived, or included in formal incident reports.

This project will demonstrate how to:

- Register a forensic case
- Inventory collected evidence
- Assign unique evidence identifiers
- Capture file metadata
- Calculate SHA-256 hashes
- Create an evidence manifest
- Record evidence-handling actions
- Maintain a chain-of-custody log
- Recalculate hashes during later review
- Identify altered evidence
- Identify missing evidence
- Preserve analyst notes about discrepancies
- Generate structured CSV and JSON reports
- Validate results against synthetic ground truth

## Planned Workflow

```text
Incident Evidence
        ↓
Case Registration
        ↓
Evidence Inventory
        ↓
Evidence ID Assignment
        ↓
Metadata Capture
        ↓
SHA-256 Hashing
        ↓
Evidence Manifest
        ↓
Chain-of-Custody Recording
        ↓
Later Integrity Verification
        ↓
VERIFIED / HASH MISMATCH / MISSING
        ↓
Analyst Verification Report
        ↓
Validation
```

## Planned Evidence Types

The synthetic case will include artifacts such as:

```text
Authentication Logs
Network Evidence
Incident Timeline
Analyst Notes
Screenshots
PowerShell Transcript
JSON Investigation Results
```

## Planned Integrity States

Evidence verification will use states such as:

```text
VERIFIED
HASH MISMATCH
MISSING
```

### VERIFIED

The current SHA-256 hash matches the original evidence manifest.

### HASH MISMATCH

The file still exists, but its current SHA-256 hash differs from the originally recorded value.

### MISSING

The evidence file recorded in the manifest can no longer be found.

## Planned Chain-of-Custody Actions

The project will record evidence-handling events such as:

```text
Collected
Registered
Transferred
Reviewed
Exported
Archived
Verified
```

Each custody event will preserve information such as:

```text
Evidence ID
Timestamp
Action
Custodian
Location
Reason
Notes
```

## Planned Project Structure

```text
evidence-integrity-tool/
├── README.md
├── register_evidence.py
├── verify_evidence.py
├── validate_integrity.py
├── sample-evidence/
├── case-data/
│   └── case_metadata.json
├── expected-results/
└── output/
```

## Planned Outputs

The tool will generate:

```text
evidence_manifest.json
evidence_inventory.csv
chain_of_custody.csv
integrity_verification.json
integrity_verification_summary.csv
```

## Skills Demonstrated

- Digital Forensics
- Evidence Integrity
- Chain of Custody
- DFIR Operations
- SHA-256 Hashing
- Forensic Documentation
- Evidence Handling
- File Metadata Analysis
- Incident Documentation
- Python
- CSV Processing
- JSON Processing
- Security Automation
- Validation Testing
- Analyst Reporting

## Analyst Guardrails

This project is an educational evidence-management workflow.

It does not claim to replace:

- Enterprise digital-evidence platforms
- Legal evidence-management systems
- Organizational forensic procedures
- Law-enforcement chain-of-custody standards

The project demonstrates the technical principles of evidence preservation and verification.

## Safety

All case records, evidence files, identities, systems, and incident artifacts used in this project are synthetic and created specifically for defensive training.

No production forensic evidence or real legal evidence is used.

## Project Status

🚧 **In Development**
