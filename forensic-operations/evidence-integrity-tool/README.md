# Digital Evidence Integrity & Chain-of-Custody Tool

A hands-on forensic-operations project focused on preserving, documenting, and verifying the integrity of digital evidence collected during cybersecurity investigations.

The project demonstrates how a security analyst can register forensic artifacts, assign evidence identifiers, capture file metadata, calculate SHA-256 hashes, maintain chain-of-custody records, and later determine whether evidence remains unchanged, has been altered, or is missing.

## Project Objective

Incident-response conclusions are only as defensible as the evidence supporting them.

Security teams may collect artifacts such as:

- Authentication logs
- Network evidence
- Incident timelines
- Analyst notes
- PowerShell transcripts
- Screenshots
- Packet captures
- Structured investigation results

Those files may later be transferred, reviewed, exported, archived, or included in formal reports.

This project demonstrates a repeatable digital-evidence workflow:

```text
Incident Evidence
        ↓
Case Registration
        ↓
Evidence Discovery
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
Independent Validation
```

# Synthetic Forensic Case

The project uses:

```text
Case ID:
CASE-2026-001

Case Name:
Northstar Ridge Suspicious Finance Activity

Case Type:
Cybersecurity Incident Investigation
```

The case is synthetic and designed specifically for forensic evidence-integrity training.

## Case Scenario

The evidence package represents a Finance-related security investigation involving synthetic activity such as:

```text
Repeated failed authentication
Successful authentication after failures
Suspicious PowerShell execution
Attempted internal SMB communication
Service persistence
External network communication
```

The goal of this project is not to reinvestigate those events.

The goal is to demonstrate how the resulting forensic artifacts can be registered and later verified for integrity.

# Evidence Package

The original evidence package is stored in:

```text
sample-evidence/
```

It contains six artifacts:

```text
analyst_notes.txt
authentication_events.csv
incident_timeline.csv
investigation_results.json
network_connections.csv
powershell_transcript.txt
```

These files represent several different forms of forensic evidence.

## Evidence Types

```text
Authentication Log
Network Evidence
Incident Timeline
Analyst Notes
Command Transcript
Investigation Results
```

# Evidence Registration

The primary registration script is:

```text
register_evidence.py
```

The tool performs several steps for every discovered evidence file.

## Evidence ID Assignment

Each file receives a unique evidence identifier.

```text
EV-001 → analyst_notes.txt
EV-002 → authentication_events.csv
EV-003 → incident_timeline.csv
EV-004 → investigation_results.json
EV-005 → network_connections.csv
EV-006 → powershell_transcript.txt
```

## Metadata Capture

For each artifact, the registration workflow records:

```text
Case ID
Evidence ID
File Name
Relative Path
Evidence Type
Source System
Description
File Size
Registered Timestamp
Registered By
Integrity Status
```

## SHA-256 Hashing

Every evidence file receives a SHA-256 hash at registration.

Example:

```text
Evidence ID:
EV-002

File:
authentication_events.csv

Integrity Status:
REGISTERED

Hash Algorithm:
SHA-256
```

The hash acts as the known-good reference used during later verification.

# Evidence Manifest

The tool creates:

```text
output/evidence_manifest.json
```

The manifest preserves:

```text
Case metadata
Manifest timestamp
Hash algorithm
Evidence count
Evidence identifiers
Evidence filenames
Evidence metadata
Original SHA-256 hashes
Registration information
```

The completed manifest contains:

```text
6 registered evidence items
```

# Evidence Inventory

The tool also creates:

```text
output/evidence_inventory.csv
```

This provides a concise analyst-facing inventory of the registered evidence package.

Fields include:

```text
Case ID
Evidence ID
Filename
Relative Path
Evidence Type
Source System
File Size
SHA-256
Registration Timestamp
Registered By
Integrity Status
```

# Chain of Custody

Initial chain-of-custody records are stored in:

```text
output/chain_of_custody.csv
```

At registration, every evidence item receives two custody events:

```text
Collected
Registered
```

With six evidence files, the initial workflow generates:

```text
12 custody records
```

Each custody record contains:

```text
Case ID
Evidence ID
Timestamp
Action
Custodian
Location
Reason
Notes
```

This demonstrates how technical integrity information can be paired with evidence-handling history.

# Initial Registration Results

Running:

```bash
python3 register_evidence.py
```

produced:

```text
Evidence registered: 6
Custody records:     12
```

All six artifacts were successfully assigned evidence IDs and SHA-256 hashes.

# Controlled Integrity Test

To demonstrate evidence verification safely, the project creates a second copy of the evidence package:

```text
verification-evidence/
```

The original:

```text
sample-evidence/
```

remains unchanged.

Two conditions are deliberately introduced into the verification copy.

## Altered Evidence

The copied version of:

```text
EV-002
authentication_events.csv
```

is modified.

The file still exists, but its content no longer matches the originally registered artifact.

Expected result:

```text
HASH MISMATCH
```

## Missing Evidence

The copied version of:

```text
EV-005
network_connections.csv
```

is removed.

Expected result:

```text
MISSING
```

The remaining four verification copies are left unchanged.

# Evidence Verification

Integrity verification is performed by:

```text
verify_evidence.py
```

The tool:

1. Loads the registered evidence manifest.
2. Locates each evidence item in `verification-evidence/`.
3. Detects whether the file exists.
4. Recalculates SHA-256 for existing files.
5. Compares current hashes against the registered manifest.
6. Assigns an integrity status.
7. Creates JSON and CSV verification reports.
8. Appends a verification event to chain of custody.

# Integrity States

The verifier uses three evidence states.

## VERIFIED

```text
Current SHA-256
        =
Registered SHA-256
```

The evidence remains unchanged.

## HASH MISMATCH

```text
File exists
        +
Current SHA-256
        ≠
Registered SHA-256
```

The file is present but no longer matches the registered evidence.

## MISSING

```text
Evidence exists in manifest
        +
File cannot be found
```

The artifact is unavailable during verification.

# Verification Results

Running:

```bash
python3 verify_evidence.py
```

produced:

```text
EV-001 | VERIFIED      | analyst_notes.txt
EV-002 | HASH MISMATCH | authentication_events.csv
EV-003 | VERIFIED      | incident_timeline.csv
EV-004 | VERIFIED      | investigation_results.json
EV-005 | MISSING       | network_connections.csv
EV-006 | VERIFIED      | powershell_transcript.txt
```

Summary:

```text
Evidence checked: 6
VERIFIED:         4
HASH MISMATCH:    1
MISSING:          1
```

# Why the Results Matter

The project demonstrates two different evidence-integrity failures.

## Evidence Can Exist and Still Fail Integrity

`EV-002` remains present.

However:

```text
Original SHA-256
        ≠
Current SHA-256
```

The integrity tool therefore identifies a:

```text
HASH MISMATCH
```

The file should not automatically be treated as equivalent to the originally registered evidence.

## Evidence Can Become Unavailable

`EV-005` cannot be found during verification.

The tool records:

```text
MISSING
```

This distinction is important because:

```text
Changed evidence
```

and:

```text
Unavailable evidence
```

are different forensic conditions.

# Original Evidence Preservation

The project deliberately modifies only:

```text
verification-evidence/
```

The original evidence remains in:

```text
sample-evidence/
```

The independent validation harness recalculates every original SHA-256 hash and confirms that all six still match the original manifest.

This demonstrates an important evidence-handling principle:

> Perform integrity testing against controlled copies while preserving the originally registered evidence package.

# Chain-of-Custody Verification Events

The verification script adds:

```text
Verified
```

as a custody action for each evidence item.

The chain of custody therefore contains, at minimum:

```text
Collected
Registered
Verified
```

for each evidence ID.

After the first verification run:

```text
12 registration custody records
+
6 verification custody records
=
18 custody records
```

# Generated Reports

The project generates:

```text
output/
├── evidence_manifest.json
├── evidence_inventory.csv
├── chain_of_custody.csv
├── integrity_verification.json
└── integrity_verification_summary.csv
```

## Evidence Manifest

Preserves the original registered evidence state.

## Evidence Inventory

Provides a concise evidence catalog.

## Chain of Custody

Records evidence-handling activity.

## Integrity Verification JSON

Preserves:

```text
Evidence ID
Filename
Expected SHA-256
Current SHA-256
Integrity Status
Verification Timestamp
Analyst Notes
```

## Integrity Verification CSV

Provides a concise verification view suitable for analyst review.

# Independent Validation

The project includes:

```text
validate_integrity.py
```

Expected ground truth is stored in:

```text
expected-results/
└── integrity_expectations.json
```

The validator confirms both evidence-integrity logic and preservation of the original evidence package.

# Validation Checks

The completed validation confirms:

```text
Integrity verification summary
Expected evidence status for all 6 artifacts
Evidence ID to filename mapping
Evidence manifest count
Original sample-evidence package remains unchanged
Altered evidence produces SHA-256 mismatch
Removed evidence is classified as MISSING
All VERIFIED evidence matches its original hash
Chain-of-custody contains registration and verification history
Every evidence item contains Collected, Registered, and Verified actions
Case identity remains consistent across records
```

Final result:

```text
Checks run:     11
Checks passed:  11
Checks failed:  0
Overall:        PASS
```

The validation report is stored at:

```text
output/
└── integrity_validation_results.json
```

# Project Structure

```text
evidence-integrity-tool/
├── README.md
├── register_evidence.py
├── verify_evidence.py
├── validate_integrity.py
├── sample-evidence/
│   ├── analyst_notes.txt
│   ├── authentication_events.csv
│   ├── incident_timeline.csv
│   ├── investigation_results.json
│   ├── network_connections.csv
│   └── powershell_transcript.txt
├── verification-evidence/
├── case-data/
│   └── case_metadata.json
├── expected-results/
│   └── integrity_expectations.json
└── output/
    ├── evidence_manifest.json
    ├── evidence_inventory.csv
    ├── chain_of_custody.csv
    ├── integrity_verification.json
    ├── integrity_verification_summary.csv
    └── integrity_validation_results.json
```

# Skills Demonstrated

```text
Digital Forensics
Evidence Integrity
Chain of Custody
DFIR Operations
SHA-256 Hashing
Forensic Documentation
Evidence Registration
Evidence Verification
Evidence Handling
File Metadata Analysis
Incident Documentation
Forensic Case Management
Python
CSV Processing
JSON Processing
Security Automation
Validation Testing
Analyst Reporting
```

# Key Lessons

## A File Existing Does Not Prove It Is Unchanged

Evidence can remain present while its contents have changed.

Hash verification provides a repeatable method for detecting that condition.

## Missing and Altered Evidence Are Different Conditions

The project distinguishes:

```text
HASH MISMATCH
```

from:

```text
MISSING
```

because they represent different evidence-management problems.

## Hashes Provide Integrity Verification

SHA-256 provides a cryptographic fingerprint that allows an analyst to compare the current artifact against the originally registered state.

## Chain of Custody Adds Handling Context

A hash proves whether bytes changed.

Chain of custody documents:

```text
Who handled the evidence
When it was handled
Why it was handled
Where it was located
What action occurred
```

Both concepts support defensible forensic practice.

## Original Evidence Should Be Protected

Testing and analysis should be performed on controlled copies when possible.

The original registered evidence package remained unchanged throughout the integrity test.

## Evidence IDs Improve Traceability

Identifiers such as:

```text
EV-001
EV-002
EV-003
```

allow manifests, custody records, reports, and analyst discussions to reference the same artifact consistently.

# Analyst Guardrails

This project demonstrates technical evidence-integrity principles.

It does not claim to replace:

```text
Enterprise forensic evidence systems
Organizational DFIR procedures
Legal evidence-management requirements
Law-enforcement standards
Court-admissibility procedures
```

Evidence-handling requirements vary by organization, jurisdiction, investigation type, and regulatory environment.

# Limitations

This project uses synthetic evidence and an educational chain-of-custody workflow.

It does not currently implement:

- Evidence encryption
- Access-control enforcement
- Digital signatures
- Trusted timestamping
- Write-blocking
- WORM storage
- Evidence database storage
- Multi-user authentication
- Custodian authorization
- Legal hold workflows
- Evidence retention policies
- Secure evidence transfer
- Evidence container formats

Future improvements could include:

- Signed evidence manifests
- HMAC verification
- Trusted timestamp integration
- Evidence ZIP packaging
- Case export bundles
- Role-based custody actions
- Secure evidence transfer records
- Evidence archival verification
- Automated case-report generation
- Database-backed evidence inventory
- Dashboard visualization

# Safety

All case records, evidence files, identities, systems, and incident artifacts used in this project are synthetic.

No production forensic evidence, legal evidence, credentials, or organizational investigation records are used.

# Project Status

✅ **Functional and Validated**

The current version successfully:

- registers 6 synthetic forensic artifacts
- assigns unique evidence IDs
- records file metadata
- calculates SHA-256 hashes
- creates an evidence manifest
- creates an evidence inventory
- creates chain-of-custody records
- records 12 initial custody events
- verifies evidence against registered hashes
- detects 1 intentionally altered artifact
- detects 1 intentionally missing artifact
- confirms 4 unchanged artifacts
- appends verification custody events
- preserves the original evidence package
- generates JSON and CSV verification reports
- validates all expected outcomes
- passes 11 of 11 validation checks
```

Use this commit message:

```text
Finalize digital evidence integrity and chain-of-custody documentation
```

After that, we can update the **root Security Operations Toolkit README** with a new **Forensic Operations** category and then make the LinkedIn post and thumbnail.
