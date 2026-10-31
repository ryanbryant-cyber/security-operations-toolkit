# Northstar Customer Portal — Risk Matrix

## Purpose

This document defines the qualitative risk model used to prioritize threats identified during the Northstar Customer Portal security architecture review.

Risk is evaluated using two factors:

```text
Likelihood
+
Impact
=
Risk
```

The model is intended to support prioritization rather than provide a precise mathematical prediction.

# Likelihood Ratings

## Low

The threat is possible but requires unusual circumstances, significant attacker capability, or failure of multiple existing controls.

## Moderate

The threat is plausible and could occur under realistic conditions, but existing controls materially reduce the probability of successful exploitation.

## High

The threat is realistic and reasonably likely if an attacker deliberately targets the relevant system or weakness.

## Critical

The threat is highly probable, already broadly exposed, or expected to occur without significant additional controls.

# Impact Ratings

## Low

Successful exploitation would create limited operational, security, financial, or customer impact.

## Moderate

Successful exploitation would create meaningful impact but would remain relatively contained and recoverable.

## High

Successful exploitation could significantly affect customers, business operations, sensitive information, or security capabilities.

## Critical

Successful exploitation could cause widespread compromise, large-scale sensitive-data exposure, major financial loss, severe business disruption, or broad privileged access.

# Risk Matrix

| Likelihood ↓ / Impact → | Low | Moderate | High | Critical |
|---|---|---|---|---|
| **Low** | Low | Low | Moderate | High |
| **Moderate** | Low | Moderate | High | High |
| **High** | Moderate | High | High | Critical |
| **Critical** | High | High | Critical | Critical |

# Risk Interpretation

## Low Risk

Generally acceptable with normal operational controls and periodic review.

## Moderate Risk

Requires documented controls and monitoring. Remediation should be planned and tracked.

## High Risk

Requires prioritized mitigation, management visibility, and active monitoring.

## Critical Risk

Requires immediate architectural or security attention before the affected capability should be considered production-ready.

# Initial Threat Distribution

The threat model identified 12 primary threat scenarios.

```text
Critical Initial Risk: 5
High Initial Risk:     7
Moderate Initial Risk: 0
Low Initial Risk:      0
```

## Critical Initial Risks

```text
TM-002 — Broken Object-Level Authorization

TM-004 — Compromised Administrative Account

TM-007 — Third-Party Payment Provider Compromise

TM-009 — Database Query Injection

TM-011 — Unauthorized Privilege or Role Modification
```

## High Initial Risks

```text
TM-001 — Stolen Customer Session Token

TM-003 — Sensitive Data Exposure From Cloud Blob Storage

TM-005 — Application Secret Exposure

TM-006 — Audit Log Tampering or Deletion

TM-008 — Application Denial of Service

TM-010 — Backup Destruction or Corruption

TM-012 — Third-Party Email Service Abuse
```

# Residual Risk Distribution

After the recommended architectural controls are applied, expected residual risk becomes:

```text
High Residual Risk:      2
Moderate Residual Risk:  9
Low Residual Risk:       1
Critical Residual Risk:  0
```

## High Residual Risks

```text
TM-004 — Compromised Administrative Account

TM-007 — Third-Party Payment Provider Compromise
```

These risks remain elevated because Northstar cannot completely eliminate:

```text
Privileged identity compromise
Human-targeted attacks
External provider compromise
Third-party operational dependency
```

## Moderate Residual Risks

```text
TM-001 — Stolen Customer Session Token

TM-002 — Broken Object-Level Authorization

TM-003 — Sensitive Data Exposure From Cloud Blob Storage

TM-005 — Application Secret Exposure

TM-008 — Application Denial of Service

TM-009 — Database Query Injection

TM-010 — Backup Destruction or Corruption

TM-011 — Unauthorized Privilege or Role Modification

TM-012 — Third-Party Email Service Abuse
```

## Low Residual Risk

```text
TM-006 — Audit Log Tampering or Deletion
```

Immutable logging, separated privileges, retention controls, and independent archival copies substantially reduce the likelihood that an attacker could successfully erase investigative evidence.

# Risk Reduction Summary

```text
Threat   Initial    Residual
TM-001   High       Moderate
TM-002   Critical   Moderate
TM-003   High       Moderate
TM-004   Critical   High
TM-005   High       Moderate
TM-006   High       Low
TM-007   Critical   High
TM-008   High       Moderate
TM-009   Critical   Moderate
TM-010   High       Moderate
TM-011   Critical   Moderate
TM-012   High       Moderate
```

# Priority Treatment Areas

## Priority 1 — Authorization

Relevant threats:

```text
TM-002
TM-011
```

Required focus:

- Server-side authorization
- Object ownership validation
- Role protection
- Deny-by-default access
- Privilege-change controls

## Priority 2 — Privileged Identity

Relevant threat:

```text
TM-004
```

Required focus:

- Phishing-resistant MFA
- Privileged Identity Management
- Just-in-time access
- Managed administrative workstations
- Privileged-session monitoring

## Priority 3 — Application and Database Security

Relevant threats:

```text
TM-005
TM-009
```

Required focus:

- Secrets management
- Managed identities
- Parameterized queries
- Least-privilege database access
- SAST / DAST
- Secure code review

## Priority 4 — Third-Party Risk

Relevant threats:

```text
TM-007
TM-012
```

Required focus:

- Credential scoping
- Cryptographic verification
- Transaction reconciliation
- Provider monitoring
- Vendor-risk governance
- Incident-notification requirements

## Priority 5 — Resilience and Auditability

Relevant threats:

```text
TM-006
TM-008
TM-010
```

Required focus:

- Immutable logging
- DDoS protection
- Resource controls
- Backup isolation
- Immutable recovery copies
- Recovery testing

# Risk Management Principle

Risk reduction does not require eliminating every possible threat.

The goal is to:

```text
Reduce likelihood
Reduce impact
Improve detection
Limit blast radius
Improve recovery
```

until remaining exposure is understood, documented, monitored, and accepted by the appropriate business owner.
