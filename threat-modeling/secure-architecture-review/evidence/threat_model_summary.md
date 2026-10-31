# Northstar Customer Portal — Threat Model Summary

## Executive Summary

A security architecture review was performed for the fictional Northstar Ridge Customer Portal before deployment.

The assessment used:

```text
System architecture analysis
Asset identification
Trust-boundary analysis
Data-flow analysis
STRIDE threat modeling
Qualitative risk assessment
Control-gap analysis
Security requirement development
Residual-risk analysis
```

The purpose was to identify realistic security weaknesses before deployment and determine which architectural controls should be incorporated into the design.

# Environment Reviewed

The modeled environment includes:

```text
Customer Browser
Web Front End
API Gateway
Application Server
Microsoft Entra ID
Customer Database
Cloud Blob Storage
Monitoring and Logging Platform
Third-Party Payment API
Email Notification Service
Admin Portal
Privileged Administrators
Backup Infrastructure
```

# Architecture Analysis

The review documented:

```text
12 primary system components
17 protected assets
7 trust boundaries
10 major data flows
12 threat scenarios
67 security requirements
```

# STRIDE Methodology

Threat scenarios were categorized using STRIDE:

```text
S — Spoofing
T — Tampering
R — Repudiation
I — Information Disclosure
D — Denial of Service
E — Elevation of Privilege
```

Multiple STRIDE categories were assigned where a threat affected more than one security property.

# Threat Register

The assessment identified:

```text
TM-001 — Stolen Customer Session Token

TM-002 — Broken Object-Level Authorization

TM-003 — Sensitive Data Exposure From Cloud Blob Storage

TM-004 — Compromised Administrative Account

TM-005 — Application Secret Exposure

TM-006 — Audit Log Tampering or Deletion

TM-007 — Third-Party Payment Provider Compromise

TM-008 — Application Denial of Service

TM-009 — Database Query Injection

TM-010 — Backup Destruction or Corruption

TM-011 — Unauthorized Privilege or Role Modification

TM-012 — Third-Party Email Service Abuse
```

# Initial Risk Results

Before additional architectural controls were considered:

```text
Critical Risks: 5
High Risks:     7
```

No identified threat began below High risk.

The Critical threats were:

```text
TM-002 — Broken Object-Level Authorization
TM-004 — Compromised Administrative Account
TM-007 — Third-Party Payment Provider Compromise
TM-009 — Database Query Injection
TM-011 — Unauthorized Privilege or Role Modification
```

# Highest-Priority Findings

## Authorization Enforcement

Object and role authorization represented one of the most significant architectural concerns.

The review identified the need to independently verify:

```text
Who the user is
```

and:

```text
What that user is allowed to access or change
```

Authentication must not automatically imply authorization.

Recommended architecture requires:

- Server-side authorization
- Object ownership validation
- Deny-by-default access
- Protected role management
- Privilege-change auditing
- Automated authorization testing

## Privileged Identity Security

Administrative identity compromise remains one of the highest residual risks.

Recommended controls include:

- Phishing-resistant MFA
- Dedicated administrator identities
- Conditional Access
- Just-in-time privilege
- Privileged Identity Management
- Managed administrative devices
- Step-up authentication
- Privileged-session monitoring

## Database and Application Security

Database query injection and application-secret exposure were identified as significant application-layer threats.

Recommended controls include:

- Parameterized database queries
- Database least privilege
- Managed identities
- Centralized secret storage
- Secret scanning
- SAST
- DAST
- Secure code review

## Third-Party Dependency Risk

The payment and email providers create trust relationships outside Northstar's direct control.

Recommended protections include:

- Strong API authentication
- Scoped credentials
- Credential rotation
- Signed callbacks
- Replay protection
- Independent transaction reconciliation
- Provider monitoring
- Vendor-risk review
- Incident-notification requirements

## Resilience

Availability and recoverability require protection beyond ordinary application controls.

Recommended controls include:

- Managed DDoS protection
- Rate limiting
- Resource quotas
- Autoscaling
- Circuit breakers
- Immutable backups
- Isolated recovery copies
- Recovery testing

## Auditability

Security evidence must remain trustworthy even when production systems are compromised.

Recommended controls include:

- Centralized logging
- Immutable or append-only storage
- Separate logging privileges
- Independent archival copies
- Retention requirements
- Logging-interruption alerts
- Time synchronization

# Security Requirements

The review produced:

```text
67 security requirements
```

covering:

```text
Identity and Authentication
Authorization
Application and API Security
Secrets and Service Identity
Data Protection
Administrative Security
Logging and Monitoring
Availability and Resilience
Backup and Recovery
Third-Party Security
Email Security
```

# Residual Risk

After recommended controls are applied:

```text
Critical:  0
High:      2
Moderate:  9
Low:       1
```

The remaining High risks are:

```text
TM-004 — Compromised Administrative Account

TM-007 — Third-Party Payment Provider Compromise
```

These remain elevated because privileged identities and external providers cannot be completely controlled through technical architecture alone.

They require continuing:

```text
Monitoring
Access review
Threat detection
Vendor governance
Incident preparedness
Management oversight
```

# Risk Reduction

Initial:

```text
5 Critical
7 High
```

Expected residual:

```text
0 Critical
2 High
9 Moderate
1 Low
```

The architecture therefore demonstrates substantial risk reduction while acknowledging that secure design does not eliminate all risk.

# Key Security Principles

## Authentication Is Not Authorization

A valid identity does not automatically have permission to access every resource.

## Trust Must Be Re-Evaluated at Boundaries

Trust should not automatically transfer from one component or security zone to another.

## Privilege Should Be Temporary and Minimal

Administrative access should be narrowly scoped and activated only when required.

## Client Input Is Untrusted

Authorization, role information, object ownership, and database commands must be validated server-side.

## Security Evidence Must Survive Compromise

Audit logs should remain trustworthy even if production systems are compromised.

## Recovery Infrastructure Is a Security Asset

Backups must be protected from the same credentials and attack paths that threaten production systems.

## Third-Party Trust Must Be Constrained

External providers should receive only the permissions and information required to perform their function.

# Analyst Guardrails

The project identifies plausible threats against a synthetic architecture.

The presence of a threat scenario does not mean:

```text
The vulnerability currently exists
The attack has occurred
The system has been compromised
```

Threat modeling evaluates potential exposure before deployment so controls can be incorporated proactively.

# Final Assessment

The proposed Northstar Customer Portal architecture can be substantially hardened through layered controls across identity, authorization, application security, data protection, monitoring, resilience, and third-party integrations.

The most important architectural priorities are:

```text
1. Strong server-side authorization
2. Privileged identity protection
3. Secure application and database development
4. Controlled third-party trust
5. Protected logging and recovery infrastructure
6. Continuous monitoring and validation
```

The completed threat model provides a security baseline that can be used during:

```text
Design review
Development
Security testing
Deployment approval
Operational monitoring
Future architecture changes
```

# Project Conclusion

Threat modeling shifts security from:

```text
Detecting problems after they occur
```

toward:

```text
Designing systems so important attack paths are harder to exploit
```

The Northstar Customer Portal review demonstrates how architecture, assets, trust boundaries, data flows, STRIDE analysis, risk assessment, and mitigation planning can be combined into a practical secure-design process.
