# Northstar Customer Portal — Threat Modeling & Secure Architecture Review

A hands-on cybersecurity architecture project focused on identifying threats, trust boundaries, attack surfaces, security requirements, and control gaps before a fictional enterprise application is deployed.

The project applies:

- STRIDE threat modeling
- Secure architecture review
- Asset classification
- Trust-boundary analysis
- Data-flow analysis
- Qualitative risk assessment
- Control-gap analysis
- Mitigation planning
- Residual-risk analysis
- Security requirement development

The goal is to demonstrate how security can be incorporated during system design instead of relying only on detection and response after deployment.

# Project Objective

Many cybersecurity projects begin after suspicious activity has already occurred.

Threat modeling asks a different question:

> What could go wrong with this system before it is deployed, and what controls should be built into the architecture to reduce that risk?

This project performs a structured security review of a fictional customer-facing application operated by Northstar Ridge.

The completed assessment identifies:

```text
12 system components
17 protected assets
7 trust boundaries
10 major data flows
12 threat scenarios
67 security requirements
```

The analysis also evaluates:

```text
Initial risk
Existing controls
Control gaps
Recommended mitigations
Residual risk
```

# Scenario

Northstar Ridge is preparing to deploy a customer-facing web portal.

Customers can use the portal to:

- Authenticate to their accounts
- View profile information
- Access billing records
- Download invoices
- Submit support requests
- Update selected account information

Administrators use a separate privileged interface to:

- Manage customer accounts
- Perform account recovery
- Review support activity
- Manage access
- Review audit information
- Perform security administration

The application also integrates with:

- Microsoft Entra ID
- Customer database services
- Cloud blob storage
- Monitoring and logging infrastructure
- Third-party payment services
- Email notification services
- Backup infrastructure

# High-Level Architecture

```text
                              INTERNET
                                 │
                                 ▼
                       ┌─────────────────┐
                       │ Customer Browser│
                       └────────┬────────┘
                                │ HTTPS
                                ▼
                       ┌─────────────────┐
                       │  Web Front End  │
                       └────────┬────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   API Gateway   │
                       └────────┬────────┘
                                │
                ┌───────────────┼────────────────┐
                │               │                │
                ▼               ▼                ▼
        ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
        │ Application  │ │ Microsoft    │ │ Monitoring / │
        │   Server     │ │   Entra ID   │ │   Logging    │
        └──────┬───────┘ └──────────────┘ └──────────────┘
               │
       ┌───────┼──────────────┬───────────────────┐
       │       │              │                   │
       ▼       ▼              ▼                   ▼
┌────────────┐ ┌────────────┐ ┌────────────────┐ ┌───────────────┐
│ Customer   │ │   Cloud    │ │ Third-Party    │ │ Email         │
│ Database   │ │   Blob     │ │ Payment API    │ │ Notification  │
└────────────┘ └────────────┘ └────────────────┘ └───────────────┘


                       ADMINISTRATIVE PATH

                       ┌─────────────────┐
                       │  Administrator  │
                       └────────┬────────┘
                                │ MFA / HTTPS
                                ▼
                       ┌─────────────────┐
                       │  Admin Portal   │
                       └────────┬────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   API Gateway   │
                       └─────────────────┘
```

# System Components

The architecture review documents 12 primary components:

```text
COMP-001 — Customer Browser
COMP-002 — Web Front End
COMP-003 — API Gateway
COMP-004 — Application Server
COMP-005 — Microsoft Entra ID
COMP-006 — Customer Database
COMP-007 — Cloud Blob Storage
COMP-008 — Monitoring and Logging Platform
COMP-009 — Third-Party Payment API
COMP-010 — Email Notification Service
COMP-011 — Admin Portal
COMP-012 — Administrator
```

Each component is reviewed for:

```text
Purpose
Trust level
Primary functions
Security considerations
Interfaces
```

# Asset Inventory

The assessment identifies 17 protected assets.

## Critical Assets

```text
ASSET-001 — Customer Credentials
ASSET-002 — Authentication and Session Tokens
ASSET-003 — Customer PII
ASSET-007 — Administrative Credentials
ASSET-008 — Administrative Session Tokens
ASSET-009 — Application Secrets
ASSET-010 — Customer Database
ASSET-014 — API Authorization Logic
ASSET-016 — Third-Party API Credentials
```

## High-Value Assets

```text
ASSET-004 — Billing Records
ASSET-005 — Customer Invoices
ASSET-006 — Payment Metadata
ASSET-011 — Cloud Blob Storage Content
ASSET-012 — Audit Logs
ASSET-013 — Monitoring and Alerting Capability
ASSET-015 — Application Source and Configuration
ASSET-017 — Backup and Recovery Data
```

The asset inventory considers:

```text
Confidentiality
Integrity
Availability
Business impact
Security impact
Recovery requirements
```

# Trust Boundary Analysis

The architecture contains seven primary trust boundaries:

```text
TB-001 — Internet → Web Front End

TB-002 — Web Front End → API Gateway

TB-003 — Application → Database / Storage

TB-004 — Application → Microsoft Entra ID

TB-005 — Application → Third-Party Services

TB-006 — Administrator → Admin Portal

TB-007 — Production Systems → Monitoring Platform
```

The core design principle is:

> Trust should not automatically transfer across a boundary.

For example:

```text
Authenticated user
≠
Authorized for every API object
```

and:

```text
Trusted application
≠
Requires unrestricted database access
```

Each boundary should independently enforce appropriate:

```text
Authentication
Authorization
Encryption
Input validation
Least privilege
Logging
Monitoring
```

# Data Flow Analysis

The project documents 10 major application and security data flows:

```text
DF-001 — Customer Authentication
DF-002 — Customer API Request
DF-003 — Customer Record Retrieval
DF-004 — Invoice Retrieval
DF-005 — Administrative Authentication
DF-006 — Administrative Action
DF-007 — Payment Transaction
DF-008 — Email Notification
DF-009 — Security Logging
DF-010 — Backup and Recovery
```

Each flow identifies:

```text
Source
Destination
Data transmitted
Trust boundaries crossed
Required security controls
Threat considerations
```

# STRIDE Threat Modeling

The project uses the STRIDE methodology:

```text
S — Spoofing
T — Tampering
R — Repudiation
I — Information Disclosure
D — Denial of Service
E — Elevation of Privilege
```

Threat scenarios may belong to more than one STRIDE category when they affect multiple security properties.

# Threat Register

The completed threat register contains 12 scenarios.

## TM-001 — Stolen Customer Session Token

**STRIDE:** Spoofing / Information Disclosure  
**Likelihood:** Moderate  
**Impact:** High  
**Initial Risk:** High  
**Residual Risk:** Moderate

Potential impact includes:

```text
Customer impersonation
PII exposure
Billing-record access
Invoice access
```

Primary mitigations include:

- Short-lived access tokens
- Secure cookies
- Reauthentication for sensitive operations
- Conditional Access
- Session anomaly detection
- Session revocation

---

## TM-002 — Broken Object-Level Authorization

**STRIDE:** Information Disclosure / Elevation of Privilege  
**Likelihood:** High  
**Impact:** Critical  
**Initial Risk:** Critical  
**Residual Risk:** Moderate

Potential impact includes:

```text
Cross-customer data access
PII disclosure
Billing exposure
Unauthorized invoice access
```

Primary mitigations include:

- Server-side object authorization
- Ownership validation
- Deny-by-default access
- Centralized authorization middleware
- Automated authorization testing
- Monitoring of repeated denied object requests

---

## TM-003 — Sensitive Data Exposure From Cloud Blob Storage

**STRIDE:** Information Disclosure  
**Likelihood:** Moderate  
**Impact:** Critical  
**Initial Risk:** High  
**Residual Risk:** Moderate

Potential exposure includes:

```text
Invoices
Reports
Customer documents
Application exports
PII
```

Primary mitigations include:

- Disable public storage access
- Private endpoints
- Least-privilege RBAC
- Managed identities
- Short-lived direct-access tokens
- Storage configuration monitoring

---

## TM-004 — Compromised Administrative Account

**STRIDE:** Spoofing / Tampering / Elevation of Privilege  
**Likelihood:** High  
**Impact:** Critical  
**Initial Risk:** Critical  
**Residual Risk:** High

Potential impact includes:

```text
Customer account modification
Role manipulation
Account recovery abuse
Security configuration changes
Broad customer-data exposure
```

Primary mitigations include:

- Phishing-resistant MFA
- Dedicated administrative identities
- Privileged Identity Management
- Just-in-time privilege
- Managed administrative devices
- Step-up authentication
- Privileged-session monitoring

---

## TM-005 — Application Secret Exposure

**STRIDE:** Information Disclosure / Spoofing / Elevation of Privilege  
**Likelihood:** High  
**Impact:** High  
**Initial Risk:** High  
**Residual Risk:** Moderate

Potentially exposed secrets include:

```text
API keys
Client secrets
Connection strings
Service credentials
Signing secrets
```

Primary mitigations include:

- Secrets-management platform
- Managed identities
- Automated secret scanning
- Credential rotation
- Minimum required permissions
- Protected CI/CD secrets

---

## TM-006 — Audit Log Tampering or Deletion

**STRIDE:** Repudiation / Tampering  
**Likelihood:** High  
**Impact:** High  
**Initial Risk:** High  
**Residual Risk:** Low

Potential impact includes:

```text
Investigation blind spots
Loss of evidence
Reduced detection capability
Repudiation of malicious actions
```

Primary mitigations include:

- Immutable or append-only logging
- Separate logging privileges
- Independent archival copies
- Logging-interruption alerts
- Retention controls
- Log-integrity verification

---

## TM-007 — Third-Party Payment Provider Compromise

**STRIDE:** Spoofing / Tampering / Information Disclosure  
**Likelihood:** High  
**Impact:** Critical  
**Initial Risk:** Critical  
**Residual Risk:** High

Potential impact includes:

```text
Fraudulent payment status
Billing manipulation
Financial loss
Customer disputes
Payment-data exposure
```

Primary mitigations include:

- Signed callbacks
- Webhook verification
- Replay protection
- Scoped API credentials
- Transaction reconciliation
- Vendor-risk review
- Incident-notification requirements

---

## TM-008 — Application Denial of Service

**STRIDE:** Denial of Service  
**Likelihood:** High  
**Impact:** High  
**Initial Risk:** High  
**Residual Risk:** Moderate

Potential impact includes:

```text
Customer portal outage
Invoice-access disruption
Billing disruption
Support-function disruption
Downstream database exhaustion
```

Primary mitigations include:

- Managed DDoS protection
- Rate limiting
- Autoscaling
- API quotas
- Caching
- Circuit breakers
- Database connection protection

---

## TM-009 — Database Query Injection

**STRIDE:** Tampering / Information Disclosure / Elevation of Privilege  
**Likelihood:** High  
**Impact:** Critical  
**Initial Risk:** Critical  
**Residual Risk:** Moderate

Potential impact includes:

```text
Large-scale PII disclosure
Billing-record manipulation
Data corruption
Application logic bypass
Operational disruption
```

Primary mitigations include:

- Parameterized queries
- Approved ORM patterns
- Database least privilege
- SAST
- DAST
- Secure code review
- Injection monitoring

---

## TM-010 — Backup Destruction or Corruption

**STRIDE:** Tampering / Denial of Service  
**Likelihood:** High  
**Impact:** High  
**Initial Risk:** High  
**Residual Risk:** Moderate

Potential impact includes:

```text
Failed recovery
Permanent data loss
Extended outages
Greater ransomware impact
```

Primary mitigations include:

- Immutable backups
- Offline or isolated copies
- Separate backup identities
- MFA
- Deletion protection
- Recovery testing
- Automated integrity validation

---

## TM-011 — Unauthorized Privilege or Role Modification

**STRIDE:** Elevation of Privilege / Tampering / Spoofing  
**Likelihood:** High  
**Impact:** Critical  
**Initial Risk:** Critical  
**Residual Risk:** Moderate

Potential impact includes:

```text
Administrative access
Customer-account control
Security configuration access
Authorization bypass
Platform-wide privilege expansion
```

Primary mitigations include:

- Server-side privilege authorization
- Deny-by-default access
- Reauthentication
- Approval workflows
- Separation of duties
- Immutable privilege-change logging
- Recurring access reviews

---

## TM-012 — Third-Party Email Service Abuse

**STRIDE:** Spoofing / Tampering / Denial of Service  
**Likelihood:** High  
**Impact:** High  
**Initial Risk:** High  
**Residual Risk:** Moderate

Potential impact includes:

```text
Customer phishing
Fraudulent password-reset messages
Fake security alerts
Notification suppression
Brand impersonation
```

Primary mitigations include:

- Scoped service credentials
- Credential rotation
- Provider-side MFA
- SPF
- DKIM
- DMARC
- Sending anomaly detection
- Independent authentication for sensitive actions

# Initial Risk Results

Before recommended architectural controls:

```text
Critical Risks: 5
High Risks:     7
Moderate Risks: 0
Low Risks:      0
```

## Critical Initial Risks

```text
TM-002 — Broken Object-Level Authorization
TM-004 — Compromised Administrative Account
TM-007 — Third-Party Payment Provider Compromise
TM-009 — Database Query Injection
TM-011 — Unauthorized Privilege or Role Modification
```

# Residual Risk Results

After recommended controls:

```text
Critical:  0
High:      2
Moderate:  9
Low:       1
```

## Highest Residual Risks

```text
TM-004 — Compromised Administrative Account

TM-007 — Third-Party Payment Provider Compromise
```

These remain High because Northstar cannot completely eliminate:

```text
Privileged identity compromise
Human-targeted attacks
Third-party compromise
External provider dependency
```

These risks require continuing monitoring and governance rather than one-time remediation.

# Risk Reduction

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

The architecture review therefore reduces the modeled threat landscape from:

```text
5 Critical
7 High
```

to:

```text
0 Critical
2 High
9 Moderate
1 Low
```

# Security Requirements

The review produced:

```text
67 security requirements
```

across 11 control domains.

## Identity and Authentication

Includes requirements for:

```text
MFA
Phishing-resistant privileged authentication
Dedicated administrator identities
Conditional Access
Token lifetime
Step-up authentication
Session revocation
```

## Authorization

Includes:

```text
Server-side authorization
Object ownership validation
Deny-by-default access
Protected privilege changes
Approval workflows
Privilege-change auditing
```

## Application and API Security

Includes:

```text
Request validation
Parameterized queries
API rate limiting
SAST
DAST
Authorization testing
WAF defense in depth
```

## Secrets and Service Identity

Includes:

```text
Secrets management
Managed identities
Secret scanning
Credential rotation
Least-privilege service accounts
```

## Data Protection

Includes:

```text
Encryption in transit
Encryption at rest
Private cloud storage
Short-lived document access
Sensitive-data access logging
```

## Administrative Security

Includes:

```text
Least privilege
Just-in-time access
Privileged-session monitoring
High-impact action verification
Periodic access review
```

## Logging and Monitoring

Includes:

```text
Centralized logging
Immutable audit storage
Logging-failure alerts
Time synchronization
Retention requirements
```

## Availability and Resilience

Includes:

```text
Rate limiting
DDoS protection
Autoscaling
Database resource protection
Circuit breakers
```

## Backup and Recovery

Includes:

```text
Immutable recovery copies
Separate backup identities
Deletion monitoring
Recovery testing
Backup integrity validation
```

## Third-Party Security

Includes:

```text
Authenticated integrations
Signed callbacks
Replay protection
Transaction reconciliation
Scoped credentials
Vendor-risk reviews
Incident-notification requirements
```

## Email Security

Includes:

```text
Provider MFA
Scoped API credentials
SPF
DKIM
DMARC
Sending anomaly detection
Independent verification for sensitive actions
```

# Project Structure

```text
secure-architecture-review/
├── README.md
├── architecture/
│   ├── system_architecture.md
│   ├── data_flows.md
│   └── trust_boundaries.md
├── analysis/
│   ├── asset_inventory.md
│   ├── threat_register.csv
│   └── risk_matrix.md
├── controls/
│   ├── security_requirements.md
│   └── mitigation_plan.md
└── evidence/
    └── threat_model_summary.md
```

# Key Security Principles

## Authentication Is Not Authorization

Successful authentication establishes identity.

It does not automatically authorize access to every:

```text
Object
API
Function
Role
Administrative operation
```

## Trust Must Be Re-Evaluated

Every trust boundary should independently validate the communication crossing it.

## Privilege Should Be Minimal and Temporary

High-impact access should be:

```text
Narrowly scoped
Explicitly authorized
Time limited
Monitored
Reviewed
```

## Client Input Must Remain Untrusted

The application should never rely on clients to determine:

```text
Role
Ownership
Privilege
Authorization
Database behavior
```

## Logs Must Survive Compromise

Security evidence should remain trustworthy even when production systems are compromised.

## Recovery Infrastructure Is a Security Asset

Backups must be protected from the same identities and attack paths that threaten production.

## Third-Party Trust Should Be Constrained

External services should receive only the:

```text
Information
Credentials
Permissions
Trust
```

required to perform their function.

# Threat Modeling vs. Incident Investigation

This project reinforces an important distinction.

Incident investigation asks:

```text
What does the available evidence prove happened?
```

Threat modeling asks:

```text
What could happen if this threat succeeds?
```

Threat ratings therefore evaluate potential likelihood and business impact rather than assuming that an incident has already occurred.

# Skills Demonstrated

```text
Threat Modeling
STRIDE
Secure Architecture
Security Architecture Review
Trust Boundary Analysis
Data Flow Analysis
Asset Classification
Risk Assessment
Residual Risk Analysis
Security Requirements
Mitigation Planning
Application Security
API Security
Identity and Access Management
Cloud Security
Third-Party Risk
Database Security
Zero Trust
Defense in Depth
Business Continuity
Security Documentation
Security Control Design
```

# Project Guardrails

This project evaluates plausible threats against a synthetic architecture.

Identification of a threat does not mean:

```text
The weakness currently exists
The threat has occurred
The system has been compromised
```

The objective is proactive architectural risk reduction.

# Safety

All:

```text
Users
Systems
Applications
Credentials
APIs
Infrastructure
Threat scenarios
Business data
```

used in this project are synthetic.

No production organization or live system is assessed.

# Project Status

✅ **Threat Model Complete**

The completed project successfully:

- documents 12 system components
- identifies 17 protected assets
- maps 7 trust boundaries
- documents 10 major data flows
- applies STRIDE threat modeling
- evaluates 12 threat scenarios
- assigns likelihood and impact
- calculates initial qualitative risk
- identifies existing security controls
- identifies architectural control gaps
- develops threat-specific mitigations
- assigns residual-risk ratings
- reduces modeled Critical residual risk to zero
- identifies 2 remaining High residual risks
- produces 67 security requirements
- prioritizes authorization, privileged identity, application security, third-party trust, resilience, and auditability
- produces a complete executive threat-model summary
- provides a security baseline for development, testing, deployment, and future architecture review
