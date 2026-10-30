# Northstar Customer Portal — Threat Modeling & Secure Architecture Review

A hands-on cybersecurity architecture project focused on identifying threats, trust boundaries, attack surfaces, security requirements, and control gaps before a fictional enterprise application is deployed.

The project applies STRIDE threat modeling, data-flow analysis, risk assessment, and defense-in-depth principles to a synthetic customer-facing application environment.

## Project Objective

Many cybersecurity projects begin after suspicious activity has already occurred.

Threat modeling approaches the problem earlier:

> What could go wrong with this system before it is deployed, and what controls should be built into the architecture to reduce that risk?

This project demonstrates a structured security review of a fictional enterprise customer portal operated by Northstar Ridge.

The assessment will identify:

- Sensitive assets
- System components
- Users and trust levels
- Entry points
- Data flows
- Trust boundaries
- Privileged functions
- External dependencies
- Threat scenarios
- Existing controls
- Control gaps
- Recommended mitigations
- Residual risk

## Scenario

Northstar Ridge is preparing to deploy a customer-facing web portal.

Customers will use the portal to:

- Authenticate to their accounts
- View profile information
- Access billing records
- Download invoices
- Submit support requests
- Update selected account information

Administrators will use a separate privileged interface to:

- Manage customer accounts
- Review support requests
- Perform account recovery
- Manage application access
- Review security and audit information

The application also communicates with:

- Microsoft Entra ID
- Customer database services
- Cloud object storage
- Logging and monitoring infrastructure
- Third-party payment services
- Email notification services

## Planned Architecture

```text
                         INTERNET
                            │
                            ▼
                    ┌───────────────┐
                    │ Customer User │
                    └───────┬───────┘
                            │ HTTPS
                            ▼
                    ┌───────────────┐
                    │ Web Front End │
                    └───────┬───────┘
                            │
                            ▼
                    ┌───────────────┐
                    │  API Gateway  │
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
       ┌────────────┐ ┌────────────┐ ┌────────────┐
       │ App Server │ │  Entra ID  │ │ Monitoring │
       └──────┬─────┘ └────────────┘ └────────────┘
              │
      ┌───────┼───────────────┐
      ▼       ▼               ▼
┌──────────┐ ┌───────────┐ ┌──────────────┐
│ Customer │ │   Blob    │ │ Third-Party  │
│ Database │ │  Storage  │ │ Payment API  │
└──────────┘ └───────────┘ └──────────────┘


Administrator
     │
     ▼
┌───────────────┐
│  Admin Portal │
└───────┬───────┘
        │
        ▼
   API Gateway
```

## Security Domains

The assessment will evaluate security across several areas:

```text
Identity and Authentication
Authorization
Application Security
API Security
Data Protection
Cloud Security
Network Security
Administrative Access
Logging and Monitoring
Third-Party Risk
Availability
Auditability
```

## STRIDE Threat Modeling

The project will use the STRIDE framework.

```text
S — Spoofing
T — Tampering
R — Repudiation
I — Information Disclosure
D — Denial of Service
E — Elevation of Privilege
```

Each threat will be evaluated against one or more STRIDE categories.

Example:

```text
Threat:
Stolen customer session token

STRIDE:
Spoofing

Affected Component:
Customer Portal / API Gateway

Potential Impact:
Unauthorized access to customer information

Potential Controls:
Short-lived tokens
Secure cookies
MFA
Token validation
Session monitoring
Conditional Access
```

## Planned Threat Register

Threats will receive identifiers such as:

```text
TM-001
TM-002
TM-003
...
```

Each threat record will contain:

```text
Threat ID
Threat Name
STRIDE Category
Affected Component
Threat Scenario
Attack Surface
Likelihood
Impact
Initial Risk
Existing Controls
Control Gaps
Recommended Mitigations
Residual Risk
Analyst Rationale
```

## Planned Risk Model

Threats will initially be rated using:

```text
Likelihood:
Low
Moderate
High
Critical

Impact:
Low
Moderate
High
Critical
```

The assessment will then determine an overall risk level based on both likelihood and business impact.

The project will distinguish:

```text
Inherent Risk
```

from:

```text
Residual Risk
```

Inherent risk represents the exposure before recommended controls are considered.

Residual risk represents the remaining risk after appropriate controls are applied.

## Planned Trust Boundaries

The architecture contains several important trust boundaries.

Examples include:

```text
Internet → Customer Web Application

Web Front End → Internal API Layer

Application Server → Customer Database

Application → Microsoft Entra ID

Application → Cloud Storage

Application → Third-Party Payment Provider

Administrator → Privileged Administrative Functions
```

Crossing a trust boundary increases the importance of:

```text
Authentication
Authorization
Encryption
Input validation
Logging
Monitoring
Least privilege
```

## Planned Assets

The security review will consider assets such as:

```text
Customer credentials
Authentication tokens
Customer PII
Billing records
Invoices
Payment metadata
Administrative credentials
Application secrets
API credentials
Audit logs
Cloud storage content
Customer database records
```

## Planned Threat Areas

The project will evaluate scenarios including:

```text
Account impersonation
Session-token theft
Broken object-level authorization
Administrative privilege misuse
API abuse
Database tampering
Sensitive data exposure
Cloud storage misconfiguration
Application secret exposure
Third-party compromise
Insufficient audit logging
Denial-of-service conditions
```

## Security Control Categories

Recommended mitigations may include:

```text
Multi-factor authentication
Conditional Access
Role-based access control
Object-level authorization
Managed identities
Least privilege
Encryption in transit
Encryption at rest
Private endpoints
API rate limiting
Input validation
Secure secret storage
Centralized logging
Alerting
Immutable audit records
Backup and recovery
Network segmentation
Web application firewall controls
```

## Planned Project Structure

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

## Skills Demonstrated

```text
Threat Modeling
STRIDE
Secure Architecture
Security Architecture Review
Trust Boundary Analysis
Data Flow Analysis
Application Security
API Security
Identity and Access Management
Risk Assessment
Security Requirements
Defense in Depth
Zero Trust
Cloud Security
Third-Party Risk
Security Documentation
Security Control Design
```

## Analyst Guardrails

This project evaluates plausible threats against a synthetic architecture.

A threat being identified does not mean:

```text
The threat has occurred
The vulnerability has been exploited
The organization has been compromised
```

Threat modeling is a proactive risk-identification process.

The goal is to identify realistic attack paths and reduce exposure before deployment.

## Safety

All:

```text
Users
Systems
Data
Applications
Credentials
APIs
Infrastructure
Threat scenarios
```

used in this project are synthetic.

No production environment or organizational system is assessed.

## Project Status

🚧 **In Development**
