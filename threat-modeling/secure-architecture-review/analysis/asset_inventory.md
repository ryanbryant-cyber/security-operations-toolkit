# Northstar Customer Portal — Asset Inventory

## Purpose

This document identifies the information, identities, credentials, services, and operational records that require protection within the Northstar Customer Portal.

An asset is anything whose loss, unauthorized disclosure, alteration, destruction, or misuse could negatively affect:

- Customers
- Business operations
- Security
- Compliance
- Financial activity
- Availability
- Investigation capability

Asset identification helps determine the potential impact of later threat scenarios.

# Asset Classification Model

Assets are assigned one of four business-impact levels:

```text
Critical
High
Moderate
Low
```

## Critical

Loss or compromise could cause severe business, security, financial, or customer impact.

## High

Loss or compromise could significantly affect customers, operations, security, or regulatory obligations.

## Moderate

Loss or compromise would create operational or security impact but would likely remain manageable.

## Low

Loss or compromise would have limited direct business impact.

# Asset Inventory

## ASSET-001 — Customer Credentials

**Classification:** Critical

**Description:**  
Authentication information used by customers to access the portal.

**Examples:**

```text
Passwords
Authentication secrets
Recovery information
```

**Primary Security Requirements:**

```text
Confidentiality
Integrity
```

**Potential Impact if Compromised:**

- Account takeover
- Unauthorized customer access
- Fraud
- Privacy exposure

**Primary Components:**

```text
Customer Browser
Entra ID
Authentication Services
```

---

## ASSET-002 — Authentication and Session Tokens

**Classification:** Critical

**Description:**  
Tokens used to represent authenticated customer or administrator sessions.

**Examples:**

```text
Access tokens
Refresh tokens
Session cookies
Administrative session tokens
```

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Limited lifetime
Correct audience and issuer validation
```

**Potential Impact if Compromised:**

- Session hijacking
- User impersonation
- Privileged access
- Unauthorized API activity

---

## ASSET-003 — Customer Personally Identifiable Information

**Classification:** Critical

**Description:**  
Information identifying or describing Northstar Ridge customers.

**Examples:**

```text
Name
Address
Email
Phone number
Account identifiers
Profile information
```

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
```

**Potential Impact if Compromised:**

- Privacy breach
- Identity theft
- Regulatory consequences
- Customer harm
- Reputational damage

---

## ASSET-004 — Billing Records

**Classification:** High

**Description:**  
Structured billing information associated with customer accounts.

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
```

**Potential Impact if Compromised:**

- Billing manipulation
- Financial disputes
- Customer privacy exposure
- Business disruption

---

## ASSET-005 — Customer Invoices

**Classification:** High

**Description:**  
Customer financial documents stored in cloud object storage and retrieved through the portal.

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
```

**Potential Impact if Compromised:**

- Unauthorized financial disclosure
- Invoice tampering
- Customer-data exposure

---

## ASSET-006 — Payment Metadata

**Classification:** High

**Description:**  
Information exchanged with the third-party payment provider.

**Examples:**

```text
Transaction identifiers
Payment status
Payment reference information
```

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
```

**Potential Impact if Compromised:**

- Transaction tampering
- Fraud
- Payment disruption
- Financial reconciliation problems

---

## ASSET-007 — Administrative Credentials

**Classification:** Critical

**Description:**  
Credentials and authentication material belonging to privileged Northstar administrators.

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Strong authentication
```

**Potential Impact if Compromised:**

- Privilege escalation
- Customer-account manipulation
- Security-control modification
- Broad application compromise

---

## ASSET-008 — Administrative Session Tokens

**Classification:** Critical

**Description:**  
Session tokens providing access to privileged administrative functionality.

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Short lifetime
Strong session controls
```

**Potential Impact if Compromised:**

- Privileged session hijacking
- Unauthorized administrative activity
- Account modification
- Security-control bypass

---

## ASSET-009 — Application Secrets

**Classification:** Critical

**Description:**  
Secrets used by applications and integrations.

**Examples:**

```text
API keys
Client secrets
Connection strings
Service credentials
Signing secrets
```

**Primary Security Requirements:**

```text
Confidentiality
Controlled access
Rotation
```

**Potential Impact if Compromised:**

- Unauthorized service access
- External API abuse
- Database compromise
- Cloud-resource compromise

---

## ASSET-010 — Customer Database

**Classification:** Critical

**Description:**  
Primary structured data store for customer and application information.

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
Backup and recovery
```

**Potential Impact if Compromised:**

- Large-scale customer-data disclosure
- Data manipulation
- Application outage
- Business disruption

---

## ASSET-011 — Cloud Blob Storage Content

**Classification:** High

**Description:**  
Files stored for customer retrieval and application workflows.

**Examples:**

```text
Invoices
Reports
Exports
Customer documents
```

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
```

**Potential Impact if Compromised:**

- Public exposure
- Unauthorized downloads
- Document tampering

---

## ASSET-012 — Audit Logs

**Classification:** High

**Description:**  
Security and operational records used to reconstruct activity.

**Examples:**

```text
Authentication logs
API activity
Administrative actions
Security alerts
Application errors
Access events
```

**Primary Security Requirements:**

```text
Integrity
Availability
Controlled access
Retention
```

**Potential Impact if Compromised:**

- Loss of investigation evidence
- Repudiation
- Detection blind spots
- Concealment of malicious activity

---

## ASSET-013 — Monitoring and Alerting Capability

**Classification:** High

**Description:**  
The ability to detect and investigate suspicious activity across the environment.

**Primary Security Requirements:**

```text
Availability
Integrity
Coverage
```

**Potential Impact if Compromised:**

- Delayed detection
- Reduced incident visibility
- Extended attacker dwell time

---

## ASSET-014 — API Authorization Logic

**Classification:** Critical

**Description:**  
Application logic that determines whether authenticated users are permitted to access resources or perform functions.

**Primary Security Requirements:**

```text
Integrity
Correctness
Consistency
```

**Potential Impact if Compromised:**

- Broken object-level authorization
- Privilege escalation
- Unauthorized administrative actions
- Cross-customer data access

---

## ASSET-015 — Application Source and Configuration

**Classification:** High

**Description:**  
Application code and configuration controlling business and security behavior.

**Primary Security Requirements:**

```text
Integrity
Controlled access
Version control
```

**Potential Impact if Compromised:**

- Backdoors
- Security-control weakening
- Data exposure
- Application failure

---

## ASSET-016 — Third-Party API Credentials

**Classification:** Critical

**Description:**  
Credentials used to authenticate Northstar systems to payment and email providers.

**Primary Security Requirements:**

```text
Confidentiality
Rotation
Least privilege
```

**Potential Impact if Compromised:**

- Fraudulent API activity
- Notification abuse
- Payment-service misuse
- Third-party account compromise

---

## ASSET-017 — Backup and Recovery Data

**Classification:** High

**Description:**  
Copies of data and configuration needed to recover from failure or destructive incidents.

**Primary Security Requirements:**

```text
Confidentiality
Integrity
Availability
Isolation
```

**Potential Impact if Compromised:**

- Failed recovery
- Data loss
- Ransomware impact
- Extended outage

# Asset Summary

```text
ASSET-001  Customer Credentials                Critical
ASSET-002  Authentication / Session Tokens     Critical
ASSET-003  Customer PII                        Critical
ASSET-004  Billing Records                     High
ASSET-005  Customer Invoices                   High
ASSET-006  Payment Metadata                    High
ASSET-007  Administrative Credentials          Critical
ASSET-008  Administrative Session Tokens       Critical
ASSET-009  Application Secrets                 Critical
ASSET-010  Customer Database                   Critical
ASSET-011  Blob Storage Content                High
ASSET-012  Audit Logs                          High
ASSET-013  Monitoring / Alerting Capability    High
ASSET-014  API Authorization Logic             Critical
ASSET-015  Application Source / Configuration  High
ASSET-016  Third-Party API Credentials         Critical
ASSET-017  Backup / Recovery Data              High
```

# Asset Review Principle

The classification assigned to an asset affects how seriously later threats against that asset should be treated.

For example:

```text
Threat against public UI content
```

may have lower business impact than:

```text
Threat against administrative credentials
```

even if the technical attack method is similar.

Threat severity should therefore consider both:

```text
Attack likelihood
+
Asset impact
```
