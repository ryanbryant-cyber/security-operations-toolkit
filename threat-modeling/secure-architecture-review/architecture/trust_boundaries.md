# Northstar Customer Portal — Trust Boundary Analysis

## Purpose

A trust boundary exists whenever data or control moves between systems, identities, networks, or security zones that operate at different levels of trust.

Crossing a trust boundary does not automatically represent a vulnerability.

It indicates a location where security controls become particularly important.

The Northstar Customer Portal contains seven primary trust boundaries.

# TB-001 — Internet to Web Front End

```text
Untrusted Internet
        ↓
Web Front End
```

**Trust Change:**  
Untrusted external traffic enters an organization-controlled application.

**Data Crossing Boundary:**

- Authentication requests
- Customer input
- HTTP headers
- Session information
- Application requests
- Uploaded content

**Primary Threat Areas:**

```text
Spoofing
Tampering
Information Disclosure
Denial of Service
```

**Expected Controls:**

- HTTPS/TLS
- Web application firewall
- Input validation
- Output encoding
- Secure headers
- Rate limiting
- Bot/abuse detection
- Application logging

---

# TB-002 — Web Front End to API Gateway

```text
Web Application
        ↓
API Gateway
```

**Trust Change:**  
Presentation-layer requests enter the application's controlled API boundary.

**Data Crossing Boundary:**

- API requests
- Authentication tokens
- Object identifiers
- Customer-submitted data
- Session context

**Primary Threat Areas:**

```text
Spoofing
Tampering
Elevation of Privilege
Information Disclosure
```

**Expected Controls:**

- Token validation
- API authentication
- Authorization
- Request schema validation
- Rate limiting
- API logging
- Object-level access controls

---

# TB-003 — API/Application Layer to Data Tier

```text
Application Server
        ↓
Customer Database / Blob Storage
```

**Trust Change:**  
Application logic accesses highly sensitive persistent data.

**Data Crossing Boundary:**

- Customer records
- Billing information
- Invoice data
- Support records
- File content
- Database queries

**Primary Threat Areas:**

```text
Tampering
Information Disclosure
Elevation of Privilege
```

**Expected Controls:**

- Managed identity
- Least-privilege permissions
- Parameterized queries
- Encryption at rest
- Private endpoints
- Network restrictions
- Data-access logging

---

# TB-004 — Application to Identity Provider

```text
Customer Portal / API
        ↔
Microsoft Entra ID
```

**Trust Change:**  
The application relies on an external identity authority for authentication and security claims.

**Data Crossing Boundary:**

- Authentication requests
- Identity claims
- Access tokens
- Refresh tokens
- Authentication responses

**Primary Threat Areas:**

```text
Spoofing
Information Disclosure
Elevation of Privilege
```

**Expected Controls:**

- Strong token validation
- MFA
- Conditional Access
- Short token lifetime
- Audience validation
- Issuer validation
- Secure token storage

---

# TB-005 — Application to Third-Party Services

```text
Application Server
        ↓
Payment API / Email Service
```

**Trust Change:**  
Northstar-controlled systems communicate with external systems outside direct organizational control.

**Data Crossing Boundary:**

- API credentials
- Payment metadata
- Transaction information
- Notification data
- Customer contact information

**Primary Threat Areas:**

```text
Spoofing
Tampering
Information Disclosure
Denial of Service
```

**Expected Controls:**

- TLS
- API authentication
- Secret management
- Minimal data sharing
- Request validation
- Response validation
- Third-party monitoring
- Vendor risk management

---

# TB-006 — Administrator to Privileged Interface

```text
Administrator
        ↓
Admin Portal
```

**Trust Change:**  
A human identity enters a highly privileged application context.

**Data Crossing Boundary:**

- Administrative credentials
- MFA challenges
- Privileged session tokens
- Customer-management actions
- Account-recovery actions
- Security configuration changes

**Primary Threat Areas:**

```text
Spoofing
Repudiation
Elevation of Privilege
Information Disclosure
```

**Expected Controls:**

- Phishing-resistant MFA where feasible
- Dedicated administrator accounts
- Conditional Access
- Least privilege
- Session timeout
- Privileged-action logging
- Administrative alerts
- Separation of duties

---

# TB-007 — Production Systems to Monitoring Platform

```text
Application / API / Identity / Infrastructure
                     ↓
             Monitoring Platform
```

**Trust Change:**  
Operational systems send evidence into a security-monitoring environment relied upon for detection and investigation.

**Data Crossing Boundary:**

- Authentication events
- API logs
- Administrative activity
- Application errors
- Security events
- Access logs

**Primary Threat Areas:**

```text
Tampering
Repudiation
Information Disclosure
```

**Expected Controls:**

- Centralized logging
- Restricted log modification
- Encryption in transit
- Role-based log access
- Retention policies
- Time synchronization
- Alerting on logging failures

# Trust Boundary Summary

```text
TB-001  Internet → Web Front End
TB-002  Web Front End → API Gateway
TB-003  Application → Database / Storage
TB-004  Application → Entra ID
TB-005  Application → Third-Party Services
TB-006  Administrator → Admin Portal
TB-007  Production Systems → Monitoring Platform
```

# Security Principle

The most important concept is:

> Trust should not automatically transfer across a boundary.

For example:

```text
User successfully authenticated
        ≠
User authorized for every API object
```

and:

```text
Application server is trusted
        ≠
Application server should have unrestricted database access
```

Each boundary should independently enforce the controls appropriate to the interaction.
