# Northstar Customer Portal — Data Flow Analysis

## Purpose

This document identifies the major flows of information through the Northstar Customer Portal architecture.

A data flow describes:

```text
Who or what sends data
Where the data goes
What information crosses the connection
Why the communication occurs
Which trust boundary is crossed
Which security controls should protect the flow
```

Understanding data flows helps identify locations where information could be:

```text
Spoofed
Modified
Intercepted
Disclosed
Blocked
Misused
```

# DF-001 — Customer Authentication

```text
Customer Browser
        ↓
Web Front End
        ↓
API / Authentication Layer
        ↓
Microsoft Entra ID
```

**Purpose:**  
Authenticate a customer to the portal.

**Data Transmitted:**

- Authentication request
- Identity information
- Authentication response
- Access token
- Session information

**Trust Boundaries Crossed:**

```text
TB-001
TB-002
TB-004
```

**Primary Security Requirements:**

- TLS
- MFA where applicable
- Secure token handling
- Token issuer validation
- Token audience validation
- Secure session storage
- Authentication logging

**Major Concerns:**

```text
Credential theft
Token theft
Session hijacking
Authentication bypass
Replay
```

---

# DF-002 — Customer API Request

```text
Customer Browser
        ↓
Web Front End
        ↓
API Gateway
        ↓
Application Server
```

**Purpose:**  
Allow authenticated customers to use application functionality.

**Data Transmitted:**

- Access token
- API endpoint
- HTTP method
- Object identifiers
- Customer input
- Request parameters

**Trust Boundaries Crossed:**

```text
TB-001
TB-002
```

**Primary Security Requirements:**

- Authentication
- Object-level authorization
- Function-level authorization
- Input validation
- Rate limiting
- Request logging

**Major Concerns:**

```text
Broken object-level authorization
Injection
API abuse
Privilege escalation
Input tampering
```

---

# DF-003 — Customer Record Retrieval

```text
Application Server
        ↓
Customer Database
```

**Purpose:**  
Retrieve customer information required by portal workflows.

**Data Transmitted:**

- Customer identifiers
- Database queries
- Customer profile records
- Billing records
- Authorization information

**Trust Boundary Crossed:**

```text
TB-003
```

**Primary Security Requirements:**

- Parameterized queries
- Managed identity
- Least privilege
- Encryption in transit
- Database access logging
- Network restrictions

**Major Concerns:**

```text
SQL injection
Unauthorized queries
Data disclosure
Database tampering
```

---

# DF-004 — Invoice Retrieval

```text
Customer Request
        ↓
API Gateway
        ↓
Application Server
        ↓
Blob Storage
        ↓
Customer
```

**Purpose:**  
Allow an authorized customer to retrieve an invoice.

**Data Transmitted:**

- Customer identity
- Invoice identifier
- Authorization decision
- Invoice document

**Trust Boundaries Crossed:**

```text
TB-001
TB-002
TB-003
```

**Primary Security Requirements:**

- Authentication
- Object ownership validation
- Private storage
- Short-lived access
- Encryption
- Download logging

**Major Concerns:**

```text
Broken object-level authorization
Public storage exposure
Insecure direct object reference
Unauthorized file download
```

---

# DF-005 — Administrative Authentication

```text
Administrator
        ↓
Admin Portal
        ↓
Microsoft Entra ID
```

**Purpose:**  
Authenticate privileged users.

**Data Transmitted:**

- Administrative identity
- MFA challenge
- Authentication claims
- Privileged access token
- Session information

**Trust Boundaries Crossed:**

```text
TB-006
TB-004
```

**Primary Security Requirements:**

- Phishing-resistant MFA where feasible
- Conditional Access
- Dedicated administrative account
- Strong token controls
- Session timeout
- Privileged-session logging

**Major Concerns:**

```text
Admin credential theft
Session hijacking
MFA fatigue / social engineering
Privilege impersonation
```

---

# DF-006 — Administrative Action

```text
Administrator
        ↓
Admin Portal
        ↓
API Gateway
        ↓
Application Server
        ↓
Customer Data / Configuration
```

**Purpose:**  
Perform privileged management operations.

**Examples:**

```text
Account recovery
Customer modification
Role changes
Access management
Security configuration
```

**Trust Boundaries Crossed:**

```text
TB-006
TB-002
TB-003
```

**Primary Security Requirements:**

- Role-based access control
- Least privilege
- Server-side authorization
- Reauthentication for sensitive actions
- Immutable audit logging
- Administrative alerting

**Major Concerns:**

```text
Privilege escalation
Administrative misuse
Repudiation
Unauthorized configuration changes
```

---

# DF-007 — Payment Transaction

```text
Application Server
        ↓
Third-Party Payment API
```

**Purpose:**  
Exchange payment-related information with the external payment provider.

**Data Transmitted:**

- Transaction identifiers
- Payment metadata
- Transaction status
- API authentication information

**Trust Boundary Crossed:**

```text
TB-005
```

**Primary Security Requirements:**

- TLS
- Secure API authentication
- Secret management
- Response validation
- Request validation
- Minimal information sharing
- Transaction logging

**Major Concerns:**

```text
API credential theft
Response spoofing
Transaction tampering
Third-party compromise
Availability failure
```

---

# DF-008 — Email Notification

```text
Application Server
        ↓
Email Notification Service
        ↓
Customer
```

**Purpose:**  
Send application and security notifications.

**Data Transmitted:**

- Customer email address
- Notification information
- Support information
- Security messages

**Trust Boundary Crossed:**

```text
TB-005
```

**Primary Security Requirements:**

- Secure API credentials
- Minimal sensitive information
- TLS
- Message integrity
- Provider monitoring

**Major Concerns:**

```text
API-key theft
Notification manipulation
Sensitive information disclosure
Service compromise
```

---

# DF-009 — Security Logging

```text
Web Front End
API Gateway
Application Server
Entra ID
Admin Portal
Infrastructure
        ↓
Monitoring and Logging Platform
```

**Purpose:**  
Preserve evidence for detection, monitoring, auditing, and investigation.

**Data Transmitted:**

- Authentication events
- API activity
- Administrative actions
- Access decisions
- Application errors
- Security alerts

**Trust Boundary Crossed:**

```text
TB-007
```

**Primary Security Requirements:**

- Encryption in transit
- Centralized collection
- Accurate timestamps
- Restricted modification
- Retention
- Access control
- Logging-failure alerts

**Major Concerns:**

```text
Log deletion
Log tampering
Missing events
Sensitive-data leakage in logs
Monitoring blind spots
```

---

# DF-010 — Backup and Recovery

```text
Customer Database / Application Data
        ↓
Backup Infrastructure
```

**Purpose:**  
Preserve recoverable copies of critical application information.

**Data Transmitted:**

- Customer records
- Configuration
- Application data
- Recovery metadata

**Primary Security Requirements:**

- Encryption
- Restricted access
- Backup isolation
- Integrity validation
- Recovery testing
- Retention controls

**Major Concerns:**

```text
Backup deletion
Backup corruption
Unauthorized backup access
Ransomware impact
Recovery failure
```

# Data Flow Summary

```text
DF-001  Customer Authentication
DF-002  Customer API Request
DF-003  Customer Record Retrieval
DF-004  Invoice Retrieval
DF-005  Administrative Authentication
DF-006  Administrative Action
DF-007  Payment Transaction
DF-008  Email Notification
DF-009  Security Logging
DF-010  Backup and Recovery
```

# Data-Flow Security Principle

Each flow should answer four questions:

```text
Who initiated the communication?

What data is being transmitted?

What trust boundary is crossed?

What validates that the action should be allowed?
```

For example:

```text
Authenticated customer
        ↓
Requests invoice INV-1002
```

Authentication proves:

```text
Who the customer is
```

but object-level authorization must separately prove:

```text
That INV-1002 belongs to that customer
```

Authentication alone should never automatically imply authorization.
