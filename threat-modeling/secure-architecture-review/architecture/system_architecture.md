# Northstar Customer Portal — System Architecture

## Architecture Purpose

This document defines the components, security roles, interfaces, and major communication paths used in the fictional Northstar Ridge Customer Portal.

The architecture provides the technical foundation for the STRIDE threat model and secure architecture review.

The system is designed as a customer-facing web application with separate privileged administrative functionality and integrations with identity, storage, monitoring, database, payment, and notification services.

## High-Level Architecture

```text
                              INTERNET
                                 │
                     HTTPS / Public Network
                                 │
                                 ▼
                       ┌─────────────────┐
                       │ Customer Browser │
                       └────────┬────────┘
                                │
                                │ HTTPS
                                ▼
                       ┌─────────────────┐
                       │  Web Front End  │
                       └────────┬────────┘
                                │
                                │ HTTPS / API Requests
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
│            │ │  Storage   │ │                │ │ Service       │
└────────────┘ └────────────┘ └────────────────┘ └───────────────┘


                       ADMINISTRATIVE PATH

                       ┌─────────────────┐
                       │  Administrator  │
                       └────────┬────────┘
                                │
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

# Component Inventory

## COMP-001 — Customer Browser

**Purpose:**  
Provides the customer-facing interface used to access the Northstar Ridge portal.

**Trust Level:**  
Untrusted external client.

**Primary Functions:**

- Customer authentication
- Account viewing
- Profile updates
- Invoice downloads
- Billing review
- Support-request submission

**Security Considerations:**

- User-controlled input
- Browser compromise
- Session-token exposure
- Cross-site scripting
- Credential theft
- Malicious or automated requests

**Primary Interfaces:**

```text
Customer Browser
        ↓ HTTPS
Web Front End
```

---

## COMP-002 — Web Front End

**Purpose:**  
Provides the public application interface presented to customers.

**Trust Level:**  
Internet-facing application tier.

**Primary Functions:**

- Application presentation
- Session interaction
- User-input collection
- API request generation
- Customer workflow presentation

**Security Considerations:**

- Input validation
- Output encoding
- Secure session handling
- Content Security Policy
- TLS enforcement
- Web application firewall protection
- Dependency security

**Primary Interfaces:**

```text
Customer Browser
        ↕
Web Front End
        ↕
API Gateway
```

---

## COMP-003 — API Gateway

**Purpose:**  
Acts as the controlled entry point for application API requests.

**Trust Level:**  
Security-sensitive boundary component.

**Primary Functions:**

- API routing
- Authentication enforcement
- Token validation
- Request filtering
- Rate limiting
- Request logging
- Policy enforcement

**Security Considerations:**

- Broken authentication
- Broken authorization
- Token validation
- API abuse
- Rate exhaustion
- Improper routing
- Injection
- Inadequate logging

**Primary Interfaces:**

```text
Web Front End
Admin Portal
        ↓
API Gateway
        ↓
Application Server
```

---

## COMP-004 — Application Server

**Purpose:**  
Hosts business logic used by the customer portal and administrative functionality.

**Trust Level:**  
Trusted internal application tier.

**Primary Functions:**

- Business logic
- Authorization decisions
- Database interaction
- Storage access
- Payment integration
- Notification requests

**Security Considerations:**

- Server-side authorization
- Input validation
- Secret management
- Service identity
- Dependency vulnerabilities
- Application compromise
- Excessive permissions

---

## COMP-005 — Microsoft Entra ID

**Purpose:**  
Provides identity and authentication services.

**Trust Level:**  
Trusted external identity provider.

**Primary Functions:**

- User authentication
- Administrator authentication
- MFA
- Conditional Access
- Identity claims
- Token issuance

**Security Considerations:**

- Credential compromise
- Token theft
- Weak MFA configuration
- Excessive token lifetime
- Misconfigured Conditional Access
- Privileged account compromise

---

## COMP-006 — Customer Database

**Purpose:**  
Stores structured customer and business information.

**Trust Level:**  
Highly trusted data tier.

**Stored Information May Include:**

- Customer profile information
- Account identifiers
- Billing information
- Support records
- Application state
- Authorization-related data

**Security Considerations:**

- Unauthorized queries
- Injection
- Excessive application permissions
- Sensitive-data disclosure
- Data tampering
- Backup exposure
- Database credential compromise

---

## COMP-007 — Cloud Blob Storage

**Purpose:**  
Stores customer-accessible and application-generated file content.

**Trust Level:**  
Trusted cloud data service.

**Stored Information May Include:**

- Customer invoices
- Downloadable documents
- Generated reports
- Application exports

**Security Considerations:**

- Public container exposure
- Incorrect access-control configuration
- Shared-access-token exposure
- Sensitive-file disclosure
- Excessive service permissions
- Missing encryption controls

---

## COMP-008 — Monitoring and Logging Platform

**Purpose:**  
Collects security, application, authentication, administrative, and infrastructure telemetry.

**Trust Level:**  
Trusted security monitoring tier.

**Primary Functions:**

- Audit logging
- Security monitoring
- Alert generation
- Administrative activity tracking
- Incident investigation support

**Security Considerations:**

- Log tampering
- Missing audit events
- Excessive log access
- Sensitive data stored in logs
- Insufficient retention
- Monitoring blind spots

---

## COMP-009 — Third-Party Payment API

**Purpose:**  
Provides external payment-processing functionality.

**Trust Level:**  
External trusted dependency.

**Primary Functions:**

- Payment transaction processing
- Payment-status communication
- Transaction metadata exchange

**Security Considerations:**

- Third-party compromise
- API credential exposure
- Webhook spoofing
- Transaction tampering
- Availability dependency
- Supply-chain risk

Northstar Ridge does not directly control the security architecture of this external provider.

---

## COMP-010 — Email Notification Service

**Purpose:**  
Sends transactional and security-related email messages.

**Trust Level:**  
External service dependency.

**Primary Functions:**

- Account notifications
- Security notifications
- Support updates
- Customer communication

**Security Considerations:**

- API-key exposure
- Email spoofing
- Account takeover
- Notification tampering
- Third-party availability

---

## COMP-011 — Admin Portal

**Purpose:**  
Provides privileged application-management functionality.

**Trust Level:**  
High-trust privileged interface.

**Primary Functions:**

- Customer administration
- Account recovery
- Support-case review
- Access management
- Audit review
- Security administration

**Security Considerations:**

- Privilege escalation
- Administrative credential compromise
- Session hijacking
- Excessive privileges
- Missing MFA
- Inadequate separation of duties
- Administrative action repudiation

---

## COMP-012 — Administrator

**Purpose:**  
Represents authorized personnel who manage the platform.

**Trust Level:**  
Privileged human identity.

**Security Expectations:**

- MFA required
- Dedicated administrative identity
- Least privilege
- Privileged-session monitoring
- Administrative actions logged
- Conditional Access
- Strong account-recovery controls

# Primary Data Types

The architecture handles several categories of sensitive information.

```text
Customer PII
Authentication tokens
Account identifiers
Billing records
Invoices
Payment metadata
Support records
Administrative activity
Audit logs
Application secrets
API credentials
```

# Privileged Operations

Operations requiring elevated trust include:

```text
Customer account modification
Account recovery
Role or access changes
Administrative user management
Audit review
Application configuration changes
Security-control modification
```

These functions should not rely solely on successful authentication.

They also require strong:

```text
Authorization
Least privilege
Audit logging
Session security
Monitoring
```

# Security Architecture Principles

The proposed design should follow:

```text
Least privilege
Defense in depth
Zero Trust principles
Explicit authorization
Strong identity verification
Secure-by-default configuration
Encryption in transit
Encryption at rest
Centralized logging
Separation of duties
Controlled external integrations
```

# Architecture Review Status

This architecture represents the **initial system design** used for threat modeling.

The next stages of the project will identify:

```text
Trust boundaries
Data flows
Threat scenarios
Control gaps
Security requirements
Recommended mitigations
Residual risk
```
