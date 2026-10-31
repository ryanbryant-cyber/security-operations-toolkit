# Northstar Customer Portal — Threat Mitigation Plan

## Purpose

This document translates the Northstar Customer Portal threat register into specific architectural security improvements.

For each threat, the review identifies:

- Existing security controls
- Remaining control gaps
- Recommended mitigations
- Expected residual risk after mitigation

Residual risk represents the level of risk expected to remain after the recommended controls are implemented effectively.

---

# TM-001 — Stolen Customer Session Token

**Initial Risk:** High

## Existing Controls

- HTTPS/TLS
- Microsoft Entra ID authentication
- Token validation
- MFA where applicable
- API logging

## Control Gaps

- Token lifetime may be longer than necessary
- No guaranteed continuous session evaluation
- No guaranteed step-up authentication
- Limited session anomaly detection
- Client-side token handling may expose session material

## Recommended Mitigations

- Use short-lived access tokens
- Secure session cookies using `Secure`, `HttpOnly`, and appropriate `SameSite` controls
- Avoid persistent storage of sensitive tokens in browser-accessible locations
- Require reauthentication for sensitive actions
- Implement session anomaly detection
- Use Conditional Access and risk-based authentication
- Revoke sessions following significant identity-risk events
- Monitor token reuse from unusual locations or devices

## Residual Risk

```text
Moderate
```

## Rationale

Strong session controls significantly reduce the usefulness and lifetime of a stolen token, but session theft cannot be eliminated completely because customer endpoints and browsers remain outside Northstar's full control.

---

# TM-002 — Broken Object-Level Authorization

**Initial Risk:** Critical

## Existing Controls

- User authentication
- API Gateway
- Token validation
- Application logging

## Control Gaps

- Authentication may be trusted without verifying object ownership
- Predictable object identifiers may enable enumeration
- Authorization enforcement may vary between endpoints
- Object permissions may depend on client-supplied identifiers

## Recommended Mitigations

- Perform server-side object authorization on every protected request
- Resolve object ownership from trusted server-side data
- Deny access by default
- Never rely on hidden fields or UI restrictions for authorization
- Implement centralized authorization middleware
- Add automated authorization tests
- Monitor repeated denied object requests
- Use indirect or nonpredictable identifiers where appropriate
- Review API endpoints specifically for BOLA exposure

## Residual Risk

```text
Moderate
```

## Rationale

Consistent server-side ownership validation significantly reduces the likelihood of cross-customer access. Residual risk remains because authorization defects may be introduced during future application changes.

---

# TM-003 — Sensitive Data Exposure From Cloud Blob Storage

**Initial Risk:** High

## Existing Controls

- HTTPS/TLS
- Encryption at rest
- Application-controlled access

## Control Gaps

- Public-access prevention is not guaranteed
- Storage permissions may be overly broad
- Shared-access tokens may remain valid too long
- Direct storage URLs may bypass application authorization
- Storage configuration monitoring is not guaranteed

## Recommended Mitigations

- Disable public container and blob access
- Use private endpoints where appropriate
- Apply least-privilege storage RBAC
- Prefer managed identities over static storage credentials
- Use short-lived signed access where direct download is required
- Restrict access by network and service identity
- Enable storage access logging
- Continuously monitor storage configuration
- Alert on public-access or permission changes

## Residual Risk

```text
Moderate
```

## Rationale

Private access, least privilege, managed identity, and configuration monitoring substantially reduce exposure, although cloud configuration errors remain possible.

---

# TM-004 — Compromised Administrative Account

**Initial Risk:** Critical

## Existing Controls

- MFA
- Conditional Access
- Dedicated administrative identities
- Administrative logging
- Least-privilege principles

## Control Gaps

- Phishing-resistant MFA is not guaranteed
- Privileges may be permanently assigned
- Sensitive actions may not require reauthentication
- Administrator endpoints may be accessible from unmanaged systems
- Privileged-session monitoring may be incomplete

## Recommended Mitigations

- Require phishing-resistant MFA for privileged identities
- Use Privileged Identity Management or just-in-time privilege
- Restrict privileged access to managed administrative workstations
- Require step-up authentication for highly sensitive actions
- Separate normal and administrative identities
- Apply Conditional Access to privileged sessions
- Monitor privileged role activation and use
- Alert on unusual administrator geography, devices, and behavior
- Perform frequent privileged-access reviews

## Residual Risk

```text
High
```

## Rationale

Privileged accounts remain high-value targets even after strong controls are implemented. The probability can be significantly reduced, but successful compromise would still carry substantial impact.

---

# TM-005 — Application Secret Exposure

**Initial Risk:** High

## Existing Controls

- Access controls
- TLS
- Service authentication
- Version control

## Control Gaps

- Secrets may exist in code or configuration
- Secret scanning is not guaranteed
- Credentials may be long-lived
- Rotation may be manual
- Applications may use static credentials where managed identity is possible

## Recommended Mitigations

- Store secrets in an approved secrets-management platform
- Prefer managed identities and workload identities
- Enable automated repository secret scanning
- Prevent secrets from appearing in application logs
- Rotate exposed or long-lived credentials
- Scope credentials to the minimum required permissions
- Use short-lived credentials where supported
- Protect CI/CD variables and deployment secrets
- Monitor use of sensitive service credentials

## Residual Risk

```text
Moderate
```

## Rationale

Centralized secrets management, automated scanning, and workload identity greatly reduce exposure, although secrets may still exist for integrations that do not support stronger identity mechanisms.

---

# TM-006 — Audit Log Tampering or Deletion

**Initial Risk:** High

## Existing Controls

- Centralized logging
- Restricted log access
- Retention controls
- Encryption in transit
- Security monitoring

## Control Gaps

- Logs may remain modifiable
- Logging administration may overlap with production administration
- Independent archival copies are not guaranteed
- Deletion events may not generate alerts

## Recommended Mitigations

- Store security logs in immutable or append-only storage
- Separate logging administration from production administration
- Restrict deletion permissions
- Maintain independent archival copies
- Alert on logging interruption, retention changes, or deletion attempts
- Synchronize system clocks
- Monitor privileged access to logging infrastructure
- Define minimum retention requirements
- Periodically verify log completeness and integrity

## Residual Risk

```text
Low
```

## Rationale

Independent, immutable log storage and separated privileges make evidence destruction significantly more difficult, although complete prevention cannot be guaranteed for every telemetry source.

---

# TM-007 — Third-Party Payment Provider Compromise

**Initial Risk:** Critical

## Existing Controls

- TLS
- API authentication
- Request validation
- Response validation
- Transaction logging
- Vendor risk management

## Control Gaps

- Signed callbacks are not guaranteed
- Replay protection may be incomplete
- Transaction state may rely too heavily on provider responses
- API credentials may be broadly scoped
- Independent transaction reconciliation is not guaranteed

## Recommended Mitigations

- Cryptographically verify payment callbacks
- Implement webhook signatures and timestamp validation
- Reject replayed transactions
- Use narrowly scoped API credentials
- Rotate integration credentials
- Reconcile provider transactions against internal records
- Alert on unusual refund or status-change patterns
- Maintain vendor incident-notification requirements
- Develop payment-provider outage and compromise procedures
- Perform recurring third-party risk reviews

## Residual Risk

```text
High
```

## Rationale

Northstar can strongly validate and constrain its integration, but it cannot eliminate risk originating inside a third-party provider. Significant residual supply-chain risk remains.

---

# TM-008 — Application Denial of Service

**Initial Risk:** High

## Existing Controls

- API Gateway
- Rate limiting
- Monitoring
- Cloud infrastructure

## Control Gaps

- Dedicated DDoS protection is not guaranteed
- Autoscaling behavior is undefined
- Expensive application functions may remain abuseable
- Database connection exhaustion may propagate downstream
- Per-user and per-IP quotas may be incomplete

## Recommended Mitigations

- Implement managed DDoS protection
- Configure autoscaling with safe upper limits
- Apply rate limits by IP, identity, token, and endpoint
- Cache frequently requested content
- Implement circuit breakers and timeouts
- Protect database connection pools
- Limit expensive queries and operations
- Define API quotas
- Alert on abnormal traffic spikes
- Maintain availability and capacity-response procedures

## Residual Risk

```text
Moderate
```

## Rationale

Layered availability controls make resource exhaustion more difficult and improve resilience, although large distributed attacks can still degrade service.

---

# TM-009 — Database Query Injection

**Initial Risk:** Critical

## Existing Controls

- Input validation
- API Gateway
- Application tier
- Database access controls

## Control Gaps

- Parameterized queries are not guaranteed everywhere
- Database identities may possess excessive permissions
- Automated application-security testing is not guaranteed
- Injection-specific protections may be inconsistent

## Recommended Mitigations

- Require parameterized queries or approved ORM patterns
- Prohibit dynamic query construction from untrusted input
- Apply least-privilege database identities
- Validate input using allowlists where practical
- Perform secure code review
- Integrate SAST into development pipelines
- Conduct DAST against test environments
- Use WAF protections as defense in depth
- Monitor anomalous database queries
- Separate application database roles by function

## Residual Risk

```text
Moderate
```

## Rationale

Parameterized queries and database least privilege significantly reduce injection risk. Residual risk remains primarily from development defects or future unsafe code changes.

---

# TM-010 — Backup Destruction or Corruption

**Initial Risk:** High

## Existing Controls

- Backup infrastructure
- Encryption
- Access controls
- Retention

## Control Gaps

- Backups may remain mutable
- Production and backup administration may share identities
- Offline or isolated copies are not guaranteed
- Recovery testing may be insufficient

## Recommended Mitigations

- Maintain immutable backup copies
- Maintain offline or logically isolated recovery copies
- Use dedicated backup administrator identities
- Require MFA for backup management
- Protect deletion operations
- Segment backup infrastructure from production
- Monitor backup modifications and deletions
- Regularly test full restoration
- Document RTO and RPO requirements
- Verify backup integrity automatically

## Residual Risk

```text
Moderate
```

## Rationale

Immutability, isolation, and tested recovery substantially reduce destructive impact, but backup failure or administrator compromise can never be eliminated completely.

---

# TM-011 — Unauthorized Privilege or Role Modification

**Initial Risk:** Critical

## Existing Controls

- Authentication
- API Gateway
- Role-based access concepts
- Application logging

## Control Gaps

- Privilege changes may not be consistently authorized server-side
- Users may be able to influence role data through requests
- Sensitive role changes may not require approval
- Reauthentication may not be required
- Privilege-change audit records may be modifiable

## Recommended Mitigations

- Enforce server-side authorization for every privilege change
- Deny privilege modification by default
- Never trust role or permission values supplied by clients
- Require reauthentication for sensitive access changes
- Require approval for high-impact privilege changes
- Implement separation of duties
- Log all privilege modifications immutably
- Alert on role assignment and privilege escalation
- Perform recurring access reviews
- Use centralized IAM rather than application-local privilege logic where practical

## Residual Risk

```text
Moderate
```

## Rationale

Centralized server-side authorization and protected privilege-change workflows significantly reduce unauthorized elevation, although configuration and implementation defects remain possible.

---

# TM-012 — Third-Party Email Service Abuse

**Initial Risk:** High

## Existing Controls

- TLS
- API authentication
- Monitoring
- Limited sensitive data sharing

## Control Gaps

- Provider-side MFA is not guaranteed
- API credentials may be long-lived
- Credential scope may be excessive
- Abuse detection may be limited
- Sensitive customer actions may rely too heavily on email trust

## Recommended Mitigations

- Use narrowly scoped email-service credentials
- Rotate API credentials regularly
- Require MFA for provider administration
- Monitor unusual sending volume and templates
- Implement domain-authentication controls such as SPF, DKIM, and DMARC
- Avoid placing highly sensitive information directly in email
- Require independent application authentication for sensitive actions
- Alert on provider configuration changes
- Maintain an alternate notification process for provider outages
- Include the provider in recurring vendor-risk review

## Residual Risk

```text
Moderate
```

## Rationale

Credential scoping, provider security, message-authentication controls, and independent verification reduce the effectiveness of email-service abuse, while third-party dependence leaves some remaining risk.

---

# Risk Treatment Summary

```text
Threat   Initial Risk   Residual Risk
TM-001   High           Moderate
TM-002   Critical       Moderate
TM-003   High           Moderate
TM-004   Critical       High
TM-005   High           Moderate
TM-006   High           Low
TM-007   Critical       High
TM-008   High           Moderate
TM-009   Critical       Moderate
TM-010   High           Moderate
TM-011   Critical       Moderate
TM-012   High           Moderate
```

## Highest Residual Risks

Two threats remain rated High after mitigation:

```text
TM-004 — Compromised Administrative Account
TM-007 — Third-Party Payment Provider Compromise
```

Both remain elevated because Northstar cannot completely eliminate:

- Human identity compromise
- Privileged-account targeting
- Third-party compromise
- External service dependency

These risks require continuing monitoring and governance rather than one-time technical remediation.
