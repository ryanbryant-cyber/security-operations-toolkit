# Northstar Customer Portal — Security Requirements

## Purpose

These requirements translate the threat model into security controls that should be included in the Northstar Customer Portal design, implementation, deployment, and operation.

# Identity and Authentication

**SR-001** — All administrative accounts must use multi-factor authentication.

**SR-002** — Privileged authentication should use phishing-resistant MFA where technically feasible.

**SR-003** — Administrative identities must be separated from normal user identities.

**SR-004** — Conditional Access must restrict privileged authentication based on approved device, risk, and access conditions.

**SR-005** — Access and session tokens must use the shortest practical lifetime.

**SR-006** — Sensitive customer or administrative operations must support reauthentication or step-up authentication.

**SR-007** — Session revocation must be supported following credential compromise, significant identity risk, or administrative action.

# Authorization

**SR-008** — All authorization decisions must be enforced server-side.

**SR-009** — Every protected object request must validate that the authenticated identity is authorized to access the requested object.

**SR-010** — Client-supplied role, privilege, ownership, or authorization information must not be trusted.

**SR-011** — Privileged administrative functions must use explicit role-based authorization.

**SR-012** — Access must be denied by default when authorization cannot be established.

**SR-013** — High-impact privilege changes must require additional authorization or approval.

**SR-014** — Role and privilege changes must generate protected audit records and security alerts.

# Application and API Security

**SR-015** — API endpoints must validate request structure and required input.

**SR-016** — Customer-controlled input must not be directly concatenated into database queries.

**SR-017** — Database access must use parameterized queries or approved safe ORM patterns.

**SR-018** — API endpoints must implement appropriate rate limits and quotas.

**SR-019** — Application security testing must include SAST and DAST where appropriate.

**SR-020** — Authorization tests must verify cross-user and cross-object access restrictions.

**SR-021** — Internet-facing web applications should use web application firewall protections as defense in depth.

# Secrets and Service Identity

**SR-022** — Application secrets must not be stored in source code.

**SR-023** — Secrets must be stored in an approved secrets-management platform.

**SR-024** — Managed or workload identities should replace static credentials where supported.

**SR-025** — CI/CD systems must scan repositories for accidentally committed secrets.

**SR-026** — Service credentials must be scoped to the minimum permissions required.

**SR-027** — Secrets and integration credentials must support rotation.

# Data Protection

**SR-028** — Sensitive information must be encrypted in transit.

**SR-029** — Sensitive persistent data must be encrypted at rest.

**SR-030** — Blob storage containing customer information must deny public access by default.

**SR-031** — Cloud storage should use private network access where practical.

**SR-032** — Direct document access must use short-lived authorization.

**SR-033** — Data-access events involving sensitive records must be logged.

# Administrative Security

**SR-034** — Privileged access must follow least-privilege principles.

**SR-035** — Privileged access should use just-in-time activation where supported.

**SR-036** — Administrative sessions must be logged and monitored.

**SR-037** — High-impact administrative actions should require additional verification.

**SR-038** — Privileged roles must be reviewed periodically.

# Logging and Monitoring

**SR-039** — Authentication, authorization, API, administrative, and security events must be centrally collected.

**SR-040** — Security logs must be protected against unauthorized modification and deletion.

**SR-041** — Critical audit logs should be stored using immutable or append-only controls.

**SR-042** — Logging interruptions must generate alerts.

**SR-043** — Security systems must use synchronized time sources.

**SR-044** — Log retention periods must support incident-response and compliance requirements.

# Availability and Resilience

**SR-045** — Internet-facing services must use rate limiting.

**SR-046** — The application architecture should use managed DDoS protection.

**SR-047** — Autoscaling must be configured with safe operational limits.

**SR-048** — Downstream database and service connections must be protected from resource exhaustion.

**SR-049** — Critical application functions must implement timeouts and circuit-breaking behavior where appropriate.

# Backup and Recovery

**SR-050** — Critical application and customer data must be backed up.

**SR-051** — At least one recovery copy must be protected from ordinary production modification.

**SR-052** — Backup administration must use identities separate from ordinary production administration.

**SR-053** — Backup deletion and configuration changes must be monitored.

**SR-054** — Recovery procedures must be tested regularly.

**SR-055** — Backup integrity must be verified.

# Third-Party Security

**SR-056** — Third-party integrations must use TLS and authenticated API communication.

**SR-057** — External callbacks and webhooks must be cryptographically verified where supported.

**SR-058** — Replay protection must be implemented for sensitive third-party transactions.

**SR-059** — Payment activity must support independent transaction reconciliation.

**SR-060** — Third-party API credentials must use minimum required permissions.

**SR-061** — Critical providers must undergo recurring vendor-risk review.

**SR-062** — Contracts with critical providers should define security and incident-notification expectations.

# Email Security

**SR-063** — Email-provider administrative access must use MFA.

**SR-064** — Email API credentials must be scoped and rotated.

**SR-065** — Northstar domains must use SPF, DKIM, and DMARC.

**SR-066** — Sensitive account actions must not rely solely on trust in an email message.

**SR-067** — Unusual sending volume or provider configuration changes must generate alerts.

# Security Requirement Summary

The requirements implement several architectural principles:

```text
Explicit verification
Least privilege
Defense in depth
Secure-by-default configuration
Strong identity
Server-side authorization
Protected auditability
Resilient recovery
Controlled third-party trust
```

The central architectural rule is:

> Authentication establishes identity. Authorization must independently establish what that identity is allowed to do.
