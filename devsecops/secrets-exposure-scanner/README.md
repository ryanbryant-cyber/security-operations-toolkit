# Secrets & Configuration Exposure Scanner

A Python-based DevSecOps and application-security project designed to identify exposed credentials, secrets, and insecure configuration patterns in a synthetic source-code repository.

This project demonstrates how automated secret scanning can identify likely exposures, suppress obvious placeholders, redact sensitive values, assign severity, and generate developer-focused remediation guidance.

## Project Workflow

Synthetic Application Files  
↓  
Detection Rules  
↓  
Recursive Repository Scan  
↓  
Pattern Matching  
↓  
Secret Classification  
↓  
Severity Assignment  
↓  
Placeholder Suppression  
↓  
Redacted Findings  
↓  
JSON / CSV Reporting  
↓  
Developer Remediation

## Detection Rules

The current version includes six detection categories:

### Hard-Coded Passwords

Detects likely password assignments such as:

```text
password=<value>
DB_PASSWORD=<value>
