# TLS/PKI Certificate Validation and HTTPS Hardening Lab

**Author:** Ryan Bryant  
**Lab dates:** November 12–13, 2026  
**Category:** Security Hardening  
**Scope:** Isolated, loopback-only educational demonstration on an Ubuntu VM.

## Objective

Understand how certificate trust and hostname validation affect HTTPS connections, then demonstrate an HTTP-to-HTTPS redirect and a short HTTP Strict Transport Security (HSTS) response policy. Document what the evidence proves, rather than treating a successful connection as proof of complete security.

## Environment and boundaries

- Ubuntu VM: `LINUX-WEBSERVER01`; tools: OpenSSL, curl, Python 3, and Oracle VirtualBox.
- Lab workspace: `~/tls-pki-lab`; test hostname: `tls-lab.test`.
- Local CA and server certificate were generated for this exercise. Server SAN: `DNS:tls-lab.test`.
- The Python harness binds **127.0.0.1 only**: HTTP on 8080 and HTTPS on 8443. Run client commands inside the same VM.
- Existing Apache on port 80 was not changed. No firewall, system-wide trust-store, or public DNS change was required.
- The harness serves a fixed text response, not files from the working directory.
- This is **not a production web server or a production hardening certification**.

## Results at a glance

| Check | Recorded result | Evidence level |
|---|---|---|
| CA key/certificate public-key comparison | Public-key hashes matched | Earlier lab observation |
| Server certificate inspection and verification | Expected SAN and issuer; OpenSSL verification OK | Earlier lab observation |
| Matching hostname with explicit lab CA trust | HTTP 200 | Earlier observation and today's HTTPS screenshot |
| CA not trusted by client | curl error 60 | Earlier lab observation |
| Trusted issuer, wrong hostname | curl error 60 for hostname mismatch | Earlier lab observation |
| HTTP endpoint | 308 redirect to `https://tls-lab.test:8443/` | Screenshot 01 |
| HTTPS endpoint | 200 OK; HSTS `max-age=300` | Screenshot 02 |
| Stop server | Ctrl+C followed by returned shell prompt | Screenshot 03 |
| Post-stop listener check | No listening entries for ports 8080 or 8443 | Screenshot 04 |

Earlier observations are summarized from the November 12 guided exercise. They are not presented as newly captured raw output. See [results and screenshots](evidence/results.md).

## Project contents

- [Architecture](architecture.md): trust relationship, request flow, and isolation.
- [Evidence and results](evidence/results.md): screenshots, exact visible output, and interpretation.
- [Remediation summary](remediation-summary.md): security lessons and practical limitations.
- [Reproduction guide](reproduce.md): inspection and client commands.
- [Local teaching server](scripts/tls_lab_server.py): unchanged harness used in the exercise.
- [.gitignore](.gitignore): excludes local private keys and generated certificate material.

## Skills demonstrated

PKI trust-chain reasoning; Subject Alternative Name validation; interpreting TLS client failures; OpenSSL certificate inspection; curl request-level CA trust and hostname resolution; HTTP response analysis; HSTS policy interpretation; safe loopback testing; reproducible evidence handling; separating configured controls from tested controls.

## Main takeaways

A certificate can be cryptographically valid yet fail a client connection because its issuer is not trusted or its name does not match the requested hostname. Using the intended CA certificate for one curl request preserves validation without changing global trust. A redirect and an HSTS response header are separate controls; seeing the header does not establish browser enforcement.

## Limitations

- The code configures a TLS 1.2 minimum. No protocol-version rejection, negotiated-version, or cipher-suite test was performed on the user's VM.
- HSTS header presence was tested. Browser enforcement, first-visit protection, preload behavior, and subdomain coverage were not tested.
- The screenshot captures an HTTP response protocol line of `HTTP/1.0`; this is **not** the negotiated TLS version.
- No baseline response without HSTS was captured from this Python server. The earlier OpenSSL listener and this harness are different services, so their results are not a controlled before/after hardening comparison.
- No replay, MITM, penetration, availability, revocation, expiry, or production deployment test is claimed.
- The observed Ctrl+C and returned prompt confirm this process ended. A subsequent socket inventory showed no listening entries on ports 8080 or 8443.
- Private keys, passphrases, and generated local certificate files are intentionally excluded.

## Technical references

- [curl: TLS certificate verification](https://curl.se/docs/sslcerts.html)
- [RFC 6797: HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797.html)
- [Python: http.server](https://docs.python.org/3/library/http.server.html)
