# Remediation and security takeaways

| Finding or risk | Demonstrated control | Remaining work for a real deployment |
|---|---|---|
| Unknown issuer prevents trusted HTTPS | Explicit lab CA certificate supplied to curl | Establish an approved trust chain and manage certificate renewal |
| Trusted issuer alone does not establish the right server name | Correct hostname validated; wrong hostname rejected in earlier test | Ensure SANs cover the actual service names; do not bypass verification |
| Users may begin with plain HTTP | Local HTTP endpoint sends a 308 HTTPS redirect | Review the real first-contact threat model and deploy HTTPS consistently |
| Client may return to HTTP | HTTPS response contains short HSTS policy | Test browser enforcement; evaluate duration, subdomains, and preload carefully |
| Weak protocol support may remain enabled | Teaching code sets TLS minimum to 1.2 | Test supported versions/ciphers against an approved deployment baseline |
| Teaching server could interfere with services | Separate loopback-only 8080/8443 listeners | Use a maintained production TLS terminator, not this harness |
| Private keys could leak into a portfolio | No keys included; local generated material excluded | Review staged files and repository history before publishing |

## Interpretation

curl verifies certificate trust and the requested name by default. `--cacert` provides the chosen trust material for the transfer; it is preferable to treating `--insecure` as a fix. The lab did not install its CA into the operating-system trust store. [curl verification documentation](https://curl.se/docs/sslcerts.html)

The demonstrated HSTS value is `max-age=300`, a five-minute teaching policy. It has neither `includeSubDomains` nor `preload`. A valid HSTS policy must be received over secure transport; inspecting a response with curl is not a browser-policy enforcement test. [HSTS specification](https://www.rfc-editor.org/rfc/rfc6797.html)

The Python harness is intentionally small and local. Python documents that `http.server` is not recommended for production. Do not expose this exercise server publicly or describe it as a complete production-hardening implementation. [Python documentation](https://docs.python.org/3/library/http.server.html)

## Cleanup recorded

The server terminal logged the two HEAD requests, followed by Ctrl+C and a returned shell prompt. That demonstrates the teaching process ended. A subsequent `ss` check returned no listening entries for ports 8080 or 8443. No unrelated Apache service was stopped by this procedure. The local certificate workspace remains available for the user's later learning; this report does not claim it was deleted or that the VirtualBox shared folder was unmounted.
