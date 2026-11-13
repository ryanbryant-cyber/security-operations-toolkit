# Reproduction and troubleshooting

These are repeatable commands for the documented setup, not a claim that every command below was captured in the screenshots. Use only an authorized isolated lab. The existing lab's certificate-generation steps are summarized in the results, not reconstructed as an exact historical transcript.

## Prerequisites

Inside the Ubuntu VM, use a private lab directory containing:

- `lab-ca.crt`: the public certificate for the intended lab CA.
- `server.crt`: a server certificate issued by that CA, with `DNS:tls-lab.test` in its SAN and validity covering the test time.
- `server.key`: its matching private key.
- `tls_lab_server.py`: a copy of [the supplied script](scripts/tls_lab_server.py).

These certificate and key files are not shipped in this repository. Keep them outside version control. Python 3, curl, and OpenSSL must be installed. Ports 8080 and 8443 must be available. Do not regenerate or overwrite existing keys just to repeat a test.

## Inspect certificate material

```bash
cd ~/tls-pki-lab
openssl x509 -in server.crt -noout -subject -issuer -dates -ext subjectAltName
openssl verify -CAfile lab-ca.crt server.crt
```

`openssl verify` checks the chain in this command, but not the application's hostname requirement. The subsequent curl test checks the URL hostname as well. A wrong-name case needs a trusted issuer to isolate that failure.

## Start the local server (terminal 1)

```bash
cd ~/tls-pki-lab
python3 tls_lab_server.py --hsts
```

Expected startup text:

```text
Local lab: HTTP 127.0.0.1:8080 -> HTTPS 127.0.0.1:8443
TLS minimum: 1.2. HSTS header: True. Ctrl+C stops this lab only.
```

Keep that process running while testing from another terminal on the **same VM**. `127.0.0.1` refers to the computer executing curl; running these commands on Windows would target Windows, not the VM.

## HTTP redirect (terminal 2)

```bash
curl -I http://127.0.0.1:8080/
```

Observed: 308 status and `Location: https://tls-lab.test:8443/`.

## Validated HTTPS response

```bash
curl -I --noproxy '*' --cacert ~/tls-pki-lab/lab-ca.crt --resolve tls-lab.test:8443:127.0.0.1 https://tls-lab.test:8443/
```

Observed: 200 status and `Strict-Transport-Security: max-age=300`.

- `-I`: send HEAD and display response headers.
- `--noproxy '*'`: keep this lab request off a configured proxy.
- `--cacert`: select the lab CA certificate for this request.
- `--resolve`: map this hostname and port to loopback without changing DNS or `/etc/hosts`.

## Optional repeat of negative certificate checks

The following are equivalent reproduction examples for the earlier trust/hostname checks. The original negative observations used an OpenSSL test listener, not this Python harness. No new execution of these examples is claimed here.

Without explicitly trusting the lab CA (assuming it is absent from default trust):

```bash
curl -I --noproxy '*' --resolve tls-lab.test:8443:127.0.0.1 https://tls-lab.test:8443/
```

With the CA trusted but a hostname absent from the certificate:

```bash
curl -I --noproxy '*' --cacert ~/tls-pki-lab/lab-ca.crt --resolve wrong-name.test:8443:127.0.0.1 https://wrong-name.test:8443/
```

Expected: certificate validation fails. Error 60 alone is not enough to distinguish trust failure from hostname mismatch; read the accompanying message. Do not add `-k` to turn the negative test into a successful connection.

## Stop and troubleshoot

Press **Ctrl+C once in terminal 1**, where the Python server is running. In the recorded session, the shell prompt returned. Then verify the lab listeners have stopped:

```bash
ss -ltn 'sport = :8080 or sport = :8443'
```

Observed: column header only, with no socket rows.

| Symptom | Check |
|---|---|
| Connection refused | Server running? Correct VM, loopback address, and port? |
| FileNotFoundError at startup | Current directory and the certificate/key filenames |
| Address already in use | Identify the listener; do not terminate unrelated services blindly |
| Unknown issuer | Correct CA file and server chain, not an automatic verification bypass |
| Name mismatch | URL hostname versus certificate SAN |
| HSTS header missing | Started with `--hsts`? Request sent to HTTPS port 8443? |
| TLS version unclear | `HTTP/1.0` is HTTP framing, not TLS negotiation evidence |

No firewall rule, global CA installation, or Apache reconfiguration is necessary for these local tests.
