#!/usr/bin/env python3
"""Local educational HTTPS/redirect demo. Not a production web server.

Run from the lab workspace containing server.crt and server.key.
No files are served from disk; private keys cannot be downloaded through HTTP.
"""
import argparse
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hsts', action='store_true', help='Send a 5-minute HSTS policy over HTTPS')
    args = parser.parse_args()
    body = b'TLS/PKI local lab: HTTPS connection succeeded.\n'

    class Handler(BaseHTTPRequestHandler):
        server_version = 'TLSLab/1.0'
        sys_version = ''

        def handle(self):
            try:
                super().handle()
            except (ConnectionError, ssl.SSLError):
                # Clients intentionally reject certificates in this lab.
                pass

        def respond(self, send_body):
            if self.server.server_port == 8080:
                self.send_response(308)
                # Fixed destination avoids trusting attacker-controlled Host/path values.
                self.send_header('Location', 'https://tls-lab.test:8443/')
                self.send_header('Content-Length', '0')
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            if args.hsts:
                self.send_header('Strict-Transport-Security', 'max-age=300')
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def do_GET(self):
            self.respond(True)

        def do_HEAD(self):
            self.respond(False)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(Path('server.crt')), str(Path('server.key')))
    servers = []
    try:
        https = ThreadingHTTPServer(('127.0.0.1', 8443), Handler)
        servers.append(https)
        https.socket = context.wrap_socket(https.socket, server_side=True)
        http = ThreadingHTTPServer(('127.0.0.1', 8080), Handler)
        servers.append(http)
        threading.Thread(target=http.serve_forever, daemon=True).start()
        print('Local lab: HTTP 127.0.0.1:8080 -> HTTPS 127.0.0.1:8443', flush=True)
        print(f'TLS minimum: 1.2. HSTS header: {args.hsts}. Ctrl+C stops this lab only.', flush=True)
        try:
            https.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            http.shutdown()
    finally:
        for server in servers:
            server.server_close()


if __name__ == '__main__':
    main()
