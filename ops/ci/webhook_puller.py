#!/usr/bin/env python3
"""
Minimal GitHub webhook receiver that verifies X-Hub-Signature-256 and triggers a pull+test script.
Intended for local CI where GitHub push events should cause the local clone to update and run smoke tests.

Usage (for testing):
  GITHUB_WEBHOOK_SECRET=... python3 webhook_puller.py

Configure GitHub webhook with the same secret and point the payload URL to this machine (HTTPS recommended).
"""
import hmac
import hashlib
import json
import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

REPO_DIR = os.environ.get("REPO_DIR", "/home/nsatech/Element.")
PULL_SCRIPT = os.environ.get("PULL_SCRIPT", os.path.join(os.path.dirname(__file__), "pull_and_test.sh"))
SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET")

if not SECRET:
    print("WARNING: GITHUB_WEBHOOK_SECRET not set. Exiting.")
    raise SystemExit(1)


def verify_signature(headers, body):
    sig = headers.get('X-Hub-Signature-256')
    if not sig:
        return False
    try:
        algo, hexsig = sig.split('=', 1)
    except Exception:
        return False
    if algo != 'sha256':
        return False
    mac = hmac.new(SECRET.encode(), msg=body, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), hexsig)


class Handler(BaseHTTPRequestHandler):
    def _respond(self, code=200, body=b'ok'):
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(content_length)

        if not verify_signature(self.headers, body):
            self._respond(403, b'forbidden')
            return

        try:
            payload = json.loads(body.decode('utf-8'))
        except Exception:
            payload = {}

        # Only respond to branch pushes on main by default
        ref = payload.get('ref')
        if ref and ref != 'refs/heads/main':
            self._respond(204, b'ignored')
            return

        # Trigger pull script asynchronously
        try:
            subprocess.Popen([PULL_SCRIPT], env=os.environ.copy())
        except Exception as e:
            print('Failed to spawn pull script:', e)
            self._respond(500, b'error')
            return

        self._respond(202, b'accepted')

    def log_message(self, format, *args):
        # reduce noisy logging
        print("[webhook] %s - - %s" % (self.client_address[0], format%args))


def run(port=9000):
    server = HTTPServer(('0.0.0.0', port), Handler)
    print(f"Webhook receiver listening on 0.0.0.0:{port}")
    server.serve_forever()


if __name__ == '__main__':
    run(int(os.environ.get('WEBHOOK_PORT', '9000')))
