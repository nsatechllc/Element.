# Plesk Integration: element.nsatech.io

This document describes how to publish the Element service securely via Plesk using HTTPS on element.nsatech.io.

## 1. Prerequisites
- Plesk server with valid license.
- Let’s Encrypt extension installed (Tools & Settings -> Updates -> Add/Remove Components -> Let’s Encrypt).
- DNS A record: element.nsatech.io -> <server_public_ip>.
- Element binary deployed at /opt/element/element (systemd unit provided in element.service).

## 2. Create Subdomain in Plesk
1. Domains -> Add Subdomain -> Name: `element` Parent: `nsatech.io`.
2. Document root can remain (unused) e.g. `/subdomains/element/httpdocs`.
3. Disable scripting not required (PHP, CGI) under Hosting settings (optional hardening).

## 3. Obtain Certificate
Domains -> element.nsatech.io -> SSL/TLS Certificates -> Issue Let’s Encrypt.
Select: Include "secure webmail" only if needed (generally not). Ensure HTTP & HTTPS accessibility.

## 4. Systemd Service
Install provided unit:
```
sudo useradd --system --home /opt/element --shell /usr/sbin/nologin element || true
sudo mkdir -p /opt/element
sudo cp target/release/element-bin /opt/element/element
sudo chown -R element:element /opt/element
sudo cp deploy/element.service /etc/systemd/system/element.service
sudo systemctl daemon-reload
sudo systemctl enable --now element.service
sudo systemctl status element.service
```

Check health:
```
curl -s http://127.0.0.1:8080/health
curl -s http://127.0.0.1:8080/ready | jq
```

## 5. Nginx Reverse Proxy Configuration
Navigate: Domains -> element.nsatech.io -> Apache & nginx Settings.
In "Additional nginx directives" paste:
```
# Force security headers
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "DENY" always;
add_header Referrer-Policy "no-referrer" always;
add_header Cache-Control "no-store";

# Primary proxy to Element service
location / {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Request-ID $request_id;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
}

# Metrics limited to internal / specific IPs
location /metrics {
    allow 127.0.0.1;
    # allow <office-ip>;
    deny all;
    proxy_pass http://127.0.0.1:8080/metrics;
}
location /metrics/text {
    allow 127.0.0.1;
    # allow <office-ip>;
    deny all;
    proxy_pass http://127.0.0.1:8080/metrics/text;
}
```
Click OK / Apply to reload configs.

## 6. Firewall
If using Plesk Firewall extension: allow 80 (HTTP), 443 (HTTPS), 22 (SSH). After first cert issuance you may close 80 ONLY if switching to DNS or TLS-ALPN challenges.

UFW example (if manually managing):
```
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow 80/tcp   # optional for HTTP challenge
sudo ufw enable
sudo ufw status
```

For future HTTP/3 support, also:
```
sudo ufw allow 443/udp
```

## 7. Validation
```
# Expect JSON readiness with git_sha & build_ts
curl -s https://element.nsatech.io/ready | jq

# Sign example (base64 digest/context 32 bytes each)
# Replace DIGEST_B64, CONTEXT_B64 appropriately
curl -s -X POST https://element.nsatech.io/sign \
  -H 'Content-Type: application/json' \
  -d '{"key_id":"<kid>","digest":"<DIGEST_B64>","context_binding":"<CONTEXT_B64>","nonce":1}'
```

## 8. Logging & Observability
- Element emits JSON logs with request IDs. Use `journalctl -u element.service -f`.
- To integrate with external logging, configure rsyslog or vector to tail systemd journal.

## 9. Optional Hardening
- Enable ModSecurity (OWASP CRS) on this domain (low false positives given JSON API, set DetectionOnly initially).
- Add IP allowlist around /sign or /sign/batch if internal-only: wrap location blocks or implement auth token header.
- Deploy Prometheus node exporter and scrape Element internally instead of exposing metrics at all.

## 10. Future QUIC / HTTP3
Once Plesk supports end-to-end QUIC proxying or you decide to bypass it, you can:
- Enable HTTP/3 in Nginx (Plesk versions with OpenSSL QUIC) and open UDP 443.
- Or run a separate QUIC listener (feature `quic-overlay`) on an alternate port and expose via firewall.

---
This file is a deployment runbook for Plesk-managed hosting of Element.
