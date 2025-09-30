CI webhook puller
=================

This folder contains a small webhook receiver that verifies GitHub HMAC signatures and runs a safe pull+test script.

Files:
- `webhook_puller.py` — minimal HTTP server to receive GitHub push events and verify `X-Hub-Signature-256`.
- `pull_and_test.sh` — pulls `origin/main` and runs a quick `cargo test` smoke test using the deploy key at `~/.ssh/github`.

Quick install (example):

1. Ensure the deploy key (private) is present at `~/.ssh/github` and readable by the CI user. Set strict permissions:

```bash
chmod 600 ~/.ssh/github
```

2. Set the webhook secret and run the server as an unprivileged user (the example exposes the product-scoped path `/webhooks/element`):

```bash
export GITHUB_WEBHOOK_SECRET="<your-secret>"
export REPO_DIR="/home/nsatech/Element."    # adjust
export PULL_SCRIPT="/home/nsatech/Element./ops/ci/pull_and_test.sh"
python3 webhook_puller.py
```

When you create the webhook in GitHub make sure to set:
- Content type: application/json
- Secret: the value you exported as `GITHUB_WEBHOOK_SECRET`

Signed test curl (generate the HMAC header and send JSON):

```bash
# payload and secret (secret from /home/nsatech/Element./ops/ci/.webhook_secret)
payload='{"ref":"refs/heads/main"}'
secret=$(cat /home/nsatech/Element./ops/ci/.webhook_secret)
sig='sha256='$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$secret" -hex | cut -d' ' -f2)

curl -v \
	-H "X-Hub-Signature-256: $sig" \
	-H "Content-Type: application/json" \
	-d "$payload" \
	https://api.nsatech.com/webhooks/element
```

3. For production, create a systemd service (template below) and run behind an HTTPS reverse proxy (nginx) with a valid certificate.

Systemd unit template (`/etc/systemd/system/webhook-puller.service`):

```
[Unit]
Description=GitHub Webhook Puller
After=network.target

[Service]
User=youruser
Environment=GITHUB_WEBHOOK_SECRET=<your-secret>
Environment=REPO_DIR=/home/nsatech/Element.
Environment=PULL_SCRIPT=/home/nsatech/Element./ops/ci/pull_and_test.sh
WorkingDirectory=/home/nsatech/Element./ops/ci
ExecStart=/usr/bin/env python3 webhook_puller.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Security Notes:
- Expose the webhook receiver over TLS only (put nginx or Caddy in front) and do not open the HTTP port directly to the public Internet.
- Use the HMAC secret and verify `X-Hub-Signature-256` as implemented.
- Run under an unprivileged user and restrict the deploy key to repository read-only access in GitHub.
