CI/CD instructions for Element (HSM)

This file explains how to create the git repository, push the current source to GitHub, and trigger the supplied GitHub Actions CI workflows located in `element/.github/workflows`.

Prerequisites
- You have a GitHub account and a repository (or permission to create one) to receive the code.
- On the machine, `git` is installed and you have configured an SSH key or Git credential (PAT) for HTTPS pushes.

Steps to publish the code and trigger CI

1. Initialize a git repository (from the `HSM` directory):

```bash
cd /home/nsatech/HSM
git init
git add .
git commit -m "Initial commit: element HSM with API updates (tag required)"
```

2. Add a remote and push:

- Using SSH:

```bash
git remote add origin git@github.com:<owner>/<repo>.git
git branch -M main
git push -u origin main
```

- Using HTTPS with a Personal Access Token (PAT):

```bash
git remote add origin https://github.com/<owner>/<repo>.git
# If required, set credentials via credential helper or use: git push https://<USER>:<TOKEN>@github.com/<owner>/<repo>.git
git branch -M main
git push -u origin main
```

3. Confirm CI triggered
- After push, GitHub Actions will automatically run the `CI` workflow (`.github/workflows/ci.yml`) on the `main` branch.
- Monitor the run at: https://github.com/<owner>/<repo>/actions

Notes about the repository state
- The repo contains GitHub Actions workflows under `element/.github/workflows/ci.yml` and `release.yml`. The CI workflow does: fmt check, clippy (fail on warnings), cargo build and cargo test.
- The project has PQC code that depends on native crates; CI uses `ubuntu-latest` and sets up the Rust toolchain. Ensure self-hosted runners have the same toolchain if using those.

If you want me to run the git commands and push, provide either:
- the remote SSH URL (git@github.com:owner/repo.git) and confirm you have an SSH key configured on this machine; OR
- the HTTPS repo URL plus a Personal Access Token (PAT) stored in an environment variable I can use to push (I won't store it, it'll only be used during this session).

Security note: I will not send credentials anywhere. I can only run push commands if you supply the remote URL and the environment is authorized to push.
