# Audit-on-Push GitHub Actions Template

Add this workflow to any Anchor repo to run /audit-quick on every push:

1. Copy `.github/workflows/audit-on-push.yml` to your repo
2. Add `ANTHROPIC_API_KEY` to repo secrets
3. Push — the audit runs automatically

What it does:
- Runs /audit-quick on every push and PR
- Posts findings as PR comments
- Fails the check if CRITICAL findings exist
- Uploads SARIF to GitHub Security tab