# Phase 0: Safety Guard

**Goal**: Pre-flight consent, scope confirmation, cluster boundary, and credential validation before any audit work begins.

This phase runs first on every audit. It must complete successfully before Phase 1 recon starts.

---

## Pre-Flight Checklist

### 1. Consent Verification

Confirm explicit operator acknowledgment of:
- Target program ID (or repo URL)
- Cluster target: **devnet / devnet-beta / localnet only** (mainnet requires `--mainnet-confirmed` flag)
- Audit scope: which programs/files are in-scope

### 2. Program Identity

Validate target program address against operator-supplied value. Reject if mismatched.

### 3. Cluster Boundary

Tag the audit session with cluster. **Block any RPC calls to mainnet** unless `--mainnet-confirmed` is set with operator acknowledgement.

| Cluster | Default |
|----------|---------|
| devnet | ✅ Allowed |
| devnet-beta | ✅ Allowed |
| mainnet | ❌ Blocked unless `--mainnet-confirmed` |

### 4. Scope Lock

Parse target `Cargo.toml` / `programs/` to derive in-scope program IDs. Reject CPI to out-of-scope programs.

---

## Real-Time Guards During Audit

| Guard | Action |
|-------|--------|
| Hallucinated CVE detection | Flag any CWE numbers not in the official CWE catalog |
| Scope drift | Warn if auditor references code outside locked program IDs; require re-confirmation |
| False positive inflation | Alert if Phase 2 generates >30 findings |
| RPC allowlist | Reject endpoints not on approved list |

---

## Post-Audit Output Validation

- **Exploit code scrub**: scan report/PoC for raw private keys, seed phrases, real wallet addresses
- **Finding traceability**: every finding must have `file_path` and `line_range`; reject `null` locations
- **Credential masking**: all PoC output uses placeholders (`[WALLET_OWNER]`, `[RECIPIENT_PUBKEY]`)

---

## Output Tags

Emit before handing off to `auditor`:

```
consent_verified: true
scope_confirmed: true
cluster_tagged: "devnet"
no_exploit_code: true
```
