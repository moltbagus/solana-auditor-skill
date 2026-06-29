# Methodology Trace — Solend Governance Historical Audit

Per-finding traces for the August 2022 Solend governance flash loan exploit ($1.26M).

## Detection Phases

1. **Phase 1: Reconnaissance** — Historical exploit analysis
2. **Phase 2: Static Analysis** — SAST pattern matching
3. **Phase 1C: Economic Security** — Flash loan and governance invariant analysis

---

## SOLEND-01: Missing signer verification on governance proposal execution

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 2 | Rule 8 | Pattern: `execute_proposal` has no `require!(ctx.accounts.governance.is_signer)` |

**Trace:** `execute_proposal` → CPI to treasury without caller signature verification → any user can execute any proposal

**Severity:** CRITICAL — $1.26M drained via governance manipulation

---

## SOLEND-02: Flash loan susceptible governance voting

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 2 | Rule 13 | Pattern: `cast_vote` has no vote-time lock, token balance snapshot, or lock delay |
| Phase 1C | — | Economic: flash loan + vote + return in single transaction bypasses governance security |

**Trace:** Flash loan tokens → `cast_vote` with full weight → return tokens → no detection

**Severity:** HIGH — enables governance capture in one tx

---

## SOLEND-03: Unchecked CPI to treasury vault

| Phase | Rule | Detection |
|-------|------|-----------|
| Phase 2 | Rule 4 | Pattern: `execute_proposal` CPI to treasury has no `require_keys_eq` for proposal authority |

**Trace:** `invoke` to treasury → no proposal→treasury delegation check → malicious proposal redirects funds

**Severity:** HIGH — enables treasury drain