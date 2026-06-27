---
name: audit-poc
description: Generate proof-of-concept exploit for a finding — REQUIRES EXPLICIT CONSENT before execution
---

# /audit-poc — Proof-of-Concept Generator

Generate a runnable PoC for a finding. Writes the PoC; does NOT execute without explicit consent every time.

## Usage

```
/audit-poc <finding-id>
/audit-poc <finding-id> --no-exec
/audit-poc <finding-id> --network devnet
/audit-poc <finding-id> --metadata
/audit-poc <finding-id> --full
/audit-poc <finding-id> --full --metadata
```

### Flags

| Flag | Description |
|------|-------------|
| `--no-exec` | Write PoC files only; skip execution (default) |
| `--network <net>` | Target network: `localnet` (default), `devnet`, `mainnet-beta`, `custom` |
| `--metadata` | Also generate `<finding-id>-metadata.json` in `audit-output/pocs/` |
| `--full` | Generate all three outputs: PoC markdown, metadata JSON, and fix verification test |

**Behavior by flag combination**:

| Flags | Outputs Generated |
|-------|-----------------|
| (none) | PoC markdown only |
| `--metadata` | PoC markdown + metadata JSON |
| `--full` | PoC markdown + metadata JSON + verification test |
| `--full --metadata` | All three (same as `--full`) |

## ⚠️ Consent gate (mandatory)

Print and require acknowledgment before anything else:

```
⚠️  PoC Execution Safety Gate
─────────────────────────────────────────────────────────
Target network: <localnet | devnet | mainnet-beta | custom>
Impact:        <CRITICAL | HIGH | MEDIUM | LOW>
Target program: <program-id>

Rules:
  1. Never run against mainnet-beta without explicit written
     authorization from the program owner.
  2. Localnet is the default and strongly preferred.
  3. Document every execution with timestamp + tx signature.
  4. Stop immediately if unintended behavior observed.

Proceed? [type YES to continue, anything else to abort]
```

**Wait for explicit "YES".** Any other response → abort cleanly.

### Metadata Generation (`--metadata`, `--full`)

When `--metadata` or `--full` is passed, generate a machine-readable metadata JSON file alongside the PoC markdown:

1. Map `rule_caught` to `rule_ids` array (e.g., `"Rule 8 — Signer Verification"` → `["Rule 8"]`).
2. Derive `exploit_class` from the vulnerability type:
   - Missing signer/auth → `privilege-escalation`
   - Reinit/mutable state → `state-manipulation`
   - Price oracle/balance snapshot → `oracle-manipulation`
   - Callback/unchecked external call → `reentrancy`
   - Arithmetic on user input → `arith`
   - Config/authority/upgrade → `config`
3. Compute `attacker_model`:
   - `privilege`: any → `none`; some auth required → `authenticated`
   - `capital`: unbounded → `none`; borrowed → `flash_loan`; own funds → specific token amounts
   - `position`: how the attacker relates to the protocol before the exploit
4. Populate `attack_surface`, `preconditions`, `steps`, `post_conditions`, `impact`, and `remediation` from the finding data.
5. Write to `audit-report/pocs/<FINDING_ID>-metadata.json`.

## Pre-flight

1. Verify finding exists in `audit-report/findings.json` or accept inline.
2. Confirm target network (default `localnet`).
3. Reject `mainnet-beta` without second confirmation including program owner's name.
4. Choose PoC type: **Type A (Anchor test)** preferred; **Type B (TypeScript)** or **Type C (manual steps)** available.

## Procedure

1. **Re-read the finding** — severity, CVSS, location, description, impact, recommendation.
2. **Build the exploit scenario** in plain English: attacker precondition, attack steps, profit/damage, cleanup.
3. **Write the PoC**:
   - Type A — `tests/poc-<FINDING_ID>.rs` (Anchor test using `ProgramTest` + `banks_client`)
     — start from `templates/poc-template-anchor.rs`
   - Type B — `poc/<FINDING_ID>.ts` (anchor + web3.js)
     — start from `templates/poc-template-typescript.ts`
   - Type C — `poc/<FINDING_ID>-manual.md` (human-executable steps)
     — start from `templates/poc-template-manual.md`
4. **Document** — `audit-report/pocs/<FINDING_ID>.md` with setup, steps, expected outcome, cleanup, files.
5. **Generate metadata** (when `--metadata` or `--full` is set):
   - Populate `skill/06-remediation.md` schema fields from the finding data.
   - Map `rule_caught` → `rule_ids`, derive `exploit_class` from vulnerability type.
   - Compute `attacker_model` from the finding description.
   - Write `audit-report/pocs/<FINDING_ID>-metadata.json`.
6. **Generate verification test** (when `--full` is set):
   - Write `tests/poc-<FINDING_ID>-fixed.rs` that asserts the exploit **fails** after fix.
   - Follow the pattern in `skill/06-remediation.md` §Exploit PoC Verification.
7. **Execute** (only if user typed YES):
   - Run the PoC.
   - Capture stdout/stderr to `audit-report/pocs/<id>-output.txt`.
   - Print transaction signatures inline.
   - Verify post-state matches expected exploit outcome.
   - Update `findings.json` `poc_status = "verified"` (or `"failed"`).
8. **Cleanup** — print state diff; offer `solana-test-validator --reset` for localnet.

Full Anchor test template, TypeScript template, manual-steps template, and failure-mode handling live in `skill/06-remediation.md` §Exploit PoC Verification.

## Rules (absolute)

- **NEVER** execute against `mainnet-beta` without two separate explicit confirmations including the program owner's identity.
- **NEVER** auto-execute. The consent gate is mandatory every time.
- **NEVER** include live exploit code in `AUDIT_REPORT.md`. Reference the PoC path only.
- All PoCs go in `audit-report/pocs/` — never in the source repo.
- Check `solana program show <id>` first; warn if upgrade authority is non-null.
