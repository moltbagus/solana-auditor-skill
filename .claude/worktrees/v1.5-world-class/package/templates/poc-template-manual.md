# PoC template — Type C: Manual steps

**Finding ID**: FINDING_ID
**Title**: FINDING_TITLE
**Severity**: CRITICAL | HIGH | MEDIUM | LOW
**CVSS**: <score>
**CWE**: <CWE-NNN>

## Attack scenario

<Describe the attacker precondition, the attack steps, the profit, and the cleanup>

## Preconditions

- [ ] Audited program deployed at: `PROGRAM_ID`
- [ ] Attacker wallet: `ATTACKER_PUBKEY`
- [ ] Network: `localnet | devnet`
- [ ] **mainnet-beta only with explicit written program-owner authorization** (see `commands/audit-poc.md` §Consent gate)
- [ ] Required accounts funded (lamports/tokens)

## Exploit steps

### Step 1: <Initial setup>

```bash
# Concrete commands a human can copy-paste
solana config set --url devnet
solana airdrop 5 ATTACKER_PUBKEY
```

### Step 2: <Trigger the vulnerability>

```bash
# Example: construct and submit the malicious transaction
solana program invoke PROGRAM_ID <malicious_instruction_data>
```

**Expected**: transaction succeeds (exploit works)
**Failure mode**: transaction fails with <error> (vulnerability doesn't exist — finding is a false positive)

### Step 3: <Verify the impact>

```bash
# Example: check that the victim account was drained
solana account VICTIM_PUBKEY
# Expected: balance = 0 (or reduced)
```

### Step 4: <Cleanup (if applicable)>

```bash
# Return funds, close accounts, etc.
```

## Success criteria

The exploit is successful if ALL of the following are true:
- [ ] Transaction succeeds without error
- [ ] Post-state matches attacker's goal (e.g., vault drained, tokens minted, etc.)
- [ ] The change is permanent and not reversible on-chain

## Cleanup

- [ ] Attacker wallet drained or returned
- [ ] No orphan accounts created
- [ ] Program state restored if applicable

## Authorization

This PoC requires explicit written authorization from the program owner
before running against mainnet-beta. See `commands/audit-poc.md` for the
mandatory consent gate.
