# Phase 1: Reconnaissance

**Goal**: Enumerate attack surface before touching source code.

## Repository Enum

### Anchor Programs
```bash
# Find all Anchor programs
find . -name "Cargo.toml" -exec grep -l "lib.rs" {} \; | xargs dirname
ls */src/lib.rs 2>/dev/null || find . -path "*/src/lib.rs"

# Get IDL if published
npm run build 2>/dev/null || anchor build 2>/dev/null
cat target/idl/*.json 2>/dev/null | head -100

# Count program size
ls -lh target/deploy/*.so 2>/dev/null
```

### Dependencies
```bash
# Audit Cargo.lock for vulnerable versions
cargo audit 2>/dev/null || echo "No cargo-audit available"

# Check Anchor version
anchor --version
rustc --version
solana-cli --version
```

### Program Accounts
```bash
# Fetch program accounts (Helius/DDRPC recommended)
# Replace PROGRAM_ID with actual program address
curl -X POST https://mainnet.helius-rpc.com/?key=YOUR_KEY \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getProgramAccounts",
    "params": ["PROGRAM_ID", {"encoding": "base64"}]
  }'

# Check upgrade authority
solana program show PROGRAM_ID
```

## Attack Surface Mapping

### 1. Identify Entry Points
- `#[program]` mod — instruction handlers
- `invoke` / `invoke_signed` calls — cross-program invocations
- `create_program_address` / `find_program_address` — PDA derivations

### 2. Account List
Extract all `#[account(...)]` structs. Map who can call each instruction.

### 3. Token Holdings
- SPL Token accounts owned by the program
- Token-2022 extensions used (metadata_pointer, mint_close_authority, etc.)
- Freeze authority, mint authority

### 4. Upgradeability
```bash
# Check if program is upgradeable
solana program show PROGRAM_ID | grep -i upgrade

# Buffer authority
solana program show PROGRAM_ID | grep -i buffer
```

### 5. CPI Surface
List all `invoke`/`invoke_signed` calls:
```bash
grep -rn "invoke" */src/**/*.rs | grep -v "//" | grep -v "invoke_signed"
grep -rn "invoke_signed" */src/**/*.rs | grep -v "//"
```

### 6. PDA Derivation Sites
```bash
grep -rn "find_program_address\|create_program_address" */src/**/*.rs
```

## IDL Analysis
```bash
# Extract instructions from IDL
cat target/idl/*.json | jq '.instructions[] | {name, accounts, args}'
```

## Quick Surface Score

| Surface Element | Risk Flag |
|----------------|-----------|
| Upgradeable authority | Externalizes upgrade risk |
| Token holdings > $10k | High-value target |
| CPI to unverified programs | Privilege escalation path |
| No token extensions | Metadata/mint manipulation risk |
| Many `invoke` calls | Large attack surface |
| Complex PDA derivations | Seed collision risk |

## Next Phase
After recon → load `skill/02-static-analysis.md` for code-level review.