# Phase 1: Reconnaissance

**Goal**: Enumerate attack surface before touching source code.

## Toolchain Auto-Detection

```bash
# Detect available tools and versions
ANCHOR_VERSION=$(anchor --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "not installed")
SOLANA_VERSION=$(solana --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "not installed")
CARGO_VERSION=$(cargo --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "not installed")
CARGO_AUDIT=$(command -v cargo-audit &> /dev/null && echo "available" || echo "not installed")
HELIUS_KEY=${HELIUS_RPC_KEY:-"not configured"}

echo "=== Toolchain Status ==="
echo "Anchor: $ANCHOR_VERSION"
echo "Solana CLI: $SOLANA_VERSION"
echo "Cargo: $CARGO_VERSION"
echo "cargo-audit: $CARGO_AUDIT"
echo "Helius RPC: $HELIUS_KEY"
```

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

#

## On-Chain State Analysis

Use Helius enhanced API or direct RPC calls to inspect deployed program state:

```bash
# Fetch program accounts via Helius
HELIUS_KEY="${HELIUS_API_KEY:-}"
PROGRAM_ID="<target_program_id>"

curl -s "https://mainnet.helius-rpc.com/?api-key=$HELIUS_KEY" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getProgramAccounts",
    "params": ["{{PROGRAM_ID}}", {"encoding": "base64"}]
  }' | jq '.result[] | .pubkey'

# Inspect account data for anomalies
# - Unusual account sizes
# - Unexpected discriminator values
# - Stale or orphaned accounts
# - Authority accounts with high value tokens
```

**What to look for:**
- Accounts with zero lamports that should be rent-exempt
- Authority accounts that are PDA vs EOAs (affects key management risk)
- Token accounts with unusual delegation states
- Program config accounts with unexpected upgrade authority

## Dependencies
```bash
# Audit Cargo.lock for vulnerable dependency versions (supply chain CVEs)
# Catches: known CVEs in transitive dependencies, yanked crates, RustSec advisories
# Critical for: dependencies with known crypto vulnerabilities, deserialization bugs
cargo audit 2>/dev/null || echo "cargo-audit: no vulnerabilities found or not installed"

# Check toolchain versions
anchor --version
rustc --version
solana-cli --version
```

**What cargo audit catches**:
- CVEs in transitive Rust dependencies
- Yanked crates (removed from crates.io)
- RustSec security advisories
- Known vulnerability patterns in common crypto/serialization libraries

## On-Chain Program State (Helius API)

### Upgrade Authority Verification
```bash
# Verify upgrade authority is multisig/timelock (never EOAs)
curl -s -X POST https://mainnet.helius-rpc.com/?key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getProgramMetadata",
    "params": ["PROGRAM_ID"]
  }' | jq '{authority: .result.authorities, lastDeploy: .result.lastDeploymentSlot}'

# Check if authority matches expected (multisig address, not pubkey)
solana program show PROGRAM_ID | grep -i "upgrade authority"
```

### Program Bytecode Analysis
```bash
# Get program size and bytecode hash for integrity verification
curl -s -X POST https://mainnet.helius-rpc.com/?key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getProgram",
    "params": ["PROGRAM_ID", {"encoding": "base64"}]
  }' | jq '{dataLen: (.result.data[0] | length), slot: .result.slot}'

# Compute sha256 of deployed bytecode for comparison
echo "Store this hash: $(solana program show PROGRAM_ID -um | grep 'Last deployed build' | awk '{print $NF}')"
```

### Last Upgrade Timestamp
```bash
# Get last upgrade slot and convert to human-readable time
LAST_SLOT=$(solana program show PROGRAM_ID -um | grep -i "last deployed" | awk '{print $NF}')
solana slot $LAST_SLOT --lamports 2>/dev/null || echo "Cannot determine upgrade time"

# Alert if program hasn't been upgraded in >1 year (stale code risk)
UPGRADE_AGE_DAYS=$(( ($(date +%s) - $(solana slot $LAST_SLOT --lamports 2>/dev/null | grep -oE '[0-9]+')) / 86400 ))
```

### Token Holder Analysis (for token programs)
```bash
# Get token supply and holder distribution
curl -s -X POST https://mainnet.helius-rpc.com/?key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getTokenSupply",
    "params": ["TOKEN_MINT_ADDRESS"]
  }' | jq '{supply: .result.amount, decimals: .result.decimals}'

# Top holders (detect concentration risk)
curl -s -X POST https://mainnet.helius-rpc.com/?key=${HELIUS_RPC_KEY} \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "getTokenLargestAccounts",
    "params": ["TOKEN_MINT_ADDRESS"]
  }' | jq '.result.value[:10] | .[] | {address: .address, amount: .amount}'
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

## CPI Surface Enumeration

Generate a structured JSON graph of all cross-program invocations for automated analysis.

### Using the Helper Script
```bash
# Generate CPI surface graph (outputs to cpi_surface.json)
./scripts/generate-cpi-graph.sh

# View summary
cat cpi_surface.json | jq '{programCount: (.nodes | length), cpiCount: (.edges | length), programs: .nodes[].label}'
```

### Manual Enumeration
```bash
# Extract all invoke calls with context
grep -rn "invoke(" programs/*/src/lib.rs | grep -v "//.*invoke" | \
  sed 's/\([^:]*:[0-9]*\):.*\(invoke[^(]*([^{]*\){.*program_id:\([^,]*\).*/\1 \2 \3/'

# Extract all invoke_signed calls
grep -rn "invoke_signed(" programs/*/src/lib.rs | grep -v "//" | \
  sed 's/\([^:]*:[0-9]*\):.*\(invoke_signed[^(]*([^{]*\){.*program_id:\([^,]*\).*/\1 \2 \3/'

# List CpiContext usages (Anchor's CPI abstraction)
grep -rn "CpiContext" programs/*/src/lib.rs | grep -v "//"
```

### CPI Graph Schema

The `cpi_surface.json` output follows this structure:

```json
{
  "metadata": {
    "generated_at": "ISO-8601 timestamp",
    "program_id": "target program pubkey",
    "total_programs": 5,
    "total_cpi_calls": 12
  },
  "nodes": [
    {
      "id": "token",
      "label": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      "type": "spl"
    }
  ],
  "edges": [
    {
      "source": "program",
      "target": "token",
      "call_type": "invoke",
      "file": "programs/vault/src/lib.rs",
      "line": 142,
      "function": "transfer_tokens",
      "signer": true
    }
  ]
}
```

### Analyzing CPI Risk

| CPI Pattern | Risk Level | Rationale |
|------------|------------|-----------|
| Unverified program ID in `invoke` | CRITICAL | Arbitrary program execution |
| `invoke_signed` without seeds validation | HIGH | PDA derivation could be manipulated |
| CPI to Token-2022 without extension checks | HIGH | New attack surface in extensions |
| System program CPI in sensitive functions | MEDIUM | Potential for unauthorized transfers |
| SPL Token CPI without amount validation | CRITICAL | Integer overflow / amount manipulation |

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
| cargo audit failures | Supply chain compromise |
| EOAs as upgrade authority | Single point of failure |

## Next Phase
After recon → load `skill/02-static-analysis.md` for code-level review.