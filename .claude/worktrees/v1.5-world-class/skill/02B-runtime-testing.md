---
name: phase-2b-runtime
description: Phase 2B — Runtime verification of Solana programs (Tier 2 only)
---

# Phase 2B: Runtime Verification

**Goal**: Execute programs in a controlled test environment to discover vulnerabilities that static analysis cannot detect.

## Two-Tier Execution Model

### Toolchain Detection

Runtime verification is only possible when the full Solana toolchain is available. The auditor must first detect what capabilities are present:

```bash
#!/bin/bash
# tier_detection.sh — Detect available runtime verification tools

TIER2_ENABLED=false
ANCHOR_VERSION=""
SOLANA_VERSION=""
CARGO_VERSION=""
RUST_VERSION=""

# Detect Anchor
if command -v anchor &> /dev/null; then
    ANCHOR_VERSION=$(anchor --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
    TIERS["anchor"]="$ANCHOR_VERSION"
fi

# Detect Solana CLI
if command -v solana &> /dev/null; then
    SOLANA_VERSION=$(solana --version 2>/dev/null | grep -oP '\d+\.\d+' | head -1)
    TIERS["solana"]="$SOLANA_VERSION"
fi

# Detect Rust toolchain
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version 2>/dev/null | grep -oP '\d+\.\d+')
    TIERS["rustc"]="$RUST_VERSION"
fi

# Tier classification
if [[ -n "$ANCHOR_VERSION" ]] && [[ -n "$SOLANA_VERSION" ]]; then
    TIERS["tier"]="TIER2"
    TIERS["enabled"]="true"
    echo "TIER2_ENABLED=true"
    echo "anchor=$ANCHOR_VERSION"
    echo "solana=$SOLANA_VERSION"
else
    TIERS["tier"]="TIER1"
    TIERS["enabled"]="false"
    echo "TIER2_ENABLED=false"
    echo "Static analysis only — install anchor + solana for runtime verification"
fi
```

### Tier Classification

| Tier | Capabilities | Use Case |
|------|-------------|----------|
| TIER1 | Static analysis only | No toolchain available |
| TIER2 | Full anchor test + BanksClient | Complete runtime verification |
| TIER2-FULL | TIER2 + QED 2A + fuzzing | Maximum coverage |

## Anchor Test Execution

### Building the Target Program

Before running tests, the program must be compiled with debug symbols:

```bash
# Clean build with maximum debug info
anchor build -- --features debug 2>&1

# Verify build artifacts exist
if [[ ! -f "target/deploy/PROGRAM.so" ]]; then
    echo "ERROR: Build failed or program not found"
    exit 1
fi

# Check IDL generation
if [[ ! -f "target/idl/PROGRAM.json" ]]; then
    echo "WARNING: IDL not generated — some checks may fail"
fi

# Get program ID from Anchor.toml
PROGRAM_ID=$(grep -oP '^\s*id\s*=\s*"\K[^"]+' Anchor.toml 2>/dev/null)
echo "PROGRAM_ID=$PROGRAM_ID"
```

### Writing Anchor Integration Tests

Anchor tests run against a program-specific BanksClient instance:

```rust
// tests/runtime_verification.rs

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program_error::ProgramError;
use anchor_spl::token::{self, Token, TokenAccount};
use std::convert::TryInto;

const U64_MAX: u64 = u64::MAX;
const LAMPORTS_PER_SOL: u64 = 1_000_000_000;

async fn setup_vault_test(program_id: Pubkey) -> (ProgramTest, Keypair, Keypair) {
    let program_test = ProgramTest::new(
        "vault_program",
        program_id,
        processor!(vault_program::processor),
    );

    let payer = Keypair::new();
    let user = Keypair::new();

    // Add payer with initial SOL
    program_test.add_lamports(&payer.pubkey(), 10_000 * LAMPORTS_PER_SOL);
    program_test.add_account(user.pubkey(), Account::default());

    (program_test, payer, user)
}

#[tokio::test]
async fn test_vault_deposit_boundary_zero() {
    let (program_test, payer, user) = setup_vault_test(PROGRAM_ID).await;
    let mut banks_client = program_test.start().await;

    let vault_pubkey = Pubkey::find_program_address(&[b"vault", &user.pubkey().to_bytes()], &PROGRAM_ID).0;

    // VULN: Zero deposit might bypass balance checks
    let result = vault_program::instruction::deposit(
        &vault_pubkey,
        &user.pubkey(),
        0, // Edge case: zero amount
    ).await;

    // Check if zero deposits are rejected
    if result.is_ok() {
        println!("VULN-RT-01: Zero deposit accepted — potential griefing vector");
    }
}

#[tokio::test]
async fn test_vault_deposit_overflow() {
    let (program_test, payer, user) = setup_vault_test(PROGRAM_ID).await;
    let mut banks_client = program_test.start().await;

    let vault_pubkey = Pubkey::find_program_address(&[b"vault", &user.pubkey().to_bytes()], &PROGRAM_ID).0;

    // Test overflow boundary
    let overflow_amount = U64_MAX;
    let result = vault_program::instruction::deposit(
        &vault_pubkey,
        &user.pubkey(),
        overflow_amount,
    ).await;

    match result {
        Err(ProgramError::ArithmeticOverflow) => {
            println!("GOOD: Overflow rejected correctly");
        }
        Ok(_) => {
            println!("VULN-RT-02: Overflow accepted — funds can be lost");
        }
        Err(e) => {
            println!("ERROR: Unexpected error: {:?}", e);
        }
    }
}

#[tokio::test]
async fn test_unauthorized_withdrawal() {
    let (program_test, payer, user) = setup_vault_test(PROGRAM_ID).await;
    let mut banks_client = program_test.start().await;

    let vault_pubkey = Pubkey::find_program_address(&[b"vault", &user.pubkey().to_bytes()], &PROGRAM_ID).0;
    let attacker = Keypair::new();

    // Attacker attempts withdrawal without being the owner
    let result = vault_program::instruction::withdraw(
        &vault_pubkey,
        &attacker.pubkey(), // Not the vault owner
        100,
    ).await;

    assert!(
        result.is_err(),
        "VULN-RT-03: Unauthorized withdrawal succeeded — critical access control failure"
    );
}

#[tokio::test]
async fn test_reentrancy_attempt() {
    let (program_test, payer, user) = setup_vault_test(PROGRAM_ID).await;
    let mut banks_client = program_test.start().await;

    // Set up a malicious program that re-enters during callback
    let malicious_program = Keypair::new();
    let malicious_id = malicious_program.pubkey();

    // Add malicious program to test context
    let mut program_test = program_test;
    program_test.add_program(
        "malicious",
        malicious_id,
        malicious_processor,
    );

    let vault_pubkey = Pubkey::find_program_address(&[b"vault", &user.pubkey().to_bytes()], &PROGRAM_ID).0;

    // Attempt reentrancy through callback
    let result = vault_program::instruction::deposit_with_callback(
        &vault_pubkey,
        &user.pubkey(),
        1000,
        malicious_id,
    ).await;

    // Check if reentrancy guard exists
    if result.is_ok() {
        println!("VULN-RT-04: Reentrancy possible — CEI pattern violated");
    }
}
```

### Running Anchor Tests

```bash
#!/bin/bash
# run_anchor_tests.sh

PROGRAM_DIR="${1:-.}"
cd "$PROGRAM_DIR" || exit 1

echo "=== Anchor Test Execution ==="
echo "Program: $(grep -oP '^\s*id\s*=\s*"\K[^"]+' Anchor.toml)"
echo "Anchor version: $(anchor --version 2>&1 | head -1)"
echo ""

# Build first
echo "[1/3] Building program..."
anchor build 2>&1 | tee /tmp/anchor_build.log
if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    echo "BUILD FAILED"
    exit 1
fi

# Run tests with verbose output
echo ""
echo "[2/3] Running anchor tests..."
anchor test --verbose 2>&1 | tee /tmp/anchor_test.log

TEST_EXIT_CODE=${PIPESTATUS[0]}

# Parse results
PASSED=$(grep -c "test result: ok" /tmp/anchor_test.log 2>/dev/null || echo "0")
FAILED=$(grep -c "test result: FAILED" /tmp/anchor_test.log 2>/dev/null || echo "0")
ERRORS=$(grep -c "error\[" /tmp/anchor_test.log 2>/dev/null || echo "0")

echo ""
echo "[3/3] Test Summary:"
echo "  Passed: $PASSED"
echo "  Failed: $FAILED"
echo "  Errors: $ERRORS"
echo "  Exit code: $TEST_EXIT_CODE"

# Extract VULN findings
echo ""
echo "=== Runtime Findings ==="
grep -E "VULN-RT-[0-9]+:" /tmp/anchor_test.log || echo "No runtime findings"

exit $TEST_EXIT_CODE
```

## Banks Client Fuzzing

### Hypothesis-Based Fuzzing

For systematic boundary testing, use Hypothesis with BanksClient:

```python
# tests/fuzz_runtime.py
"""
BanksClient Fuzzing with Hypothesis
Generates 1000+ test cases for instruction parameters
"""

import subprocess
import json
from dataclasses import dataclass
from typing import List, Optional
from hypothesis import given, settings, example, assume
from hypothesis import strategies as st
import struct
import sys

@dataclass
class FuzzResult:
    case_id: int
    instruction: str
    params: dict
    result: str  # "ok", "error", "panic"
    error_code: Optional[int]
    crash_output: Optional[str]

class SolanaFuzzer:
    def __init__(self, program_path: str, program_id: str):
        self.program_path = program_path
        self.program_id = program_id
        self.cases_run = 0
        self.failures: List[FuzzResult] = []
        self.crashes: List[FuzzResult] = []

    # Strategy: Generate boundary values for amounts
    @staticmethod
    def amount_strategy():
        """Generate boundary values for token amounts"""
        return st.one_of([
            st.just(0),                          # Zero
            st.just(1),                          # Minimum non-zero
            st.just(u64_max - 1),               # Near max
            st.just(u64_max),                    # u64::MAX
            st.integers(min_value=2, max_value=1000),  # Small values
            st.integers(min_value=2**32, max_value=u64_max - 1),  # Large values
        ])

    # Strategy: Generate account combinations
    @staticmethod
    def account_strategy():
        """Generate valid and invalid account combinations"""
        return st.dictionaries(
            st.sampled_from([
                "vault", "user", "authority", "mint", "token_account",
                "system_program", "token_program", "rent", "metadata"
            ]),
            st.builds(
                AccountSpec,
                pubkey=st.binary(min_length=32, max_length=32),
                is_signer=st.booleans(),
                is_writable=st.booleans(),
            )
        )

    # Strategy: Generate instruction discriminators
    @staticmethod
    def discriminator_strategy():
        """Generate valid and invalid discriminators"""
        return st.one_of([
            st.sampled_from([0, 1, 2, 3, 4, 5, 6, 7]),  # Common valid
            st.integers(min_value=256, max_value=2**32 - 1),  # Invalid
        ])

    def run_test_case(self, case: TestCase) -> FuzzResult:
        """Execute a single test case via anchor test"""
        result = subprocess.run([
            "anchor", "test",
            "--run", case.instruction,
            "--", case.params
        ], capture_output=True, text=True, timeout=30)

        self.cases_run += 1

        if "panicked at" in result.stderr:
            return FuzzResult(
                case_id=self.cases_run,
                instruction=case.instruction,
                params=case.params,
                result="panic",
                error_code=None,
                crash_output=result.stderr
            )
        elif result.returncode == 0:
            return FuzzResult(
                case_id=self.cases_run,
                instruction=case.instruction,
                params=case.params,
                result="ok",
                error_code=None,
                crash_output=None
            )
        else:
            error_code = self._parse_error_code(result.stderr)
            return FuzzResult(
                case_id=self.cases_run,
                instruction=case.instruction,
                params=case.params,
                result="error",
                error_code=error_code,
                crash_output=result.stderr if error_code else None
            )

    def _parse_error_code(self, stderr: str) -> Optional[int]:
        """Extract error code from anchor error output"""
        import re
        match = re.search(r'Error\s+\d+:\s+(\d+)', stderr)
        return int(match.group(1)) if match else None


# Test case generation strategies
u64_max = 2**64 - 1

# Boundary value tests
@given(amount=st.sampled_from([
    0, 1, u64_max - 1, u64_max,
    100, 1000, 1_000_000,
    2**32, 2**48, 2**56, 2**63
]))
@example(amount=0)
@example(amount=1)
@example(amount=u64_max)
@example(amount=u64_max - 1)
@settings(max_examples=1000, deadline=None)
def test_deposit_boundaries(amount: int):
    """Test deposit with all boundary values"""
    print(f"Testing deposit with amount={amount}")

    # Run via subprocess
    result = subprocess.run([
        "anchor", "test",
        "--test", "test_deposit",
        "--", f"amount={amount}"
    ], capture_output=True, text=True, timeout=30)

    # Record findings
    if result.returncode != 0 and "ArithmeticOverflow" not in result.stderr:
        print(f"VULN-FUZZ-01: Amount {amount} caused unexpected error")


@given(
    discriminator=st.integers(min_value=0, max_value=2**32 - 1)
)
@example(discriminator=0)
@example(discriminator=1)
@example(discriminator=255)
@example(discriminator=256)
@settings(max_examples=500)
def test_invalid_discriminator(discriminator: int):
    """Test if invalid discriminators are properly rejected"""
    result = subprocess.run([
        "anchor", "test",
        "--test", "test_custom_instruction",
        "--", f"discriminator={discriminator}"
    ], capture_output=True, text=True, timeout=30)

    # Valid discriminators: 0-7 for common instructions
    is_valid = discriminator < 8
    rejected = result.returncode != 0

    if is_valid and not rejected:
        print(f"WARNING: Valid discriminator {discriminator} was rejected")
    elif not is_valid and not rejected:
        print(f"VULN-FUZZ-02: Invalid discriminator {discriminator} was accepted!")


@given(
    num_accounts=st.integers(min_value=0, max_value=20)
)
@settings(max_examples=100)
def test_missing_accounts(num_accounts: int):
    """Test with varying numbers of accounts"""
    accounts = ["vault", "user", "authority"][:num_accounts]

    result = subprocess.run([
        "anchor", "test",
        "--test", "test_with_accounts",
        "--", f"accounts={','.join(accounts)}"
    ], capture_output=True, text=True, timeout=30)

    # Should always fail when required accounts missing
    if result.returncode == 0 and num_accounts < 3:
        print(f"VULN-FUZZ-03: Operation succeeded with only {num_accounts} accounts")


# Reentrancy fuzzing
@given(depth=st.integers(min_value=1, max_value=10))
@example(depth=1)
@example(depth=5)
@example(depth=10)
@settings(max_examples=50)
def test_reentrancy_depth(depth: int):
    """Test maximum reentrancy depth"""
    result = subprocess.run([
        "anchor", "test",
        "--test", "test_reentrant_call",
        "--", f"depth={depth}"
    ], capture_output=True, text=True, timeout=60)

    if result.returncode == 0 and depth > 1:
        print(f"VULN-FUZZ-04: Reentrancy to depth {depth} succeeded — CEI violated")
    elif "ExceededMaximumReentrancyDepth" in result.stderr:
        print(f"GOOD: Reentrancy depth {depth} properly rejected")
```

### Fuzzing with Custom Accounts

```rust
// tests/fuzz_accounts.rs

use anchor_lang::prelude::*;
use std::cell::RefCell;

thread_local! {
    static FUZZ_COUNTER: RefCell<u32> = RefCell::new(0);
}

/// Generate fuzz test cases for account validation
#[tokio::test]
async fn test_account_combinations_fuzz() {
    // Test all combinations of account flags
    let test_cases = generate_account_combinations();

    for case in test_cases {
        FUZZ_COUNTER.with(|c| {
            *c.borrow_mut() += 1;
            println!("Running case {}", *c.borrow());
        });

        let result = execute_with_accounts(case).await;

        // Check for unexpected success/failure
        match (case.expected_fail, result.is_ok()) {
            (true, false) => { /* Expected */ }
            (false, true) => { /* Expected */ }
            (true, true) => {
                panic!("VULN-FUZZ-05: Operation succeeded but should fail with {:?}", case.flags)
            }
            (false, false) => {
                panic!("VULN-FUZZ-06: Operation failed but should succeed: {:?}", result)
            }
        }
    }
}

#[derive(Debug)]
struct AccountCase {
    accounts: Vec<AccountSetup>,
    expected_fail: bool,
}

struct AccountSetup {
    key: Pubkey,
    is_signer: bool,
    is_writable: bool,
    is_mut: bool,
}

fn generate_account_combinations() -> Vec<AccountCase> {
    let mut cases = Vec::new();

    // Test missing signer flag
    cases.push(AccountCase {
        accounts: vec![
            AccountSetup { key: Pubkey::new_unique(), is_signer: false, is_writable: true, is_mut: true },
            AccountSetup { key: Pubkey::new_unique(), is_signer: true, is_writable: false, is_mut: false },
        ],
        expected_fail: true, // Should fail without signer
    });

    // Test writable without mut
    cases.push(AccountCase {
        accounts: vec![
            AccountSetup { key: Pubkey::new_unique(), is_signer: true, is_writable: true, is_mut: false },
            AccountSetup { key: Pubkey::new_unique(), is_signer: false, is_writable: false, is_mut: false },
        ],
        expected_fail: true,
    });

    // Valid case
    cases.push(AccountCase {
        accounts: vec![
            AccountSetup { key: Pubkey::new_unique(), is_signer: true, is_writable: true, is_mut: true },
            AccountSetup { key: Pubkey::new_unique(), is_signer: false, is_writable: false, is_mut: false },
        ],
        expected_fail: false,
    });

    cases
}
```

## Solana CLI Simulation

### Test Validator Setup

```bash
#!/bin/bash
# test_validator_setup.sh

PROGRAM_ID="${1:-$(grep -oP '^\s*id\s*=\s*"\K[^"]+' Anchor.toml)}"
PROGRAM_SO="target/deploy/${PROGRAM_ID:0:8}.so"

# Check if we can use test-validator
if ! command -v solana &> /dev/null; then
    echo "solana CLI not found — skipping test-validator"
    exit 1
fi

# Find the compiled program
SO_FILE=$(find target/deploy -name "*.so" -type f 2>/dev/null | head -1)
if [[ -z "$SO_FILE" ]]; then
    echo "No .so file found — run anchor build first"
    exit 1
fi

echo "=== Test Validator Configuration ==="
echo "Program: $PROGRAM_ID"
echo "SO file: $SO_FILE"
echo ""

# Kill any existing test validator
solana-test-validator --kill 2>/dev/null || true

# Start test validator with program loaded
echo "[1/2] Starting test validator..."
solana-test-validator \
    --ledger /tmp/test-ledger-$(date +%s) \
    --program "$SO_FILE" \
    --rpc-port 8899 \
    --bind-address localhost \
    > /tmp/test_validator.log 2>&1 &

VALIDATOR_PID=$!
echo "Validator PID: $VALIDATOR_PID"

# Wait for validator to be ready
sleep 5

# Check if running
if ! kill -0 $VALIDATOR_PID 2>/dev/null; then
    echo "ERROR: Test validator failed to start"
    cat /tmp/test_validator.log
    exit 1
fi

echo "Validator started successfully"
echo ""

# Verify program is deployed
echo "[2/2] Checking program deployment..."
solana program show "$PROGRAM_ID" --url localhost 2>&1 || echo "Program not found on-chain"

# Get account data
echo ""
echo "=== Program Accounts ==="
solana program show "$PROGRAM_ID" --url localhost --layout 2>&1 | head -50

# Cleanup function
cleanup() {
    echo ""
    echo "=== Cleanup ==="
    kill $VALIDATOR_PID 2>/dev/null || true
    solana-test-validator --kill 2>/dev/null || true
    echo "Validator stopped"
}

trap cleanup EXIT
```

### Dumping Program State

```bash
#!/bin/bash
# dump_program_state.sh

RPC_URL="${1:-http://localhost:8899}"
PROGRAM_ID="${2:-$(grep -oP '^\s*id\s*=\s*"\K[^"]+' Anchor.toml)}"

echo "=== Program State Dump ==="
echo "RPC: $RPC_URL"
echo "Program: $PROGRAM_ID"
echo ""

# Get all program accounts
echo "[1/4] Fetching program accounts..."
ACCOUNTS=$(solana program show "$PROGRAM_ID" --url "$RPC_URL" 2>&1)

if [[ $? -ne 0 ]]; then
    echo "Failed to fetch program accounts"
    exit 1
fi

echo "$ACCOUNTS"
echo ""

# Get program data size
echo "[2/4] Program data size..."
DATA_SIZE=$(echo "$ACCOUNTS" | grep -oP 'Data length:\s+\K[0-9]+' || echo "0")
echo "Data size: $DATA_SIZE bytes"
echo ""

# Parse account list
echo "[3/4] Account details..."
echo "$ACCOUNTS" | grep -E "^[A-Za-z0-9]{44}\s" | while read -r line; do
    PUBKEY=$(echo "$line" | awk '{print $1}')
    echo "  Account: $PUBKEY"

    # Get raw account data
    solana account "$PUBKEY" --url "$RPC_URL" --output json 2>/dev/null | \
        jq -r '.data' 2>/dev/null || echo "    (could not decode)"
done
echo ""

# Check upgrade authority
echo "[4/4] Upgrade authority..."
UPGRADE_AUTH=$(echo "$ACCOUNTS" | grep -i "upgrade authority" -A1 | tail -1 | xargs)
if [[ -z "$UPGRADE_AUTH" ]] || [[ "$UPGRADE_AUTH" == "(not set)" ]]; then
    echo "  WARNING: No upgrade authority — immutable"
else
    echo "  Upgrade authority: $UPGRADE_AUTH"
fi
```

## QED 2A Fallback Chain

When running verification, try tools in order of capability:

```bash
#!/bin/bash
# qed_fallback_chain.sh

PROGRAM_ID=$(grep -oP '^\s*id\s*=\s*"\K[^"]+' Anchor.toml)
SO_FILE=$(find target/deploy -name "*.so" -type f 2>/dev/null | head -1)

echo "=== Verification Fallback Chain ==="
echo "Program: $PROGRAM_ID"
echo ""

run_qed() {
    echo "[1/3] Attempting QED 2A..."
    if command -v qed-solana &> /dev/null; then
        qed-solana verify \
            --program "$SO_FILE" \
            --idl "target/idl/${PROGRAM_ID}.json" \
            --timeout 300 \
            2>&1 | tee /tmp/qed_output.log

        if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
            echo "QED 2A: PROVED"
            return 0
        else
            echo "QED 2A: Failed or timeout"
            return 1
        fi
    else
        echo "QED 2A: Not installed"
        return 2
    fi
}

run_anchor_invariants() {
    echo ""
    echo "[2/3] Running Anchor invariant tests..."
    if [[ -d "tests/invariants" ]]; then
        anchor test tests/invariants/ 2>&1 | tee /tmp/anchor_invariants.log

        PASSED=$(grep -c "test result: ok" /tmp/anchor_invariants.log 2>/dev/null || echo "0")
        FAILED=$(grep -c "test result: FAILED" /tmp/anchor_invariants.log 2>/dev/null || echo "0")

        echo "Anchor invariants: $PASSED passed, $FAILED failed"
        return 0
    else
        echo "Anchor invariants: No tests found"
        return 1
    fi
}

run_fuzz() {
    echo ""
    echo "[3/3] Running auto-generated fuzz tests..."
    if [[ -f "tests/fuzz_runtime.py" ]]; then
        python3 -m pytest tests/fuzz_runtime.py \
            --hypothesis-show-statistics \
            2>&1 | tee /tmp/fuzz_output.log

        CASES=$(grep -oP 'Hypothesis mode: standard.*?\K[0-9]+' /tmp/fuzz_output.log | tail -1 || echo "0")
        FAILURES=$(grep -c "VULN-FUZZ" /tmp/fuzz_output.log 2>/dev/null || echo "0")

        echo "Fuzz: $CASES cases, $FAILURES potential issues found"
        return 0
    else
        echo "Fuzz: No tests found"
        return 1
    fi
}

manual_review() {
    echo ""
    echo "[FALLBACK] Manual review required for:"
    echo "  - Complex state transitions not covered by tests"
    echo "  - CPI edge cases"
    echo "  - Flash loan attack patterns"
    echo ""
    echo "Review: $SO_FILE with:"
    echo "  anchor build -- --verbose"
    echo "  solana program show $PROGRAM_ID"
}

# Execute fallback chain
if run_qed; then
    exit 0
fi

if run_anchor_invariants; then
    exit 0
fi

if run_fuzz; then
    exit 0
fi

manual_review
```

## Output Format

### runtime_findings.json Schema

After running all runtime verification tests, aggregate results into a structured format:

```json
{
  "audit_session": {
    "program_id": "7vfCXTWiX7eCjJ2n5V8X3M3H1y5vZ9qRk4sW6pB8cD1",
    "toolchain": {
      "anchor": "0.31.1",
      "solana": "2.0.4",
      "rustc": "1.75.0",
      "qed": "2A-beta"
    },
    "tier": "TIER2-FULL",
    "timestamp": "2026-06-25T10:30:00Z"
  },
  "tier2_enabled": true,
  "toolchain_version": {
    "anchor": "0.31.1",
    "solana": "2.0.4",
    "rustc": "1.75.0"
  },
  "build_status": {
    "success": true,
    "idl_generated": true,
    "program_size_bytes": 204800,
    "warnings": ["Unused variable 'depth' in withdraw function"]
  },
  "anchor_test_results": {
    "total": 42,
    "passed": 38,
    "failed": 2,
    "skipped": 2,
    "errors": [
      {
        "test": "test_token_transfer_boundary",
        "error": "ArithmeticOverflow",
        "line": 156
      },
      {
        "test": "test_reentrancy_depth_10",
        "error": "Transaction simulation failed",
        "line": 203
      }
    ],
    "vuln_findings": [
      {
        "id": "VULN-RT-01",
        "test": "test_deposit_boundary_zero",
        "description": "Zero deposit accepted without validation",
        "severity": "MEDIUM"
      },
      {
        "id": "VULN-RT-04",
        "test": "test_reentrancy_attempt",
        "description": "Reentrancy possible through callback",
        "severity": "CRITICAL"
      }
    ]
  },
  "fuzz_results": {
    "cases_run": 1650,
    "cases_passed": 1647,
    "failures": [
      {
        "id": "VULN-FUZZ-02",
        "input": {"discriminator": 512},
        "description": "Invalid discriminator accepted",
        "severity": "HIGH"
      }
    ],
    "crashes": [],
    "hypothesis_stats": {
      "max_examples": 1650,
      "average_runtime_ms": 12,
      "slowest_case_ms": 340
    }
  },
  "qv_results": {
    "status": "timeout",
    "invariants_tested": 8,
    "invariants_proved": 5,
    "invariants_failed": 1,
    "invariants_timeout": 2,
    "counterexamples": [
      {
        "invariant": "token_supply_conserved",
        "sequence": [
          {"instruction": "deposit", "amount": "u64::MAX"},
          {"instruction": "withdraw", "amount": "u64::MAX"}
        ],
        "final_state": {"supply": "u64::MAX + 1"}
      }
    ]
  },
  "findings": [
    {
      "id": "RT-01",
      "severity": "MEDIUM",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L",
      "cvss_score": 5.3,
      "cwe": "CWE-190",
      "title": "Integer Overflow in Deposit Amount Calculation",
      "location": {
        "file": "programs/vault/src/lib.rs",
        "line": 156,
        "function": "process_deposit"
      },
      "description": "The deposit function does not check for overflow when adding the deposited amount to the vault balance.",
      "impact": "An attacker could deposit tokens that cause the vault balance to overflow, resulting in loss of funds for subsequent depositors.",
      "recommendation": "Use checked_add() for all amount arithmetic: vault.amount.checked_add(amount).ok_or(ErrorCode::Overflow)?",
      "poc_status": "confirmed",
      "poc_test": "test_deposit_overflow",
      "status": "Open"
    },
    {
      "id": "RT-02",
      "severity": "CRITICAL",
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "cvss_score": 10.0,
      "cwe": "CWE-362",
      "title": "Reentrancy Vulnerability in Withdrawal",
      "location": {
        "file": "programs/vault/src/lib.rs",
        "line": 203,
        "function": "process_withdraw"
      },
      "description": "The withdrawal function transfers tokens before updating internal state, violating CEI pattern.",
      "impact": "A malicious contract could re-enter the vault during withdrawal and drain all funds.",
      "recommendation": "Follow CEI pattern: update state before any external calls or use reentrancy guard.",
      "poc_status": "confirmed",
      "poc_test": "test_reentrancy_attempt",
      "status": "Open"
    }
  ],
  "summary": {
    "total_findings": 2,
    "critical": 1,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 0
  }
}
```

### Generating the Report

```bash
#!/bin/bash
# generate_runtime_report.sh

OUTPUT_DIR="audit-output/runtime"
mkdir -p "$OUTPUT_DIR"

echo "=== Runtime Verification Report Generator ==="
echo ""

# Run all verification steps
echo "[1/5] Detecting toolchain..."
source <(bash tier_detection.sh)
echo "Tier: ${TIERS[tier]}"
echo ""

echo "[2/5] Building program..."
anchor build 2>&1 | tail -5
BUILD_STATUS=$?
echo ""

echo "[3/5] Running anchor tests..."
bash run_anchor_tests.sh 2>&1 | tee "$OUTPUT_DIR/anchor_tests.log"
ANCHOR_EXIT=$?
echo ""

echo "[4/5] Running fuzz tests..."
python3 -m pytest tests/fuzz_runtime.py -v --tb=short 2>&1 | tee "$OUTPUT_DIR/fuzz_results.log"
echo ""

echo "[5/5] Generating findings.json..."
python3 << 'PYEOF'
import json
import re
from pathlib import Path

results = {
    "tier2_enabled": True,
    "toolchain_version": {
        "anchor": "0.31.1",
        "solana": "2.0.4"
    },
    "anchor_test_results": {"passed": 0, "failed": 0, "errors": []},
    "fuzz_results": {"cases_run": 0, "failures": [], "crashes": []},
    "qv_results": {"status": "unavailable", "invariants_tested": 0},
    "findings": []
}

# Parse anchor test output
anchor_log = Path("audit-output/runtime/anchor_tests.log")
if anchor_log.exists():
    content = anchor_log.read_text()
    passed = len(re.findall(r"test result: ok", content))
    failed = len(re.findall(r"test result: FAILED", content))
    results["anchor_test_results"]["passed"] = passed
    results["anchor_test_results"]["failed"] = failed

    # Extract VULN findings
    for match in re.finditer(r"(VULN-RT-\d+): (.+)", content):
        results["findings"].append({
            "id": match.group(1),
            "description": match.group(2),
            "source": "anchor_test"
        })

# Parse fuzz output
fuzz_log = Path("audit-output/runtime/fuzz_results.log")
if fuzz_log.exists():
    content = fuzz_log.read_text()

    # Extract hypothesis stats
    cases = re.search(r"(\d+) cases passed", content)
    if cases:
        results["fuzz_results"]["cases_run"] = int(cases.group(1))

    for match in re.finditer(r"(VULN-FUZZ-\d+): (.+)", content):
        results["findings"].append({
            "id": match.group(1),
            "description": match.group(2),
            "source": "fuzz"
        })

# Write findings.json
with open("audit-output/runtime/findings.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"Generated findings.json with {len(results['findings'])} runtime findings")
PYEOF

echo ""
echo "=== Report Complete ==="
echo "Output: audit-output/runtime/findings.json"
```

## Runtime vs Static Coverage

| Vulnerability Class | Static | Runtime | Notes |
|---------------------|--------|---------|-------|
| Missing discriminator | Yes | Yes | Runtime confirms rejection |
| Integer overflow | Yes | Yes | Runtime tests boundary values |
| Access control | Yes | Yes | Runtime tests unauthorized calls |
| Reentrancy | Partial | Yes | Runtime can detect CEI violations |
| Flash loan | No | Yes | Requires simulation |
| Front-running | No | Yes | Transaction ordering |
| PDA collision | Yes | Partial | Runtime only on lucky fuzz |

## Next Phase

After runtime verification → load `skill/04-findings-triage.md` to classify and prioritize findings.
