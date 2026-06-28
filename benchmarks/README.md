# Solana Security Tool Benchmarks

Benchmark results comparing Solana security tools using the sample-vulnerable-program fixture.

## Overview

This directory contains benchmark comparisons of security tools for Solana smart contract auditing:

- **solhint** - Static analysis for Solana programs
- **cargo audit** - Rust dependency vulnerability scanner
- **Manual Review** - Traditional expert-led audit
- **This Skill** - Claude-powered automated security analysis

## Files

| File | Description |
|------|-------------|
| `README.md` | This file |
| `RESULTS.md` | Detailed benchmark results and comparison table |

## Tool Coverage Matrix

| Vulnerability Type | solhint | cargo audit | Manual | This Skill |
|-------------------|---------|-------------|--------|------------|
| Reentrancy | Yes | No | Yes | Yes |
| Access Control | Yes | No | Yes | Yes |
| Integer Overflow | Partial | No | Yes | Yes |
| Token-2022 | No | No | Yes | Yes |
| PDA Validation | No | No | Yes | Yes |
| Anchor CPI | No | No | Yes | Yes |
| Account Confusion | No | No | Yes | Yes |
| Deps Vulnerabilities | No | Yes | Yes | No |

## Running Benchmarks

```bash
# Clone the benchmark fixture
git clone https://github.com/coral-xyz/anchor test-program

# Run each tool and compare results
solhint test-program/**/*.sol > solhint-results.json
cargo audit > cargo-audit-results.txt
python -m solana_auditor audit test-program > skill-results.md

# Compare findings
diff solhint-results.json skill-results.md
```

## Contributing

To add a new tool to the benchmark:

1. Add the tool to `RESULTS.md` comparison table
2. Document the command used and time taken
3. Report findings by severity level
4. Update this README with coverage matrix changes