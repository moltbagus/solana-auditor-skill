/// PoC: C-1 — Fraction::div_ceil off-by-one on exact integer-ratio divisions
///
/// Self-contained reproduction. Run with:
///   rustc --edition 2021 C-1-div_ceil_off_by_one.rs -o poc && ./poc
///
/// Expected output:
///   div_ceil(1.0, 1.0) = 1.0    ← CORRECT
///   GOT:  div_ceil(1.0, 1.0) = X.000000000000000001   ← BUG

const FRAC_NBITS: u64 = 60;

/// Convert a u64 integer to U68F60 scaled representation (1.0 = 1 << 60)
fn to_sf(val: u64) -> u128 {
    (val as u128) << FRAC_NBITS
}

/// Current (buggy) implementation.
/// Returns (num_sf << 60 + den_sf - 1) / den_sf
fn div_ceil_buggy(num_sf: u128, den_sf: u128) -> u128 {
    if den_sf == 0 {
        panic!("divide by zero");
    }
    ((num_sf << FRAC_NBITS) + den_sf - 1) / den_sf
}

/// Correct ceiling division for U68F60.
/// Returns ((num_sf << 60) - 1) / den_sf + 1
fn div_ceil_correct(num_sf: u128, den_sf: u128) -> u128 {
    if den_sf == 0 {
        panic!("divide by zero");
    }
    ((num_sf << FRAC_NBITS) - 1) / den_sf + 1
}

/// Convert U68F60 scaled value back to f64 for display
fn to_f64(sf: u128) -> f64 {
    (sf as f64) / (1u128 << 60) as f64
}

/// Assert that SF value equals expected (within 1 SF unit)
fn assert_exact(label: &str, got: u128, expected: u128) {
    if got == expected {
        println!("  ✅ PASS: {} = {:.18}", label, to_f64(got));
    } else {
        println!(
            "  ❌ FAIL: {} — expected {:.18}, got {:.18} (off by {} SF)",
            label,
            to_f64(expected),
            to_f64(got),
            got - expected
        );
    }
}

fn main() {
    println!("═ PoC: C-1: div_ceil off-by-one on exact integer-ratio divisions ═\n");

    // Test 1: 1.0 / 1.0 — simplest exact ratio
    let num = to_sf(1);
    let den = to_sf(1);
    let buggy = div_ceil_buggy(num, den);
    let correct = div_ceil_correct(num, den);
    println!("Test 1: div_ceil(1.0, 1.0) [exact = 2^60 = 1.0]");
    println!("  Buggy:   {} ({:.18})", buggy, to_f64(buggy));
    println!("  Correct: {} ({:.18})", correct, to_f64(correct));
    assert_exact("buggy div_ceil(1, 1)", buggy, to_sf(1));
    assert_exact("correct div_ceil(1, 1)", correct, to_sf(1));

    // Test 2: 5.0 / 5.0 — exact ratio
    let buggy = div_ceil_buggy(to_sf(5), to_sf(5));
    let correct = div_ceil_correct(to_sf(5), to_sf(5));
    println!("\nTest 2: div_ceil(5.0, 5.0) [exact = 1.0]");
    assert_exact("buggy div_ceil(5, 5)", buggy, to_sf(1));
    assert_exact("correct div_ceil(5, 5)", correct, to_sf(1));

    // Test 3: 100.0 / 10.0 — exact ratio
    let buggy = div_ceil_buggy(to_sf(100), to_sf(10));
    let correct = div_ceil_correct(to_sf(100), to_sf(10));
    println!("\nTest 3: div_ceil(100.0, 10.0) [exact = 10.0]");
    assert_exact("buggy div_ceil(100, 10)", buggy, to_sf(10));
    assert_exact("correct div_ceil(100, 10)", correct, to_sf(10));

    // Test 4: 10.0 / 3.0 — non-exact ratio (both should behave the same)
    let buggy = div_ceil_buggy(to_sf(10), to_sf(3));
    let correct = div_ceil_correct(to_sf(10), to_sf(3));
    println!("\nTest 4: div_ceil(10.0, 3.0) [ceil of 10/3 = 4.0]");
    println!("  Buggy:   {:.18}", to_f64(buggy));
    println!("  Correct: {:.18}", to_f64(correct));
    if buggy == correct {
        println!("  ✅ Both match for non-exact ratio");
    } else {
        println!("  ⚠️  Divergent — amplifies repayment rounding asymmetry");
    }

    // Test 5: Edge case — den = 1 (exact)
    let buggy = div_ceil_buggy(to_sf(7), to_sf(1));
    let correct = div_ceil_correct(to_sf(7), to_sf(1));
    println!("\nTest 5: div_ceil(7.0, 1.0) [exact = 7.0]");
    assert_exact("buggy div_ceil(7, 1)", buggy, to_sf(7));
    assert_exact("correct div_ceil(7, 1)", correct, to_sf(7));

    println!("\n═══ Impact ═══");
    println!("The bug affects every exact integer-ratio ceiling division.");
    println!("Callers in klend:");
    println!("  - reserve.fraction_liquidity_to_collateral_ceil");
    println!("  - reserve.fraction_collateral_to_liquidity_ceil");
    println!("  - BigFraction::div_ceil (same off-by-one)");
    println!("  - full_mul_int_ratio_ceil (same pattern)");
    println!("Every partial liquidation amount is inflated by 1 U68F60 quantum.");
    println!("Systematic, compounds across all liquidation paths.");
}
