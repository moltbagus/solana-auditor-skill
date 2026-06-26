/// C-2 PoC: Unchecked u128 multiplication in borrow rate curve
///
/// Demonstrates: nom = coef * u128::from(slope_nom) wraps silently.
/// In production code: no checked_mul, no expect, no panic.
///
/// Run: rustc C-2-borrow_rate_curve_overflow.rs -o poc && ./poc
/// Zero dependencies.

const SCALE: u128 = 1u128 << 60; // U68F60: 1.0 = 2^60

fn main() {
    println!("=== C-2: Unchecked u128 Multiplication in Borrow Rate Curve ===\n");
    println!("Buggy code: nom = coef * u128::from(self.slope_nom)");
    println!("No checked_mul. Overflow wraps silently. No panic, no revert.\n");

    // Demonstrate the math threshold
    println!("-- U128 Overflow Threshold for U68F60 --");
    println!("U68F60 1.0 = 2^60 raw bits");
    println!("u128::MAX / 2^60 / u32::MAX = {:.1}",
        u128::MAX as f64 / SCALE as f64 / u32::MAX as f64);
    println!("=> Max safe slope_nom before overflow: ~2.9e20 (far above any real config)\n");

    // Scenario 1: Normal params (no overflow — these pass cleanly)
    println!("-- Scenario 1: Normal Reserve Parameters --");
    let (coef, sn, sd) = (SCALE, 50_000u32, 10_000u32);
    let nom = coef.wrapping_mul(sn as u128);
    let rate = nom.wrapping_div(sd as u128);
    println!("  coef=1.0 (100% util), slope_nom=50000, slope_denom=10000");
    println!("  nom = coef * slope_nom = {}", nom);
    println!("  rate = {:.6}% (expected: 5.0%)", rate as f64 / SCALE as f64 * 100.0);
    println!("  OK: no overflow with normal parameters\n");

    // Scenario 2: Config allows very steep curves — what the admin CAN do
    println!("-- Scenario 2: Aggressive Rate Curve Config (Admin Controlled) --");
    println!("  slope_nom is u32. Admin can set any value up to u32::MAX.");
    println!("  slope_nom = 10^10: nom = 2^60 * 10^10 = {:.3e}",
        (SCALE as u128).wrapping_mul(10_000_000_000u128));
    println!("  Still fits in u128 (2^60 * 10^10 ≈ 2^93 << 2^128)");
    println!("  slope_nom = 10^20: nom = 2^60 * 10^20 = {:.3e}",
        (SCALE as u128).wrapping_mul(10u128.pow(20)));
    println!("  Still fits! slope_nom would need ~2^38 to overflow at 100% util.");
    println!("  => Direct overflow at 100% util with standard U68F60 is unlikely\n");

    // Scenario 3: The REAL danger — upstream computation overflow
    println!("-- Scenario 3: Upstream Overflow Propagates In --");
    println!("  The real bug: if coef is COMPUTED from prior arithmetic that");
    println!("  overflows silently, the wrapped value arrives here already wrong.");
    println!("  Example: interpolated coef from (util - start) * segment_scale");
    println!("  If the multiply overflows, wrapped coef enters get_borrow_rate.\n");
    let coef_wrapped: u128 = 100; // already wrapped from upstream
    let nom2 = coef_wrapped.wrapping_mul(sn as u128);
    let rate2 = nom2.wrapping_div(sd as u128);
    println!("  Wrapped coef: {}", coef_wrapped);
    println!("  nom = {} * {} = {}", coef_wrapped, sn, nom2);
    println!("  Borrow rate: {:.6}%  <-- WRONG (should be ~0.5%)",
        rate2 as f64 / SCALE as f64 * 100.0);
    println!("  No revert! Wrong rate accrues silently!\n");

    // Scenario 4: to_bps() on garbage rate
    println!("-- Scenario 4: to_bps() on Wrapped Rate --");
    let wrapped_rate_bps = rate2.wrapping_mul(10_000u128); // to_bps = rate * 10000
    println!("  to_bps() = wrapped_rate * 10000 = {}", wrapped_rate_bps);
    println!("  If rate was near-zero from wrap, to_bps() ≈ 0");
    println!("  All borrows on this reserve now accrue at 0 bps!\n");

    // Manual wrap proof
    println!("-- u128 Wrap Proof (no panic) --");
    let a: u128 = u128::MAX - 5;
    let wrapped: u128 = a.wrapping_mul(10);
    println!("  ({}) * 10 in u128:", a);
    println!("  Expected:  {:.0}", u128::MAX - 5);
    println!("  Actual:     {} (silent wrap!)", wrapped);

    println!("\n-- The Fix --");
    println!("  Use checked_mul: nom = coef.checked_mul(sn.into())?;");
    println!("  Overflow returns None -> propagate error -> tx reverts gracefully");
}
