// M-7 PoC: Liquidation Bonus Formula Bug
// Demonstrates that amount * (1 - 1/1.05) = 4.762% not 5%
//
// Run: rustc M-7-liquidation_bonus_formula.rs -o poc_m7 && ./poc_m7
// Zero dependencies.

fn main() {
    println!("=== Liquidation Bonus Formula Bug ===\n");

    let amount_liquidated: f64 = 1_000_000.0; // $1M liquidation

    // Configured liquidation bonus rate = 5%
    let bonus_multiplier: f64 = 1.05;
    let liquidation_bonus_rate: f64 = 0.05;

    // Current (buggy) formula: bonus = amount * (1 - 1/bonus_multiplier)
    let buggy_bonus = amount_liquidated * (1.0 - 1.0 / bonus_multiplier);

    // Correct formula: bonus = amount * liquidation_bonus_rate
    let correct_bonus = amount_liquidated * liquidation_bonus_rate;

    // Protocol fee: 20% of bonus (typical config)
    let protocol_fee_pct: f64 = 0.20;
    let buggy_protocol_fee = buggy_bonus * protocol_fee_pct;
    let correct_protocol_fee = correct_bonus * protocol_fee_pct;

    println!("Configuration: 5% bonus rate, 20% protocol fee share\n");
    println!("On a $1,000,000 liquidation:");
    println!();
    println!("  INTENDED (correct formula):");
    println!("    Liquidator bonus:   ${:.2}", correct_bonus);
    println!("    Protocol fee:      ${:.2}", correct_protocol_fee);
    println!("    Liquidator net:    ${:.2}", correct_bonus - correct_protocol_fee);
    println!();
    println!("  ACTUAL (buggy formula):");
    println!("    Liquidator bonus:   ${:.2}  <-- WRONG", buggy_bonus);
    println!("    Protocol fee:      ${:.2}", buggy_protocol_fee);
    println!("    Liquidator net:    ${:.2}", buggy_bonus - buggy_protocol_fee);
    println!();
    println!("  LEAK:");
    println!("    Liquidator loses: ${:.2} per liquidation", correct_bonus - buggy_bonus);
    println!("    Percentage loss:    {:.2}%", 100.0 * (correct_bonus - buggy_bonus) / correct_bonus);
    println!();

    // Demonstrate the formula algebra
    println!("=== Why the formula is wrong ===\n");
    println!("  Buggy: bonus = amount * (1 - 1/1.05)");
    println!("             = amount * (1 - 0.952381)");
    println!("             = amount * 0.047619");
    println!("  Correct: bonus = amount * 0.05");
    println!();
    println!("  The formula 'amount - amount/1.05' computes");
    println!("  amount * (1 - 1/1.05), not amount * 0.05.");
    println!();

    // Scale impact
    println!("=== Scale Impact ===\n");
    let daily_volume: f64 = 1_000_000.0;
    let daily_leak = daily_volume * liquidation_bonus_rate * (1.0 - (1.0 - 1.0/1.05) / liquidation_bonus_rate);
    let daily_leak = correct_bonus - buggy_bonus;
    println!("  Daily liquidation volume: $1,000,000");
    println!("  Daily leak (liquidators lose): ${:.2}", daily_leak);
    println!("  Monthly leak: ${:.2}", daily_leak * 30.0);
    println!("  Annual leak:  ${:.2}", daily_leak * 365.0);
    println!();
    println!("  At $100M daily volume:");
    println!("    Annual leak: ${:.2}", (correct_bonus - buggy_bonus) / 1_000_000.0 * 100_000_000.0 * 365.0);

    // Confirm the math for different rates
    println!();
    println!("=== Bonus Rate Comparison ===\n");
    for rate in [0.05, 0.10, 0.15] {
        let multiplier = 1.0 + rate;
        let buggy = rate * (1.0 - 1.0/multiplier);
        let correct = rate;
        println!("  {:.0}% rate: buggy={:.4f}, correct={:.4f}, gap={:.2}%",
            rate * 100.0, buggy, correct,
            100.0 * (correct - buggy) / correct);
    }
}
