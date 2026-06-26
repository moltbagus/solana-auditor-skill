//! Sample native (non-Anchor) Solana program with intentional vulnerabilities.
//!
//! DO NOT DEPLOY. This is a documentation fixture for the
//! solana-auditor-skill skill. Each `// VULN-Nxx:` tag marks a bug that
//! a rule in `rules/audit.rules` is designed to catch. See
//! `audit-output/native-vault-findings.json` for the expected findings when
//! this program is run through `/audit`.
//!
//! Native programs use `entrypoint!` and manual account parsing — no Anchor
//! derive macros — which exposes different vulnerability classes than Anchor.
//! This program mirrors the Anchor vault fixture's bug taxonomy for cross-
//! framework comparison.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

// ---------------------------------------------------------------------------
// Program ID
// ---------------------------------------------------------------------------
solana_program::declare_id!("NatiV8XCvFhMtNTSg9qV9u1KKrn3DLzNaX7cSC8K8H2");

// ---------------------------------------------------------------------------
// Vault state (borsh-serialised, NOT Anchor account)
// ---------------------------------------------------------------------------
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct VaultState {
    pub authority: Pubkey,
    pub bump: u8,          // VULN-N04: hardcoded bump stored
    pub total_deposits: u64,
    pub slot_initialised: u64,
}

// ---------------------------------------------------------------------------
// Instruction enum
// ---------------------------------------------------------------------------
#[derive(BorshDeserialize)]
pub enum VaultInstruction {
    /// Initialize a new vault.
    /// Accounts: [vault (writable), authority (signer), system_program]
    Initialize { bump: u8 },
    /// Deposit lamports into the vault.
    /// Accounts: [vault (writable), user (signer)]
    Deposit { amount: u64 },
    /// Withdraw lamports from the vault.
    /// Accounts: [vault (writable), destination (writable), authority (signer)]
    Withdraw { amount: u64 },
    /// Set a new authority (admin-only).
    /// Accounts: [vault (writable), current_authority (signer)]
    SetAuthority { new_authority: Pubkey },
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let instruction = VaultInstruction::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        VaultInstruction::Initialize { bump } => initialize(program_id, accounts, bump),
        VaultInstruction::Deposit { amount } => deposit(program_id, accounts, amount),
        VaultInstruction::Withdraw { amount } => withdraw(program_id, accounts, amount),
        VaultInstruction::SetAuthority { new_authority } => {
            set_authority(program_id, accounts, new_authority)
        }
    }
}

// ---------------------------------------------------------------------------
// Instruction handlers
// ---------------------------------------------------------------------------

/// Initialise the vault with a hardcoded bump.
/// VULN-N04: bump is passed as an instruction argument (non-canonical).
/// The correct pattern uses `Pubkey::find_program_address(seeds, program_id)`
/// and stores the canonical bump returned by that call.
fn initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    bump: u8,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let vault = next_account_info(account_info_iter)?;
    let authority = next_account_info(account_info_iter)?;
    let _system_program = next_account_info(account_info_iter)?;

    // VULN-N04: bump stored directly from instruction data — not canonical.
    // Storing a non-canonical bump allows an attacker who finds a different
    // valid bump to derive a colliding PDA and pass verify_authority checks.
    let vault_state = VaultState {
        authority: *authority.key,
        bump, // <-- VULN-N04: passed in, not derived
        total_deposits: 0,
        slot_initialised: 0,
    };

    vault_state.serialize(&mut &mut vault.data.borrow_mut()[..])?;

    msg!("vault initialized with bump {}", bump);
    Ok(())
}

/// Deposit lamports into the vault.
/// VULN-N03: u64 overflow on amount calculation — no checked_add.
fn deposit(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let vault = next_account_info(account_info_iter)?;
    let _user = next_account_info(account_info_iter)?;

    // Verify caller is a signer (correct — this check is present)
    if !_user.is_signer {
        msg!("deposit: caller must sign");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut vault_state =
        VaultState::try_from_slice(&vault.data.borrow()).map_err(|_| ProgramError::InvalidAccountData)?;

    // VULN-N03: unchecked addition — wraps silently on u64 overflow in release mode.
    // An attacker can craft `amount` such that `total_deposits + amount` wraps
    // past u64::MAX back to a small value, then call withdraw for inflated
    // amounts against the wrapped balance.
    vault_state.total_deposits = vault_state.total_deposits + amount; // <-- VULN-N03

    vault_state.serialize(&mut &mut vault.data.borrow_mut()[..])?;

    // Transfer lamports from user to vault
    let vault_lamports = vault.lamports();
    **vault.lamports.borrow_mut() = vault_lamports
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    **_user.lamports.borrow_mut() = _user.lamports();

    msg!(
        "deposited {} — total_deposits now {}",
        amount,
        vault_state.total_deposits
    );
    Ok(())
}

/// Withdraw lamports from the vault.
/// VULN-N01: reads Clock via account data instead of Clock::get()
/// VULN-N02: missing signer check on authority
fn withdraw(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    amount: u64,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let vault = next_account_info(account_info_iter)?;
    let destination = next_account_info(account_info_iter)?;
    let authority = next_account_info(account_info_iter)?;

    let mut vault_state =
        VaultState::try_from_slice(&vault.data.borrow()).map_err(|_| ProgramError::InvalidAccountData)?;

    // ---------------------------------------------------------------------------
    // VULN-N01: sysvar spoofing — Clock read from account data
    // ---------------------------------------------------------------------------
    // The correct pattern is:
    //   let clock = Clock::get()?;
    //   let slot = clock.slot;
    // The code below instead deserialises a Clock from `clock_account.data`,
    // which is attacker-controlled if the caller supplies a fake sysvar account.
    // ---------------------------------------------------------------------------
    let clock_account = next_account_info(account_info_iter)?;

    // VULN-N01: deserialize Clock from account data — attacker can supply a
    // faked Clock struct with any slot/epoch values to bypass time-based logic.
    let clock = Clock::from_account_info(clock_account)
        .map_err(|_| ProgramError::InvalidArgument)?;
    let _current_slot = clock.slot; // <-- VULN-N01: spoofable

    // ---------------------------------------------------------------------------
    // VULN-N02: missing signer check on authority
    // ---------------------------------------------------------------------------
    // The `authority` account is checked for its pubkey match (has_one equivalent)
    // but NOT for `is_signer`. A transaction signed by a non-authority key can
    // pass the pubkey check if it supplies an account whose key equals the stored
    // authority — a classic key mismatch.
    // ---------------------------------------------------------------------------
    if authority.key != &vault_state.authority {
        msg!("withdraw: authority mismatch");
        return Err(ProgramError::IncorrectAuthority);
    }
    // VULN-N02: is_signer check is MISSING — anyone can submit this instruction
    // if they control an account whose pubkey matches vault_state.authority
    // (e.g., a keypair used as both authority and payer in testing scenarios).
    // Should be: `if !authority.is_signer { return Err(ProgramError::MissingRequiredSignature); }`

    // Check vault has sufficient balance
    if vault.lamports() < amount {
        msg!("withdraw: insufficient vault balance");
        return Err(ProgramError::InsufficientFunds);
    }

    // Update state
    vault_state.total_deposits = vault_state
        .total_deposits
        .checked_sub(amount)
        .ok_or(ProgramError::InsufficientFunds)?;

    vault_state.serialize(&mut &mut vault.data.borrow_mut()[..])?;

    // Transfer lamports
    **vault.lamports.borrow_mut() -= amount;
    **destination.lamports.borrow_mut() += amount;

    msg!("withdrew {} to {:?}", amount, destination.key);
    Ok(())
}

/// Set a new authority on the vault.
fn set_authority(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    new_authority: Pubkey,
) -> ProgramResult {
    let account_info_iter = &mut accounts.iter();
    let vault = next_account_info(account_info_iter)?;
    let current_authority = next_account_info(account_info_iter)?;

    // Signer check is present here (correctly)
    if !current_authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut vault_state =
        VaultState::try_from_slice(&vault.data.borrow()).map_err(|_| ProgramError::InvalidAccountData)?;

    if current_authority.key != &vault_state.authority {
        return Err(ProgramError::IncorrectAuthority);
    }

    vault_state.authority = new_authority;
    vault_state.serialize(&mut &mut vault.data.borrow_mut()[..])?;

    msg!("authority changed to {:?}", new_authority);
    Ok(())
}
