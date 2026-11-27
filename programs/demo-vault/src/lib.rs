//! Demo vault for the Bastion exploit replay.
//!
//! `sweep` was meant to be owner-only but the check was forgotten — missing signer/authority
//! checks are among the most common Solana exploit classes. The same program can be
//! initialized unprotected or behind Bastion, so tests show the same bug both ways.
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use bastion_guard::program::BastionGuard;

declare_id!("gStKd68ZtxeZ6cVUrJdwwrNAwd38sT5QFcmabUXesKU");

pub const AUTHORITY_SEED: &[u8] = b"authority";
pub const TOKENS_SEED: &[u8] = b"tokens";
pub const POSITION_SEED: &[u8] = b"position";

#[program]
pub mod demo_vault {
    use super::*;

    /// Create a vault. If `bastion_admin` is set, the vault registers with Bastion
    /// (its authority PDA signs the registration) and every outflow goes through the guard.
    pub fn initialize<'info>(
        ctx: Context<'_, '_, '_, 'info, Initialize<'info>>,
        bastion_admin: Option<Pubkey>,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.owner = ctx.accounts.owner.key();
        vault.mint = ctx.accounts.mint.key();
        vault.authority_bump = ctx.bumps.authority;
        vault.protected = bastion_admin.is_some();

        if let Some(admin) = bastion_admin {
            let guard = ctx.accounts.bastion_program.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
            let protection = ctx.accounts.protection.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
            let vault_key = vault.key();
            let seeds: &[&[u8]] = &[AUTHORITY_SEED, vault_key.as_ref(), &[vault.authority_bump]];
            bastion_guard::cpi::register(
                CpiContext::new_with_signer(
                    guard.to_account_info(),
                    bastion_guard::cpi::accounts::Register {
                        protected: ctx.accounts.authority.to_account_info(),
                        protection: protection.to_account_info(),
                        payer: ctx.accounts.owner.to_account_info(),
                        system_program: ctx.accounts.system_program.to_account_info(),
                    },
                    &[seeds],
                ),
                admin,
            )?;
        }
        Ok(())
    }

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let vault = &ctx.accounts.vault;
        if vault.protected {
            let guard = ctx.accounts.bastion_program.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
            let protection = ctx.accounts.protection.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
            bastion_guard::cpi::check_not_paused(CpiContext::new(
                guard.to_account_info(),
                bastion_guard::cpi::accounts::CheckNotPaused {
                    protected: ctx.accounts.authority.to_account_info(),
                    protection: protection.to_account_info(),
                },
            ))?;
        }
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.user_tokens.to_account_info(),
                    to: ctx.accounts.vault_tokens.to_account_info(),
                    authority: ctx.accounts.user.to_account_info(),
                },
            ),
            amount,
        )?;
        let pos = &mut ctx.accounts.position;
        pos.amount = pos.amount.checked_add(amount).ok_or(VaultError::Overflow)?;
        Ok(())
    }

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let pos = &mut ctx.accounts.position;
        pos.amount = pos.amount.checked_sub(amount).ok_or(VaultError::InsufficientBalance)?;
        let a = &ctx.accounts.outflow;
        outflow(a, amount)
    }

    /// BUG: no `require_keys_eq!(ctx.accounts.caller.key(), vault.owner)`.
    pub fn sweep(ctx: Context<Sweep>, amount: u64) -> Result<()> {
        outflow(&ctx.accounts.outflow, amount)
    }
}

/// Shared outflow path: Bastion check (if protected), then the PDA-signed transfer.
fn outflow(a: &Outflow, amount: u64) -> Result<()> {
    let vault_key = a.vault.key();
    let seeds: &[&[u8]] = &[AUTHORITY_SEED, vault_key.as_ref(), &[a.vault.authority_bump]];

    if a.vault.protected {
        // Bastion accounts are mandatory for a protected vault: an attacker cannot opt out
        // by omitting them, and the guard pins every account by PDA seeds.
        let guard = a.bastion_program.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
        let protection = a.protection.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
        let limit = a.outflow_limit.as_ref().ok_or(VaultError::MissingBastionAccounts)?;
        bastion_guard::cpi::check_outflow(
            CpiContext::new_with_signer(
                guard.to_account_info(),
                bastion_guard::cpi::accounts::CheckOutflow {
                    protected: a.authority.to_account_info(),
                    protection: protection.to_account_info(),
                    mint: a.mint.to_account_info(),
                    outflow_limit: limit.to_account_info(),
                },
                &[seeds],
            ),
            amount,
        )?;
    }

    token::transfer(
        CpiContext::new_with_signer(
            a.token_program.to_account_info(),
            Transfer {
                from: a.vault_tokens.to_account_info(),
                to: a.destination.to_account_info(),
                authority: a.authority.to_account_info(),
            },
            &[seeds],
        ),
        amount,
    )
}

#[account]
#[derive(InitSpace)]
pub struct Vault {
    pub owner: Pubkey,
    pub mint: Pubkey,
    pub authority_bump: u8,
    pub protected: bool,
}

#[account]
#[derive(InitSpace)]
pub struct Position {
    pub amount: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub owner: Signer<'info>,
    #[account(init, payer = owner, space = 8 + Vault::INIT_SPACE)]
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA that owns the vault's tokens and signs outflows / Bastion registration.
    #[account(seeds = [AUTHORITY_SEED, vault.key().as_ref()], bump)]
    pub authority: UncheckedAccount<'info>,
    pub mint: Account<'info, Mint>,
    #[account(
        init,
        payer = owner,
        seeds = [TOKENS_SEED, vault.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = authority,
    )]
    pub vault_tokens: Account<'info, TokenAccount>,
    pub bastion_program: Option<Program<'info, BastionGuard>>,
    /// CHECK: created by Bastion's `register`, which verifies its seeds.
    #[account(mut)]
    pub protection: Option<UncheckedAccount<'info>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user: Signer<'info>,
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA, seeds verified.
    #[account(seeds = [AUTHORITY_SEED, vault.key().as_ref()], bump = vault.authority_bump)]
    pub authority: UncheckedAccount<'info>,
    #[account(mut, token::mint = vault.mint, token::authority = user)]
    pub user_tokens: Account<'info, TokenAccount>,
    #[account(mut, seeds = [TOKENS_SEED, vault.key().as_ref()], bump)]
    pub vault_tokens: Account<'info, TokenAccount>,
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + Position::INIT_SPACE,
        seeds = [POSITION_SEED, vault.key().as_ref(), user.key().as_ref()],
        bump,
    )]
    pub position: Account<'info, Position>,
    pub bastion_program: Option<Program<'info, BastionGuard>>,
    /// CHECK: seeds verified by Bastion.
    pub protection: Option<UncheckedAccount<'info>>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// Accounts common to every outflow.
#[derive(Accounts)]
pub struct Outflow<'info> {
    pub vault: Account<'info, Vault>,
    /// CHECK: PDA, seeds verified.
    #[account(seeds = [AUTHORITY_SEED, vault.key().as_ref()], bump = vault.authority_bump)]
    pub authority: UncheckedAccount<'info>,
    #[account(address = vault.mint)]
    pub mint: Account<'info, Mint>,
    #[account(mut, seeds = [TOKENS_SEED, vault.key().as_ref()], bump)]
    pub vault_tokens: Account<'info, TokenAccount>,
    #[account(mut, token::mint = vault.mint)]
    pub destination: Account<'info, TokenAccount>,
    pub bastion_program: Option<Program<'info, BastionGuard>>,
    /// CHECK: seeds verified by Bastion.
    pub protection: Option<UncheckedAccount<'info>>,
    /// CHECK: seeds verified by Bastion.
    #[account(mut)]
    pub outflow_limit: Option<UncheckedAccount<'info>>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    pub user: Signer<'info>,
    #[account(
        mut,
        seeds = [POSITION_SEED, outflow.vault.key().as_ref(), user.key().as_ref()],
        bump,
    )]
    pub position: Account<'info, Position>,
    pub outflow: Outflow<'info>,
}

#[derive(Accounts)]
pub struct Sweep<'info> {
    /// BUG: should be constrained to `vault.owner`.
    pub caller: Signer<'info>,
    pub outflow: Outflow<'info>,
}

#[error_code]
pub enum VaultError {
    #[msg("Protected vault requires Bastion accounts")]
    MissingBastionAccounts,
    #[msg("Insufficient balance")]
    InsufficientBalance,
    #[msg("Overflow")]
    Overflow,
}
