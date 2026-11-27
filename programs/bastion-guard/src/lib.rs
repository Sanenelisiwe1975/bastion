//! Bastion Guard — onchain firewall for Solana programs.
//!
//! A protected program registers itself by signing with the PDA that owns its token
//! accounts (its "protected authority"). Before any tokens leave, the protected program
//! CPIs into `check_outflow`, which enforces:
//!   1. a circuit breaker: guardians (monitor bots / AI agents) can pause; only the admin
//!      (e.g. a Squads multisig) can unpause, so a leaked guardian key can halt but never steal;
//!   2. per-mint outflow rate limits: a refilling token bucket bounds the loss from any bug.
//!
//! Every account the caller supplies is pinned by PDA seeds, so an attacker who controls
//! the transaction's account list cannot swap in a different config or skip the rate limit.
use anchor_lang::prelude::*;

declare_id!("2eace2zRjWZb6faQm3YcVn6NNfrRGVJw9F9FsRFvNP6M");

pub const PROTECTION_SEED: &[u8] = b"protection";
pub const LIMIT_SEED: &[u8] = b"limit";
pub const MAX_GUARDIANS: usize = 8;
pub const MAX_REASON_LEN: usize = 200;

#[program]
pub mod bastion_guard {
    use super::*;

    /// Called by the protected program via CPI, signed by its protected-authority PDA.
    pub fn register(ctx: Context<Register>, admin: Pubkey) -> Result<()> {
        let p = &mut ctx.accounts.protection;
        p.protected = ctx.accounts.protected.key();
        p.admin = admin;
        p.paused = false;
        p.guardians = Vec::new();
        p.bump = ctx.bumps.protection;
        emit!(Registered { protected: p.protected, admin });
        Ok(())
    }

    pub fn transfer_admin(ctx: Context<AdminOnly>, new_admin: Pubkey) -> Result<()> {
        let p = &mut ctx.accounts.protection;
        emit!(AdminTransferred { protected: p.protected, previous_admin: p.admin, new_admin });
        p.admin = new_admin;
        Ok(())
    }

    pub fn set_guardian(ctx: Context<AdminOnly>, guardian: Pubkey, enabled: bool) -> Result<()> {
        let p = &mut ctx.accounts.protection;
        let pos = p.guardians.iter().position(|g| *g == guardian);
        match (enabled, pos) {
            (true, None) => {
                require!(p.guardians.len() < MAX_GUARDIANS, GuardError::TooManyGuardians);
                p.guardians.push(guardian);
            }
            (false, Some(i)) => {
                p.guardians.swap_remove(i);
            }
            _ => {}
        }
        emit!(GuardianSet { protected: p.protected, guardian, enabled });
        Ok(())
    }

    /// Cap outflows of `mint` to `capacity` per `window` seconds (linear refill).
    pub fn set_outflow_limit(ctx: Context<SetOutflowLimit>, capacity: u64, window: i64) -> Result<()> {
        require!(capacity > 0 && window > 0, GuardError::InvalidLimit);
        let now = Clock::get()?.unix_timestamp;
        let l = &mut ctx.accounts.outflow_limit;
        l.protection = ctx.accounts.protection.key();
        l.mint = ctx.accounts.mint.key();
        l.capacity = capacity;
        l.window = window;
        l.available = capacity;
        l.last_update = now;
        l.bump = ctx.bumps.outflow_limit;
        emit!(OutflowLimitSet { protected: ctx.accounts.protection.protected, mint: l.mint, capacity, window });
        Ok(())
    }

    pub fn remove_outflow_limit(ctx: Context<RemoveOutflowLimit>) -> Result<()> {
        emit!(OutflowLimitRemoved {
            protected: ctx.accounts.protection.protected,
            mint: ctx.accounts.outflow_limit.mint,
        });
        Ok(())
    }

    /// Guardians or the admin can halt a protocol. Guardians cannot unpause.
    pub fn pause(ctx: Context<Pause>, reason: String) -> Result<()> {
        let p = &mut ctx.accounts.protection;
        let who = ctx.accounts.authority.key();
        require!(who == p.admin || p.guardians.contains(&who), GuardError::NotGuardianOrAdmin);
        let mut reason = reason;
        reason.truncate(MAX_REASON_LEN);
        p.paused = true;
        emit!(Paused { protected: p.protected, by: who, reason });
        Ok(())
    }

    pub fn unpause(ctx: Context<AdminOnly>) -> Result<()> {
        let p = &mut ctx.accounts.protection;
        p.paused = false;
        emit!(Unpaused { protected: p.protected, by: ctx.accounts.admin.key() });
        Ok(())
    }

    /// CPI hook: fails if the protected program is paused.
    pub fn check_not_paused(ctx: Context<CheckNotPaused>) -> Result<()> {
        require!(!ctx.accounts.protection.paused, GuardError::ProtocolPaused);
        Ok(())
    }

    /// CPI hook: record an outflow of `amount` of `mint`; fails if paused or over the limit.
    /// Mints with no configured limit pass (still subject to pause).
    pub fn check_outflow(ctx: Context<CheckOutflow>, amount: u64) -> Result<()> {
        let protection = &ctx.accounts.protection;
        require!(!protection.paused, GuardError::ProtocolPaused);

        let info = ctx.accounts.outflow_limit.to_account_info();
        if info.data_is_empty() {
            return Ok(()); // no limit configured for this mint
        }
        require_keys_eq!(*info.owner, crate::ID, GuardError::InvalidLimitAccount);

        let mut limit = {
            let data = info.try_borrow_data()?;
            OutflowLimit::try_deserialize(&mut &data[..])?
        };
        let now = Clock::get()?.unix_timestamp;
        let available = limit.refilled(now);
        if amount > available {
            msg!("Bastion: outflow {} exceeds available {}", amount, available);
            return err!(GuardError::OutflowLimitExceeded);
        }
        limit.available = available - amount;
        limit.last_update = now;
        {
            let mut data = info.try_borrow_mut_data()?;
            limit.try_serialize(&mut &mut data[..])?;
        }
        emit!(Outflow { protected: protection.protected, mint: limit.mint, amount, remaining: limit.available });
        Ok(())
    }
}

// -------------------------------------------------------------------------
// State
// -------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct Protection {
    /// The protected program's authority PDA (the key that signs its token transfers).
    pub protected: Pubkey,
    /// Protocol admin — use a Squads multisig.
    pub admin: Pubkey,
    pub paused: bool,
    #[max_len(MAX_GUARDIANS)]
    pub guardians: Vec<Pubkey>,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct OutflowLimit {
    pub protection: Pubkey,
    pub mint: Pubkey,
    /// Max amount that may leave in one full window (base units).
    pub capacity: u64,
    /// Seconds to fully refill.
    pub window: i64,
    pub available: u64,
    pub last_update: i64,
    pub bump: u8,
}

impl OutflowLimit {
    pub fn refilled(&self, now: i64) -> u64 {
        let elapsed = now.saturating_sub(self.last_update).max(0) as u128;
        let refill = elapsed * self.capacity as u128 / self.window as u128;
        let total = self.available as u128 + refill;
        total.min(self.capacity as u128) as u64
    }
}

// -------------------------------------------------------------------------
// Accounts
// -------------------------------------------------------------------------

#[derive(Accounts)]
pub struct Register<'info> {
    /// The protected program's authority PDA, signing via invoke_signed.
    pub protected: Signer<'info>,
    #[account(
        init,
        payer = payer,
        space = 8 + Protection::INIT_SPACE,
        seeds = [PROTECTION_SEED, protected.key().as_ref()],
        bump,
    )]
    pub protection: Account<'info, Protection>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    pub admin: Signer<'info>,
    #[account(
        mut,
        has_one = admin @ GuardError::NotAdmin,
        seeds = [PROTECTION_SEED, protection.protected.as_ref()],
        bump = protection.bump,
    )]
    pub protection: Account<'info, Protection>,
}

#[derive(Accounts)]
pub struct SetOutflowLimit<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        has_one = admin @ GuardError::NotAdmin,
        seeds = [PROTECTION_SEED, protection.protected.as_ref()],
        bump = protection.bump,
    )]
    pub protection: Account<'info, Protection>,
    /// CHECK: only the key is used, as a seed.
    pub mint: UncheckedAccount<'info>,
    #[account(
        init_if_needed,
        payer = admin,
        space = 8 + OutflowLimit::INIT_SPACE,
        seeds = [LIMIT_SEED, protection.key().as_ref(), mint.key().as_ref()],
        bump,
    )]
    pub outflow_limit: Account<'info, OutflowLimit>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveOutflowLimit<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        has_one = admin @ GuardError::NotAdmin,
        seeds = [PROTECTION_SEED, protection.protected.as_ref()],
        bump = protection.bump,
    )]
    pub protection: Account<'info, Protection>,
    #[account(
        mut,
        close = admin,
        seeds = [LIMIT_SEED, protection.key().as_ref(), outflow_limit.mint.as_ref()],
        bump = outflow_limit.bump,
    )]
    pub outflow_limit: Account<'info, OutflowLimit>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    pub authority: Signer<'info>,
    #[account(
        mut,
        seeds = [PROTECTION_SEED, protection.protected.as_ref()],
        bump = protection.bump,
    )]
    pub protection: Account<'info, Protection>,
}

#[derive(Accounts)]
pub struct CheckNotPaused<'info> {
    /// CHECK: the protected authority; only used to derive the protection PDA.
    pub protected: UncheckedAccount<'info>,
    #[account(seeds = [PROTECTION_SEED, protected.key().as_ref()], bump = protection.bump)]
    pub protection: Account<'info, Protection>,
}

#[derive(Accounts)]
pub struct CheckOutflow<'info> {
    /// Must sign: only the protected program itself can consume its own rate limit.
    pub protected: Signer<'info>,
    #[account(seeds = [PROTECTION_SEED, protected.key().as_ref()], bump = protection.bump)]
    pub protection: Account<'info, Protection>,
    /// CHECK: key used as a seed; the protected program passes the mint it is transferring.
    pub mint: UncheckedAccount<'info>,
    /// CHECK: address pinned by seeds so it cannot be swapped or omitted. May be uninitialized
    /// (no limit configured); otherwise owner-checked and deserialized in the handler.
    #[account(mut, seeds = [LIMIT_SEED, protection.key().as_ref(), mint.key().as_ref()], bump)]
    pub outflow_limit: UncheckedAccount<'info>,
}

// -------------------------------------------------------------------------
// Events & errors
// -------------------------------------------------------------------------

#[event]
pub struct Registered { pub protected: Pubkey, pub admin: Pubkey }
#[event]
pub struct AdminTransferred { pub protected: Pubkey, pub previous_admin: Pubkey, pub new_admin: Pubkey }
#[event]
pub struct GuardianSet { pub protected: Pubkey, pub guardian: Pubkey, pub enabled: bool }
#[event]
pub struct Paused { pub protected: Pubkey, pub by: Pubkey, pub reason: String }
#[event]
pub struct Unpaused { pub protected: Pubkey, pub by: Pubkey }
#[event]
pub struct OutflowLimitSet { pub protected: Pubkey, pub mint: Pubkey, pub capacity: u64, pub window: i64 }
#[event]
pub struct OutflowLimitRemoved { pub protected: Pubkey, pub mint: Pubkey }
#[event]
pub struct Outflow { pub protected: Pubkey, pub mint: Pubkey, pub amount: u64, pub remaining: u64 }

#[error_code]
pub enum GuardError {
    #[msg("Caller is not the protection admin")]
    NotAdmin,
    #[msg("Caller is neither a guardian nor the admin")]
    NotGuardianOrAdmin,
    #[msg("Protocol is paused by Bastion")]
    ProtocolPaused,
    #[msg("Outflow exceeds the Bastion rate limit")]
    OutflowLimitExceeded,
    #[msg("Capacity and window must be > 0")]
    InvalidLimit,
    #[msg("Outflow limit account is not owned by Bastion")]
    InvalidLimitAccount,
    #[msg("Guardian list is full")]
    TooManyGuardians,
}
