# 🏰 Bastion for Solana

Onchain firewall for Solana programs: a **circuit breaker** and **per-mint outflow rate limits**, enforced by CPI before any tokens leave a protected program.

| Program | ID |
|---|---|
| `bastion_guard` (the firewall) | `2eace2zRjWZb6faQm3YcVn6NNfrRGVJw9F9FsRFvNP6M` |
| `demo_vault` (vulnerable vault for the demo) | `gStKd68ZtxeZ6cVUrJdwwrNAwd38sT5QFcmabUXesKU` |

## Exploit replay

`demo_vault::sweep` is missing its owner check, the classic Solana missing-authority bug. The same program is run unprotected and behind Bastion:

```
WITHOUT Bastion: attacker drained 1,000,000 / 1,000,000 tokens in one tx
WITH Bastion:    full drain ❌ OutflowLimitExceeded
                 attacker capped at 100,000 → guardian pauses → ❌ ProtocolPaused
                 900,000 (90%) of user funds safe
```

### Bypass attempts (all fail)
On Solana the attacker builds the account list, so the guard must not trust any of it:

| Attack | Result |
|---|---|
| Omit the Bastion accounts on a protected vault | `MissingBastionAccounts`: protected vaults require them |
| Swap `outflow_limit` for an empty account ("no limit") | `ConstraintSeeds`: the limit PDA is pinned to (protection, mint) |
| Pass the limit PDA of a different, unlimited mint | `ConstraintSeeds`: the mint is the vault's own, checked by `address = vault.mint` |
| Borrow another protocol's protection account | `ConstraintSeeds`: protection is derived from the *signing* protected authority |
| A random wallet calls `pause` | `NotGuardianOrAdmin` |
| A guardian calls `unpause` | `NotAdmin` |

## Design

```
protection PDA   = ["protection", protected_authority]        // admin, guardians, paused
limit PDA        = ["limit", protection, mint]                 // token bucket
```

- **Registration:** the protected program CPIs `register(admin)`, signed by the PDA that owns its token accounts. This proves the protected program controls the funds being guarded.
- **`check_outflow(amount)`:** CPI'd before every transfer out, signed by the same PDA, so only the program itself can spend its own allowance. If no limit is configured for a mint (empty limit PDA), the outflow passes but is still subject to pause.
- **Roles:** the admin (use a Squads multisig) configures guardians and limits and is the only role that can unpause. Guardians (monitor bot / AI agent) can only pause.
- **Events:** `Paused`, `Outflow`, `OutflowLimitSet/Removed`, `GuardianSet`, `AdminTransferred`, for the off-chain monitor.

### Integrating (Anchor)

```rust
bastion_guard::cpi::check_outflow(
    CpiContext::new_with_signer(guard.to_account_info(), bastion_guard::cpi::accounts::CheckOutflow {
        protected: vault_authority.to_account_info(),   // your token-owning PDA
        protection: protection.to_account_info(),
        mint: mint.to_account_info(),
        outflow_limit: outflow_limit.to_account_info(),
    }, &[authority_seeds]),
    amount,
)?;
token::transfer(/* ... */)?;
```

`programs/demo-vault/src/lib.rs` is a complete reference integration, including how to make the Bastion accounts mandatory.

## Build & test

Requires the Agave/Solana CLI 2.2.x (for `cargo build-sbf`) and Rust.

```bash
cargo build-sbf                          # builds target/deploy/*.so
cargo test -p bastion-tests -- --nocapture   # 11 tests on LiteSVM against the real binaries
```

`Cargo.lock` is committed and pinned for the Solana toolchain's Rust 1.84 (`blake3 = 1.5.5`, MSRV-aware resolution). If you regenerate it, use:

```bash
CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback cargo generate-lockfile
cargo update -p blake3 --precise 1.5.5
```

## Deploy to devnet

```bash
solana config set --url devnet
solana airdrop 5        # or https://faucet.solana.com
solana program deploy target/deploy/bastion_guard.so --program-id target/deploy/bastion_guard-keypair.json
solana program deploy target/deploy/demo_vault.so    --program-id target/deploy/demo_vault-keypair.json
```

The program keypairs in `target/deploy/` match the `declare_id!` values. If you generate new ones, update `declare_id!` and `Anchor.toml` to match.

## Next
- Monitor port: `logsSubscribe` / Helius webhooks → decode Bastion events and token-balance deltas → rules → alerts
- AI guardian agent: explain the suspicious transaction in plain language, decide whether to pause, and sign `pause` with a key that can only pause
- Devnet demo script: deploy, fund, run the attack, and link each transaction on Solana Explorer
