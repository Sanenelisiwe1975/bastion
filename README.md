# 🏰 Bastion: an onchain firewall for Solana programs

**Audits find bugs before launch. Bastion limits the damage from the ones they miss.**

Most big Solana exploits come down to one missing check, such as a missing signer or authority check, or a spoofed account. Once the transaction lands, the funds are gone in a single slot. Bastion caps that loss onchain, catches the attack as it starts, and has an AI guardian explain and respond to it:

| Layer | What it does | Where |
|---|---|---|
| **`bastion_guard`** (onchain program) | Per-mint **outflow rate limits** (a token bucket that refills over time) and a **circuit breaker**, enforced by a CPI before any tokens leave a protected program. Guardians can pause; only the admin (e.g. a Squads multisig) can unpause. | [`programs/bastion-guard`](programs/bastion-guard/src/lib.rs) |
| **Bastion Monitor** (offchain) | Watches the protocol's accounts, runs detection rules on every transaction (failed ones too), sends alerts to Discord, Slack or Telegram, and **auto-pauses** the protocol on a critical alert. | [`monitor/`](monitor/) |
| **AI guardian** (Claude) | Reviews each incident, explains it in plain language, can pause gray-zone cases the rules only warn about, and **publishes its report onchain** as an SPL Memo signed by the guardian. | [`monitor/src/ai/`](monitor/src/ai/guardian.ts) |
| **Live demo page** | Reads the devnet vaults live and lets anyone simulate the exploit against the deployed program. No wallet needed. | [`app/`](app/index.html) |

| | |
|---|---|
| 🎥 Demo video | _TODO: add link_ |
| 🌐 Live demo | _TODO: add link (hosted `app/`)_ |
| 💻 Source | _TODO: add GitHub repo link_ |

| Program (devnet) | ID |
|---|---|
| `bastion_guard` (the firewall) | `2eace2zRjWZb6faQm3YcVn6NNfrRGVJw9F9FsRFvNP6M` |
| `demo_vault` (vulnerable vault for the demo) | `gStKd68ZtxeZ6cVUrJdwwrNAwd38sT5QFcmabUXesKU` |

## Demo: same bug, with and without Bastion

`demo_vault::sweep` is missing its owner check, the classic Solana missing-authority bug. Two identical vaults each hold 1,000,000 tokens of user deposits:

```
WITHOUT Bastion:  sweep(1,000,000) → drained 1,000,000 / 1,000,000 in one tx

WITH Bastion (limit 100,000 / hour):
  [1] sweep(1,000,000)   ❌ OutflowLimitExceeded   ← the failed tx still lands onchain
      monitor: 🚨 guard-rejection "drain over the rate limit attempted" → 🛑 AUTO-PAUSE
  [2] sweep(100,000)     at most 100,000 gets out before the pause lands
  [3] sweep(100,000)     ❌ ProtocolPaused
  Result: ≥ 900,000 (90%+) of user funds safe
```

This works because a failed Solana transaction is still recorded onchain with its logs. The attacker's first probe of the limit is visible to the monitor before any funds have moved.

```bash
cargo build-sbf          # builds target/deploy/*.so (Agave 2.2.x toolchain)
./demo.sh                # local validator + setup + monitor + attack
```

`demo.sh` starts `solana-test-validator` with both programs loaded, creates the mint, vaults and deposits ([`demo-setup.ts`](monitor/scripts/demo-setup.ts)), starts the monitor with the guardian key, and runs the attacker ([`demo-attack.ts`](monitor/scripts/demo-attack.ts)). Each transaction is printed with a Solana Explorer link.

## AI guardian

The deterministic rules pause critical incidents immediately, so there's no LLM in the hot path. Claude (`claude-opus-5-5`) then reviews each incident:

- **Explains** what happened from the chain data (token movements, guard errors, events, logs) in plain language for the team and users.
- **Decides**: `pause` / `monitor` / `none`, with a confidence score. In `act` mode it pauses gray-zone incidents (warnings the rules wouldn't act on) when confidence ≥ `minConfidence`.
- **Publishes** its report onchain as an SPL Memo signed by the guardian key, next to the pause it caused: a verifiable public record of the AI's reasoning. The live page shows these reports.

**Safety model:** the AI's key can only `pause`; it can't unpause or move funds. Transaction logs are attacker-controlled, so they're passed to the model fenced as data, never as instructions. The worst a fooled or prompt-injected AI can do is pause (or fail to pause, in which case the rate limit still caps the loss). If the model declines or the API fails, the rules-only response stands.

```bash
export ANTHROPIC_API_KEY=...      # demo-setup.ts then turns the AI guardian on
./demo.sh
```

Config (`ai` block in the monitor config): `mode` (`act` | `advise`), `model`, `effort`, `minConfidence`, `minSeverity`, `publishOnchain`.

## Live demo page

[`app/index.html`](app/index.html) is a static page with no build step. It reads the devnet deployment from `app/demo.json`, which `demo-setup.ts` writes when run against devnet:

- live balances of both vaults, the rate-limit bucket and the paused state
- **"Attack it yourself"**: builds the attacker's real `sweep()` transaction and *simulates* it against the deployed program (no keys, nothing sent), then shows the guard's verdict
- the AI guardian's onchain reports and the full incident timeline, with Solana Explorer links

Host the `app/` folder on GitHub Pages or Vercel. To view it locally: `cd app && python3 -m http.server`, then open `http://localhost:8000` (add `?config=demo.local.json` for a local-validator run).

## Bypass attempts (all fail)

On Solana the attacker builds the account list, so the guard can't trust any account it's given. [`tests/tests/exploit_replay.rs`](tests/tests/exploit_replay.rs) runs each of these against the real SBF binaries in LiteSVM:

| Attack | Result |
|---|---|
| Omit the Bastion accounts on a protected vault | `MissingBastionAccounts`: protected vaults require them |
| Swap `outflow_limit` for an empty account ("no limit") | `ConstraintSeeds`: the limit PDA is pinned to (protection, mint) |
| Pass the limit PDA of a different, unlimited mint | `ConstraintSeeds`: the mint must be the vault's own (`address = vault.mint`) |
| Borrow another protocol's protection account | `ConstraintSeeds`: protection is derived from the *signing* protected authority |
| A random wallet calls `pause` | `NotGuardianOrAdmin` |
| A guardian calls `unpause` | `NotAdmin` |
| A malicious program logs fake Bastion events | Ignored: the monitor only reads events from the guard program's own invocation (it tracks the invoke stack) |

## Design

```
protection PDA   = ["protection", protected_authority]        // admin, guardians, paused
limit PDA        = ["limit", protection, mint]                 // token bucket
```

- **Registration:** the protected program calls `register(admin)` by CPI, signed by the PDA that owns its token accounts. This proves the program controls the funds being guarded.
- **`check_outflow(amount)`:** called by CPI before every transfer out and signed by the same PDA, so only the program itself can use up its own allowance. If a mint has no limit configured (empty limit PDA), the outflow passes but is still blocked while paused.
- **Roles:** the admin (use a Squads multisig) sets guardians and limits, and is the only role that can unpause. Guardians (the monitor bot) can only pause, so a leaked guardian key can halt the protocol but can't move funds.
- **The limit caps losses from any bug**, including ones no detection rule recognises, for as long as humans take to respond.

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

[`programs/demo-vault/src/lib.rs`](programs/demo-vault/src/lib.rs) is a complete reference integration, including how to make the Bastion accounts mandatory.

## Monitor

The monitor polls `getSignaturesForAddress` for each protocol's **protection PDA**, **token accounts** and **programData accounts**. This works on any RPC, includes failed transactions, and saves its position to `stateFile`, so a restart picks up where it stopped.

| Rule | Catches | Severity |
|---|---|---|
| `guard-rejection` | A transaction the guard **rejected**: `OutflowLimitExceeded` (an exploit in progress), unauthorized `pause`/admin calls, attempts while paused | critical / warning / info |
| `large-outflow` | A single large outflow from a protocol token account (from token balance changes, so it also covers mints with no limit) | warning / critical |
| `drain-velocity` | Total outflow over a sliding time window (a drain split into small txs) | critical |
| `guard-config` | Limit removed, admin changed, guardian changes, pause/unpause | critical → info |
| `program-upgrade` | Upgrade, upgrade-authority change or close of a protocol's program (BPF upgradeable loader, including via CPI from a multisig) | critical |

```bash
cd monitor && npm install
cp bastion.config.example.json bastion.config.json      # set your authority PDA, token accounts, thresholds
GUARDIAN_KEYPAIR=~/guardian.json npm start bastion.config.json
```

Rules implement a small `Rule` interface ([`monitor/src/types.ts`](monitor/src/types.ts)), so adding a rule means adding one file.

## Build & test

Requires the Agave/Solana CLI 2.2.x (for `cargo build-sbf`), Rust, and Node 20+.

```bash
cargo build-sbf                               # builds target/deploy/*.so
cargo test -p bastion-tests -- --nocapture    # 11 exploit-replay tests on LiteSVM against the real binaries
cd monitor && npm test                        # 26 tests: encoding, log attribution, every rule, AI guardian, config
```

`Cargo.lock` is committed and pinned for the Solana toolchain's Rust 1.84 (`blake3 = 1.5.5`, resolution that respects each crate's minimum Rust version). If you regenerate it, use:

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

# run the demo against devnet
cd monitor
RPC_URL=https://api.devnet.solana.com npx tsx scripts/demo-setup.ts
GUARDIAN_KEYPAIR=../demo/keys/guardian.json npx tsx src/index.ts ../demo/monitor.config.json &
RPC_URL=https://api.devnet.solana.com npx tsx scripts/demo-attack.ts
```

The program keypairs in `target/deploy/` match the `declare_id!` values. If you generate new ones, update `declare_id!`, `Anchor.toml`, `monitor/src/bastion.ts` and `demo.sh` to match. On devnet the setup script's airdrops may be rate-limited; fund the keys in `demo/keys/` from the faucet if so.

## Layout

```
programs/bastion-guard/     the firewall program
programs/demo-vault/        vulnerable vault + reference integration
tests/                      LiteSVM exploit replay (Rust)
monitor/
  src/bastion.ts            PDAs, instruction builders, event/account decoders (no IDL needed)
  src/tx.ts                 tx → record: invoke-stack log parsing, token deltas, loader actions
  src/engine.ts             signature polling with saved positions
  src/rules/*               detection rules
  src/responder.ts          auto-pause + onchain memo with the guardian key
  src/ai/guardian.ts        AI guardian (Claude): incident review, decision, onchain report
  scripts/demo-*.ts         local/devnet demo
app/index.html              live demo page (static; reads devnet)
docs/demo-video-script.md   timed script for the <3 min demo video
demo.sh                     one-command local demo
evm/                        the same design for EVM chains (Avalanche C-Chain & L1s)
```

## Roadmap
- **Pre-execution defence**: simulate transactions headed for the protocol and pause *before* the exploit lands
- Helius webhooks / Geyser streaming in place of polling, for sub-slot reaction
- Per-user and per-destination limits; oracle-deviation rules
- Squads integration: the admin unpause runs through a multisig proposal with the incident report attached

Bastion also ships an EVM port ([`evm/`](evm/README.md)) with the same guard design and monitor, for Avalanche C-Chain and L1s.

## License

MIT, see [LICENSE](LICENSE).
