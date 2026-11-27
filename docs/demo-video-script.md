# Bastion demo video script (target 2:45, hard limit 3:00)

**Setup before recording**
- Devnet demo already run once, so the live page has the full incident history (`app/demo.json` committed and the page hosted).
- Terminal: large font (18pt+), dark theme, `clear` before each shot.
- Browser tabs: (1) live page, (2) Solana Explorer on the blocked drain transaction, (3) `programs/demo-vault/src/lib.rs` at `sweep`, (4) `programs/bastion-guard/src/lib.rs` at `check_outflow`.
- Run `./demo.sh` once off-camera to warm caches. Record the terminal run as a separate clip so you can cut the waiting.
- `export ANTHROPIC_API_KEY=...` so the AI guardian shows up.

| Time | On screen | Say (roughly) |
|---|---|---|
| **0:00–0:15** | Live page, top of the fold | "Most big Solana exploits come down to one missing check, and the money is gone in a single slot. Audits catch bugs before launch. Bastion limits the damage from the ones they miss." |
| **0:15–0:35** | Editor: `sweep` in `demo_vault` with the missing owner check highlighted | "Here's a vault with the classic Solana bug: `sweep` never checks who's calling it. Anyone can call it. We deployed it twice on devnet: once on its own, once behind Bastion." |
| **0:35–1:05** | Terminal: `./demo.sh` running, the "WITHOUT Bastion" line, then steps 1–3 | "Without Bastion, the attacker drains all one million tokens in one transaction. Behind Bastion, the same call fails: `OutflowLimitExceeded`. The vault calls our guard program by CPI before any tokens leave, and the guard enforces a per-mint rate limit. The attacker gets at most one hour's budget." |
| **1:05–1:30** | Terminal: monitor output, the 🚨 `guard-rejection` alert, then 🛑 AUTO-PAUSED | "On Solana, a failed transaction still lands onchain. Our monitor sees the rejected drain, which is the attacker's first move, and pauses the vault with a guardian key that can *only* pause. The next attempt: `ProtocolPaused`. 90% of user funds are safe." |
| **1:30–2:00** | Terminal: 🧠 AI guardian report, then the live page's AI report card and memo link | "Then Claude reviews the incident. It explains what happened in plain language, decides whether the vault should stay paused, and can pause gray-zone cases the rules only warn about. Its report is published onchain as a memo signed by the guardian, so the AI's reasoning is a public, verifiable record. A prompt-injected AI can't do damage: its key can only pause." |
| **2:00–2:20** | Live page: click **Drain the whole vault** → "Blocked by Bastion: ProtocolPaused", scroll the timeline | "You can try it yourself on the live page. This builds the attacker's real transaction and simulates it against the deployed program. No keys, nothing sent. Every step of the incident links to Solana Explorer." |
| **2:20–2:40** | Editor: `CheckOutflow` accounts (PDA seeds), then the README bypass table | "The attacker controls the account list, so the guard trusts none of it. The protection and limit accounts are PDAs pinned by seeds. Every bypass we could think of fails, and LiteSVM tests replay each one against the real binaries." |
| **2:40–2:55** | README top: program IDs + integration snippet | "Integrating takes one CPI before your transfers. Bastion is open source, Anchor on devnet today. Bastion: an onchain firewall for Solana." |

**Cut list if you run long:** drop the bypass-table shot (2:20–2:40) first, then shorten the editor shot.
