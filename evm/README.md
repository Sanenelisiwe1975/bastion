# 🏰 Bastion for EVM (Avalanche C-Chain & L1s)

The same firewall design, ported to EVM. **The main project is the Solana version: see the [root README](../README.md).** All commands below run from this `evm/` folder.

Audits find bugs before launch. Bastion limits the damage from the ones they miss.

Bastion is two layers that work together on Avalanche C-Chain and any Avalanche L1:

| Layer | What it does | Where |
|---|---|---|
| **BastionGuard** (onchain firewall) | Per-token **outflow rate limits** (refilling token bucket) and a **circuit breaker**. Guardians can pause; only the protocol admin can unpause. | `contracts/` |
| **Bastion Monitor** (offchain) | Streams C-Chain/L1 logs, runs detection rules, sends alerts to Discord/Slack/Telegram, and **auto-pauses** the protocol through the guard on critical alerts. | `monitor/` |

## Demo result

The demo vault ships with a classic bug: `sweep()` is missing its owner check (missing access control is one of the most common causes of DeFi losses).

```
WITHOUT Bastion:  attacker drains 1,000,000 / 1,000,000 dUSD in one tx
WITH Bastion:
  [1] full drain             ❌ OutflowLimitExceeded
  [2] takes the hourly limit ✅ 100,000 dUSD
      monitor: 🚨 large-outflow + drain-velocity → 🛑 AUTO-PAUSED in the next block
  [3] comes back an hour later ❌ ProtocolPaused
  Result: 900,000 dUSD (90%) of user funds safe
```

Run it yourself:

```bash
cd contracts && npm install && cd ../monitor && npm install && cd ..
./demo.sh
```

## Integrating a protocol (3 lines)

```solidity
import {BastionProtected} from "bastion/BastionProtected.sol";

contract MyVault is BastionProtected {
    constructor(BastionGuard guard, address multisig) BastionProtected(guard, multisig) {}

    function withdraw(uint256 amt) external whenBastionActive {
        // ... accounting ...
        _bastionOutflow(address(asset), amt);   // before value leaves
        asset.safeTransfer(msg.sender, amt);
    }
}
```

The protocol's admin (multisig/timelock) then configures:

```solidity
guard.setGuardian(vault, monitorBot, true);
guard.setOutflowLimit(vault, USDC, 250_000e6, 1 hours);  // max 250k USDC/hour, linear refill
```

Use `address(0)` as the token for native AVAX or an L1's native gas token.

### Security model
- **Guardian key (monitor bot)**: can only `pause`. A leaked key can halt the protocol but can't unpause it or move funds.
- **Admin**: configures limits/guardians and is the only role that can `unpause`. Use a multisig or timelock.
- **Rate limits** cap the worst-case loss of *any* bug in the time it takes humans to respond, including bugs the monitor doesn't recognise.
- The guard can only stop and slow value moving out. It never holds or moves funds.

## Detection rules

| Rule | Catches | Severity |
|---|---|---|
| `large-outflow` | Single token transfer out of a watched contract above threshold | warning / critical |
| `drain-velocity` | Cumulative outflow over a sliding window (drains split into small txs) | critical |
| `privileged-change` | `Upgraded`, `AdminChanged`, `OwnershipTransferred`, `BeaconUpgraded`, role grants/revokes | critical / warning |
| `guard-config` | Outflow limit removed, Bastion admin changed, guardian changes, pause/unpause | critical → info |
| `icm-untrusted-sender` | **Avalanche ICM/Teleporter**: a message delivered to a watched contract from a (source chain, sender) not on its allowlist | critical |

Rules implement a small `Rule` interface (`monitor/src/types.ts`), so adding one is a single file.

## Running the monitor against Fuji / C-Chain / an L1

```bash
# 1. deploy the guard (once per chain)
cd contracts
DEPLOYER_KEY=0x... npx hardhat run scripts/deploy-guard.ts --network fuji
DEPLOYER_KEY=0x... L1_RPC_URL=... L1_CHAIN_ID=... npx hardhat run scripts/deploy-guard.ts --network l1

# 2. configure & run the monitor
cd ../monitor
cp bastion.config.example.json bastion.config.json   # edit addresses/thresholds
GUARDIAN_KEY=0x... npm start bastion.config.json
```

Before production use, check that the `teleporter` address and the C-Chain `sourceBlockchainID` in the example config match the current Avalanche docs for your network.

## Tests

```bash
cd contracts && npx hardhat test   # 10 tests: exploit replay + guard unit tests
cd monitor   && npm test           # 15 tests: every rule + config validation
```

## Layout

```
contracts/
  contracts/BastionGuard.sol        shared firewall (one per chain)
  contracts/BastionProtected.sol    base contract for protocols
  contracts/demo/DemoVaults.sol     vulnerable vs protected vault
  test/ExploitReplay.test.ts
  scripts/deploy-guard.ts | deploy-demo.ts | attack-demo.ts
monitor/
  src/engine.ts      block streaming (catch-up + polling, multi-chain)
  src/rules/*        detection rules
  src/responder.ts   auto-pause via guardian key
  src/alerts.ts      console / webhook / Telegram
demo.sh              one-command local demo
```

> Compiler note: `hardhat.config.ts` uses the npm `solc` 0.8.24 build so it compiles offline. Delete the `subtask` override to use Hardhat's native compiler download.

## Roadmap
- **Pre-execution firewall**: simulate pending txs (mempool/`debug_traceCall`) and pause *before* the exploit lands
- Per-L1 deployment via a factory + dashboard for L1 operators
- Stolen-fund tracing across C-Chain ↔ L1s via ICM and bridge events
- Oracle-deviation and flash-loan rules; ML anomaly scoring on historical baselines
- Hosted monitoring for audit clients
