import type { Account, Address, Chain, PublicClient, Transport, WalletClient } from "viem";
import { bastionGuardAbi } from "./abis.js";
import type { ChainConfig, WatchedContract } from "./config.js";
import type { Alert } from "./types.js";

/**
 * Pulls the Bastion circuit breaker when a critical alert fires on a contract with autoPause.
 * The guardian key can only pause — it cannot unpause or move funds — so a leaked bot key
 * is a nuisance, not a theft vector.
 */
export class AutoPauseResponder {
  private inFlight = new Set<string>();

  constructor(
    private chain: ChainConfig,
    private publicClient: PublicClient,
    private wallet: WalletClient<Transport, Chain, Account> | undefined,
    private contracts: WatchedContract[],
  ) {}

  async handle(alerts: Alert[]): Promise<{ contract: Address; txHash: `0x${string}` }[]> {
    const done: { contract: Address; txHash: `0x${string}` }[] = [];
    if (!this.wallet || !this.chain.guard) return done;
    const guard = this.chain.guard;

    for (const a of alerts) {
      if (a.severity !== "critical") continue;
      const c = this.contracts.find((w) => w.address === a.contract);
      if (!c?.autoPause) continue;
      const key = c.address;
      if (this.inFlight.has(key)) continue;
      this.inFlight.add(key);
      try {
        const paused = await this.publicClient.readContract({
          address: guard, abi: bastionGuardAbi, functionName: "isPaused", args: [c.address],
        });
        if (paused) continue;
        const reason = `[bastion:${a.rule}] ${a.message}`.slice(0, 200);
        const txHash = await this.wallet.writeContract({
          address: guard, abi: bastionGuardAbi, functionName: "pause", args: [c.address, reason],
        });
        await this.publicClient.waitForTransactionReceipt({ hash: txHash });
        console.log(`\n🛑 AUTO-PAUSED ${c.name} on ${this.chain.name} (tx ${txHash})`);
        done.push({ contract: c.address, txHash });
      } catch (e) {
        console.error(`auto-pause of ${c.name} failed:`, (e as Error).message);
      } finally {
        this.inFlight.delete(key);
      }
    }
    return done;
  }
}
