import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { Connection, Keypair, PublicKey, type ConfirmedSignatureInfo } from "@solana/web3.js";
import { addressesToWatch, resolveProtocols, type Config } from "./config.js";
import type { AlertDispatcher } from "./alerts.js";
import { AutoPauseResponder } from "./responder.js";
import { runRules } from "./rules/index.js";
import { toTxRecord } from "./tx.js";
import type { Alert, ResolvedProtocol, Rule, TxRecord } from "./types.js";
import type { AiGuardian } from "./ai/guardian.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Polls `getSignaturesForAddress` for every watched address (protection PDA, token accounts,
 * programData accounts). This works on any RPC, includes failed transactions, and keeps a
 * per-address cursor that can be persisted so restarts resume where they left off.
 */
export class Watcher {
  readonly connection: Connection;
  readonly protocols: ResolvedProtocol[];
  readonly responder: AutoPauseResponder;
  ai?: AiGuardian;
  private guard: PublicKey;
  private cursors: Record<string, string | undefined> = {};
  private seen = new Set<string>();
  private pending = new Map<string, ConfirmedSignatureInfo>();
  private stopped = false;

  constructor(private cfg: Config, private rules: Rule[], private dispatcher: AlertDispatcher, guardian?: Keypair) {
    this.connection = new Connection(cfg.rpcUrl, cfg.commitment);
    this.protocols = resolveProtocols(cfg);
    this.guard = new PublicKey(cfg.guardProgram);
    this.responder = new AutoPauseResponder(this.connection, this.guard, guardian, this.protocols);
    if (cfg.stateFile && existsSync(cfg.stateFile)) {
      this.cursors = JSON.parse(readFileSync(cfg.stateFile, "utf8"));
    }
  }

  stop() {
    this.stopped = true;
  }

  private async newSignatures(address: string): Promise<ConfirmedSignatureInfo[]> {
    const key = new PublicKey(address);
    const until = this.cursors[address];
    const out: ConfirmedSignatureInfo[] = [];
    let before: string | undefined;
    // Page backwards until we reach the cursor (or the start of history).
    for (;;) {
      const page = await this.connection.getSignaturesForAddress(key, { until, before, limit: 1000 }, this.cfg.commitment);
      out.push(...page);
      if (page.length < 1000) break;
      before = page[page.length - 1].signature;
    }
    if (out.length) this.cursors[address] = out[0].signature;
    return out;
  }

  /** Initialise cursors for addresses without one. */
  private async baseline(addresses: string[]) {
    for (const a of addresses) {
      if (a in this.cursors || this.cfg.startFrom === "all") continue;
      const [latest] = await this.connection.getSignaturesForAddress(new PublicKey(a), { limit: 1 }, this.cfg.commitment);
      this.cursors[a] = latest?.signature;
    }
  }

  /** One polling round: fetch new transactions, run rules, respond. */
  async poll(): Promise<Alert[]> {
    const sigs = new Map<string, ConfirmedSignatureInfo>(this.pending);
    this.pending.clear();
    for (const a of addressesToWatch(this.protocols)) {
      for (const s of await this.newSignatures(a)) if (!this.seen.has(s.signature)) sigs.set(s.signature, s);
    }
    if (!sigs.size) return [];

    const ordered = [...sigs.values()].sort((a, b) => a.slot - b.slot);
    const txs: TxRecord[] = [];
    for (const s of ordered) {
      const tx = await this.connection.getTransaction(s.signature, {
        commitment: this.cfg.commitment,
        maxSupportedTransactionVersion: 0,
      });
      if (!tx) {
        this.pending.set(s.signature, s); // not indexed yet at this commitment: retry next round
        continue;
      }
      this.seen.add(s.signature);
      const rec = toTxRecord(s.signature, tx, this.guard);
      if (rec.logsTruncated) console.warn(`⚠️  logs truncated for ${s.signature}; some guard events may be missing`);
      txs.push(rec);
    }

    const alerts = runRules(this.rules, { txs, protocols: this.protocols, config: this.cfg });
    if (alerts.length) {
      // Respond first: every slot counts during a live drain.
      const [paused] = await Promise.all([this.responder.handle(alerts), this.dispatcher.dispatch(alerts)]);
      // The AI review runs in the background so it never delays the next poll.
      if (this.ai) {
        const pausedByRules = new Set(paused.map((x) => x.protocol));
        void this.ai.review(alerts, txs, this.protocols, pausedByRules).catch((e) => console.error("AI review failed:", e));
      }
    }
    if (this.cfg.stateFile) writeFileSync(this.cfg.stateFile, JSON.stringify(this.cursors, null, 2));
    if (this.seen.size > 50_000) this.seen = new Set([...this.seen].slice(-10_000));
    return alerts;
  }

  async run() {
    const addresses = addressesToWatch(this.protocols);
    await this.baseline(addresses);
    console.log(`[${this.cfg.cluster}] watching ${this.protocols.length} protocol(s), ${addresses.length} address(es)`);
    while (!this.stopped) {
      try {
        await this.poll();
      } catch (e) {
        console.error(`poll error:`, (e as Error).message);
      }
      await sleep(this.cfg.pollIntervalMs);
    }
  }
}
