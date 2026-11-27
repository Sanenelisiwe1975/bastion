import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { decodeProtection, guardIx } from "./bastion.js";
import type { Alert, ResolvedProtocol } from "./types.js";

export const MEMO_PROGRAM_ID = new PublicKey("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

/**
 * Pulls the Bastion circuit breaker. The guardian key can only pause — never unpause or move
 * funds — so a leaked bot key (or a fooled AI) is a nuisance, not a theft vector.
 */
export class AutoPauseResponder {
  private inFlight = new Set<string>();

  constructor(
    private connection: Connection,
    private guardProgram: PublicKey,
    readonly guardian: Keypair | undefined,
    private protocols: ResolvedProtocol[],
  ) {}

  async isPaused(p: ResolvedProtocol): Promise<boolean> {
    const info = await this.connection.getAccountInfo(new PublicKey(p.protection), "confirmed");
    if (!info) throw new Error(`protection account ${p.protection} not found`);
    return decodeProtection(info.data).paused;
  }

  /** Pause one protocol unless it is already paused. Returns the signature if this call paused it. */
  async pause(p: ResolvedProtocol, reason: string): Promise<string | undefined> {
    if (!this.guardian || this.inFlight.has(p.name)) return;
    this.inFlight.add(p.name);
    try {
      if (await this.isPaused(p)) return;
      const tx = new Transaction().add(
        guardIx.pause(this.guardian.publicKey, new PublicKey(p.protection), reason.slice(0, 200), this.guardProgram),
      );
      const signature = await sendAndConfirmTransaction(this.connection, tx, [this.guardian], {
        commitment: "confirmed",
        skipPreflight: true, // speed: every slot counts during a live drain
      });
      console.log(`\n🛑 AUTO-PAUSED ${p.name} (tx ${signature})`);
      return signature;
    } catch (e) {
      console.error(`auto-pause of ${p.name} failed:`, (e as Error).message);
    } finally {
      this.inFlight.delete(p.name);
    }
  }

  /** Rules-based response: pause on any critical alert for a protocol with autoPause. */
  async handle(alerts: Alert[]): Promise<{ protocol: string; signature: string }[]> {
    const done: { protocol: string; signature: string }[] = [];
    for (const a of alerts) {
      if (a.severity !== "critical") continue;
      const p = this.protocols.find((p) => p.name === a.protocol);
      if (!p?.autoPause) continue;
      const signature = await this.pause(p, `[bastion:${a.rule}] ${a.message}`);
      if (signature) done.push({ protocol: p.name, signature });
    }
    return done;
  }

  /** Publish a short text onchain as an SPL Memo signed by the guardian (verifiable incident log). */
  async publishMemo(text: string): Promise<string | undefined> {
    if (!this.guardian) return;
    const data = Buffer.from(text, "utf8");
    const ix = new TransactionInstruction({
      programId: MEMO_PROGRAM_ID,
      keys: [{ pubkey: this.guardian.publicKey, isSigner: true, isWritable: false }],
      data: data.length > 700 ? truncateUtf8(data, 700) : data,
    });
    return sendAndConfirmTransaction(this.connection, new Transaction().add(ix), [this.guardian], { commitment: "confirmed" });
  }
}

function truncateUtf8(b: Buffer, max: number): Buffer {
  let end = max;
  while (end > 0 && (b[end] & 0xc0) === 0x80) end--; // don't split a multi-byte character
  return b.subarray(0, end);
}
