import { describe, expect, it } from "vitest";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  DEMO_VAULT_PROGRAM_ID,
  GUARD_PROGRAM_ID,
  decodeEvent,
  decodeOutflowLimit,
  decodeProtection,
  discriminator,
  encodeEvent,
  guardIx,
  limitPda,
  protectionPda,
  refilled,
  vaultIx,
  vaultPdas,
} from "../src/bastion.js";
import { parseLogs } from "../src/tx.js";

const key = () => Keypair.generate().publicKey;

describe("encoding", () => {
  it("matches Anchor's discriminator scheme", () => {
    // Well-known value for Anchor's `initialize` instruction.
    expect([...discriminator("global", "initialize")]).toEqual([175, 175, 109, 31, 13, 152, 155, 237]);
  });

  it("encodes pause(reason) as disc + borsh string", () => {
    const ix = guardIx.pause(key(), key(), "drain");
    expect(ix.programId.equals(GUARD_PROGRAM_ID)).toBe(true);
    expect(ix.data.subarray(0, 8)).toEqual(discriminator("global", "pause"));
    expect(ix.data.readUInt32LE(8)).toBe(5);
    expect(ix.data.subarray(12).toString()).toBe("drain");
    expect(ix.keys[0].isSigner).toBe(true);
    expect(ix.keys[1].isWritable).toBe(true);
  });

  it("passes the Bastion accounts only for protected vaults", () => {
    const v = { vault: key(), mint: key(), protected: true };
    const prot = vaultIx.sweep(key(), key(), v, 1n);
    const { authority } = vaultPdas(v.vault);
    const protection = protectionPda(authority);
    expect(prot.keys.map((k) => k.pubkey.toBase58())).toEqual(expect.arrayContaining([
      GUARD_PROGRAM_ID.toBase58(), protection.toBase58(), limitPda(protection, v.mint).toBase58(),
    ]));
    const unprot = vaultIx.sweep(key(), key(), { ...v, protected: false }, 1n);
    expect(unprot.keys.slice(6, 9).every((k) => k.pubkey.equals(DEMO_VAULT_PROGRAM_ID))).toBe(true);
  });

  it("round-trips every event", () => {
    const p = key();
    const events = [
      { name: "Paused", protected: p, by: key(), reason: "x" },
      { name: "Outflow", protected: p, mint: key(), amount: 5n, remaining: 7n },
      { name: "OutflowLimitSet", protected: p, mint: key(), capacity: 10n, window: 3600n },
      { name: "GuardianSet", protected: p, guardian: key(), enabled: true },
    ] as const;
    for (const e of events) expect(decodeEvent(encodeEvent(e))).toEqual(e);
  });

  it("decodes Protection and OutflowLimit accounts and refills like the program", () => {
    const [prot, admin, g1, g2] = [key(), key(), key(), key()];
    const vec = Buffer.alloc(4);
    vec.writeUInt32LE(2);
    const data = Buffer.concat([discriminator("account", "Protection"), prot.toBuffer(), admin.toBuffer(),
      Buffer.from([1]), vec, g1.toBuffer(), g2.toBuffer(), Buffer.from([255])]);
    const d = decodeProtection(data);
    expect(d.paused).toBe(true);
    expect(d.admin.equals(admin)).toBe(true);
    expect(d.guardians.map(String)).toEqual([g1.toBase58(), g2.toBase58()]);

    const n = (v: bigint) => { const b = Buffer.alloc(8); b.writeBigInt64LE(v); return b; };
    const lim = decodeOutflowLimit(Buffer.concat([discriminator("account", "OutflowLimit"), key().toBuffer(),
      key().toBuffer(), n(100n), n(3600n), n(0n), n(1000n), Buffer.from([254])]));
    expect(refilled(lim, 1000n + 1800n)).toBe(50n);
    expect(refilled(lim, 1000n + 99999n)).toBe(100n);
  });
});

describe("parseLogs", () => {
  const G = GUARD_PROGRAM_ID.toBase58();
  const V = DEMO_VAULT_PROGRAM_ID.toBase58();
  const ev = { name: "Outflow", protected: key(), mint: key(), amount: 1n, remaining: 2n } as const;
  const data = `Program data: ${encodeEvent(ev).toString("base64")}`;

  it("attributes events emitted by the guard during CPI", () => {
    const out = parseLogs([
      `Program ${V} invoke [1]`, `Program ${G} invoke [2]`, data, `Program ${G} success`, `Program ${V} success`,
    ], GUARD_PROGRAM_ID);
    expect(out.events).toEqual([ev]);
  });

  it("ignores forged event data written by another program", () => {
    const out = parseLogs([`Program ${V} invoke [1]`, data, `Program ${V} success`], GUARD_PROGRAM_ID);
    expect(out.events).toEqual([]);
  });

  it("names the guard error that failed the transaction", () => {
    const out = parseLogs([
      `Program ${V} invoke [1]`, `Program ${G} invoke [2]`,
      `Program ${G} failed: custom program error: 0x1773`,
      `Program ${V} failed: custom program error: 0x1773`,
    ], GUARD_PROGRAM_ID);
    expect(out.guardError).toBe("OutflowLimitExceeded");
  });

  it("does not blame the guard for a vault error with the same code", () => {
    const out = parseLogs([`Program ${V} invoke [1]`, `Program ${V} failed: custom program error: 0x1770`], GUARD_PROGRAM_ID);
    expect(out.guardError).toBeUndefined();
  });
});
