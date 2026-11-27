/**
 * Client-side encoding for the Bastion guard and demo vault programs: program IDs, PDAs,
 * instruction builders, account/event decoders and error codes.
 *
 * Hand-written against programs/*\/src/lib.rs (Anchor 0.31 layout), so the monitor and the demo
 * need no generated IDL. Discriminators are sha256("<namespace>:<name>")[..8].
 */
import { createHash } from "node:crypto";
import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
  type AccountMeta,
} from "@solana/web3.js";

export const GUARD_PROGRAM_ID = new PublicKey("2eace2zRjWZb6faQm3YcVn6NNfrRGVJw9F9FsRFvNP6M");
export const DEMO_VAULT_PROGRAM_ID = new PublicKey("gStKd68ZtxeZ6cVUrJdwwrNAwd38sT5QFcmabUXesKU");
export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
export const BPF_UPGRADEABLE_LOADER_ID = new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111");

// ---------------------------------------------------------------------------
// Discriminators & borsh helpers
// ---------------------------------------------------------------------------

export function discriminator(namespace: "global" | "account" | "event", name: string): Buffer {
  return createHash("sha256").update(`${namespace}:${name}`).digest().subarray(0, 8);
}

const u64 = (v: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(v);
  return b;
};
const i64 = (v: bigint) => {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(v);
  return b;
};
const bool = (v: boolean) => Buffer.from([v ? 1 : 0]);
const str = (s: string) => {
  const bytes = Buffer.from(s, "utf8");
  const len = Buffer.alloc(4);
  len.writeUInt32LE(bytes.length);
  return Buffer.concat([len, bytes]);
};
const optionPubkey = (k: PublicKey | null) => (k ? Buffer.concat([Buffer.from([1]), k.toBuffer()]) : Buffer.from([0]));

const ix = (name: string, ...args: Buffer[]) => Buffer.concat([discriminator("global", name), ...args]);

class Reader {
  private o = 0;
  constructor(private b: Buffer) {}
  pubkey() {
    const k = new PublicKey(this.b.subarray(this.o, this.o + 32));
    this.o += 32;
    return k;
  }
  u64() {
    const v = this.b.readBigUInt64LE(this.o);
    this.o += 8;
    return v;
  }
  i64() {
    const v = this.b.readBigInt64LE(this.o);
    this.o += 8;
    return v;
  }
  bool() {
    return this.b[this.o++] === 1;
  }
  string() {
    const len = this.b.readUInt32LE(this.o);
    this.o += 4;
    const s = this.b.subarray(this.o, this.o + len).toString("utf8");
    this.o += len;
    return s;
  }
}

// ---------------------------------------------------------------------------
// PDAs
// ---------------------------------------------------------------------------

export const protectionPda = (protectedAuthority: PublicKey, guard = GUARD_PROGRAM_ID) =>
  PublicKey.findProgramAddressSync([Buffer.from("protection"), protectedAuthority.toBuffer()], guard)[0];

export const limitPda = (protection: PublicKey, mint: PublicKey, guard = GUARD_PROGRAM_ID) =>
  PublicKey.findProgramAddressSync([Buffer.from("limit"), protection.toBuffer(), mint.toBuffer()], guard)[0];

export const programDataAddress = (programId: PublicKey) =>
  PublicKey.findProgramAddressSync([programId.toBuffer()], BPF_UPGRADEABLE_LOADER_ID)[0];

export const vaultPdas = (vault: PublicKey, program = DEMO_VAULT_PROGRAM_ID) => ({
  authority: PublicKey.findProgramAddressSync([Buffer.from("authority"), vault.toBuffer()], program)[0],
  vaultTokens: PublicKey.findProgramAddressSync([Buffer.from("tokens"), vault.toBuffer()], program)[0],
  position: (user: PublicKey) =>
    PublicKey.findProgramAddressSync([Buffer.from("position"), vault.toBuffer(), user.toBuffer()], program)[0],
});

// ---------------------------------------------------------------------------
// Guard instructions
// ---------------------------------------------------------------------------

const w = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true });
const r = (pubkey: PublicKey, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false });

export const guardIx = {
  pause(authority: PublicKey, protection: PublicKey, reason: string, guard = GUARD_PROGRAM_ID) {
    return new TransactionInstruction({
      programId: guard,
      keys: [r(authority, true), w(protection)],
      data: ix("pause", str(reason)),
    });
  },
  unpause(admin: PublicKey, protection: PublicKey, guard = GUARD_PROGRAM_ID) {
    return new TransactionInstruction({ programId: guard, keys: [r(admin, true), w(protection)], data: ix("unpause") });
  },
  setGuardian(admin: PublicKey, protection: PublicKey, guardian: PublicKey, enabled: boolean, guard = GUARD_PROGRAM_ID) {
    return new TransactionInstruction({
      programId: guard,
      keys: [r(admin, true), w(protection)],
      data: ix("set_guardian", guardian.toBuffer(), bool(enabled)),
    });
  },
  setOutflowLimit(admin: PublicKey, protection: PublicKey, mint: PublicKey, capacity: bigint, windowSec: bigint,
    guard = GUARD_PROGRAM_ID) {
    return new TransactionInstruction({
      programId: guard,
      keys: [w(admin, true), r(protection), r(mint), w(limitPda(protection, mint, guard)), r(SystemProgram.programId)],
      data: ix("set_outflow_limit", u64(capacity), i64(windowSec)),
    });
  },
  removeOutflowLimit(admin: PublicKey, protection: PublicKey, mint: PublicKey, guard = GUARD_PROGRAM_ID) {
    return new TransactionInstruction({
      programId: guard,
      keys: [w(admin, true), r(protection), w(limitPda(protection, mint, guard))],
      data: ix("remove_outflow_limit"),
    });
  },
};

// ---------------------------------------------------------------------------
// Demo vault instructions
// ---------------------------------------------------------------------------

/** Anchor encodes a `None` optional account as the instruction's own program ID. */
const NONE = DEMO_VAULT_PROGRAM_ID;

export interface VaultRef {
  vault: PublicKey;
  mint: PublicKey;
  /** Behind Bastion? Determines whether the Bastion accounts are passed. */
  protected: boolean;
}

function bastionAccounts(v: VaultRef) {
  const { authority } = vaultPdas(v.vault);
  const protection = protectionPda(authority);
  return v.protected
    ? { program: GUARD_PROGRAM_ID, protection, limit: limitPda(protection, v.mint) }
    : { program: NONE, protection: NONE, limit: NONE };
}

export const vaultIx = {
  initialize(owner: PublicKey, v: VaultRef, bastionAdmin: PublicKey | null) {
    const { authority, vaultTokens } = vaultPdas(v.vault);
    const b = bastionAccounts(v);
    return new TransactionInstruction({
      programId: DEMO_VAULT_PROGRAM_ID,
      keys: [
        w(owner, true), w(v.vault, true), r(authority), r(v.mint), w(vaultTokens),
        r(b.program), v.protected ? w(b.protection) : r(b.protection),
        r(TOKEN_PROGRAM_ID), r(SystemProgram.programId),
      ],
      data: ix("initialize", optionPubkey(bastionAdmin)),
    });
  },
  deposit(user: PublicKey, userTokens: PublicKey, v: VaultRef, amount: bigint) {
    const pdas = vaultPdas(v.vault);
    const b = bastionAccounts(v);
    return new TransactionInstruction({
      programId: DEMO_VAULT_PROGRAM_ID,
      keys: [
        w(user, true), r(v.vault), r(pdas.authority), w(userTokens), w(pdas.vaultTokens), w(pdas.position(user)),
        r(b.program), r(b.protection), r(TOKEN_PROGRAM_ID), r(SystemProgram.programId),
      ],
      data: ix("deposit", u64(amount)),
    });
  },
  /** The buggy instruction: anyone can call it. */
  sweep(caller: PublicKey, destination: PublicKey, v: VaultRef, amount: bigint) {
    const pdas = vaultPdas(v.vault);
    const b = bastionAccounts(v);
    return new TransactionInstruction({
      programId: DEMO_VAULT_PROGRAM_ID,
      keys: [
        r(caller, true),
        // Outflow<'info> (flattened)
        r(v.vault), r(pdas.authority), r(v.mint), w(pdas.vaultTokens), w(destination),
        r(b.program), r(b.protection), v.protected ? w(b.limit) : r(b.limit), r(TOKEN_PROGRAM_ID),
      ],
      data: ix("sweep", u64(amount)),
    });
  },
};

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

export interface ProtectionAccount {
  protected: PublicKey;
  admin: PublicKey;
  paused: boolean;
  guardians: PublicKey[];
}

export function decodeProtection(data: Buffer): ProtectionAccount {
  if (!data.subarray(0, 8).equals(discriminator("account", "Protection"))) throw new Error("not a Protection account");
  const rd = new Reader(data.subarray(8));
  const prot = rd.pubkey();
  const admin = rd.pubkey();
  const paused = rd.bool();
  const n = data.readUInt32LE(8 + 65);
  const guardians: PublicKey[] = [];
  const g = new Reader(data.subarray(8 + 69));
  for (let i = 0; i < n; i++) guardians.push(g.pubkey());
  return { protected: prot, admin, paused, guardians };
}

export interface OutflowLimitAccount {
  protection: PublicKey;
  mint: PublicKey;
  capacity: bigint;
  window: bigint;
  available: bigint;
  lastUpdate: bigint;
}

export function decodeOutflowLimit(data: Buffer): OutflowLimitAccount {
  if (!data.subarray(0, 8).equals(discriminator("account", "OutflowLimit"))) throw new Error("not an OutflowLimit account");
  const rd = new Reader(data.subarray(8));
  return { protection: rd.pubkey(), mint: rd.pubkey(), capacity: rd.u64(), window: rd.i64(), available: rd.u64(), lastUpdate: rd.i64() };
}

/** Same math as `OutflowLimit::refilled` onchain. */
export function refilled(l: OutflowLimitAccount, now: bigint): bigint {
  const elapsed = now > l.lastUpdate ? now - l.lastUpdate : 0n;
  const total = l.available + (elapsed * l.capacity) / l.window;
  return total > l.capacity ? l.capacity : total;
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

export type BastionEvent =
  | { name: "Registered"; protected: PublicKey; admin: PublicKey }
  | { name: "AdminTransferred"; protected: PublicKey; previousAdmin: PublicKey; newAdmin: PublicKey }
  | { name: "GuardianSet"; protected: PublicKey; guardian: PublicKey; enabled: boolean }
  | { name: "Paused"; protected: PublicKey; by: PublicKey; reason: string }
  | { name: "Unpaused"; protected: PublicKey; by: PublicKey }
  | { name: "OutflowLimitSet"; protected: PublicKey; mint: PublicKey; capacity: bigint; window: bigint }
  | { name: "OutflowLimitRemoved"; protected: PublicKey; mint: PublicKey }
  | { name: "Outflow"; protected: PublicKey; mint: PublicKey; amount: bigint; remaining: bigint };

const EVENT_DECODERS: Record<string, (r: Reader) => BastionEvent> = {
  Registered: (r) => ({ name: "Registered", protected: r.pubkey(), admin: r.pubkey() }),
  AdminTransferred: (r) => ({ name: "AdminTransferred", protected: r.pubkey(), previousAdmin: r.pubkey(), newAdmin: r.pubkey() }),
  GuardianSet: (r) => ({ name: "GuardianSet", protected: r.pubkey(), guardian: r.pubkey(), enabled: r.bool() }),
  Paused: (r) => ({ name: "Paused", protected: r.pubkey(), by: r.pubkey(), reason: r.string() }),
  Unpaused: (r) => ({ name: "Unpaused", protected: r.pubkey(), by: r.pubkey() }),
  OutflowLimitSet: (r) => ({ name: "OutflowLimitSet", protected: r.pubkey(), mint: r.pubkey(), capacity: r.u64(), window: r.i64() }),
  OutflowLimitRemoved: (r) => ({ name: "OutflowLimitRemoved", protected: r.pubkey(), mint: r.pubkey() }),
  Outflow: (r) => ({ name: "Outflow", protected: r.pubkey(), mint: r.pubkey(), amount: r.u64(), remaining: r.u64() }),
};
const EVENT_BY_DISC = new Map(Object.keys(EVENT_DECODERS).map((n) => [discriminator("event", n).toString("hex"), n]));

export function decodeEvent(data: Buffer): BastionEvent | undefined {
  const name = EVENT_BY_DISC.get(data.subarray(0, 8).toString("hex"));
  if (!name) return undefined;
  try {
    return EVENT_DECODERS[name](new Reader(data.subarray(8)));
  } catch {
    return undefined;
  }
}

/** Test helper / reference encoder: the bytes Anchor's `emit!` writes for an event. */
export function encodeEvent(e: BastionEvent): Buffer {
  const parts: Buffer[] = [discriminator("event", e.name), e.protected.toBuffer()];
  switch (e.name) {
    case "Registered": parts.push(e.admin.toBuffer()); break;
    case "AdminTransferred": parts.push(e.previousAdmin.toBuffer(), e.newAdmin.toBuffer()); break;
    case "GuardianSet": parts.push(e.guardian.toBuffer(), bool(e.enabled)); break;
    case "Paused": parts.push(e.by.toBuffer(), str(e.reason)); break;
    case "Unpaused": parts.push(e.by.toBuffer()); break;
    case "OutflowLimitSet": parts.push(e.mint.toBuffer(), u64(e.capacity), i64(e.window)); break;
    case "OutflowLimitRemoved": parts.push(e.mint.toBuffer()); break;
    case "Outflow": parts.push(e.mint.toBuffer(), u64(e.amount), u64(e.remaining)); break;
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// Errors (Anchor custom codes = 6000 + variant index)
// ---------------------------------------------------------------------------

export const GUARD_ERRORS = [
  "NotAdmin", "NotGuardianOrAdmin", "ProtocolPaused", "OutflowLimitExceeded",
  "InvalidLimit", "InvalidLimitAccount", "TooManyGuardians",
] as const;
export type GuardErrorName = (typeof GUARD_ERRORS)[number];
export const guardErrorName = (code: number): GuardErrorName | undefined => GUARD_ERRORS[code - 6000];
