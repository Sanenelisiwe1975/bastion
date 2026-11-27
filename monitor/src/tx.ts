import {
  PublicKey,
  type CompiledInstruction,
  type MessageCompiledInstruction,
  type VersionedTransactionResponse,
} from "@solana/web3.js";
import { BPF_UPGRADEABLE_LOADER_ID, decodeEvent, guardErrorName, type BastionEvent } from "./bastion.js";
import type { TxRecord, LoaderAction, TokenDelta } from "./types.js";

const INVOKE = /^Program (\w+) invoke \[(\d+)\]$/;
const SUCCESS = /^Program (\w+) success$/;
const FAILED = /^Program (\w+) failed: (.*)$/;
const DATA = /^Program data: (.+)$/;
const CUSTOM_ERR = /custom program error: 0x([0-9a-fA-F]+)/;

export interface ParsedLogs {
  /** Events emitted by the guard program itself (attributed via the invoke stack). */
  events: BastionEvent[];
  /** Name of the guard error, if the guard program is the one that failed. */
  guardError?: string;
  truncated: boolean;
}

/**
 * Walks the log lines keeping a stack of invoked programs, so a `Program data:` line is only
 * decoded as a Bastion event when the guard program is the one currently executing. Any program
 * can write arbitrary `Program data:` lines, so without this an attacker could forge events.
 */
export function parseLogs(logs: string[], guardProgram: PublicKey): ParsedLogs {
  const guard = guardProgram.toBase58();
  const stack: string[] = [];
  const out: ParsedLogs = { events: [], truncated: false };
  for (const line of logs) {
    let m: RegExpMatchArray | null;
    if ((m = line.match(INVOKE))) {
      stack.push(m[1]);
    } else if ((m = line.match(SUCCESS))) {
      stack.pop();
    } else if ((m = line.match(FAILED))) {
      if (m[1] === guard) {
        const code = m[2].match(CUSTOM_ERR);
        out.guardError = code ? guardErrorName(parseInt(code[1], 16)) ?? `0x${code[1]}` : m[2];
      }
      stack.pop();
    } else if ((m = line.match(DATA)) && stack[stack.length - 1] === guard) {
      const ev = decodeEvent(Buffer.from(m[1], "base64"));
      if (ev) out.events.push(ev);
    } else if (line === "Log truncated") {
      out.truncated = true;
    }
  }
  return out;
}

/** Signed token balance change per token account in this transaction. */
export function tokenDeltas(tx: VersionedTransactionResponse, keys: PublicKey[]): TokenDelta[] {
  const meta = tx.meta;
  if (!meta) return [];
  const pre = new Map((meta.preTokenBalances ?? []).map((b) => [b.accountIndex, b]));
  const post = new Map((meta.postTokenBalances ?? []).map((b) => [b.accountIndex, b]));
  const out: TokenDelta[] = [];
  for (const idx of new Set([...pre.keys(), ...post.keys()])) {
    const a = pre.get(idx);
    const b = post.get(idx);
    const before = BigInt(a?.uiTokenAmount.amount ?? "0");
    const after = BigInt(b?.uiTokenAmount.amount ?? "0");
    if (before === after) continue;
    out.push({
      account: keys[idx].toBase58(),
      mint: (b ?? a)!.mint,
      owner: (b ?? a)!.owner ?? undefined,
      delta: after - before,
      decimals: (b ?? a)!.uiTokenAmount.decimals,
    });
  }
  return out;
}

const LOADER_ACTIONS: Record<number, LoaderAction["kind"]> = {
  3: "Upgrade",
  4: "SetAuthority",
  5: "Close",
  7: "SetAuthorityChecked",
};

/** BPF upgradeable loader instructions (top-level and CPI) and the program they target. */
export function loaderActions(tx: VersionedTransactionResponse, keys: PublicKey[]): LoaderAction[] {
  const loader = BPF_UPGRADEABLE_LOADER_ID.toBase58();
  const out: LoaderAction[] = [];
  const consider = (programIdx: number, accounts: number[], data: Buffer) => {
    if (keys[programIdx]?.toBase58() !== loader || data.length < 4) return;
    const kind = LOADER_ACTIONS[data.readUInt32LE(0)];
    if (!kind) return;
    // Upgrade: [programData, program, buffer, spill, rent, clock, authority]
    // SetAuthority(Checked) / Close: [programData (or buffer), ...]
    const acct = (i: number) => (accounts[i] !== undefined ? keys[accounts[i]]?.toBase58() : undefined);
    out.push({ kind, programData: acct(0)!, program: kind === "Upgrade" ? acct(1) : kind === "Close" ? acct(3) : undefined });
  };
  for (const ci of tx.transaction.message.compiledInstructions as MessageCompiledInstruction[]) {
    consider(ci.programIdIndex, [...ci.accountKeyIndexes], Buffer.from(ci.data));
  }
  for (const inner of tx.meta?.innerInstructions ?? []) {
    for (const ci of inner.instructions as CompiledInstruction[]) {
      consider(ci.programIdIndex, ci.accounts, Buffer.from(bs58decode(ci.data)));
    }
  }
  return out;
}

/** Normalises an RPC transaction into what rules consume. */
export function toTxRecord(signature: string, tx: VersionedTransactionResponse, guardProgram: PublicKey): TxRecord {
  const keys = tx.transaction.message
    .getAccountKeys({ accountKeysFromLookups: tx.meta?.loadedAddresses })
    .keySegments()
    .flat();
  const logs = parseLogs(tx.meta?.logMessages ?? [], guardProgram);
  return {
    signature,
    slot: tx.slot,
    blockTime: tx.blockTime ?? Math.floor(Date.now() / 1000),
    failed: !!tx.meta?.err,
    accountKeys: keys.map((k) => k.toBase58()),
    events: logs.events,
    guardError: logs.guardError,
    logsTruncated: logs.truncated,
    logs: (tx.meta?.logMessages ?? []).slice(0, 80),
    tokenDeltas: tokenDeltas(tx, keys),
    loaderActions: loaderActions(tx, keys),
  };
}

// Inner instruction data comes back base58-encoded.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function bs58decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const v = B58.indexOf(c);
    if (v < 0) throw new Error("bad base58");
    n = n * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return Uint8Array.from(bytes);
}
