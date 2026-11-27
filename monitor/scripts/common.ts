import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Connection,
  Keypair,
  LAMPORTS_PER_SOL,
  Transaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import { GUARD_PROGRAM_ID } from "../src/bastion.js";
import { parseLogs } from "../src/tx.js";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
export const DEMO_DIR = resolve(ROOT, "demo");
export const RPC_URL = process.env.RPC_URL ?? "http://127.0.0.1:8899";
export const DECIMALS = 6;
export const UNIT = 10n ** BigInt(DECIMALS);
export const tokens = (n: number) => BigInt(n) * UNIT;
export const fmt = (v: bigint) => (v / UNIT).toLocaleString("en-US");
export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export const connection = () => new Connection(RPC_URL, "confirmed");

export function saveKeypair(name: string, kp: Keypair) {
  mkdirSync(resolve(DEMO_DIR, "keys"), { recursive: true });
  writeFileSync(resolve(DEMO_DIR, "keys", `${name}.json`), JSON.stringify([...kp.secretKey]));
}

export function loadKeypair(name: string): Keypair {
  const p = resolve(DEMO_DIR, "keys", `${name}.json`);
  if (!existsSync(p)) throw new Error(`${p} missing: run the demo setup first`);
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(p, "utf8"))));
}

export async function airdrop(conn: Connection, kp: Keypair, sol = 10) {
  const sig = await conn.requestAirdrop(kp.publicKey, sol * LAMPORTS_PER_SOL);
  const bh = await conn.getLatestBlockhash();
  await conn.confirmTransaction({ signature: sig, ...bh }, "confirmed");
}

export interface SendResult {
  ok: boolean;
  signature: string;
  /** Guard error name, Anchor error name, or the raw error. */
  error?: string;
}

/**
 * Sends and confirms. With `skipPreflight` a failing transaction still lands onchain (as a real
 * attacker's would), which is what lets the monitor see rejected drain attempts.
 */
export async function send(
  conn: Connection,
  ixs: TransactionInstruction[],
  signers: Keypair[],
  { skipPreflight = false } = {},
): Promise<SendResult> {
  const tx = new Transaction().add(...ixs);
  const bh = await conn.getLatestBlockhash("confirmed");
  tx.recentBlockhash = bh.blockhash;
  tx.feePayer = signers[0].publicKey;
  tx.sign(...signers);
  let signature: string;
  try {
    signature = await conn.sendRawTransaction(tx.serialize(), { skipPreflight });
  } catch (e) {
    const logs: string[] = (e as { logs?: string[] }).logs ?? [];
    return { ok: false, signature: "", error: errorFromLogs(logs) ?? (e as Error).message };
  }
  const res = await conn.confirmTransaction({ signature, ...bh }, "confirmed");
  if (!res.value.err) return { ok: true, signature };
  const full = await conn.getTransaction(signature, { commitment: "confirmed", maxSupportedTransactionVersion: 0 });
  return { ok: false, signature, error: errorFromLogs(full?.meta?.logMessages ?? []) ?? JSON.stringify(res.value.err) };
}

function errorFromLogs(logs: string[]): string | undefined {
  const g = parseLogs(logs, GUARD_PROGRAM_ID).guardError;
  if (g) return g;
  for (const l of logs) {
    const m = l.match(/Error Code: (\w+)/);
    if (m) return m[1];
  }
}

export interface DemoAddresses {
  mint: string;
  protectedVault: string;
  unprotectedVault: string;
  admin: string;
  guardian: string;
}

export const readAddresses = (): DemoAddresses =>
  JSON.parse(readFileSync(resolve(DEMO_DIR, "addresses.json"), "utf8"));
