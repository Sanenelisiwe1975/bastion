import { readFileSync } from "node:fs";
import { PublicKey } from "@solana/web3.js";
import { z } from "zod";
import { GUARD_PROGRAM_ID, programDataAddress, protectionPda } from "./bastion.js";
import type { ResolvedProtocol } from "./types.js";

const pubkey = z.string().refine((s) => {
  try {
    new PublicKey(s);
    return true;
  } catch {
    return false;
  }
}, "invalid base58 public key");
const bigintish = z.union([z.string(), z.number()]).transform((v) => BigInt(v));

const TokenAccountSchema = z.object({
  /** The protocol's token account (e.g. the vault's PDA-owned account). */
  address: pubkey,
  symbol: z.string(),
  decimals: z.number().int().nonnegative(),
  /** Single outflow at or above this (base units) raises a warning. */
  warnOutflow: bigintish,
  /** Single outflow at or above this is critical (may auto-pause). */
  criticalOutflow: bigintish,
  /** Cumulative outflow within `velocityWindowSec` at or above this is critical. */
  velocityLimit: bigintish.optional(),
  velocityWindowSec: z.number().int().positive().default(600),
});

const ProtocolSchema = z.object({
  name: z.string(),
  /** The protected authority PDA: the key that registered with Bastion and signs outflows. */
  protectedAuthority: pubkey,
  /** Programs whose upgrade authority / binary changes should be flagged. */
  programs: z.array(pubkey).default([]),
  tokenAccounts: z.array(TokenAccountSchema).default([]),
  /** Pause through Bastion when a critical alert fires on this protocol. */
  autoPause: z.boolean().default(false),
});

const ConfigSchema = z.object({
  cluster: z.string().default("custom"),
  rpcUrl: z.string().url(),
  commitment: z.enum(["confirmed", "finalized"]).default("confirmed"),
  pollIntervalMs: z.number().int().positive().default(1000),
  guardProgram: pubkey.default(GUARD_PROGRAM_ID.toBase58()),
  /** Where to persist per-address cursors so a restart resumes instead of skipping. */
  stateFile: z.string().optional(),
  /** "latest" = only new activity; "all" = backfill each address's full history (up to RPC limits). */
  startFrom: z.enum(["latest", "all"]).default("latest"),
  /** Explorer URL template; `{sig}` is replaced with the signature. */
  explorer: z.string().default("https://explorer.solana.com/tx/{sig}"),
  protocols: z.array(ProtocolSchema).min(1),
  /** AI guardian (Claude). Needs ANTHROPIC_API_KEY (or another Anthropic SDK credential). */
  ai: z
    .object({
      /** "act": the AI may pause gray-zone incidents itself; "advise": reports only. */
      mode: z.enum(["act", "advise"]).default("act"),
      model: z.string().default("claude-opus-5-5"),
      effort: z.enum(["low", "medium", "high", "xhigh", "max"]).default("high"),
      /** Minimum confidence (0–1) for the AI to pause on its own. */
      minConfidence: z.number().min(0).max(1).default(0.8),
      /** Lowest alert severity that triggers an AI review. */
      minSeverity: z.enum(["info", "warning", "critical"]).default("warning"),
      /** Publish each incident report onchain as an SPL Memo signed by the guardian. */
      publishOnchain: z.boolean().default(true),
    })
    .optional(),
  alerts: z
    .object({
      webhooks: z.array(z.string().url()).default([]),
      telegram: z.object({ botToken: z.string(), chatId: z.string() }).optional(),
      minSeverity: z.enum(["info", "warning", "critical"]).default("info"),
    })
    .default({}),
});

export type Config = z.infer<typeof ConfigSchema>;
export type Protocol = z.infer<typeof ProtocolSchema>;
export type TokenAccountConfig = z.infer<typeof TokenAccountSchema>;

export function parseConfig(raw: unknown): Config {
  const cfg = ConfigSchema.parse(raw);
  const names = new Set<string>();
  for (const p of cfg.protocols) {
    if (names.has(p.name)) throw new Error(`Duplicate protocol name "${p.name}"`);
    names.add(p.name);
    if (p.protectedAuthority === PublicKey.default.toBase58()) {
      throw new Error(`Protocol ${p.name}: protectedAuthority is the all-zero key; set the real authority PDA`);
    }
    for (const t of p.tokenAccounts) {
      if (t.criticalOutflow < t.warnOutflow) throw new Error(`Protocol ${p.name} ${t.symbol}: criticalOutflow < warnOutflow`);
    }
  }
  return cfg;
}

export function loadConfig(path: string): Config {
  return parseConfig(JSON.parse(readFileSync(path, "utf8")));
}

export function resolveProtocols(cfg: Config): ResolvedProtocol[] {
  const guard = new PublicKey(cfg.guardProgram);
  return cfg.protocols.map((p) => ({
    ...p,
    protection: protectionPda(new PublicKey(p.protectedAuthority), guard).toBase58(),
    programData: new Map(p.programs.map((id) => [programDataAddress(new PublicKey(id)).toBase58(), id])),
  }));
}

/** Every address whose transaction history the engine polls. */
export function addressesToWatch(protocols: ResolvedProtocol[]): string[] {
  const set = new Set<string>();
  for (const p of protocols) {
    set.add(p.protection); // every guard call for this protocol: outflows, pause, config, rejected drains
    for (const t of p.tokenAccounts) set.add(t.address); // catches outflows even for mints with no limit
    for (const pd of p.programData.keys()) set.add(pd); // upgrades / authority changes
  }
  return [...set];
}
