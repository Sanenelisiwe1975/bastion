import { readFileSync } from "node:fs";
import { z } from "zod";
import { getAddress, type Address, type Hex } from "viem";

const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/).transform((a) => getAddress(a) as Address);
const bytes32 = z.string().regex(/^0x[0-9a-fA-F]{64}$/).transform((h) => h.toLowerCase() as Hex);
const bigintish = z.union([z.string(), z.number()]).transform((v) => BigInt(v));

const TokenSchema = z.object({
  address,
  symbol: z.string(),
  decimals: z.number().int().default(18),
  /** Single outflow at or above this (base units) raises a warning. */
  warnOutflow: bigintish,
  /** Single outflow at or above this raises a critical alert (may trigger auto-pause). */
  criticalOutflow: bigintish,
  /** Cumulative outflow within `velocityWindowSec` at or above this is critical. */
  velocityLimit: bigintish.optional(),
  velocityWindowSec: z.number().int().positive().default(600),
});

const TrustedSenderSchema = z.object({
  sourceBlockchainID: bytes32,
  sender: address,
});

const WatchedContractSchema = z.object({
  name: z.string(),
  address,
  chain: z.string(),
  tokens: z.array(TokenSchema).default([]),
  /** Auto-pause through BastionGuard when a critical alert fires on this contract. */
  autoPause: z.boolean().default(false),
  /** If set, ICM messages delivered to this contract from anyone else are critical. */
  icmTrustedSenders: z.array(TrustedSenderSchema).optional(),
});

const ChainSchema = z.object({
  name: z.string(),
  rpcUrl: z.string().url(),
  chainId: z.number().int(),
  pollIntervalMs: z.number().int().positive().default(2000),
  /** Blocks to process per getLogs call when catching up. */
  maxBlockRange: z.number().int().positive().default(50),
  /** BastionGuard deployment on this chain. */
  guard: address.optional(),
  /** TeleporterMessenger (ICM) on this chain. Universal v1.0.0 deployment by default. */
  teleporter: address.default("0x253b2784c75e510dD0fF1da844684a1aC0aa5fcf"),
  startBlock: z.union([z.literal("latest"), z.number().int().nonnegative()]).default("latest"),
});

const ConfigSchema = z.object({
  chains: z.array(ChainSchema).min(1),
  contracts: z.array(WatchedContractSchema).min(1),
  alerts: z
    .object({
      webhooks: z.array(z.string().url()).default([]),
      telegram: z.object({ botToken: z.string(), chatId: z.string() }).optional(),
      minSeverity: z.enum(["info", "warning", "critical"]).default("info"),
    })
    .default({}),
});

export type Config = z.infer<typeof ConfigSchema>;
export type ChainConfig = z.infer<typeof ChainSchema>;
export type WatchedContract = z.infer<typeof WatchedContractSchema>;
export type TokenConfig = z.infer<typeof TokenSchema>;

export function parseConfig(raw: unknown): Config {
  const cfg = ConfigSchema.parse(raw);
  const chainNames = new Set(cfg.chains.map((c) => c.name));
  for (const c of cfg.contracts) {
    if (!chainNames.has(c.chain)) throw new Error(`Contract ${c.name} references unknown chain "${c.chain}"`);
    if (c.autoPause && !cfg.chains.find((ch) => ch.name === c.chain)?.guard) {
      throw new Error(`Contract ${c.name} has autoPause but chain "${c.chain}" has no guard address`);
    }
  }
  return cfg;
}

export function loadConfig(path: string): Config {
  return parseConfig(JSON.parse(readFileSync(path, "utf8")));
}
