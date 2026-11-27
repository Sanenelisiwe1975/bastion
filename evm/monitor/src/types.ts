import type { Address, Hex, Log } from "viem";
import type { ChainConfig, WatchedContract } from "./config.js";

export type Severity = "info" | "warning" | "critical";
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export interface Alert {
  severity: Severity;
  rule: string;
  chain: string;
  contract: Address; // the watched contract this alert concerns
  contractName: string;
  message: string;
  txHash?: Hex;
  blockNumber: bigint;
  timestamp: number; // unix seconds of the block
}

/** Everything a rule needs to evaluate one batch of blocks on one chain. */
export interface BlockBatch {
  chain: ChainConfig;
  fromBlock: bigint;
  toBlock: bigint;
  logs: Log[];
  /** Block timestamps keyed by block number (only for blocks that have relevant logs). */
  timestamps: Map<bigint, number>;
  contracts: WatchedContract[]; // watched contracts on this chain
}

export interface Rule {
  name: string;
  evaluate(batch: BlockBatch): Alert[];
}
