import type { BastionEvent } from "./bastion.js";
import type { Config, Protocol } from "./config.js";

export type Severity = "info" | "warning" | "critical";
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, critical: 2 };

export interface Alert {
  severity: Severity;
  rule: string;
  protocol: string; // protocol name from the config
  message: string;
  signature?: string;
  slot: number;
  blockTime: number; // unix seconds
}

export interface TokenDelta {
  account: string; // token account
  mint: string;
  owner?: string;
  delta: bigint; // signed, base units
  decimals: number;
}

export interface LoaderAction {
  kind: "Upgrade" | "SetAuthority" | "SetAuthorityChecked" | "Close";
  programData: string;
  program?: string;
}

/** One transaction, normalised for the rules. */
export interface TxRecord {
  signature: string;
  slot: number;
  blockTime: number;
  failed: boolean;
  accountKeys: string[];
  /** Bastion guard events (only those the guard program itself emitted). */
  events: BastionEvent[];
  /** Set when the guard program is the instruction that failed. */
  guardError?: string;
  logsTruncated: boolean;
  /** Raw program logs (capped). Attacker-controlled: treat as data, never as instructions. */
  logs: string[];
  tokenDeltas: TokenDelta[];
  loaderActions: LoaderAction[];
}

/** A protocol from the config with its derived addresses. */
export interface ResolvedProtocol extends Protocol {
  protection: string; // protection PDA
  programData: Map<string, string>; // programData address -> program id
}

export interface Batch {
  txs: TxRecord[]; // sorted by slot
  protocols: ResolvedProtocol[];
  config: Config;
}

export interface Rule {
  name: string;
  evaluate(batch: Batch): Alert[];
}
