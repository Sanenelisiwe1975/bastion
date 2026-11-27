import type { Alert, ResolvedProtocol, Severity, TxRecord } from "../types.js";

export function fmt(amount: bigint, decimals: number, symbol: string): string {
  const neg = amount < 0n;
  const abs = neg ? -amount : amount;
  const base = 10n ** BigInt(decimals);
  const whole = abs / base;
  const frac = decimals ? (abs % base).toString().padStart(decimals, "0").slice(0, 2).replace(/0+$/, "") : "";
  return `${neg ? "-" : ""}${whole.toLocaleString("en-US")}${frac ? "." + frac : ""} ${symbol}`;
}

export const short = (k: string) => `${k.slice(0, 4)}…${k.slice(-4)}`;

export function makeAlert(
  p: ResolvedProtocol,
  rule: string,
  severity: Severity,
  message: string,
  tx: TxRecord,
): Alert {
  return { severity, rule, protocol: p.name, message, signature: tx.signature, slot: tx.slot, blockTime: tx.blockTime };
}
