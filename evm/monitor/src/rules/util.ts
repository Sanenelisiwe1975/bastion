import { decodeEventLog, formatUnits, isAddressEqual, type Abi, type Address, type Log } from "viem";
import type { Alert, BlockBatch, Severity } from "../types.js";
import type { WatchedContract } from "../config.js";

export function tryDecode<const A extends Abi>(abi: A, log: Log) {
  try {
    return decodeEventLog({ abi, data: log.data, topics: log.topics, strict: true });
  } catch {
    return undefined;
  }
}

export const same = (a: Address | undefined | null, b: Address | undefined | null) =>
  !!a && !!b && isAddressEqual(a, b);

export function fmt(amount: bigint, decimals: number, symbol: string) {
  const n = Number(formatUnits(amount, decimals));
  return `${n.toLocaleString("en-US", { maximumFractionDigits: 2 })} ${symbol}`;
}

export function makeAlert(
  batch: BlockBatch,
  contract: WatchedContract,
  rule: string,
  severity: Severity,
  message: string,
  log?: Log,
): Alert {
  const blockNumber = log?.blockNumber ?? batch.toBlock;
  return {
    severity,
    rule,
    chain: batch.chain.name,
    contract: contract.address,
    contractName: contract.name,
    message,
    txHash: log?.transactionHash ?? undefined,
    blockNumber,
    timestamp: batch.timestamps.get(blockNumber) ?? Math.floor(Date.now() / 1000),
  };
}
