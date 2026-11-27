import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  type Address,
  type Log,
  type PublicClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import type { ChainConfig, Config, WatchedContract } from "./config.js";
import type { AlertDispatcher } from "./alerts.js";
import { AutoPauseResponder } from "./responder.js";
import type { Alert, BlockBatch, Rule } from "./types.js";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Addresses whose logs any rule might need. */
export function addressesToWatch(chain: ChainConfig, contracts: WatchedContract[]): Address[] {
  const set = new Set<Address>();
  for (const c of contracts) {
    set.add(c.address);
    for (const t of c.tokens) set.add(t.address);
  }
  if (chain.guard) set.add(chain.guard);
  if (contracts.some((c) => c.icmTrustedSenders)) set.add(chain.teleporter);
  return [...set];
}

export function runRules(rules: Rule[], batch: BlockBatch): Alert[] {
  const alerts: Alert[] = [];
  for (const r of rules) {
    try {
      alerts.push(...r.evaluate(batch));
    } catch (e) {
      console.error(`rule ${r.name} threw:`, e);
    }
  }
  return alerts;
}

export class ChainWatcher {
  readonly client: PublicClient;
  private responder: AutoPauseResponder;
  private stopped = false;
  private cursor?: bigint;

  constructor(
    private chain: ChainConfig,
    private contracts: WatchedContract[],
    private rules: Rule[],
    private dispatcher: AlertDispatcher,
    guardianKey?: `0x${string}`,
  ) {
    const viemChain = defineChain({
      id: chain.chainId,
      name: chain.name,
      nativeCurrency: { name: "AVAX", symbol: "AVAX", decimals: 18 },
      rpcUrls: { default: { http: [chain.rpcUrl] } },
    });
    this.client = createPublicClient({ chain: viemChain, transport: http(chain.rpcUrl) }) as PublicClient;
    const wallet = guardianKey
      ? createWalletClient({ chain: viemChain, transport: http(chain.rpcUrl), account: privateKeyToAccount(guardianKey) })
      : undefined;
    this.responder = new AutoPauseResponder(chain, this.client, wallet, contracts);
  }

  stop() {
    this.stopped = true;
  }

  /** Process one range of blocks. Exposed for tests and backfills. */
  async processRange(fromBlock: bigint, toBlock: bigint): Promise<Alert[]> {
    const logs: Log[] = await this.client.getLogs({
      address: addressesToWatch(this.chain, this.contracts),
      fromBlock,
      toBlock,
    });
    const timestamps = new Map<bigint, number>();
    const blockNumbers = [...new Set(logs.map((l) => l.blockNumber!))];
    await Promise.all(
      blockNumbers.map(async (n) => {
        const b = await this.client.getBlock({ blockNumber: n });
        timestamps.set(n, Number(b.timestamp));
      }),
    );
    const batch: BlockBatch = { chain: this.chain, fromBlock, toBlock, logs, timestamps, contracts: this.contracts };
    const alerts = runRules(this.rules, batch);
    if (alerts.length) {
      // Respond first: every second counts during a live drain.
      await Promise.all([this.responder.handle(alerts), this.dispatcher.dispatch(alerts)]);
    }
    return alerts;
  }

  async run() {
    const head = await this.client.getBlockNumber();
    let cursor: bigint = this.chain.startBlock === "latest" ? head : BigInt(this.chain.startBlock);
    console.log(`[${this.chain.name}] watching ${this.contracts.length} contract(s) from block ${cursor}`);

    while (!this.stopped) {
      try {
        const latest = await this.client.getBlockNumber();
        while (cursor <= latest && !this.stopped) {
          const end: bigint = cursor + BigInt(this.chain.maxBlockRange - 1);
          const to: bigint = end < latest ? end : latest;
          await this.processRange(cursor, to);
          cursor = to + 1n;
          this.cursor = cursor;
        }
      } catch (e) {
        console.error(`[${this.chain.name}] poll error:`, (e as Error).message);
      }
      await sleep(this.chain.pollIntervalMs);
    }
  }
}

export function startAll(cfg: Config, rules: () => Rule[], dispatcher: AlertDispatcher, guardianKey?: `0x${string}`) {
  return cfg.chains.map((chain) => {
    const contracts = cfg.contracts.filter((c) => c.chain === chain.name);
    const w = new ChainWatcher(chain, contracts, rules(), dispatcher, guardianKey);
    void w.run();
    return w;
  });
}
