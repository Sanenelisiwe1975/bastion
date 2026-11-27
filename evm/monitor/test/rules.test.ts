import { describe, expect, it } from "vitest";
import {
  encodeAbiParameters,
  encodeEventTopics,
  getAbiItem,
  parseUnits,
  type Abi,
  type Address,
  type Hex,
  type Log,
} from "viem";
import { parseConfig } from "../src/config.js";
import { bastionGuardAbi, erc20Abi, privilegedAbi, teleporterAbi } from "../src/abis.js";
import {
  DrainVelocityRule,
  GuardConfigRule,
  IcmUntrustedSenderRule,
  LargeOutflowRule,
  PrivilegedChangeRule,
} from "../src/rules/index.js";
import type { BlockBatch } from "../src/types.js";

const VAULT = "0x1111111111111111111111111111111111111111" as Address;
const USDC = "0x2222222222222222222222222222222222222222" as Address;
const GUARD = "0x3333333333333333333333333333333333333333" as Address;
const TELEPORTER = "0x253b2784c75e510dD0fF1da844684a1aC0aa5fcf" as Address;
const ATTACKER = "0x4444444444444444444444444444444444444444" as Address;
const TRUSTED = "0x5555555555555555555555555555555555555555" as Address;
const SRC_CHAIN = ("0x" + "ab".repeat(32)) as Hex;

const cfg = parseConfig({
  chains: [{ name: "c-chain", rpcUrl: "http://localhost:8545", chainId: 43114, guard: GUARD }],
  contracts: [
    {
      name: "Vault",
      address: VAULT,
      chain: "c-chain",
      autoPause: true,
      tokens: [{
        address: USDC, symbol: "USDC", decimals: 6,
        warnOutflow: parseUnits("10000", 6).toString(),
        criticalOutflow: parseUnits("250000", 6).toString(),
        velocityLimit: parseUnits("300000", 6).toString(),
        velocityWindowSec: 600,
      }],
      icmTrustedSenders: [{ sourceBlockchainID: SRC_CHAIN, sender: TRUSTED }],
    },
  ],
});

let logIndex = 0;
function mkLog<A extends Abi>(
  abi: A, eventName: string, args: Record<string, unknown>, address: Address, blockNumber = 100n,
): Log {
  const item = getAbiItem({ abi, name: eventName } as never) as { inputs: readonly { name: string; indexed?: boolean }[] };
  const topics = encodeEventTopics({ abi, eventName, args } as never) as [Hex, ...Hex[]];
  const nonIndexed = item.inputs.filter((i) => !i.indexed);
  const data = encodeAbiParameters(nonIndexed as never, nonIndexed.map((i) => args[i.name]) as never);
  return {
    address, topics, data, blockNumber, logIndex: logIndex++, transactionIndex: 0,
    transactionHash: ("0x" + "cd".repeat(32)) as Hex, blockHash: ("0x" + "ef".repeat(32)) as Hex, removed: false,
  } as Log;
}

function batch(logs: Log[], ts = 1_700_000_000): BlockBatch {
  const timestamps = new Map<bigint, number>();
  for (const l of logs) timestamps.set(l.blockNumber!, ts);
  return { chain: cfg.chains[0], fromBlock: 100n, toBlock: 100n, logs, timestamps, contracts: cfg.contracts };
}

const transfer = (from: Address, value: string, block = 100n) =>
  mkLog(erc20Abi, "Transfer", { from, to: ATTACKER, value: parseUnits(value, 6) }, USDC, block);

describe("LargeOutflowRule", () => {
  const rule = new LargeOutflowRule();
  it("ignores small outflows and inflows", () => {
    expect(rule.evaluate(batch([transfer(VAULT, "500"), transfer(ATTACKER, "1000000")]))).toHaveLength(0);
  });
  it("warns on medium outflow", () => {
    const [a] = rule.evaluate(batch([transfer(VAULT, "50000")]));
    expect(a.severity).toBe("warning");
    expect(a.message).toContain("50,000 USDC");
  });
  it("is critical on large outflow", () => {
    const [a] = rule.evaluate(batch([transfer(VAULT, "900000")]));
    expect(a.severity).toBe("critical");
    expect(a.contract).toBe(VAULT);
  });
  it("ignores transfers of tokens not configured", () => {
    const other = mkLog(erc20Abi, "Transfer", { from: VAULT, to: ATTACKER, value: 10n ** 30n },
      "0x9999999999999999999999999999999999999999");
    expect(rule.evaluate(batch([other]))).toHaveLength(0);
  });
});

describe("DrainVelocityRule", () => {
  it("catches a drain split into sub-threshold chunks, alerting once per window", () => {
    const rule = new DrainVelocityRule();
    const chunks = Array.from({ length: 8 }, (_, i) => transfer(VAULT, "49000", 100n + BigInt(i)));
    const alerts = chunks.flatMap((l, i) => rule.evaluate(batch([l], 1_700_000_000 + i * 10)));
    expect(alerts).toHaveLength(1);
    expect(alerts[0].severity).toBe("critical");
    expect(alerts[0].message).toMatch(/across 7 transfers/);
  });
  it("forgets outflows that fall out of the window", () => {
    const rule = new DrainVelocityRule();
    const alerts = [0, 1, 2, 3, 4, 5, 6, 7].flatMap((i) =>
      rule.evaluate(batch([transfer(VAULT, "49000", 100n + BigInt(i))], 1_700_000_000 + i * 700)));
    expect(alerts).toHaveLength(0);
  });
});

describe("PrivilegedChangeRule", () => {
  const rule = new PrivilegedChangeRule();
  it("flags proxy upgrades as critical", () => {
    const [a] = rule.evaluate(batch([mkLog(privilegedAbi, "Upgraded", { implementation: ATTACKER }, VAULT)]));
    expect(a.severity).toBe("critical");
  });
  it("flags ownership transfer", () => {
    const [a] = rule.evaluate(batch([
      mkLog(privilegedAbi, "OwnershipTransferred", { previousOwner: TRUSTED, newOwner: ATTACKER }, VAULT),
    ]));
    expect(a.message).toContain(ATTACKER);
  });
  it("ignores the same event on unwatched contracts", () => {
    expect(rule.evaluate(batch([mkLog(privilegedAbi, "Upgraded", { implementation: ATTACKER }, USDC)]))).toHaveLength(0);
  });
});

describe("GuardConfigRule", () => {
  const rule = new GuardConfigRule();
  it("is critical when an outflow limit is removed", () => {
    const [a] = rule.evaluate(batch([
      mkLog(bastionGuardAbi, "OutflowLimitRemoved", { protectedContract: VAULT, token: USDC }, GUARD),
    ]));
    expect(a.severity).toBe("critical");
  });
  it("ignores events not emitted by the configured guard", () => {
    expect(rule.evaluate(batch([
      mkLog(bastionGuardAbi, "OutflowLimitRemoved", { protectedContract: VAULT, token: USDC }, ATTACKER),
    ]))).toHaveLength(0);
  });
});

describe("IcmUntrustedSenderRule", () => {
  const rule = new IcmUntrustedSenderRule();
  const msg = (sender: Address, src: Hex = SRC_CHAIN) =>
    mkLog(teleporterAbi, "ReceiveCrossChainMessage", {
      messageID: ("0x" + "01".repeat(32)) as Hex,
      sourceBlockchainID: src,
      deliverer: TRUSTED,
      rewardRedeemer: TRUSTED,
      message: {
        messageNonce: 1n, originSenderAddress: sender, destinationBlockchainID: ("0x" + "02".repeat(32)) as Hex,
        destinationAddress: VAULT, requiredGasLimit: 200000n, allowedRelayerAddresses: [], receipts: [], message: "0x",
      },
    }, TELEPORTER);

  it("passes messages from the trusted (chain, sender)", () => {
    expect(rule.evaluate(batch([msg(TRUSTED)]))).toHaveLength(0);
  });
  it("is critical for an untrusted sender", () => {
    const [a] = rule.evaluate(batch([msg(ATTACKER)]));
    expect(a.severity).toBe("critical");
  });
  it("is critical for the trusted sender address on the wrong source chain", () => {
    expect(rule.evaluate(batch([msg(TRUSTED, ("0x" + "cc".repeat(32)) as Hex)]))).toHaveLength(1);
  });
});

describe("config", () => {
  it("rejects autoPause without a guard", () => {
    expect(() => parseConfig({
      chains: [{ name: "x", rpcUrl: "http://localhost:1", chainId: 1 }],
      contracts: [{ name: "v", address: VAULT, chain: "x", autoPause: true }],
    })).toThrow(/no guard/);
  });
});
