import { describe, expect, it } from "vitest";
import { Keypair } from "@solana/web3.js";
import { parseConfig, resolveProtocols, addressesToWatch } from "../src/config.js";
import { programDataAddress, DEMO_VAULT_PROGRAM_ID } from "../src/bastion.js";
import {
  DrainVelocityRule,
  GuardConfigRule,
  GuardRejectionRule,
  LargeOutflowRule,
  ProgramUpgradeRule,
} from "../src/rules/index.js";
import type { Batch, TxRecord } from "../src/types.js";

const k = () => Keypair.generate().publicKey;
const authority = k();
const vaultTokens = k().toBase58();
const mint = k().toBase58();
const U = 1_000_000n;

const config = parseConfig({
  rpcUrl: "http://127.0.0.1:8899",
  protocols: [{
    name: "Vault",
    protectedAuthority: authority.toBase58(),
    programs: [DEMO_VAULT_PROGRAM_ID.toBase58()],
    autoPause: true,
    tokenAccounts: [{
      address: vaultTokens, symbol: "dUSD", decimals: 6,
      warnOutflow: (10_000n * U).toString(), criticalOutflow: (50_000n * U).toString(),
      velocityLimit: (80_000n * U).toString(), velocityWindowSec: 600,
    }],
  }],
});
const protocols = resolveProtocols(config);
const protection = protocols[0].protection;

let n = 0;
function tx(p: Partial<TxRecord>): TxRecord {
  n++;
  return {
    signature: `sig${n}`, slot: n, blockTime: 1_700_000_000 + n, failed: false, accountKeys: [k().toBase58()],
    events: [], logsTruncated: false, logs: [], tokenDeltas: [], loaderActions: [], ...p,
  };
}
const outflow = (amount: bigint, extra: Partial<TxRecord> = {}) =>
  tx({ tokenDeltas: [{ account: vaultTokens, mint, delta: -amount * U, decimals: 6 },
    { account: k().toBase58(), mint, owner: "Attacker111", delta: amount * U, decimals: 6 }], ...extra });
const batch = (...txs: TxRecord[]): Batch => ({ txs, protocols, config });

describe("large-outflow", () => {
  const rule = new LargeOutflowRule();
  it("is critical above the critical threshold, warning above warn, silent below", () => {
    expect(rule.evaluate(batch(outflow(100_000n))).map((a) => a.severity)).toEqual(["critical"]);
    expect(rule.evaluate(batch(outflow(20_000n))).map((a) => a.severity)).toEqual(["warning"]);
    expect(rule.evaluate(batch(outflow(1_000n)))).toEqual([]);
  });
  it("ignores inflows and other token accounts", () => {
    const inflow = tx({ tokenDeltas: [{ account: vaultTokens, mint, delta: 900_000n * U, decimals: 6 }] });
    const other = tx({ tokenDeltas: [{ account: k().toBase58(), mint, delta: -900_000n * U, decimals: 6 }] });
    expect(rule.evaluate(batch(inflow, other))).toEqual([]);
  });
});

describe("drain-velocity", () => {
  it("catches a drain split into small transfers, once per window", () => {
    const rule = new DrainVelocityRule();
    const t0 = 1_800_000_000;
    const txs = Array.from({ length: 10 }, (_, i) => outflow(9_000n, { blockTime: t0 + i * 10 }));
    const alerts = rule.evaluate(batch(...txs));
    expect(alerts).toHaveLength(1);
    expect(alerts[0].severity).toBe("critical");
    expect(alerts[0].message).toContain("9 tx(s)");
  });
  it("does not fire when transfers are spread beyond the window", () => {
    const rule = new DrainVelocityRule();
    const txs = Array.from({ length: 10 }, (_, i) => outflow(9_000n, { blockTime: 1_900_000_000 + i * 700 }));
    expect(rule.evaluate(batch(...txs))).toEqual([]);
  });
});

describe("guard-rejection", () => {
  const rule = new GuardRejectionRule();
  it("is critical when a drain is blocked by the rate limit", () => {
    const a = rule.evaluate(batch(tx({ failed: true, guardError: "OutflowLimitExceeded", accountKeys: [k().toBase58(), protection] })));
    expect(a.map((x) => x.severity)).toEqual(["critical"]);
  });
  it("only concerns transactions that reference this protocol's protection PDA", () => {
    expect(rule.evaluate(batch(tx({ failed: true, guardError: "OutflowLimitExceeded" })))).toEqual([]);
  });
  it("flags unauthorized pause attempts as warnings", () => {
    const a = rule.evaluate(batch(tx({ failed: true, guardError: "NotGuardianOrAdmin", accountKeys: [k().toBase58(), protection] })));
    expect(a.map((x) => x.severity)).toEqual(["warning"]);
  });
});

describe("guard-config", () => {
  const rule = new GuardConfigRule();
  it("is critical on limit removal and admin change, ignores other protocols", () => {
    const a = rule.evaluate(batch(
      tx({ events: [{ name: "OutflowLimitRemoved", protected: authority, mint: k() }] }),
      tx({ events: [{ name: "AdminTransferred", protected: authority, previousAdmin: k(), newAdmin: k() }] }),
      tx({ events: [{ name: "OutflowLimitRemoved", protected: k(), mint: k() }] }),
    ));
    expect(a.map((x) => x.severity)).toEqual(["critical", "critical"]);
  });
  it("reports pause as info and unpause as warning", () => {
    const a = rule.evaluate(batch(
      tx({ events: [{ name: "Paused", protected: authority, by: k(), reason: "r" }] }),
      tx({ events: [{ name: "Unpaused", protected: authority, by: k() }] }),
    ));
    expect(a.map((x) => x.severity)).toEqual(["info", "warning"]);
  });
});

describe("program-upgrade", () => {
  it("is critical when a watched program is upgraded", () => {
    const pd = programDataAddress(DEMO_VAULT_PROGRAM_ID).toBase58();
    const a = new ProgramUpgradeRule().evaluate(batch(tx({ loaderActions: [{ kind: "Upgrade", programData: pd }] }),
      tx({ loaderActions: [{ kind: "Upgrade", programData: k().toBase58() }] })));
    expect(a.map((x) => x.severity)).toEqual(["critical"]);
  });
});

describe("config", () => {
  it("watches the protection PDA, token accounts and programData", () => {
    const w = addressesToWatch(protocols);
    expect(w).toContain(protection);
    expect(w).toContain(vaultTokens);
    expect(w).toContain(programDataAddress(DEMO_VAULT_PROGRAM_ID).toBase58());
  });
  it("rejects bad keys, the zero key and inverted thresholds", () => {
    const base = { rpcUrl: "http://x.y", protocols: [{ name: "a", protectedAuthority: "nope" }] };
    expect(() => parseConfig(base)).toThrow();
    expect(() => parseConfig({ ...base, protocols: [{ name: "a", protectedAuthority: "11111111111111111111111111111111" }] }))
      .toThrow(/all-zero/);
    expect(() => parseConfig({ ...base, protocols: [{ name: "a", protectedAuthority: authority.toBase58(),
      tokenAccounts: [{ address: vaultTokens, symbol: "x", decimals: 6, warnOutflow: 10, criticalOutflow: 5 }] }] }))
      .toThrow(/criticalOutflow/);
  });
});
