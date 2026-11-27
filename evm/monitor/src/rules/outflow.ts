import { erc20Abi } from "../abis.js";
import type { Alert, BlockBatch, Rule } from "../types.js";
import { fmt, makeAlert, same, tryDecode } from "./util.js";

/**
 * Flags single large token transfers out of a watched contract.
 * Catches one-shot drains (missing access control, bad math, compromised keys).
 */
export class LargeOutflowRule implements Rule {
  name = "large-outflow";

  evaluate(batch: BlockBatch): Alert[] {
    const alerts: Alert[] = [];
    for (const log of batch.logs) {
      const ev = tryDecode(erc20Abi, log);
      if (!ev || ev.eventName !== "Transfer") continue;
      for (const c of batch.contracts) {
        if (!same(ev.args.from, c.address)) continue;
        const token = c.tokens.find((t) => same(t.address, log.address));
        if (!token) continue;
        const v = ev.args.value;
        if (v >= token.criticalOutflow) {
          alerts.push(
            makeAlert(batch, c, this.name, "critical",
              `${fmt(v, token.decimals, token.symbol)} left ${c.name} to ${ev.args.to} in one transfer`, log),
          );
        } else if (v >= token.warnOutflow) {
          alerts.push(
            makeAlert(batch, c, this.name, "warning",
              `${fmt(v, token.decimals, token.symbol)} left ${c.name} to ${ev.args.to}`, log),
          );
        }
      }
    }
    return alerts;
  }
}

/**
 * Flags cumulative outflow over a sliding time window.
 * Catches attackers who split a drain into many transactions to stay under per-tx thresholds.
 */
export class DrainVelocityRule implements Rule {
  name = "drain-velocity";
  private history = new Map<string, { ts: number; amount: bigint }[]>();
  private lastAlertTs = new Map<string, number>();

  evaluate(batch: BlockBatch): Alert[] {
    const alerts: Alert[] = [];
    for (const log of batch.logs) {
      const ev = tryDecode(erc20Abi, log);
      if (!ev || ev.eventName !== "Transfer") continue;
      for (const c of batch.contracts) {
        if (!same(ev.args.from, c.address)) continue;
        const token = c.tokens.find((t) => same(t.address, log.address));
        if (!token?.velocityLimit) continue;

        const key = `${batch.chain.name}:${c.address}:${token.address}`;
        const ts = batch.timestamps.get(log.blockNumber!) ?? Math.floor(Date.now() / 1000);
        const windowStart = ts - token.velocityWindowSec;
        const h = (this.history.get(key) ?? []).filter((e) => e.ts > windowStart);
        h.push({ ts, amount: ev.args.value });
        this.history.set(key, h);

        const total = h.reduce((s, e) => s + e.amount, 0n);
        const last = this.lastAlertTs.get(key) ?? -Infinity;
        if (total >= token.velocityLimit && last <= windowStart) {
          this.lastAlertTs.set(key, ts);
          alerts.push(
            makeAlert(batch, c, this.name, "critical",
              `${fmt(total, token.decimals, token.symbol)} left ${c.name} across ${h.length} transfers in ` +
                `${token.velocityWindowSec}s (limit ${fmt(token.velocityLimit, token.decimals, token.symbol)})`, log),
          );
        }
      }
    }
    return alerts;
  }
}
