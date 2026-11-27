import type { Alert, Batch, Rule } from "../types.js";
import { fmt, makeAlert, short } from "./util.js";

/**
 * A single large token outflow from a watched protocol token account.
 * Works from token balance deltas, so it also covers mints with no Bastion limit.
 */
export class LargeOutflowRule implements Rule {
  name = "large-outflow";

  evaluate({ txs, protocols }: Batch): Alert[] {
    const alerts: Alert[] = [];
    for (const tx of txs) {
      if (tx.failed) continue;
      for (const d of tx.tokenDeltas) {
        if (d.delta >= 0n) continue;
        for (const p of protocols) {
          const t = p.tokenAccounts.find((t) => t.address === d.account);
          if (!t) continue;
          const out = -d.delta;
          const dest = tx.tokenDeltas.find((o) => o.mint === d.mint && o.delta > 0n);
          const to = dest ? ` to ${short(dest.owner ?? dest.account)}` : "";
          if (out >= t.criticalOutflow) {
            alerts.push(makeAlert(p, this.name, "critical", `${fmt(out, t.decimals, t.symbol)} left ${p.name}${to} in one tx`, tx));
          } else if (out >= t.warnOutflow) {
            alerts.push(makeAlert(p, this.name, "warning", `${fmt(out, t.decimals, t.symbol)} left ${p.name}${to}`, tx));
          }
        }
      }
    }
    return alerts;
  }
}

/**
 * Cumulative outflow over a sliding window: catches drains split into many small transactions.
 * Stateful across batches.
 */
export class DrainVelocityRule implements Rule {
  name = "drain-velocity";
  private history = new Map<string, { ts: number; amount: bigint }[]>();
  private lastAlertTs = new Map<string, number>();

  evaluate({ txs, protocols }: Batch): Alert[] {
    const alerts: Alert[] = [];
    for (const tx of txs) {
      if (tx.failed) continue;
      for (const d of tx.tokenDeltas) {
        if (d.delta >= 0n) continue;
        for (const p of protocols) {
          const t = p.tokenAccounts.find((t) => t.address === d.account);
          if (!t?.velocityLimit) continue;
          const key = `${p.name}:${t.address}`;
          const windowStart = tx.blockTime - t.velocityWindowSec;
          const h = (this.history.get(key) ?? []).filter((e) => e.ts > windowStart);
          h.push({ ts: tx.blockTime, amount: -d.delta });
          this.history.set(key, h);

          const total = h.reduce((s, e) => s + e.amount, 0n);
          const last = this.lastAlertTs.get(key) ?? -Infinity;
          if (total >= t.velocityLimit && last <= windowStart) {
            this.lastAlertTs.set(key, tx.blockTime);
            alerts.push(makeAlert(p, this.name, "critical",
              `${fmt(total, t.decimals, t.symbol)} left ${p.name} across ${h.length} tx(s) in ${t.velocityWindowSec}s ` +
                `(limit ${fmt(t.velocityLimit, t.decimals, t.symbol)})`, tx));
          }
        }
      }
    }
    return alerts;
  }
}
