import type { Alert, Batch, Rule } from "../types.js";
import { makeAlert, short } from "./util.js";

/**
 * A transaction the guard *rejected*. On Solana failed transactions still land onchain with
 * their logs, so an attacker probing the rate limit is visible before any funds move.
 * `OutflowLimitExceeded` is the strongest early signal Bastion has: someone just tried to move
 * more than the protocol's hourly budget in one go.
 */
export class GuardRejectionRule implements Rule {
  name = "guard-rejection";

  evaluate({ txs, protocols }: Batch): Alert[] {
    const alerts: Alert[] = [];
    for (const tx of txs) {
      if (!tx.failed || !tx.guardError) continue;
      for (const p of protocols) {
        if (!tx.accountKeys.includes(p.protection)) continue;
        const signer = short(tx.accountKeys[0]);
        switch (tx.guardError) {
          case "OutflowLimitExceeded":
            alerts.push(makeAlert(p, this.name, "critical",
              `Outflow over the Bastion rate limit was attempted and blocked (fee payer ${signer}). ` +
                `Likely an exploit in progress.`, tx));
            break;
          case "ProtocolPaused":
            alerts.push(makeAlert(p, this.name, "info", `Blocked a transaction from ${signer}: protocol is paused`, tx));
            break;
          case "NotGuardianOrAdmin":
          case "NotAdmin":
            alerts.push(makeAlert(p, this.name, "warning",
              `Unauthorized Bastion call from ${signer} rejected (${tx.guardError})`, tx));
            break;
        }
      }
    }
    return alerts;
  }
}

/**
 * Changes to a protocol's own Bastion configuration. Removing a limit or swapping the admin
 * is classic preparation right before an attack.
 */
export class GuardConfigRule implements Rule {
  name = "guard-config";

  evaluate({ txs, protocols }: Batch): Alert[] {
    const alerts: Alert[] = [];
    for (const tx of txs) {
      if (tx.failed) continue;
      for (const ev of tx.events) {
        const p = protocols.find((p) => p.protectedAuthority === ev.protected.toBase58());
        if (!p) continue;
        switch (ev.name) {
          case "OutflowLimitRemoved":
            alerts.push(makeAlert(p, this.name, "critical", `Outflow limit REMOVED for mint ${short(ev.mint.toBase58())}`, tx));
            break;
          case "AdminTransferred":
            alerts.push(makeAlert(p, this.name, "critical", `Bastion admin changed to ${ev.newAdmin.toBase58()}`, tx));
            break;
          case "GuardianSet":
            alerts.push(makeAlert(p, this.name, "warning",
              `Guardian ${short(ev.guardian.toBase58())} ${ev.enabled ? "added" : "removed"}`, tx));
            break;
          case "OutflowLimitSet":
            alerts.push(makeAlert(p, this.name, "info",
              `Outflow limit for ${short(ev.mint.toBase58())} set to ${ev.capacity} per ${ev.window}s`, tx));
            break;
          case "Paused":
            alerts.push(makeAlert(p, this.name, "info", `Paused by ${short(ev.by.toBase58())}: ${ev.reason}`, tx));
            break;
          case "Unpaused":
            alerts.push(makeAlert(p, this.name, "warning", `Unpaused by ${short(ev.by.toBase58())}`, tx));
            break;
        }
      }
    }
    return alerts;
  }
}

/** Upgrades, upgrade-authority changes and closes of a protocol's programs. */
export class ProgramUpgradeRule implements Rule {
  name = "program-upgrade";

  evaluate({ txs, protocols }: Batch): Alert[] {
    const alerts: Alert[] = [];
    for (const tx of txs) {
      if (tx.failed) continue;
      for (const a of tx.loaderActions) {
        for (const p of protocols) {
          const program = p.programData.get(a.programData);
          if (!program) continue;
          const what = {
            Upgrade: "Program binary UPGRADED",
            SetAuthority: "Upgrade authority changed",
            SetAuthorityChecked: "Upgrade authority changed",
            Close: "Program CLOSED",
          }[a.kind];
          alerts.push(makeAlert(p, this.name, "critical", `${what}: ${program}`, tx));
        }
      }
    }
    return alerts;
  }
}
