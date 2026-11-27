import { bastionGuardAbi, privilegedAbi } from "../abis.js";
import type { Alert, BlockBatch, Rule, Severity } from "../types.js";
import { makeAlert, same, tryDecode } from "./util.js";

/**
 * Ownership, proxy upgrades and role changes on a watched contract.
 * Most key-compromise and governance attacks start with one of these.
 */
export class PrivilegedChangeRule implements Rule {
  name = "privileged-change";

  evaluate(batch: BlockBatch): Alert[] {
    const alerts: Alert[] = [];
    for (const log of batch.logs) {
      const c = batch.contracts.find((w) => same(w.address, log.address));
      if (!c) continue;
      const ev = tryDecode(privilegedAbi, log);
      if (!ev) continue;
      let severity: Severity = "warning";
      let msg: string;
      switch (ev.eventName) {
        case "Upgraded":
          severity = "critical";
          msg = `Proxy implementation upgraded to ${ev.args.implementation}`;
          break;
        case "BeaconUpgraded":
          severity = "critical";
          msg = `Beacon changed to ${ev.args.beacon}`;
          break;
        case "AdminChanged":
          severity = "critical";
          msg = `Proxy admin changed ${ev.args.previousAdmin} → ${ev.args.newAdmin}`;
          break;
        case "OwnershipTransferred":
          severity = "critical";
          msg = `Ownership transferred ${ev.args.previousOwner} → ${ev.args.newOwner}`;
          break;
        case "RoleGranted":
          msg = `Role ${ev.args.role.slice(0, 10)}… granted to ${ev.args.account} by ${ev.args.sender}`;
          break;
        case "RoleRevoked":
          msg = `Role ${ev.args.role.slice(0, 10)}… revoked from ${ev.args.account} by ${ev.args.sender}`;
          break;
      }
      alerts.push(makeAlert(batch, c, this.name, severity, msg, log));
    }
    return alerts;
  }
}

/**
 * Changes to a contract's own Bastion protection. Removing a rate limit or swapping the
 * Bastion admin is a classic preparation step right before an attack.
 */
export class GuardConfigRule implements Rule {
  name = "guard-config";

  evaluate(batch: BlockBatch): Alert[] {
    if (!batch.chain.guard) return [];
    const alerts: Alert[] = [];
    for (const log of batch.logs) {
      if (!same(log.address, batch.chain.guard)) continue;
      const ev = tryDecode(bastionGuardAbi, log);
      if (!ev || !("protected" in ev.args)) continue;
      const c = batch.contracts.find((w) => same(w.address, ev.args.protected as `0x${string}`));
      if (!c) continue;
      switch (ev.eventName) {
        case "OutflowLimitRemoved":
          alerts.push(makeAlert(batch, c, this.name, "critical", `Outflow limit REMOVED for token ${ev.args.token}`, log));
          break;
        case "AdminTransferred":
          alerts.push(makeAlert(batch, c, this.name, "critical", `Bastion admin changed to ${ev.args.newAdmin}`, log));
          break;
        case "GuardianSet":
          alerts.push(makeAlert(batch, c, this.name, "warning",
            `Guardian ${ev.args.guardian} ${ev.args.enabled ? "added" : "removed"}`, log));
          break;
        case "OutflowLimitSet":
          alerts.push(makeAlert(batch, c, this.name, "info",
            `Outflow limit set for ${ev.args.token}: ${ev.args.capacity} per ${ev.args.window}s`, log));
          break;
        case "Paused":
          alerts.push(makeAlert(batch, c, this.name, "info", `Paused by ${ev.args.by}: ${ev.args.reason}`, log));
          break;
        case "Unpaused":
          alerts.push(makeAlert(batch, c, this.name, "warning", `Unpaused by ${ev.args.by}`, log));
          break;
      }
    }
    return alerts;
  }
}
