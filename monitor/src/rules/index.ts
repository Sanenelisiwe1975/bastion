import type { Alert, Batch, Rule } from "../types.js";
import { DrainVelocityRule, LargeOutflowRule } from "./outflow.js";
import { GuardConfigRule, GuardRejectionRule, ProgramUpgradeRule } from "./guard.js";

export { DrainVelocityRule, LargeOutflowRule, GuardConfigRule, GuardRejectionRule, ProgramUpgradeRule };

export function defaultRules(): Rule[] {
  return [
    new LargeOutflowRule(),
    new DrainVelocityRule(),
    new GuardRejectionRule(),
    new GuardConfigRule(),
    new ProgramUpgradeRule(),
  ];
}

export function runRules(rules: Rule[], batch: Batch): Alert[] {
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
