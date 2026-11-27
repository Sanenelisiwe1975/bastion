import type { Rule } from "../types.js";
import { DrainVelocityRule, LargeOutflowRule } from "./outflow.js";
import { GuardConfigRule, PrivilegedChangeRule } from "./privileged.js";
import { IcmUntrustedSenderRule } from "./icm.js";

export { DrainVelocityRule, LargeOutflowRule, GuardConfigRule, PrivilegedChangeRule, IcmUntrustedSenderRule };

export function defaultRules(): Rule[] {
  return [
    new LargeOutflowRule(),
    new DrainVelocityRule(),
    new PrivilegedChangeRule(),
    new GuardConfigRule(),
    new IcmUntrustedSenderRule(),
  ];
}
