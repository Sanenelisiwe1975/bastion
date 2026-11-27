#!/usr/bin/env node
import { loadConfig } from "./config.js";
import { AlertDispatcher } from "./alerts.js";
import { startAll } from "./engine.js";
import { defaultRules } from "./rules/index.js";

const configPath = process.argv[2] ?? process.env.BASTION_CONFIG ?? "bastion.config.json";
const guardianKey = process.env.GUARDIAN_KEY as `0x${string}` | undefined;

const cfg = loadConfig(configPath);
const autoPause = cfg.contracts.filter((c) => c.autoPause).map((c) => c.name);
if (autoPause.length && !guardianKey) {
  console.warn(`⚠️  autoPause is on for ${autoPause.join(", ")} but GUARDIAN_KEY is not set — alerts only.`);
}

console.log(`🏰 Bastion monitor — ${cfg.chains.length} chain(s), ${cfg.contracts.length} contract(s)`);
const watchers = startAll(cfg, defaultRules, AlertDispatcher.fromConfig(cfg), guardianKey);

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    watchers.forEach((w) => w.stop());
    process.exit(0);
  });
}
