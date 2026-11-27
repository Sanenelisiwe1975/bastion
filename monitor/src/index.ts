#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { Keypair } from "@solana/web3.js";
import { loadConfig } from "./config.js";
import { AlertDispatcher } from "./alerts.js";
import { Watcher } from "./engine.js";
import { defaultRules } from "./rules/index.js";
import { AiGuardian, claudeAssess } from "./ai/guardian.js";

const configPath = process.argv[2] ?? process.env.BASTION_CONFIG ?? "bastion.config.json";

/** GUARDIAN_KEYPAIR = path to a Solana CLI keypair JSON file (an array of 64 numbers). */
function loadGuardian(): Keypair | undefined {
  const path = process.env.GUARDIAN_KEYPAIR;
  if (!path) return undefined;
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(readFileSync(path, "utf8"))));
}

const cfg = loadConfig(configPath);
const guardian = loadGuardian();
const autoPause = cfg.protocols.filter((p) => p.autoPause).map((p) => p.name);
if (autoPause.length && !guardian) {
  console.warn(`⚠️  autoPause is on for ${autoPause.join(", ")} but GUARDIAN_KEYPAIR is not set — alerts only.`);
}

console.log(`🏰 Bastion monitor (Solana) — ${cfg.protocols.length} protocol(s) on ${cfg.cluster}` +
  (guardian ? `, guardian ${guardian.publicKey.toBase58()}` : ""));
const watcher = new Watcher(cfg, defaultRules(), AlertDispatcher.fromConfig(cfg), guardian);
if (cfg.ai) {
  const hasCreds = !!(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN || process.env.ANTHROPIC_PROFILE);
  if (!hasCreds) console.warn("⚠️  ai is configured but no ANTHROPIC_API_KEY is set; the SDK will try other credential sources.");
  watcher.ai = new AiGuardian(cfg.ai, claudeAssess(cfg.ai), watcher.responder);
  console.log(`🧠 AI guardian on: ${cfg.ai.model}, mode=${cfg.ai.mode}, reports ${cfg.ai.publishOnchain ? "published onchain" : "local only"}`);
}
void watcher.run();

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    watcher.stop();
    process.exit(0);
  });
}
