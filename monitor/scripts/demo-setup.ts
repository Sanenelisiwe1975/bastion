/**
 * Demo setup against a local validator (or RPC_URL) with both programs deployed:
 *   - a demo mint and two copies of the same vault with the sweep() bug:
 *       unprotected, and behind Bastion (100,000 tokens/hour limit, guardian = monitor bot)
 *   - 1,000,000 tokens of user deposits in each
 *   - writes demo/addresses.json, demo/monitor.config.json and demo/keys/*.json
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { Keypair } from "@solana/web3.js";
import { createAccount, createMint, mintTo } from "@solana/spl-token";
import {
  DEMO_VAULT_PROGRAM_ID,
  GUARD_PROGRAM_ID,
  guardIx,
  limitPda,
  protectionPda,
  vaultIx,
  vaultPdas,
  type VaultRef,
} from "../src/bastion.js";
import { DECIMALS, DEMO_DIR, ROOT, RPC_URL, airdrop, connection, fmt, saveKeypair, send, tokens } from "./common.js";

const LIMIT = tokens(100_000);
const WINDOW_SEC = 3600n;

async function main() {
  const conn = connection();
  for (const [id, name] of [[GUARD_PROGRAM_ID, "bastion_guard"], [DEMO_VAULT_PROGRAM_ID, "demo_vault"]] as const) {
    const info = await conn.getAccountInfo(id);
    if (!info?.executable) throw new Error(`${name} (${id.toBase58()}) is not deployed on ${RPC_URL}`);
  }

  const [owner, admin, guardian, alice, bob, attacker] = Array.from({ length: 6 }, () => Keypair.generate());
  const names = { owner, admin, guardian, alice, bob, attacker };
  for (const [n, kp] of Object.entries(names)) saveKeypair(n, kp);
  await Promise.all(Object.values(names).map((kp) => airdrop(conn, kp)));

  const mint = await createMint(conn, owner, owner.publicKey, null, DECIMALS);
  const vaults: { ref: VaultRef; kp: Keypair }[] = [];
  for (const prot of [false, true]) {
    const kp = Keypair.generate();
    const ref: VaultRef = { vault: kp.publicKey, mint, protected: prot };
    const r = await send(conn, [vaultIx.initialize(owner.publicKey, ref, prot ? admin.publicKey : null)], [owner, kp]);
    if (!r.ok) throw new Error(`initialize failed: ${r.error}`);
    vaults.push({ ref, kp });
  }
  const [unprotected, protectedVault] = vaults.map((v) => v.ref);

  const protection = protectionPda(vaultPdas(protectedVault.vault).authority);
  for (const ixn of [
    guardIx.setGuardian(admin.publicKey, protection, guardian.publicKey, true),
    guardIx.setOutflowLimit(admin.publicKey, protection, mint, LIMIT, WINDOW_SEC),
  ]) {
    const r = await send(conn, [ixn], [admin]);
    if (!r.ok) throw new Error(`guard config failed: ${r.error}`);
  }

  for (const [user, amount] of [[alice, 600_000], [bob, 400_000]] as const) {
    const ata = await createAccount(conn, owner, mint, user.publicKey);
    await mintTo(conn, owner, mint, ata, owner, tokens(amount) * 2n);
    for (const v of [unprotected, protectedVault]) {
      const r = await send(conn, [vaultIx.deposit(user.publicKey, ata, v, tokens(amount))], [user]);
      if (!r.ok) throw new Error(`deposit failed: ${r.error}`);
    }
  }

  const pv = vaultPdas(protectedVault.vault);
  const addresses = {
    mint: mint.toBase58(),
    protectedVault: protectedVault.vault.toBase58(),
    unprotectedVault: unprotected.vault.toBase58(),
    admin: admin.publicKey.toBase58(),
    guardian: guardian.publicKey.toBase58(),
  };
  const local = RPC_URL.includes("127.0.0.1") || RPC_URL.includes("localhost");
  const monitorConfig = {
    cluster: local ? "localnet" : "custom",
    rpcUrl: RPC_URL,
    pollIntervalMs: 400,
    explorer: local
      ? "https://explorer.solana.com/tx/{sig}?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899"
      : "https://explorer.solana.com/tx/{sig}?cluster=devnet",
    protocols: [{
      name: "DemoVault",
      protectedAuthority: pv.authority.toBase58(),
      programs: [DEMO_VAULT_PROGRAM_ID.toBase58()],
      autoPause: true,
      tokenAccounts: [{
        address: pv.vaultTokens.toBase58(),
        symbol: "dUSD",
        decimals: DECIMALS,
        warnOutflow: tokens(10_000).toString(),
        criticalOutflow: tokens(50_000).toString(),
        velocityLimit: tokens(80_000).toString(),
        velocityWindowSec: 600,
      }],
    }],
    alerts: { webhooks: [], minSeverity: "info" },
    // AI guardian (Claude) when credentials are available.
    ...(process.env.ANTHROPIC_API_KEY ? { ai: { mode: "act", publishOnchain: true } } : {}),
  };
  // Addresses for the live demo page (app/index.html).
  const uv = vaultPdas(unprotected.vault);
  const appConfig = {
    cluster: local ? "localnet" : "devnet",
    rpcUrl: RPC_URL,
    explorerQuery: local ? "?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899" : "?cluster=devnet",
    guardProgram: GUARD_PROGRAM_ID.toBase58(),
    vaultProgram: DEMO_VAULT_PROGRAM_ID.toBase58(),
    mint: mint.toBase58(),
    symbol: "dUSD",
    decimals: DECIMALS,
    unprotected: { vault: unprotected.vault.toBase58(), vaultTokens: uv.vaultTokens.toBase58() },
    protected: {
      vault: protectedVault.vault.toBase58(),
      authority: pv.authority.toBase58(),
      vaultTokens: pv.vaultTokens.toBase58(),
      protection: protection.toBase58(),
      limit: limitPda(protection, mint).toBase58(),
    },
    admin: admin.publicKey.toBase58(),
    guardian: guardian.publicKey.toBase58(),
  };
  mkdirSync(resolve(ROOT, "app"), { recursive: true });
  writeFileSync(resolve(ROOT, "app", local ? "demo.local.json" : "demo.json"), JSON.stringify(appConfig, null, 2));
  mkdirSync(DEMO_DIR, { recursive: true });
  writeFileSync(resolve(DEMO_DIR, "addresses.json"), JSON.stringify(addresses, null, 2));
  writeFileSync(resolve(DEMO_DIR, "monitor.config.json"), JSON.stringify(monitorConfig, null, 2));

  console.log(`Mint ${addresses.mint}`);
  console.log(`Unprotected vault ${addresses.unprotectedVault}: TVL 1,000,000 dUSD`);
  console.log(`Protected vault   ${addresses.protectedVault}: TVL 1,000,000 dUSD, limit ${fmt(LIMIT)} dUSD/hour`);
  console.log(`Guardian ${addresses.guardian} · config written to demo/monitor.config.json`);
  console.log(process.env.ANTHROPIC_API_KEY ? "AI guardian: on (Claude)" : "AI guardian: off (set ANTHROPIC_API_KEY to enable)");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
