/**
 * Plays the attacker against both demo vaults via the unprotected sweep().
 * Run with the monitor running to watch Bastion cap the loss and auto-pause the vault.
 */
import { PublicKey } from "@solana/web3.js";
import { createAccount, getAccount } from "@solana/spl-token";
import {
  decodeOutflowLimit,
  decodeProtection,
  limitPda,
  protectionPda,
  vaultIx,
  vaultPdas,
  type VaultRef,
} from "../src/bastion.js";
import { connection, fmt, loadKeypair, readAddresses, send, sleep, tokens } from "./common.js";

const explorer = (sig: string) =>
  process.env.RPC_URL && !process.env.RPC_URL.includes("127.0.0.1")
    ? `https://explorer.solana.com/tx/${sig}?cluster=devnet`
    : `https://explorer.solana.com/tx/${sig}?cluster=custom&customUrl=http%3A%2F%2F127.0.0.1%3A8899`;

async function main() {
  const conn = connection();
  const addr = readAddresses();
  const owner = loadKeypair("owner");
  const attacker = loadKeypair("attacker");
  const mint = new PublicKey(addr.mint);
  const unprotected: VaultRef = { vault: new PublicKey(addr.unprotectedVault), mint, protected: false };
  const prot: VaultRef = { vault: new PublicKey(addr.protectedVault), mint, protected: true };
  const pv = vaultPdas(prot.vault);
  const protection = protectionPda(pv.authority);

  const loot = await createAccount(conn, owner, mint, attacker.publicKey);
  const balance = async (a: PublicKey) => (await getAccount(conn, a, "confirmed")).amount;
  const paused = async () => decodeProtection((await conn.getAccountInfo(protection, "confirmed"))!.data).paused;
  const sweep = (v: VaultRef, amount: bigint) =>
    send(conn, [vaultIx.sweep(attacker.publicKey, loot, v, amount)], [attacker], { skipPreflight: true });

  console.log(`\n😈 Attacker ${attacker.publicKey.toBase58()} calls the unchecked sweep() on two identical vaults`);

  // -- Without Bastion ------------------------------------------------------
  const uTvl = await balance(vaultPdas(unprotected.vault).vaultTokens);
  const u = await sweep(unprotected, uTvl);
  console.log(`\nWITHOUT Bastion: sweep(${fmt(uTvl)}) → ${u.ok ? `✅ drained ${fmt(uTvl)} / ${fmt(uTvl)} dUSD in one tx` : `❌ ${u.error}`}`);

  // -- With Bastion ---------------------------------------------------------
  const tvl = await balance(pv.vaultTokens);
  const before = await balance(loot);
  console.log(`\nWITH Bastion (vault holds ${fmt(tvl)} dUSD):`);

  console.log(`[1] Drain everything in one tx...`);
  const r1 = await sweep(prot, tvl);
  console.log(`    ${r1.ok ? "drained!" : `❌ ${r1.error}`}   ${r1.signature ? explorer(r1.signature) : ""}`);

  const limit = decodeOutflowLimit((await conn.getAccountInfo(limitPda(protection, mint), "confirmed"))!.data);
  const take = limit.available; // never more than the onchain bucket allows at this instant
  console.log(`[2] Take what the rate limit allows: ${fmt(take)} dUSD...`);
  const r2 = await sweep(prot, take);
  console.log(`    ${r2.ok ? `✅ took ${fmt(take)} dUSD` : `❌ ${r2.error} (the monitor already paused the vault)`}`);

  console.log(`[3] Come back for more (waiting for the monitor)...`);
  for (let i = 0; i < 40 && !(await paused()); i++) await sleep(250);
  const r3 = await sweep(prot, tokens(100_000));
  console.log(`    ${r3.ok ? "took another 100,000 dUSD" : `❌ ${r3.error}`}`);

  const stolen = (await balance(loot)) - before;
  const left = await balance(pv.vaultTokens);
  const pct = Number((left * 1000n) / tvl) / 10;
  console.log(`\n📊 Result: attacker got ${fmt(stolen)} dUSD; ${fmt(left)} dUSD (${pct.toFixed(1)}%) of user funds safe.`);
  console.log(`   Vault paused: ${await paused()}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
