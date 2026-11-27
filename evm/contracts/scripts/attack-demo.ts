/**
 * Plays the attacker against the local demo vault. Run with the monitor running to watch
 * Bastion cap the loss and auto-pause the vault.
 *
 *   npx hardhat run scripts/attack-demo.ts --network localhost
 */
import { ethers, network } from "hardhat";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const USD = (n: number) => ethers.parseUnits(String(n), 18);
const fmt = (v: bigint) => Number(ethers.formatUnits(v, 18)).toLocaleString("en-US");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Find the revert data hex wherever the provider nested it. */
function revertData(e: any): string | undefined {
  for (const d of [e?.data, e?.data?.data, e?.error?.data, e?.error?.data?.data, e?.info?.error?.data]) {
    if (typeof d === "string" && d.startsWith("0x")) return d;
  }
}

async function main() {
  const addr = JSON.parse(readFileSync(resolve(__dirname, "../../demo/addresses.json"), "utf8"));
  const signers = await ethers.getSigners();
  const attacker = signers[5];
  const token = await ethers.getContractAt("DemoUSD", addr.token);
  const vault = await ethers.getContractAt("ProtectedVault", addr.vault);
  const guard = await ethers.getContractAt("BastionGuard", addr.guard);

  const reason = (e: unknown) => {
    const d = revertData(e);
    return (d && guard.interface.parseError(d)?.name) ?? (e as Error).message;
  };

  const tvl = await token.balanceOf(vault);
  console.log(`\n😈 Attacker ${attacker.address} targets vault holding ${fmt(tvl)} dUSD via unprotected sweep()`);

  console.log(`\n[1] Try to drain everything in one tx...`);
  try {
    await (await vault.connect(attacker).sweep(attacker.address, tvl)).wait();
    console.log("    drained!");
  } catch (e) {
    console.log(`    ❌ reverted: ${reason(e)}`);
  }

  const available = await guard.availableOutflow(vault, token);
  console.log(`\n[2] Take what the rate limit allows: ${fmt(available)} dUSD`);
  await (await vault.connect(attacker).sweep(attacker.address, available)).wait();
  console.log(`    ✅ took ${fmt(available)} dUSD`);

  console.log(`\n[3] Wait for the bucket to refill (fast-forward 1h) and go again...`);
  await sleep(4000); // give the monitor a few polls to react in real time
  await network.provider.send("evm_increaseTime", [3600]);
  await network.provider.send("evm_mine");
  try {
    await (await vault.connect(attacker).sweep(attacker.address, USD(100_000))).wait();
    console.log("    took another 100,000 dUSD");
  } catch (e) {
    console.log(`    ❌ reverted: ${reason(e)}`);
  }

  const stolen = await token.balanceOf(attacker.address);
  const left = await token.balanceOf(vault);
  console.log(`\n📊 Result: attacker got ${fmt(stolen)} dUSD; ${fmt(left)} dUSD (${(Number(left * 1000n / tvl) / 10).toFixed(1)}%) of user funds safe.`);
  console.log(`   Vault paused: ${await guard.isPaused(vault)}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
