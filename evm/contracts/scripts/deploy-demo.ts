/**
 * Local demo: deploys BastionGuard, a demo token and a ProtectedVault with the sweep() bug,
 * funds it with user deposits, and writes a monitor config + addresses for the attack script.
 *
 *   npx hardhat node                                  # terminal 1
 *   npx hardhat run scripts/deploy-demo.ts --network localhost
 */
import { ethers } from "hardhat";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const USD = (n: number) => ethers.parseUnits(String(n), 18);
const HARDHAT_MNEMONIC = "test test test test test test test test test test test junk";

async function main() {
  const [deployer, admin, guardian, alice, bob] = await ethers.getSigners();

  const token = await ethers.deployContract("DemoUSD");
  const guard = await ethers.deployContract("BastionGuard");
  const vault = await ethers.deployContract("ProtectedVault", [token, guard, admin.address]);
  await Promise.all([token.waitForDeployment(), guard.waitForDeployment(), vault.waitForDeployment()]);

  await (await guard.connect(admin).setGuardian(vault, guardian.address, true)).wait();
  await (await guard.connect(admin).setOutflowLimit(vault, token, USD(100_000), 3600)).wait();

  for (const [user, amt] of [[alice, 600_000], [bob, 400_000]] as const) {
    await (await token.mint(user.address, USD(amt))).wait();
    await (await token.connect(user).approve(vault, USD(amt))).wait();
    await (await vault.connect(user).deposit(USD(amt))).wait();
  }

  const addresses = {
    token: await token.getAddress(),
    guard: await guard.getAddress(),
    vault: await vault.getAddress(),
  };
  const head = await ethers.provider.getBlockNumber();

  const monitorConfig = {
    chains: [{
      name: "local-avalanche",
      rpcUrl: "http://127.0.0.1:8545",
      chainId: Number((await ethers.provider.getNetwork()).chainId),
      pollIntervalMs: 500,
      guard: addresses.guard,
      startBlock: head + 1,
    }],
    contracts: [{
      name: "DemoVault",
      address: addresses.vault,
      chain: "local-avalanche",
      autoPause: true,
      tokens: [{
        address: addresses.token, symbol: "dUSD", decimals: 18,
        warnOutflow: USD(10_000).toString(),
        criticalOutflow: USD(50_000).toString(),
        velocityLimit: USD(80_000).toString(),
        velocityWindowSec: 600,
      }],
    }],
    alerts: { webhooks: [], minSeverity: "info" },
  };

  const guardianKey = ethers.HDNodeWallet.fromPhrase(HARDHAT_MNEMONIC, undefined, "m/44'/60'/0'/0/2").privateKey;
  if (ethers.computeAddress(guardianKey) !== guardian.address) throw new Error("guardian key mismatch");

  const demoDir = resolve(__dirname, "../../demo");
  mkdirSync(demoDir, { recursive: true });
  writeFileSync(resolve(demoDir, "addresses.json"), JSON.stringify(addresses, null, 2));
  writeFileSync(resolve(demoDir, "monitor.config.json"), JSON.stringify(monitorConfig, null, 2));
  writeFileSync(resolve(demoDir, ".env.demo"), `GUARDIAN_KEY=${guardianKey}\n`);

  console.log("Deployed:", addresses);
  console.log(`Vault TVL: 1,000,000 dUSD. Limit: 100,000 dUSD/hour. Guardian: ${guardian.address}`);
  console.log(`Monitor config written to demo/monitor.config.json`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
