/**
 * Deploy the shared BastionGuard to Fuji, C-Chain or any Avalanche L1.
 *
 *   DEPLOYER_KEY=0x... npx hardhat run scripts/deploy-guard.ts --network fuji
 *   DEPLOYER_KEY=0x... L1_RPC_URL=... L1_CHAIN_ID=... npx hardhat run scripts/deploy-guard.ts --network l1
 */
import { ethers, network } from "hardhat";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log(`Deploying BastionGuard to ${network.name} from ${deployer.address}`);
  const guard = await ethers.deployContract("BastionGuard");
  await guard.waitForDeployment();
  console.log(`BastionGuard: ${await guard.getAddress()}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
