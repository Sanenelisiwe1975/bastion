import { HardhatUserConfig, subtask } from "hardhat/config";
import { TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD } from "hardhat/builtin-tasks/task-names";
import "@nomicfoundation/hardhat-toolbox";

// Use the solc-js compiler bundled via npm (works offline / behind restrictive networks).
// Remove this override to let Hardhat download the native compiler instead.
subtask(TASK_COMPILE_SOLIDITY_GET_SOLC_BUILD, async (args: { solcVersion: string }, _hre, runSuper) => {
  if (args.solcVersion === "0.8.24") {
    const compilerPath = require.resolve("solc/soljson.js");
    return { compilerPath, isSolcJs: true, version: args.solcVersion, longVersion: "0.8.24+commit.e11b9ed9" };
  }
  return runSuper();
});

const PRIVATE_KEY = process.env.DEPLOYER_KEY;
const accounts = PRIVATE_KEY ? [PRIVATE_KEY] : [];

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "cancun" },
  },
  networks: {
    hardhat: { chainId: 43112 },
    localhost: { url: "http://127.0.0.1:8545" },
    fuji: { url: "https://api.avax-test.network/ext/bc/C/rpc", chainId: 43113, accounts },
    avalanche: { url: "https://api.avax.network/ext/bc/C/rpc", chainId: 43114, accounts },
    // Any Avalanche L1: set L1_RPC_URL and L1_CHAIN_ID
    l1: {
      url: process.env.L1_RPC_URL ?? "http://127.0.0.1:9650/ext/bc/mychain/rpc",
      chainId: process.env.L1_CHAIN_ID ? Number(process.env.L1_CHAIN_ID) : undefined,
      accounts,
    },
  },
};

export default config;
