#!/usr/bin/env bash
# One-command local demo: chain + deploy + monitor + attack.
set -euo pipefail
cd "$(dirname "$0")"
# Kill the node and monitor (and their children) when the demo ends.
trap 'trap "" TERM; trap - EXIT; kill 0 2>/dev/null; exit 0' EXIT

(cd contracts && npx hardhat node > /tmp/bastion-node.log 2>&1) &
sleep 6
(cd contracts && npx hardhat run scripts/deploy-demo.ts --network localhost)
set -a; . demo/.env.demo; set +a
(cd monitor && npx tsx src/index.ts ../demo/monitor.config.json) &
sleep 4
(cd contracts && npx hardhat run scripts/attack-demo.ts --network localhost)
sleep 3
