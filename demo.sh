#!/usr/bin/env bash
# One-command local demo: validator with both programs + setup + monitor + attack.
# Needs: solana-test-validator (Agave 2.2.x), the built programs (cargo build-sbf), node 20+.
set -euo pipefail
cd "$(dirname "$0")"
# On exit, stop the validator and monitor (the whole process group) but keep the real exit status.
trap 'status=$?; trap "" TERM; trap - EXIT; kill 0 2>/dev/null; exit $status' EXIT

for so in bastion_guard demo_vault; do
  [ -f "target/deploy/$so.so" ] || { echo "target/deploy/$so.so missing: run 'cargo build-sbf' first"; exit 1; }
done
[ -d monitor/node_modules ] || (cd monitor && npm install --silent)

mkdir -p demo
solana-test-validator --reset --quiet --ledger demo/ledger \
  --bpf-program 2eace2zRjWZb6faQm3YcVn6NNfrRGVJw9F9FsRFvNP6M target/deploy/bastion_guard.so \
  --bpf-program gStKd68ZtxeZ6cVUrJdwwrNAwd38sT5QFcmabUXesKU target/deploy/demo_vault.so \
  > demo/validator.log 2>&1 &

echo "Starting local validator..."
until curl -s -X POST -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getHealth"}' http://127.0.0.1:8899 | grep -q '"ok"'; do sleep 1; done

(cd monitor && npx tsx scripts/demo-setup.ts)
(cd monitor && GUARDIAN_KEYPAIR=../demo/keys/guardian.json npx tsx src/index.ts ../demo/monitor.config.json) &
sleep 3
(cd monitor && npx tsx scripts/demo-attack.ts)
# Give the AI guardian time to finish its incident report (if enabled).
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then echo; echo "Waiting for the AI guardian's report..."; sleep 60; else sleep 3; fi
