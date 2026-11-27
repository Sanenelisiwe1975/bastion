import { teleporterAbi } from "../abis.js";
import type { Alert, BlockBatch, Rule } from "../types.js";
import { makeAlert, same, tryDecode } from "./util.js";

/**
 * Avalanche Interchain Messaging (ICM / Teleporter).
 * Bridges and cross-L1 apps trust messages from specific (source chain, sender) pairs.
 * A message delivered to a watched contract from any other origin is either a misconfiguration
 * or an attack on the receiver's sender check — flag it before it is exploited.
 */
export class IcmUntrustedSenderRule implements Rule {
  name = "icm-untrusted-sender";

  evaluate(batch: BlockBatch): Alert[] {
    const alerts: Alert[] = [];
    for (const log of batch.logs) {
      if (!same(log.address, batch.chain.teleporter)) continue;
      const ev = tryDecode(teleporterAbi, log);
      if (!ev || ev.eventName !== "ReceiveCrossChainMessage") continue;
      const m = ev.args.message;
      const c = batch.contracts.find((w) => same(w.address, m.destinationAddress));
      if (!c?.icmTrustedSenders) continue;

      const src = ev.args.sourceBlockchainID.toLowerCase();
      const trusted = c.icmTrustedSenders.some(
        (t) => t.sourceBlockchainID === src && same(t.sender, m.originSenderAddress),
      );
      if (!trusted) {
        alerts.push(
          makeAlert(batch, c, this.name, "critical",
            `ICM message from untrusted origin ${m.originSenderAddress} on chain ${src.slice(0, 10)}… ` +
              `delivered to ${c.name} (messageID ${ev.args.messageID.slice(0, 10)}…)`, log),
        );
      }
    }
    return alerts;
  }
}
