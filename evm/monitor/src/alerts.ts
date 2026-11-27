import type { Config } from "./config.js";
import { SEVERITY_RANK, type Alert } from "./types.js";

export interface AlertSink {
  send(alert: Alert): Promise<void>;
}

const ICON = { info: "ℹ️", warning: "⚠️", critical: "🚨" } as const;

export function formatAlert(a: Alert): string {
  const tx = a.txHash ? `\ntx: ${a.txHash}` : "";
  return `${ICON[a.severity]} [${a.severity.toUpperCase()}] ${a.contractName} on ${a.chain} — ${a.rule}\n` +
    `${a.message}\nblock ${a.blockNumber}${tx}`;
}

export class ConsoleSink implements AlertSink {
  async send(a: Alert) {
    console.log(`\n${formatAlert(a)}`);
  }
}

/** Posts `{content, text}` so it works for Discord and Slack incoming webhooks alike. */
export class WebhookSink implements AlertSink {
  constructor(private url: string) {}
  async send(a: Alert) {
    const text = formatAlert(a);
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content: text, text, alert: { ...a, blockNumber: a.blockNumber.toString() } }),
    });
    if (!res.ok) console.error(`webhook ${this.url} failed: ${res.status}`);
  }
}

export class TelegramSink implements AlertSink {
  constructor(private botToken: string, private chatId: string) {}
  async send(a: Alert) {
    const res = await fetch(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: this.chatId, text: formatAlert(a) }),
    });
    if (!res.ok) console.error(`telegram failed: ${res.status}`);
  }
}

export class AlertDispatcher {
  constructor(private sinks: AlertSink[], private minSeverity: Alert["severity"]) {}

  static fromConfig(cfg: Config): AlertDispatcher {
    const sinks: AlertSink[] = [new ConsoleSink(), ...cfg.alerts.webhooks.map((u) => new WebhookSink(u))];
    if (cfg.alerts.telegram) sinks.push(new TelegramSink(cfg.alerts.telegram.botToken, cfg.alerts.telegram.chatId));
    return new AlertDispatcher(sinks, cfg.alerts.minSeverity);
  }

  async dispatch(alerts: Alert[]) {
    const relevant = alerts.filter((a) => SEVERITY_RANK[a.severity] >= SEVERITY_RANK[this.minSeverity]);
    await Promise.all(
      relevant.flatMap((a) => this.sinks.map((s) => s.send(a).catch((e) => console.error("sink error", e)))),
    );
  }
}
