import type { Config } from "./config.js";
import { SEVERITY_RANK, type Alert } from "./types.js";

export interface AlertSink {
  send(alert: Alert): Promise<void>;
}

const ICON = { info: "ℹ️", warning: "⚠️", critical: "🚨" } as const;

export function formatAlert(a: Alert, explorer?: string): string {
  const tx = a.signature ? `\ntx: ${explorer ? explorer.replace("{sig}", a.signature) : a.signature}` : "";
  return `${ICON[a.severity]} [${a.severity.toUpperCase()}] ${a.protocol} — ${a.rule}\n${a.message}\nslot ${a.slot}${tx}`;
}

export class ConsoleSink implements AlertSink {
  constructor(private explorer?: string) {}
  async send(a: Alert) {
    console.log(`\n${formatAlert(a, this.explorer)}`);
  }
}

/** Posts `{content, text}` so it works for Discord and Slack incoming webhooks alike. */
export class WebhookSink implements AlertSink {
  constructor(private url: string, private explorer?: string) {}
  async send(a: Alert) {
    const text = formatAlert(a, this.explorer);
    const res = await fetch(this.url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ content: text, text, alert: a }),
    });
    if (!res.ok) console.error(`webhook failed: ${res.status}`);
  }
}

export class TelegramSink implements AlertSink {
  constructor(private botToken: string, private chatId: string, private explorer?: string) {}
  async send(a: Alert) {
    const res = await fetch(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: this.chatId, text: formatAlert(a, this.explorer) }),
    });
    if (!res.ok) console.error(`telegram failed: ${res.status}`);
  }
}

export class AlertDispatcher {
  constructor(private sinks: AlertSink[], private minSeverity: Alert["severity"]) {}

  static fromConfig(cfg: Config): AlertDispatcher {
    const ex = cfg.explorer;
    const sinks: AlertSink[] = [new ConsoleSink(ex), ...cfg.alerts.webhooks.map((u) => new WebhookSink(u, ex))];
    if (cfg.alerts.telegram) sinks.push(new TelegramSink(cfg.alerts.telegram.botToken, cfg.alerts.telegram.chatId, ex));
    return new AlertDispatcher(sinks, cfg.alerts.minSeverity);
  }

  async dispatch(alerts: Alert[]) {
    const relevant = alerts.filter((a) => SEVERITY_RANK[a.severity] >= SEVERITY_RANK[this.minSeverity]);
    await Promise.all(
      relevant.flatMap((a) => this.sinks.map((s) => s.send(a).catch((e) => console.error("sink error", e)))),
    );
  }
}
