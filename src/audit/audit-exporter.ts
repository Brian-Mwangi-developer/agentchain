/** AuditExporter interface + ConsoleAuditExporter (stdout) and HttpAuditExporter (POST batches). */

import type { AuditEntry } from "../types/audit.js";

export interface AuditExporter {
    export(entries: AuditEntry[]): Promise<void>;
}

// ─── ConsoleAuditExporter ─────────────────────────────────────────────────────


export class ConsoleAuditExporter implements AuditExporter {
    async export(entries: AuditEntry[]): Promise<void> {
        for (const entry of entries) {
            console.log(JSON.stringify({
                ...entry,
                timestamp_iso: new Date(entry.timestamp).toISOString(),
            }));
        }
    }
}

// ─── HttpAuditExporter ────────────────────────────────────────────────────────

export type HttpAuditExporterConfig = {
    endpoint: string;
    apiKey?: string;
    headers?: Record<string, string>;
    /** Default: 50 */
    batchSize?: number;
    /** Default: 10_000 */
    timeoutMs?: number;
};


export class HttpAuditExporter implements AuditExporter {
    private readonly batchSize: number;
    private readonly timeoutMs: number;
    private readonly headers: Record<string, string>;

    constructor(private readonly config: HttpAuditExporterConfig) {
        this.batchSize = config.batchSize ?? 50;
        this.timeoutMs = config.timeoutMs ?? 10_000;
        this.headers = {
            "Content-Type": "application/json",
            ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
            ...config.headers,
        };
    }

    async export(entries: AuditEntry[]): Promise<void> {
        if (entries.length === 0) return;

        // Split into batches
        for (let i = 0; i < entries.length; i += this.batchSize) {
            const batch = entries.slice(i, i + this.batchSize);
            await this.sendBatch(batch);
        }
    }

    private async sendBatch(batch: AuditEntry[]): Promise<void> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await fetch(this.config.endpoint, {
                method: "POST",
                headers: this.headers,
                body: JSON.stringify({ entries: batch }),
                signal: controller.signal,
            });
            if (!res.ok) {
                const body = await res.text().catch(() => "(unreadable)");
                console.error(`[agents-chain] HttpAuditExporter: ${res.status} — ${body}`);
            }
        } catch (err) {
            console.error(
                `[agents-chain] HttpAuditExporter: failed to send ${batch.length} entries:`,
                err instanceof Error ? err.message : String(err)
            );
        } finally {
            clearTimeout(timer);
        }
    }
}
