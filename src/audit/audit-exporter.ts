/**
 * AuditExporter — interface and built-in implementations for draining audit entries.
 *
 * The AuditLog is in-memory and ephemeral. Use an exporter to push entries to
 * a persistent destination: a remote API, a database, a log aggregator, etc.
 *
 * Built-in exporters:
 *   ConsoleAuditExporter  — pretty-prints to stdout (good for development)
 *   HttpAuditExporter     — POSTs batches to any HTTP endpoint (production)
 *
 * Usage:
 *   // Flush on process exit
 *   process.on("SIGTERM", async () => {
 *     await chain.drain(new HttpAuditExporter({ endpoint: "https://audit.melduo.com/ingest", apiKey: "xxx" }));
 *   });
 *
 *   // Or flush periodically
 *   setInterval(async () => {
 *     await chain.drain(exporter);
 *   }, 30_000);
 */

import type { AuditEntry } from "../types/audit.js";

// ─── Interface ────────────────────────────────────────────────────────────────

export interface AuditExporter {
    /**
     * Export a batch of audit entries to a destination.
     * Called by AuditLog.drain(). Must not throw — errors should be handled internally.
     */
    export(entries: AuditEntry[]): Promise<void>;
}

// ─── ConsoleAuditExporter ─────────────────────────────────────────────────────

/**
 * Prints audit entries to stdout as JSON lines.
 * Use in development or when piping logs to a collector.
 */
export class ConsoleAuditExporter implements AuditExporter {
    async export(entries: AuditEntry[]): Promise<void> {
        for (const entry of entries) {
            console.log(JSON.stringify({
                ...entry,
                // Human-readable timestamp
                timestamp_iso: new Date(entry.timestamp).toISOString(),
            }));
        }
    }
}

// ─── HttpAuditExporter ────────────────────────────────────────────────────────

export type HttpAuditExporterConfig = {
    /**
     * The HTTP endpoint to POST batches to.
     * e.g. "https://audit.melduo.com/ingest"
     */
    endpoint: string;

    /**
     * Optional API key sent as "Authorization: Bearer <apiKey>".
     */
    apiKey?: string;

    /**
     * Additional headers to include in every request.
     */
    headers?: Record<string, string>;

    /**
     * Maximum entries per POST request. Default: 50.
     */
    batchSize?: number;

    /**
     * Request timeout in milliseconds. Default: 10_000.
     */
    timeoutMs?: number;
};

/**
 * POSTs audit entries to any HTTP endpoint in configurable batches.
 * Suitable for the Melduo hosted audit service or any self-hosted receiver.
 *
 * Request format:
 *   POST <endpoint>
 *   Content-Type: application/json
 *   Authorization: Bearer <apiKey>  (if configured)
 *   Body: { "entries": AuditEntry[] }
 *
 * Errors are logged to stderr but never thrown — audit export failures
 * should never crash the application.
 */
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
                console.error(
                    `[agents-chain] HttpAuditExporter: server returned ${res.status} — ${body}`
                );
            }
        } catch (err) {
            console.error(
                `[agents-chain] HttpAuditExporter: failed to send batch of ${batch.length} entries:`,
                err instanceof Error ? err.message : String(err)
            );
        } finally {
            clearTimeout(timer);
        }
    }
}
