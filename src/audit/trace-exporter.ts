/** TraceExporter — ships one complete TraceRun to the collector. */

import type { TraceRun } from "../types/trace.js";

export interface TraceExporter {
    export(run: TraceRun): Promise<void>;
}

export class ConsoleTraceExporter implements TraceExporter {
    async export(run: TraceRun): Promise<void> {
        console.log(JSON.stringify({
            ...run,
            startedAt_iso: new Date(run.startedAt).toISOString(),
            endedAt_iso: new Date(run.endedAt).toISOString(),
        }, null, 2));
    }
}

export type HttpTraceExporterConfig = {
    endpoint: string;
    apiKey?: string;
    headers?: Record<string, string>;
    /** Default: 10_000 */
    timeoutMs?: number;
};

/**
 * Ships one TraceRun as a single POST to the collector endpoint.
 * The gateway receives { run: TraceRun } and stores it as one row.
 */
export class HttpTraceExporter implements TraceExporter {
    private readonly timeoutMs: number;
    private readonly headers: Record<string, string>;

    constructor(private readonly config: HttpTraceExporterConfig) {
        this.timeoutMs = config.timeoutMs ?? 10_000;
        this.headers = {
            "Content-Type": "application/json",
            ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
            ...config.headers,
        };
    }

    async export(run: TraceRun): Promise<void> {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await fetch(this.config.endpoint, {
                method: "POST",
                headers: this.headers,
                body: JSON.stringify({ run }),
                signal: controller.signal,
            });
            if (!res.ok) {
                const body = await res.text().catch(() => "(unreadable)");
                console.error(`[agents-chain] HttpTraceExporter: ${res.status} — ${body}`);
            }
        } catch (err) {
            console.error(
                `[agents-chain] HttpTraceExporter: failed to export trace ${run.traceId}:`,
                err instanceof Error ? err.message : String(err)
            );
        } finally {
            clearTimeout(timer);
        }
    }
}
