/** Append-only audit log. Secret keys in args are auto-redacted. */

import { generateId } from "../crypto/utils.js";
import type { EncryptedStore } from "../memory/encrypted-store.js";
import type { AuditEntry, AuditResult } from "../types/audit.js";
import type { TraceRun, TraceSpan, TraceRunStatus } from "../types/trace.js";
import type { VerifiedCallContext } from "../auth/token-verifier.js";
import type { AuditExporter } from "./audit-exporter.js";
import type { TraceExporter } from "./trace-exporter.js";
import type { ApprovalScope } from "../types/access-request.js";
import type { ModelMetadata } from "../types/trace.js";

const STORE_KEY_LOG = "audit:log";
const MAX_ENTRIES = 1000;

export type RecordDeniedOptions = {
    agentId: string;
    agentName: string;
    hostname: string;
    hostThumbprint: string;
    capability: string;
    args: Record<string, unknown>;
    reason: string;
    jti: string;
    authOverheadMs: number;
};

export type RecordCallOptions = {
    context: VerifiedCallContext;
    args: Record<string, unknown>;
    result: Exclude<AuditResult, "denied">;
    durationMs: number;
    errorMessage?: string;
    authOverheadMs: number;
    /** Model metadata attached by the LLM wrapper, if applicable */
    modelMetadata?: ModelMetadata;
};

export type RecordAccessRequestedOptions = {
    agentId: string;
    agentName: string;
    hostname: string;
    hostThumbprint: string;
    capability: string;
    args: Record<string, unknown>;
    reason: string;
    accessRequestId: string;
};

export type RecordAccessResolvedOptions = {
    agentId: string;
    agentName: string;
    hostname: string;
    hostThumbprint: string;
    capability: string;
    args: Record<string, unknown>;
    accessRequestId: string;
    resolution: "access_approved" | "access_denied";
    approvalScope?: ApprovalScope;
};

// ─── Active trace context (in-memory only, not persisted) ─────────────────────

type ActiveTrace = {
    traceId: string;
    agentId: string;
    agentName: string;
    hostThumbprint: string;
    startedAt: number;
    spans: TraceSpan[];
};

export class AuditLog {
    private readonly store: EncryptedStore;
    private buffer: AuditEntry[] = [];
    private loaded = false;
    private activeTraces = new Map<string, ActiveTrace>();

    constructor(store: EncryptedStore) {
        this.store = store;
    }

    // ─── Trace lifecycle ────────────────────────────────────────────────────

    /**
     * Open a new trace run. Returns a traceId that must be passed to
     * closeTrace() when the agent session ends.
     * All recordCall/recordDenied calls made while a trace is open will
     * attach a span to the corresponding TraceRun.
     */
    openTrace(agentId: string, agentName: string, hostThumbprint: string): string {
        const traceId = generateId("trace");
        this.activeTraces.set(traceId, {
            traceId,
            agentId,
            agentName,
            hostThumbprint,
            startedAt: Date.now(),
            spans: [],
        });
        return traceId;
    }

    /**
     * Close the trace run and return the completed TraceRun.
     * If a traceExporter is provided, the run is exported immediately.
     * Returns undefined if the traceId is not found.
     */
    async closeTrace(
        traceId: string,
        status: TraceRunStatus,
        traceExporter?: TraceExporter
    ): Promise<TraceRun | undefined> {
        const active = this.activeTraces.get(traceId);
        if (!active) return undefined;

        this.activeTraces.delete(traceId);

        const endedAt = Date.now();
        const run: TraceRun = {
            traceId: active.traceId,
            agentId: active.agentId,
            agentName: active.agentName,
            hostThumbprint: active.hostThumbprint,
            status,
            startedAt: active.startedAt,
            endedAt,
            totalDurationMs: endedAt - active.startedAt,
            spans: active.spans,
            summary: buildSummary(active.spans),
        };

        if (traceExporter) {
            await traceExporter.export(run);
        }

        return run;
    }

    /** Returns the active trace for the given traceId, if any. */
    getActiveTrace(traceId: string): Readonly<ActiveTrace> | undefined {
        return this.activeTraces.get(traceId);
    }

    // ─── Record methods (existing API, now also append spans) ──────────────

    recordDenied(opts: RecordDeniedOptions, traceId?: string): AuditEntry {
        const entry: AuditEntry = {
            id: generateId("aud"),
            agentId: opts.agentId,
            agentName: opts.agentName,
            hostname: opts.hostname,
            hostThumbprint: opts.hostThumbprint,
            capability: opts.capability,
            args: sanitizeArgs(opts.args),
            result: "denied",
            denialReason: opts.reason,
            jti: opts.jti,
            timestamp: Date.now(),
            durationMs: 0,
            authOverheadMs: opts.authOverheadMs,
        };
        this.appendCapped(entry);
        this.appendSpan(traceId, entry);
        return entry;
    }

    recordCall(opts: RecordCallOptions, traceId?: string): AuditEntry {
        const entry: AuditEntry = {
            id: generateId("aud"),
            agentId: opts.context.agentId,
            agentName: opts.context.agentName,
            hostname: opts.context.hostname,
            hostThumbprint: opts.context.hostThumbprint,
            capability: opts.context.capability,
            args: sanitizeArgs(opts.args),
            result: opts.result,
            errorMessage: opts.errorMessage,
            jti: opts.context.jti,
            timestamp: Date.now(),
            durationMs: opts.durationMs,
            authOverheadMs: opts.authOverheadMs,
            modelMetadata: opts.modelMetadata,
        };
        this.appendCapped(entry);
        this.appendSpan(traceId, entry);
        return entry;
    }

    recordAccessRequested(opts: RecordAccessRequestedOptions, traceId?: string): AuditEntry {
        const entry: AuditEntry = {
            id: generateId("aud"),
            agentId: opts.agentId,
            agentName: opts.agentName,
            hostname: opts.hostname,
            hostThumbprint: opts.hostThumbprint,
            capability: opts.capability,
            args: sanitizeArgs(opts.args),
            result: "access_requested",
            denialReason: opts.reason,
            accessRequestId: opts.accessRequestId,
            jti: "access_request",
            timestamp: Date.now(),
            durationMs: 0,
            authOverheadMs: 0,
        };
        this.appendCapped(entry);
        this.appendSpan(traceId, entry);
        return entry;
    }

    recordAccessResolved(opts: RecordAccessResolvedOptions, traceId?: string): AuditEntry {
        const entry: AuditEntry = {
            id: generateId("aud"),
            agentId: opts.agentId,
            agentName: opts.agentName,
            hostname: opts.hostname,
            hostThumbprint: opts.hostThumbprint,
            capability: opts.capability,
            args: sanitizeArgs(opts.args),
            result: opts.resolution,
            accessRequestId: opts.accessRequestId,
            approvalScope: opts.approvalScope,
            jti: "access_resolution",
            timestamp: Date.now(),
            durationMs: 0,
            authOverheadMs: 0,
        };
        this.appendCapped(entry);
        this.appendSpan(traceId, entry);
        return entry;
    }

    // ─── Existing query API ────────────────────────────────────────────────

    getAll(): AuditEntry[] {
        this.ensureLoaded();
        return [...this.buffer];
    }

    getByResult(result: AuditResult): AuditEntry[] {
        return this.getAll().filter((e) => e.result === result);
    }

    getByCapability(capability: string): AuditEntry[] {
        return this.getAll().filter((e) => e.capability === capability);
    }

    get count(): number {
        this.ensureLoaded();
        return this.buffer.length;
    }

    async drain(exporter?: AuditExporter): Promise<void> {
        this.ensureLoaded();
        const entries = this.buffer;
        if (entries.length === 0) return;
        if (exporter) {
            await exporter.export(entries);
        }
        this.buffer = [];
        this.store.set(STORE_KEY_LOG, [] as AuditEntry[]);
    }

    flush(): void {
        this.store.set(STORE_KEY_LOG, this.buffer);
    }

    // ─── Private ───────────────────────────────────────────────────────────

    private ensureLoaded(): void {
        if (!this.loaded) {
            this.buffer = this.store.get<AuditEntry[]>(STORE_KEY_LOG) ?? [];
            this.loaded = true;
        }
    }

    private appendCapped(entry: AuditEntry): void {
        this.ensureLoaded();
        if (this.buffer.length >= MAX_ENTRIES) {
            this.buffer.shift();
        }
        this.buffer.push(entry);
    }

    private appendSpan(traceId: string | undefined, entry: AuditEntry): void {
        if (!traceId) return;
        const active = this.activeTraces.get(traceId);
        if (!active) return;

        const span: TraceSpan = {
            spanId: entry.id,
            capability: entry.capability,
            result: entry.result as TraceSpan["result"],
            startedAt: entry.timestamp,
            durationMs: entry.durationMs,
            authOverheadMs: entry.authOverheadMs,
            jti: entry.jti,
            args: entry.args,
            denialReason: entry.denialReason,
            errorMessage: entry.errorMessage,
            accessRequestId: entry.accessRequestId,
            approvalScope: entry.approvalScope,
            modelMetadata: entry.modelMetadata,
            toolCalls: entry.modelMetadata?.toolCalls,
            stopReason: entry.modelMetadata?.stopReason,
        };

        active.spans.push(span);
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function buildSummary(spans: TraceSpan[]) {
    let totalInputTokens = 0;
    let totalOutputTokens = 0;
    const modelsUsed = new Set<string>();
    const providersUsed = new Set<string>();

    for (const span of spans) {
        if (span.modelMetadata) {
            totalInputTokens += span.modelMetadata.inputTokens ?? 0;
            totalOutputTokens += span.modelMetadata.outputTokens ?? 0;
            modelsUsed.add(span.modelMetadata.model);
            providersUsed.add(span.modelMetadata.provider);
        }
    }

    return {
        totalSpans: spans.length,
        successSpans: spans.filter((s) => s.result === "success").length,
        deniedSpans: spans.filter((s) => s.result === "denied").length,
        errorSpans: spans.filter((s) => s.result === "error").length,
        totalInputTokens,
        totalOutputTokens,
        totalTokens: totalInputTokens + totalOutputTokens,
        modelsUsed: [...modelsUsed],
        providersUsed: [...providersUsed],
    };
}

const SECRET_KEY_PATTERN = /(?:key|secret|token|password|auth|credential|bearer)/i;

function sanitizeArgs(args: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(args)) {
        if (SECRET_KEY_PATTERN.test(k)) {
            out[k] = "[REDACTED]";
        } else if (typeof v === "object" && v !== null && !Array.isArray(v)) {
            out[k] = sanitizeArgs(v as Record<string, unknown>);
        } else {
            out[k] = v;
        }
    }
    return out;
}
