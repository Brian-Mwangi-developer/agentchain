/** Append-only audit log capped at 1000 entries. Secret keys in args are auto-redacted.
 *  Uses an in-memory buffer for O(1) appends; encrypts to store on drain/getAll. */

import { generateId } from "../crypto/utils.js";
import type { EncryptedStore } from "../memory/encrypted-store.js";
import type { AuditEntry, AuditResult } from "../types/audit.js";
import type { VerifiedCallContext } from "../auth/token-verifier.js";
import type { AuditExporter } from "./audit-exporter.js";

const STORE_KEY_LOG = "audit:log";

/** Maximum number of entries held in memory before oldest are evicted. */
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
};

export class AuditLog {
    private readonly store: EncryptedStore;
    private buffer: AuditEntry[] = [];
    private loaded = false;

    constructor(store: EncryptedStore) {
        this.store = store;
    }

    recordDenied(opts: RecordDeniedOptions): AuditEntry {
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
        return entry;
    }

    recordCall(opts: RecordCallOptions): AuditEntry {
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
        };
        this.appendCapped(entry);
        return entry;
    }

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

    /** Flush the in-memory buffer to the encrypted store. */
    flush(): void {
        this.store.set(STORE_KEY_LOG, this.buffer);
    }

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
