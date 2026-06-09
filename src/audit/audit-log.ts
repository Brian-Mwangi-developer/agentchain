/** Append-only encrypted audit log capped at 1000 entries. Secret keys in args are auto-redacted. */

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
    /** The host thumbprint from the agent registration. */
    hostThumbprint: string;
    capability: string;
    args: Record<string, unknown>;
    reason: string;
    jti: string;
    /** Milliseconds spent inside the auth pipeline before the denial. */
    authOverheadMs: number;
};

export type RecordCallOptions = {
    context: VerifiedCallContext;
    args: Record<string, unknown>;
    result: Exclude<AuditResult, "denied">;
    durationMs: number;
    errorMessage?: string;
    /** Milliseconds spent inside build+verify JWT pipeline. */
    authOverheadMs: number;
};

export class AuditLog {
    constructor(private readonly store: EncryptedStore) {}

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
        return this.store.get<AuditEntry[]>(STORE_KEY_LOG) ?? [];
    }

    getByResult(result: AuditResult): AuditEntry[] {
        return this.getAll().filter((e) => e.result === result);
    }

    getByCapability(capability: string): AuditEntry[] {
        return this.getAll().filter((e) => e.capability === capability);
    }

    get count(): number {
        return this.getAll().length;
    }

    async drain(exporter?: AuditExporter): Promise<void> {
        const entries = this.getAll();
        if (entries.length === 0) return;
        if (exporter) {
            await exporter.export(entries);
        }
        this.store.set(STORE_KEY_LOG, [] as AuditEntry[]);
    }

    private appendCapped(entry: AuditEntry): void {
        const existing = this.store.get<AuditEntry[]>(STORE_KEY_LOG) ?? [];
        if (existing.length >= MAX_ENTRIES) {
            existing.shift(); // remove oldest
        }
        existing.push(entry);
        this.store.set(STORE_KEY_LOG, existing);
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
