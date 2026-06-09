/**
 * AuditLog — append-only encrypted log of all capability call attempts.
 *
 * Every intercepted call (success, denied, or error) is recorded with full
 * attribution: agentId, agentName, hostname, hostThumbprint (new), capability,
 * sanitized args, result, and timing.
 *
 * Entries are encrypted with AES-256-GCM before being written to the store.
 * The log is append-only within a session. There is no delete API.
 *
 * Memory management:
 * The log is capped at MAX_ENTRIES. When the cap is reached, the oldest entry
 * is evicted before a new one is appended. This prevents unbounded memory
 * growth in long-running processes. Call drain() to flush + clear before the
 * cap is hit in high-throughput scenarios.
 */

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

    /** Record a denied capability call (before the underlying SDK/service is touched). */
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

    /** Record a completed capability call (success or error). */
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

    /** Return all decrypted audit entries for this session. */
    getAll(): AuditEntry[] {
        return this.store.get<AuditEntry[]>(STORE_KEY_LOG) ?? [];
    }

    /** Return entries filtered by result type. */
    getByResult(result: AuditResult): AuditEntry[] {
        return this.getAll().filter((e) => e.result === result);
    }

    /** Return entries filtered by capability name. */
    getByCapability(capability: string): AuditEntry[] {
        return this.getAll().filter((e) => e.capability === capability);
    }

    get count(): number {
        return this.getAll().length;
    }

    /**
     * Export all entries via the provided exporter, then clear the in-memory log.
     *
     * Call periodically or on process shutdown to push entries to a persistent
     * destination (database, HTTP endpoint, log aggregator, etc.).
     * If no exporter is provided, the log is cleared without exporting.
     */
    async drain(exporter?: AuditExporter): Promise<void> {
        const entries = this.getAll();
        if (entries.length === 0) return;
        if (exporter) {
            await exporter.export(entries);
        }
        this.store.set(STORE_KEY_LOG, [] as AuditEntry[]);
    }

    /**
     * Append an entry, evicting the oldest if at the cap.
     * O(n) on eviction — acceptable since eviction only happens after MAX_ENTRIES
     */
    private appendCapped(entry: AuditEntry): void {
        const existing = this.store.get<AuditEntry[]>(STORE_KEY_LOG) ?? [];
        if (existing.length >= MAX_ENTRIES) {
            existing.shift(); // remove oldest
        }
        existing.push(entry);
        this.store.set(STORE_KEY_LOG, existing);
    }
}

/**
 * Strip values that look like secrets from args before logging.
 * Keys matching this pattern are replaced with "[REDACTED]".
 */
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
