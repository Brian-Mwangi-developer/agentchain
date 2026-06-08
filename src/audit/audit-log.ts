/**
 * AuditLog — append-only encrypted log of all capability call attempts.
 *
 * Every intercepted call (success, denied, or error) is recorded.
 * Entries are encrypted with AES-256-GCM before being written to the store,
 * so even if someone inspects process memory they see only ciphertext.
 *
 * The log is append-only within a session. There is no delete API.
 */

import { generateId } from "../crypto/utils.js";
import type { EncryptedStore } from "../memory/encrypted-store.js";
import type { AuditEntry, AuditResult } from "../types/audit.js";
import type { VerifiedCallContext } from "../auth/token-verifier.js";
import type { AuditExporter } from "./audit-exporter.js";

const STORE_KEY_LOG = "audit:log";

export type RecordDeniedOptions = {
    agentId: string;
    agentName: string;
    hostname: string;
    capability: string;
    args: Record<string, unknown>;
    reason: string;
    jti: string;
};

export type RecordCallOptions = {
    context: VerifiedCallContext; //NOTE: This is  not complete 
    args: Record<string, unknown>;
    result: Exclude<AuditResult, "denied">;
    durationMs: number;
    errorMessage?: string;
};

export class AuditLog {
    constructor(private readonly store: EncryptedStore) {}

    /** Record a denied capability call (before the SDK is touched). */
    recordDenied(opts: RecordDeniedOptions): AuditEntry {
        const entry: AuditEntry = {
            id: generateId("aud"),
            agentId: opts.agentId,
            agentName: opts.agentName,
            hostname: opts.hostname,
            capability: opts.capability,
            args: sanitizeArgs(opts.args),
            result: "denied",
            denialReason: opts.reason,
            jti: opts.jti,
            timestamp: Date.now(),
            durationMs: 0,
        };
        //NOTE:Fix this since it does not Contain Hosts credentials
        this.store.append<AuditEntry>(STORE_KEY_LOG, entry);
        return entry;
    }

    /** Record a completed capability call (success or error). */
    recordCall(opts: RecordCallOptions): AuditEntry {
        const entry: AuditEntry = {
            id: generateId("aud"),
            agentId: opts.context.agentId,
            agentName: opts.context.agentName,
            hostname: opts.context.hostname,
            capability: opts.context.capability,
            args: sanitizeArgs(opts.args),
            result: opts.result,
            errorMessage: opts.errorMessage,
            jti: opts.context.jti,
            timestamp: Date.now(),
            durationMs: opts.durationMs,
        };
        this.store.append<AuditEntry>(STORE_KEY_LOG, entry);
        return entry;
    }
    //NOTE:Fix this also it contains wrong Agent Identity

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
     * Call this periodically or on process shutdown to push entries to a
     * persistent destination (database, HTTP endpoint, log aggregator, etc.).
     *
     * If no exporter is provided, the log is simply cleared without exporting.
     */
    async drain(exporter?: AuditExporter): Promise<void> {
        const entries = this.getAll();
        if (entries.length === 0) return;

        if (exporter) {
            await exporter.export(entries);
        }

        // Clear the log after export
        this.store.set(STORE_KEY_LOG, [] as AuditEntry[]);
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
