import type { AuditExporter } from "../audit/audit-exporter.js";
import type { VerifierConfig } from "../auth/token-verifier.js";
import type { JtiPersistenceAdapter } from "../memory/jti-cache.js";
import type { AuditEntry } from "./audit.js";
import type { Capability } from "./capabilities.js";
import type { AgentConfig } from "./identity.js";

export type { AgentConfig };

export type AppChainConfig = {
    /**
     * Short name for this app, e.g. "billing-service", "github".
     * Used in well-known config as provider_name.
     */
    providerName: string;

    /**
     * The base URL of this server, e.g. "https://billing.mycompany.com".
     * Used in well-known config as issuer and in Host JWT aud claim.
     */
    issuer: string;

    /**
     * The capabilities this app exposes.
     * Registered in the CapabilityRegistry at chain creation.
     */
    capabilities: Capability[];

    /**
     * Optional AES-256-GCM encryption key (64 hex chars = 32 bytes).
     * If omitted, a random key is generated per session.
     */
    encryptionKey?: string;

    /**
     * Optional Host identity overrides.
     * Defaults to { name: providerName, issuerUrl: issuer }.
     */
    host?: {
        name?: string;
        issuerUrl?: string;
    };

    /**
     * Optional JTI persistence adapter (e.g. Redis).
     * If omitted, JTI cache is in-memory (resets on process restart).
     */
    jtiAdapter?: JtiPersistenceAdapter;

    /**
     * Optional audit exporter for auto-draining entries on drain().
     */
    auditExporter?: AuditExporter;

    /**
     * Optional external grant resolver.
     * If provided, grants are resolved from this function instead of
     * the grants passed to chain.wrap().
     * Useful for looking up grants from your DB/Redis.
     */
    grantResolver?: VerifierConfig["grantResolver"];
};

export type ChainStats = {
    agentId: string;
    /** The Host ID (JWK thumbprint) that registered this agent. */
    hostId: string;
    agentName: string;
    hostname: string;
    totalCalls: number;
    successfulCalls: number;
    deniedCalls: number;
    errorCalls: number;
    registeredAt: number;
    /**
     * Auth pipeline overhead stats across all recorded calls.
     * Use these to measure the latency cost of the security layer.
     */
    authOverhead: {
        avgMs: number;
        maxMs: number;
    };
};

export type AuditSnapshot = {
    agentId: string;
    entries: AuditEntry[];
    exportedAt: number;
};
