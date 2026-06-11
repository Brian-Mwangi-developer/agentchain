import type { AuditExporter } from "../audit/audit-exporter.js";
import type { VerifierConfig } from "../auth/token-verifier.js";
import type { JtiPersistenceAdapter } from "../memory/jti-cache.js";
import type { AuditEntry } from "./audit.js";
import type { Capability } from "./capabilities.js";
import type { AgentConfig } from "./identity.js";

export type { AgentConfig };

export type AppChainConfig = {
    providerName: string;
    /** The issuer URL for the host. Use `host.issuerUrl` instead if both are specified; they must match. */
    issuer?: string;
    capabilities: Capability[];
    encryptionKey?: string;
    host?: {
        name?: string;
        issuerUrl?: string;
        /** Restore a persisted host identity. Both private and public JWKs required. */
        privateKeyJwk?: JsonWebKey;
        publicKeyJwk?: JsonWebKey;
    };
    agent?: {
        /** Restore a persisted agent identity. All three fields required together. */
        agentId?: string;
        privateKeyJwk?: JsonWebKey;
        publicKeyJwk?: JsonWebKey;
    };
    jtiAdapter?: JtiPersistenceAdapter;
    auditExporter?: AuditExporter;
    /** Resolve grants from DB/Redis instead of the grants passed to wrap(). */
    grantResolver?: VerifierConfig["grantResolver"];
};

export type ChainStats = {
    agentId: string;
    hostId: string;
    agentName: string;
    hostname: string;
    totalCalls: number;
    successfulCalls: number;
    deniedCalls: number;
    errorCalls: number;
    registeredAt: number;
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
