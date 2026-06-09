// ─── Agent Identity Types ─────────────────────────────────────────────────────

// Re-export constraint types from capabilities.ts (canonical location).
// ConstraintPrimitive, ConstraintOperator, ConstraintValue live there only.
export type { GrantConstraints as CapabilityConstraints } from "./capabilities.js";
export type { ConstraintPrimitive, ConstraintOperator, ConstraintValue } from "./capabilities.js";

export type AgentConfig = {
    agentName: string;
    hostname: string;
    capabilities: string[];
    /**
     * Optional AES-256-GCM encryption key (64 hex chars = 32 bytes).
     * If omitted, a random key is generated per session.
     * Provide this if you need to persist and reload audit logs.
     */
    encryptionKey?: string;
    /**
     * Optional JTI persistence adapter (e.g. Redis).
     * If omitted, the JTI replay cache is in-memory only (resets on restart).
     * Provide this for multi-process or multi-instance deployments.
     */
    jtiAdapter?: import("../memory/jti-cache.js").JtiPersistenceAdapter;
    /**
     * Optional audit exporter. If provided, drain() will use it by default.
     */
    auditExporter?: import("../audit/audit-exporter.js").AuditExporter;
    /**
     * The Host thumbprint (JWK SHA-256 thumbprint of the host public key).
     * Agents must carry this so any verifier can trace the delegation chain:
     * Host → Agent. Without it, a malicious actor could present a valid agent
     * JWT without any legitimate host having registered the agent.
     *
     * Set automatically by AgentsChain/AppChain — consumers do not set this
     * manually unless restoring a persisted identity.
     */
    hostThumbprint?: string;
    /**
     * The Host public key JWK. Stored alongside the agent registration so the
     * verifier can confirm the agent was registered by a known host without
     * contacting an external server.
     */
    hostPublicKeyJwk?: JsonWebKey;
};

export type CapabilityGrant = {
    capability: string;
    grantedAt: number;
    constraints?: import("./capabilities.js").GrantConstraints;
};

/**
 * The full registration record for one agent, encrypted and stored in
 * EncryptedStore. Includes host credentials so the verifier can always
 * reconstruct the Host → Agent delegation chain locally.
 */
export type RegisteredAgent = {
    agentId: string;
    agentName: string;
    hostname: string;
    publicKeyJwk: JsonWebKey;
    thumbprint: string;
    capabilities: CapabilityGrant[];
    registeredAt: number;
    /**
     * The thumbprint of the Host that registered this agent.
     * Required for delegation chain verification — this is the `iss` the
     * host+jwt carries when it signs agent registration.
     */
    hostThumbprint: string;
    /**
     * The Host's public key JWK, stored here so the verifier can verify
     * host+jwt tokens locally without a round-trip to a server.
     */
    hostPublicKeyJwk: JsonWebKey;
};
