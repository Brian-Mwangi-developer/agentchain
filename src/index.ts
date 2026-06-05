// ─── Main classes ─────────────────────────────────────────────────────────────

export { AgentsChain } from "./chain.js";
export { AppChain } from "./chain.js";

// ─── Host layer ───────────────────────────────────────────────────────────────

export { HostIdentity } from "./host/host-identity.js";
export type { HostConfig, HostRegistration } from "./host/host-identity.js";

// ─── App wrapper ──────────────────────────────────────────────────────────────

export { CapabilityRegistry } from "./app/capability-registry.js";
export { wrapApp } from "./app/app-wrapper.js";
export type { AppInterceptContext } from "./app/app-wrapper.js";

// ─── Audit exporters ─────────────────────────────────────────────────────────

export { ConsoleAuditExporter, HttpAuditExporter } from "./audit/audit-exporter.js";
export type { AuditExporter, HttpAuditExporterConfig } from "./audit/audit-exporter.js";

// ─── Errors ───────────────────────────────────────────────────────────────────

export { ChainAuthError } from "./errors/chain-error.js";
export type { ChainErrorCode } from "./errors/chain-error.js";

// ─── Types: chain config ──────────────────────────────────────────────────────

export type { AgentConfig, ChainStats, AuditSnapshot, AppChainConfig } from "./types/chain.js";

// ─── Types: audit ─────────────────────────────────────────────────────────────

export type { AuditEntry, AuditResult } from "./types/audit.js";

// ─── Types: identity (legacy AgentsChain) ─────────────────────────────────────

export type {
    RegisteredAgent,
    CapabilityGrant,
    CapabilityConstraints,
    ConstraintOperator,
    ConstraintValue,
    ConstraintPrimitive,
} from "./types/identity.js";

// ─── Types: capabilities ──────────────────────────────────────────────────────

export type {
    Capability,
    AgentContext,
    GrantConstraints,
    JsonSchemaObject,
} from "./types/capabilities.js";

// Re-export constraint types from capabilities (canonical location)
export type {
    ConstraintOperator as CapabilityConstraintOperator,
    ConstraintValue as CapabilityConstraintValue,
    ConstraintPrimitive as CapabilityConstraintPrimitive,
} from "./types/capabilities.js";

// ─── Types: protocol (wire format) ───────────────────────────────────────────

export type {
    HostJwtClaims,
    AgentJwtClaims,
    AgentConfiguration,
    GrantStatus,
    ResolvedGrant,
} from "./types/protocol.js";

// ─── Types: JTI persistence adapter ──────────────────────────────────────────

export type { JtiPersistenceAdapter } from "./memory/jti-cache.js";

// ─── Types: token verifier config ────────────────────────────────────────────

export type { VerifierConfig, VerifiedCallContext } from "./auth/token-verifier.js";

// ─── Crypto utilities ─────────────────────────────────────────────────────────

export {
    generateKeyPair,
    exportPublicKeyJwk,
    exportPrivateKeyJwk,
    importPublicKeyJwk,
    computeJwkThumbprint,
    signJwt,
    verifyJwtSignature,
    decodeJwtUnsafe,
} from "./crypto/ed25519.js";

export { generateId, generateAgentId, base64UrlEncode, base64UrlDecode } from "./crypto/utils.js";
