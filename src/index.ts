
export { AgentsChain } from "./chain.js";
export { ChainAuthError } from "./errors/chain-error.js";
export type { ChainErrorCode } from "./errors/chain-error.js";
export type { AgentConfig, ChainStats, AuditSnapshot } from "./types/chain.js";
export type { AuditEntry, AuditResult } from "./types/audit.js";
export type {
    RegisteredAgent,
    CapabilityGrant,
    CapabilityConstraints,
    ConstraintOperator,
    ConstraintValue,
    ConstraintPrimitive,
} from "./types/identity.js";

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
