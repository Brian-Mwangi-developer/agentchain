/**
 * Protocol types — the wire format shared between agents-chain and any
 * compliant agent-auth server.
 *
 * These mirror the types in agent-auth/src/types/protocol.ts so that
 * agents-chain can participate in the same Host → Agent → CapabilityGrant
 * protocol without coupling to the server implementation.
 */

import type { GrantConstraints } from "./capabilities.js";

// ─── JWT Claims ───────────────────────────────────────────────────────────────

/**
 * Claims carried in a host+jwt — signed by the Host's private key.
 * Used for management operations: registering agents, revoking, rotating keys.
 */
export type HostJwtClaims = {
    iss: string;                    // Host JWK thumbprint (stable identity)
    aud: string;                    // Server issuer URL
    iat: number;                    // Issued at (Unix seconds)
    exp: number;                    // Expires at (iat + 60)
    jti: string;                    // Single-use nonce
    host_public_key?: JsonWebKey;   // Embedded during dynamic registration
    agent_public_key?: JsonWebKey;  // Embedded when registering an agent
};

/**
 * Claims carried in an agent+jwt — signed by the Agent's private key.
 * Used for capability execution.
 *
 * Claim semantics (aligned with agent-auth protocol):
 *   iss  — The AGENT's own JWK thumbprint (identifies the signing key).
 *           The verifier uses this to look up the agent's public key.
 *   sub  — The stable agentId (<hostname>-agent-<32hex>).
 *   aud  — The capability name being requested (scope-bound token).
 *           A token for "chat.completion" cannot authorize "embedding".
 *   hostThumbprint — The thumbprint of the Host that registered this agent.
 *           Carried in every token so any verifier can reconstruct the
 *           Host → Agent delegation chain without an external server call.
 *           This is the critical field that was previously missing — without
 *           it a token issued by an unregistered "rogue" agent looks identical
 *           to a legitimately-registered one.
 */
export type AgentJwtClaims = {
    iss: string;            // Agent's own JWK thumbprint
    sub: string;            // Stable agent ID
    aud: string;            // Capability name (scope-bound)
    iat: number;
    exp: number;            // Must be ≤ 60 seconds after iat
    jti: string;            // Single-use nonce (replay protection)
    hostname: string;       // Human-readable hostname for audit
    agentName: string;      // Human-readable agent name for audit
    hostThumbprint: string; // Thumbprint of the registering Host
};

// ─── Well-Known Discovery ─────────────────────────────────────────────────────

/**
 * The response shape for GET /.well-known/agent-configuration.
 * Tells agents what capabilities are available and where the endpoints are.
 * Aligned with the agent-auth protocol spec (1.0-draft).
 */
export type AgentConfiguration = {
    version: string;                        // "1.0-draft"
    provider_name: string;
    description?: string;                   // Human-readable service summary
    issuer: string;
    algorithms: string[];                   // ["Ed25519"]
    modes: string[];                        // ["delegated", "autonomous"]
    approval_methods: string[];             // ["device_authorization", "ciba"]
    endpoints: Record<string, string>;      // endpoint name → path
    default_capabilities: string[];
    jwks_uri?: string;                      // URL to server's JWKS (optional)
};

// ─── Capability Grants ────────────────────────────────────────────────────────

export type GrantStatus = "active" | "pending" | "denied";

/**
 * A resolved capability grant — what an agent is allowed (or not) to do.
 * Returned by a grantResolver or held in-memory after registration.
 */
export type ResolvedGrant = {
    capability: string;
    status: GrantStatus;
    constraints?: GrantConstraints;
    expiresAt?: number;    // Unix ms; undefined = no expiry
};
