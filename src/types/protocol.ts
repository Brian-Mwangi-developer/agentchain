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
 */
export type AgentJwtClaims = {
    iss: string;                // Host thumbprint (who delegated this agent)
    sub: string;                // Agent ID
    aud: string;                // Server issuer URL
    iat: number;
    exp: number;                // Must be ≤ 60 seconds after iat
    jti: string;                // Single-use nonce
    capabilities?: string[];    // Optional scope restriction
};

// ─── Well-Known Discovery ─────────────────────────────────────────────────────

/**
 * The response shape for GET /.well-known/agent-configuration.
 * Tells agents what capabilities are available and where the endpoints are.
 */
export type AgentConfiguration = {
    version: string;                        // "1.0-draft"
    provider_name: string;
    issuer: string;
    algorithms: string[];                   // ["Ed25519"]
    modes: string[];                        // ["delegated", "autonomous"]
    approval_methods: string[];             // ["device_authorization"]
    endpoints: Record<string, string>;      // endpoint name → path
    default_capabilities: string[];
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
