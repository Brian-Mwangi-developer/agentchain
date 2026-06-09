/** Wire-format types shared with any agent-auth compliant server. */

import type { GrantConstraints } from "./capabilities.js";

export type HostJwtClaims = {
    iss: string;                    // Host JWK thumbprint (stable identity)
    aud: string;                    // Server issuer URL
    iat: number;                    // Issued at (Unix seconds)
    exp: number;                    // Expires at (iat + 60)
    jti: string;                    // Single-use nonce
    host_public_key?: JsonWebKey;   // Embedded during dynamic registration
    agent_public_key?: JsonWebKey;  // Embedded when registering an agent
};

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

export type GrantStatus = "active" | "pending" | "denied";


export type ResolvedGrant = {
    capability: string;
    status: GrantStatus;
    constraints?: GrantConstraints;
    expiresAt?: number;    // Unix ms; undefined = no expiry
};
