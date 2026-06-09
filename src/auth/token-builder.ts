/**
 * TokenBuilder — creates signed agent+jwt tokens per capability call.
 *
 * Security design:
 * - Every token is single-use: a fresh cryptographically random jti per call.
 * - TTL is 60 seconds — minimal viable window for a synchronous SDK call.
 * - iss = agent's own JWK thumbprint — ties the token to this specific keypair.
 * - sub = agentId (<hostname>-agent-<32hex>) — stable agent identifier.
 * - aud = capability name — a token for "chat.completion" cannot authorize
 *   "embedding". Scope-bound tokens prevent capability escalation.
 * - hostThumbprint = the Host that registered this agent, embedded in every
 *   token. Verifiers can confirm the agent has a legitimate parent host
 *   without needing an external registry call. This closes the gap where
 *   a rogue self-issued agent was indistinguishable from a registered one.
 */

import { randomBytes } from "node:crypto";
import { signJwt } from "../crypto/ed25519.js";
import { base64UrlEncode } from "../crypto/utils.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { AgentJwtClaims } from "../types/protocol.js";

export type { AgentJwtClaims };

const TOKEN_TTL_SECONDS = 60;

export class TokenBuilder {
    constructor(private readonly identity: AgentIdentity) {}

    async build(capability: string): Promise<{ token: string; claims: AgentJwtClaims }> {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const jti = base64UrlEncode(randomBytes(16));

        const claims: AgentJwtClaims = {
            iss: this.identity.thumbprint,
            sub: this.identity.agentId,
            aud: capability,
            iat: nowSeconds,
            exp: nowSeconds + TOKEN_TTL_SECONDS,
            jti,
            hostname: this.identity.registration.hostname,
            agentName: this.identity.registration.agentName,
            hostThumbprint: this.identity.registration.hostThumbprint,
        };

        const token = await signJwt(claims, this.identity.privateKey, "agent+jwt");
        return { token, claims };
    }
}
