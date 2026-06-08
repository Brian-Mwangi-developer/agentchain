/**
 * TokenBuilder — creates signed agent+jwt tokens per capability call.
 *
 * Security design:
 * - Every token is single-use: a fresh cryptographically random jti per call.
 * - TTL is 60 seconds — minimal viable window for a synchronous SDK call.
 * - The iss claim is the public key thumbprint (not a mutable name string).
 *   This ties the token cryptographically to the specific keypair.
 * - The sub is the agentId (<hostname>-agent-<32hex>).
 * - The aud is the capability name — a token for "chat.completion" cannot
 *   be presented as authorization for "embedding".
 */

import { randomBytes } from "node:crypto";
import { signJwt } from "../crypto/ed25519.js";
import { base64UrlEncode } from "../crypto/utils.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
//NOTE:Confirm this Agent Issuing.
export type AgentJwtClaims = {
    iss: string;
    sub: string;
    aud: string;
    iat: number;
    exp: number;
    jti: string;
    hostname: string;
    agentName: string;
};

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
        };

        const token = await signJwt(claims, this.identity.privateKey, "agent+jwt");
        return { token, claims };
    }
}
