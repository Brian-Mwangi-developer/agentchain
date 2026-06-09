/** Mints single-use Ed25519-signed agent+jwt tokens scoped to one capability. */

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
