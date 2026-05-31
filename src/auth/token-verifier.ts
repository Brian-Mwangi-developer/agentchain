/**
 * TokenVerifier — verifies an agent+jwt token against the registered identity.
 *
 * Verification steps (must all pass before a capability call proceeds):
 *
 * 1. Decode JWT header — confirm typ = "agent+jwt"
 * 2. Decode payload — extract iss (thumbprint), sub (agentId), aud (capability)
 * 3. Verify sub matches the registered agentId — no foreign agents
 * 4. Verify iss matches the registered public key thumbprint — no key swap
 * 5. Verify aud matches the requested capability — scope-bound token
 * 6. Import the registered public key and verify the Ed25519 signature
 * 7. Check exp / iat temporal claims + clock skew
 * 8. Check jti uniqueness (replay protection) via JtiCache
 * 9. Verify the agent holds an active grant for the capability
 *
 * Steps 3-4 together prevent a valid token issued for a different agent
 * (or different key) from being presented against this identity.
 */

import { verifyJwtSignature, decodeJwtUnsafe } from "../crypto/ed25519.js";
import { ChainAuthError } from "../errors/chain-error.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { JtiCache } from "../memory/jti-cache.js";
import type { AgentJwtClaims } from "./token-builder.js";

const CLOCK_SKEW_MS = 30_000;  // 30 seconds tolerance
const JWT_MAX_AGE_MS = 60_000; // 60 seconds — matches TOKEN_TTL_SECONDS

export type VerifiedCallContext = {
    agentId: string;
    agentName: string;
    hostname: string;
    capability: string;
    jti: string;
    iat: number;
    exp: number;
};

export class TokenVerifier {
    constructor(
        private readonly identity: AgentIdentity,
        private readonly jtiCache: JtiCache
    ) {}

    async verify(token: string, capability: string): Promise<VerifiedCallContext> {
        let unsafeClaims: AgentJwtClaims;
        try {
            const decoded = decodeJwtUnsafe<AgentJwtClaims>(token);
            unsafeClaims = decoded.payload;
        } catch (err) {
            throw new ChainAuthError(
                "token_invalid",
                `JWT decode failed: ${err instanceof Error ? err.message : String(err)}`
            );
        }

        if (unsafeClaims.sub !== this.identity.agentId) {
            throw new ChainAuthError(
                "agent_not_found",
                `JWT sub "${unsafeClaims.sub}" does not match registered agentId "${this.identity.agentId}"`
            );
        }

        if (unsafeClaims.iss !== this.identity.thumbprint) {
            throw new ChainAuthError(
                "token_invalid",
                "JWT iss does not match registered public key thumbprint — possible key substitution attack"
            );
        }

        if (unsafeClaims.aud !== capability) {
            throw new ChainAuthError(
                "capability_denied",
                `JWT aud "${unsafeClaims.aud}" does not match requested capability "${capability}"`
            );
        }

        const publicKey = await this.identity.getPublicKey();
        try {
            await verifyJwtSignature<AgentJwtClaims>(token, publicKey, { expectedTyp: "agent+jwt" });
        } catch (err) {
            throw new ChainAuthError(
                "token_invalid",
                `Signature verification failed: ${err instanceof Error ? err.message : String(err)}`
            );
        }

        this.assertTemporal(unsafeClaims);

        this.jtiCache.assert(this.identity.agentId, unsafeClaims.jti);

        if (!this.identity.hasCapability(capability)) {
            throw new ChainAuthError(
                "capability_denied",
                `Agent "${this.identity.agentId}" does not hold a grant for capability "${capability}"`
            );
        }

        return {
            agentId: this.identity.agentId,
            agentName: this.identity.registration.agentName,
            hostname: this.identity.registration.hostname,
            capability,
            jti: unsafeClaims.jti,
            iat: unsafeClaims.iat,
            exp: unsafeClaims.exp,
        };
    }

    private assertTemporal(claims: AgentJwtClaims): void {
        if (typeof claims.iat !== "number" || typeof claims.exp !== "number") {
            throw new ChainAuthError("token_invalid", "JWT missing iat or exp claims");
        }

        const nowMs = Date.now();
        const iatMs = claims.iat * 1000;
        const expMs = claims.exp * 1000;

        if (iatMs > nowMs + CLOCK_SKEW_MS) {
            throw new ChainAuthError("token_invalid", "JWT iat is in the future — clock skew too large or token pre-generated");
        }

        if (expMs < nowMs - CLOCK_SKEW_MS) {
            throw new ChainAuthError("token_expired", "JWT has expired");
        }

        if (expMs - iatMs > JWT_MAX_AGE_MS + CLOCK_SKEW_MS) {
            throw new ChainAuthError(
                "token_invalid",
                `JWT lifetime of ${Math.round((expMs - iatMs) / 1000)}s exceeds maximum of ${JWT_MAX_AGE_MS / 1000}s`
            );
        }
    }
}
