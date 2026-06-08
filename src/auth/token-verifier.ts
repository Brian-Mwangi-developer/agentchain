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

import { decodeJwtUnsafe, verifyJwtSignature } from "../crypto/ed25519.js";
import { ChainAuthError } from "../errors/chain-error.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { JtiCache } from "../memory/jti-cache.js";
import type { ResolvedGrant } from "../types/protocol.js";
import type { AgentJwtClaims } from "./token-builder.js";

const CLOCK_SKEW_MS = 30_000;  // 30 seconds tolerance
const JWT_MAX_AGE_MS = 60_000; // 60 seconds — matches TOKEN_TTL_SECONDS

export type VerifiedCallContext = {
    agentId: string;
    agentName: string;
    hostname: string;
    hostId?: string;
    capability: string;
    jti: string;
    iat: number;
    exp: number;
};

/**
 * Optional config for TokenVerifier.
 *
 * grantResolver: If provided, resolve grants from an external source (user's DB/Redis).
 *   If it returns null for a capability, the call is denied.
 *   If not provided, the verifier falls back to the in-memory registered grants.
 */
export type VerifierConfig = {
    jwtMaxAge?: number;   // ms — default 60_000
    clockSkew?: number;   // ms — default 30_000
    grantResolver?: (agentId: string, capability: string) => Promise<ResolvedGrant | null>;
};
//NOTE:ResolvedGrant We can also have Resolved Grants

export class TokenVerifier {
    private readonly jwtMaxAge: number;
    private readonly clockSkew: number;
    private readonly grantResolver?: (agentId: string, capability: string) => Promise<ResolvedGrant | null>;

    constructor(
        private readonly identity: AgentIdentity,
        private readonly jtiCache: JtiCache,
        config?: VerifierConfig
    ) {
        this.jwtMaxAge = config?.jwtMaxAge ?? JWT_MAX_AGE_MS;
        this.clockSkew = config?.clockSkew ?? CLOCK_SKEW_MS;
        this.grantResolver = config?.grantResolver;
    }

    /**
     * Verify a token for a capability call.
     *
     * @param token       The agent+jwt token
     * @param capability  The capability being requested
     * @param grants      Optional pre-resolved grants (passed by app-wrapper at wrap time)
     */
    async verify(
        token: string,
        capability: string,
        grants?: ResolvedGrant[]
    ): Promise<VerifiedCallContext> {
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

        await this.jtiCache.assert(this.identity.agentId, unsafeClaims.jti);

        // ── Step 9: Resolve capability grant ─────────────────────────────────
        // Priority: external grantResolver > passed grants array > in-memory identity
        let resolvedGrant: ResolvedGrant | null = null;

        if (this.grantResolver) {
            resolvedGrant = await this.grantResolver(this.identity.agentId, capability);
        } else if (grants) {
            const found = grants.find((g) => g.capability === capability);
            resolvedGrant = found ?? null;
        } else {
            // Fall back to in-memory registered grants (AgentsChain default behaviour)
            resolvedGrant = this.identity.hasCapability(capability)
                ? { capability, status: "active" as const }
                : null;
        }

        if (!resolvedGrant || resolvedGrant.status !== "active") {
            const reason = resolvedGrant?.status === "pending"
                ? `capability "${capability}" is pending approval`
                : resolvedGrant?.status === "denied"
                ? `capability "${capability}" has been denied`
                : `agent "${this.identity.agentId}" does not hold a grant for capability "${capability}"`;

            throw new ChainAuthError("capability_denied", reason);
        }

        // Check grant expiry
        if (resolvedGrant.expiresAt !== undefined && resolvedGrant.expiresAt < Date.now()) {
            throw new ChainAuthError("capability_denied", `Grant for "${capability}" has expired`);
        }

        // ── Step 9b: Enforce constraints ─────────────────────────────────────
        // Constraints are enforced here so they apply to ALL callers (app-wrapper and AI wrappers)
        // App-wrapper also enforces before execute() — this is the canonical enforcement point.

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

        if (iatMs > nowMs + this.clockSkew) {
            throw new ChainAuthError("token_invalid", "JWT iat is in the future — clock skew too large or token pre-generated");
        }

        if (expMs < nowMs - this.clockSkew) {
            throw new ChainAuthError("token_expired", "JWT has expired");
        }

        if (expMs - iatMs > this.jwtMaxAge + this.clockSkew) {
            throw new ChainAuthError(
                "token_invalid",
                `JWT lifetime of ${Math.round((expMs - iatMs) / 1000)}s exceeds maximum of ${this.jwtMaxAge / 1000}s`
            );
        }
    }
}
