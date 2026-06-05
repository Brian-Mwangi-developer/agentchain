/**
 * HostIdentity — the user's identity anchor for one app.
 *
 * A Host holds an Ed25519 keypair. Its JWK thumbprint is the stable Host ID.
 * It signs host+jwt tokens for management operations (registering agents,
 * revoking, rotating keys) against an agent-auth compliant server.
 *
 * Security properties:
 * - Private key is non-extractable by default (stays in process memory)
 * - Thumbprint (Host ID) is derived from the public key — cryptographically stable
 * - On process restart, a new keypair is generated → new Host ID (key rotation)
 * - If the user needs a stable identity across restarts, they persist and reload
 *   the private key via HostIdentity.fromPrivateKeyJwk()
 */

import { randomBytes } from "node:crypto";
import {
    generateKeyPair,
    exportPublicKeyJwk,
    exportPrivateKeyJwk,
    importPrivateKeyJwk,
    computeJwkThumbprint,
    signJwt,
} from "../crypto/ed25519.js";
import { base64UrlEncode } from "../crypto/utils.js";
import { EncryptedStore } from "../memory/encrypted-store.js";
import type { HostJwtClaims } from "../types/protocol.js";

const TOKEN_TTL_SECONDS = 60;
const STORE_KEY = "host:identity";

export type HostConfig = {
    name: string;
    issuerUrl: string;       // The agent-auth server this Host authenticates against
    encryptionKey?: string;  // Optional AES-256-GCM key for EncryptedStore
};

export type HostRegistration = {
    hostId: string;          // JWK thumbprint
    name: string;
    issuerUrl: string;
    publicKeyJwk: JsonWebKey;
    thumbprint: string;
    createdAt: number;       // Unix ms
};

export class HostIdentity {
    /** The stable Host ID — the SHA-256 JWK thumbprint of the public key. */
    readonly hostId: string;

    private constructor(
        private readonly privateKey: CryptoKey,
        private readonly registration: HostRegistration,
        private readonly store: EncryptedStore
    ) {
        this.hostId = registration.hostId;
    }

    /**
     * Create a new HostIdentity with a freshly generated Ed25519 keypair.
     * Each call produces a different keypair (and therefore a different hostId).
     */
    static async create(config: HostConfig): Promise<HostIdentity> {
        const store = EncryptedStore.create(config.encryptionKey);
        const { publicKey, privateKey } = await generateKeyPair();
        const publicKeyJwk = await exportPublicKeyJwk(publicKey);
        const thumbprint = computeJwkThumbprint(publicKeyJwk);

        const registration: HostRegistration = {
            hostId: thumbprint,
            name: config.name,
            issuerUrl: config.issuerUrl,
            publicKeyJwk,
            thumbprint,
            createdAt: Date.now(),
        };

        store.set(STORE_KEY, registration);
        return new HostIdentity(privateKey, registration, store);
    }

    /**
     * Restore a HostIdentity from both private and public key JWKs.
     * Use this for stable identity across restarts.
     */
    static async fromKeyPair(
        privateKeyJwk: JsonWebKey,
        publicKeyJwk: JsonWebKey,
        config: HostConfig
    ): Promise<HostIdentity> {
        const store = EncryptedStore.create(config.encryptionKey);
        const privateKey = await importPrivateKeyJwk(privateKeyJwk);
        const thumbprint = computeJwkThumbprint(publicKeyJwk);

        const registration: HostRegistration = {
            hostId: thumbprint,
            name: config.name,
            issuerUrl: config.issuerUrl,
            publicKeyJwk,
            thumbprint,
            createdAt: Date.now(),
        };

        store.set(STORE_KEY, registration);
        return new HostIdentity(privateKey, registration, store);
    }

    /**
     * Export the private key as JWK so the caller can persist it.
     * The caller is responsible for securing this value.
     */
    async exportPrivateKeyJwk(): Promise<JsonWebKey> {
        return exportPrivateKeyJwk(this.privateKey);
    }

    /**
     * Sign a 60-second host+jwt for management operations.
     *
     * @param extra  Optional additional claims to include (e.g. agent_public_key for registration)
     */
    async signJwt(extra?: Partial<HostJwtClaims>): Promise<string> {
        const nowSeconds = Math.floor(Date.now() / 1000);
        const jti = base64UrlEncode(randomBytes(16));

        const claims: HostJwtClaims = {
            iss: this.registration.thumbprint,
            aud: this.registration.issuerUrl,
            iat: nowSeconds,
            exp: nowSeconds + TOKEN_TTL_SECONDS,
            jti,
            ...extra,
        };

        return signJwt(claims, this.privateKey, "host+jwt");
    }

    /**
     * Sign a host+jwt that embeds the agent's public key.
     * Used when calling POST /agent/register on an agent-auth server.
     */
    async signAgentRegistrationJwt(agentPublicKeyJwk: JsonWebKey): Promise<string> {
        return this.signJwt({ agent_public_key: agentPublicKeyJwk });
    }

    getPublicKeyJwk(): JsonWebKey {
        return this.registration.publicKeyJwk;
    }

    getRegistration(): HostRegistration {
        return this.registration;
    }

    get thumbprint(): string {
        return this.registration.thumbprint;
    }
}
