/** Ed25519 keypair and stable thumbprint for the Host. Signs host+jwt management tokens. */

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
import type { EncryptedStore } from "../memory/encrypted-store.js";
import type { HostJwtClaims } from "../types/protocol.js";

const TOKEN_TTL_SECONDS = 60;
const STORE_KEY = "host:identity";

export type HostConfig = {
    name: string;
    issuerUrl: string;  // The agent-auth server this Host authenticates against
};

export type HostRegistration = {
    hostId: string;       // JWK thumbprint (= thumbprint for convenience)
    name: string;
    issuerUrl: string;
    publicKeyJwk: JsonWebKey;
    thumbprint: string;
    createdAt: number;    // Unix ms
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

    static async create(config: HostConfig, store: EncryptedStore): Promise<HostIdentity> {
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

    /** Restore from persisted JWKs for stable identity across process restarts. */
    static async fromKeyPair(
        privateKeyJwk: JsonWebKey,
        publicKeyJwk: JsonWebKey,
        config: HostConfig,
        store: EncryptedStore
    ): Promise<HostIdentity> {
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

    /** Export private key as JWK for optional persistence. Secure this value yourself. */
    async exportPrivateKeyJwk(): Promise<JsonWebKey> {
        return exportPrivateKeyJwk(this.privateKey);
    }

    async signHostJwt(extra?: Partial<HostJwtClaims>): Promise<string> {
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

    /** Sign a host+jwt embedding the agent's public key for POST /agent/register. */
    async signAgentRegistrationJwt(agentPublicKeyJwk: JsonWebKey): Promise<string> {
        return this.signHostJwt({ agent_public_key: agentPublicKeyJwk });
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
