/**
 * AgentIdentity — holds the Ed25519 keypair and registration record for one agent.
 *
 * The private key is held exclusively in memory as a non-exportable CryptoKey
 * after the initial setup. The public key is stored (encrypted) in the
 * EncryptedStore as a JWK for verification during token checks.
 *
 * Agent ID format: <hostname>-agent-<32 hex chars>
 * Example: myapp-agent-a3f9bc1d2e4f6789abcdef0123456789
 */

import {
    generateKeyPair,
    exportPublicKeyJwk,
    computeJwkThumbprint,
    importPublicKeyJwk,
} from "../crypto/ed25519.js";
import { generateAgentId } from "../crypto/utils.js";
import type { AgentConfig, CapabilityGrant, RegisteredAgent } from "../types/identity.js";
import type { EncryptedStore } from "../memory/encrypted-store.js";

const STORE_KEY_IDENTITY = "agent:identity";

export class AgentIdentity {
    readonly privateKey: CryptoKey;
    readonly registration: RegisteredAgent;

    private constructor(privateKey: CryptoKey, registration: RegisteredAgent) {
        this.privateKey = privateKey;
        this.registration = registration;
    }

    /**
     * Create a new agent identity:
     * 1. Generate an Ed25519 keypair
     * 2. Derive the agentId from hostname
     * 3. Compute the public key thumbprint (used as the JWT `iss`)
     * 4. Store the registration (encrypted) in the provided store
     */
    static async create(config: AgentConfig, store: EncryptedStore): Promise<AgentIdentity> {
        const { publicKey, privateKey } = await generateKeyPair();
        const publicKeyJwk = await exportPublicKeyJwk(publicKey);
        const thumbprint = computeJwkThumbprint(publicKeyJwk);
        const agentId = generateAgentId(config.hostname);

        const grants: CapabilityGrant[] = config.capabilities.map((cap) => ({
            capability: cap,
            grantedAt: Date.now(),
        }));

        const registration: RegisteredAgent = {
            agentId,
            agentName: config.agentName,
            hostname: config.hostname,
            publicKeyJwk,
            thumbprint,
            capabilities: grants,
            registeredAt: Date.now(),
        };

        store.set(STORE_KEY_IDENTITY, registration);

        return new AgentIdentity(privateKey, registration);
    }

    static async restore(privateKey: CryptoKey, store: EncryptedStore): Promise<AgentIdentity> {
        const registration = store.get<RegisteredAgent>(STORE_KEY_IDENTITY);
        if (!registration) {
            throw new Error("AgentIdentity.restore: no identity found in store");
        }
        return new AgentIdentity(privateKey, registration);
    }

   
    get agentId(): string {
        return this.registration.agentId;
    }

    get thumbprint(): string {
        return this.registration.thumbprint;
    }

   
    get capabilityNames(): string[] {
        return this.registration.capabilities.map((g) => g.capability);
    }
  
    hasCapability(name: string): boolean {
        return this.registration.capabilities.some((g) => g.capability === name);
    }

    getGrant(name: string): CapabilityGrant | undefined {
        return this.registration.capabilities.find((g) => g.capability === name);
    }

    async getPublicKey(): Promise<CryptoKey> {
        return importPublicKeyJwk(this.registration.publicKeyJwk);
    }
}
