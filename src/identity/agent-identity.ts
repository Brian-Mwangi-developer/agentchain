/** Ed25519 keypair and registration record for one agent, linked to its Host. */

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

    /** hostThumbprint + hostPublicKeyJwk required — they anchor the Host → Agent chain. */
    static async create(config: AgentConfig, store: EncryptedStore): Promise<AgentIdentity> {
        if (!config.hostThumbprint || !config.hostPublicKeyJwk) {
            throw new Error(
                "AgentIdentity.create: hostThumbprint and hostPublicKeyJwk are required. " +
                "Every agent must be cryptographically linked to a Host. " +
                "Use AgentsChain.create() or AppChain.create() which supply these automatically."
            );
        }

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
            hostThumbprint: config.hostThumbprint,
            hostPublicKeyJwk: config.hostPublicKeyJwk,
        };

        store.set(STORE_KEY_IDENTITY, registration);
        return new AgentIdentity(privateKey, registration);
    }

    static async restore(privateKey: CryptoKey, store: EncryptedStore): Promise<AgentIdentity> {
        const registration = store.get<RegisteredAgent>(STORE_KEY_IDENTITY);
        if (!registration) throw new Error("AgentIdentity.restore: no identity found in store");
        if (!registration.hostThumbprint || !registration.hostPublicKeyJwk) {
            throw new Error(
                "AgentIdentity.restore: missing host credentials. " +
                "Re-create via AgentsChain.create() to generate a protocol-compliant registration."
            );
        }
        return new AgentIdentity(privateKey, registration);
    }

    get agentId(): string {
        return this.registration.agentId;
    }

    get thumbprint(): string {
        return this.registration.thumbprint;
    }

    get hostThumbprint(): string {
        return this.registration.hostThumbprint;
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

    async getHostPublicKey(): Promise<CryptoKey> {
        return importPublicKeyJwk(this.registration.hostPublicKeyJwk);
    }
}
