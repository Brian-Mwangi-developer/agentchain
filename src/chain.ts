/**
 * AgentsChain — the main entry point for the agents-chain package.
 *
 * Usage:
 *
 *   const chain = await AgentsChain.create({
 *     agentName: "summarizer",
 *     hostname: "my-app",        // → agentId: "my-app-agent-<32hex>"
 *     capabilities: ["chat.completion", "embedding"],
 *   });
 *
 *   const ai = chain.openai(new OpenAI({ apiKey }));
 *   const result = await ai.chat.completions.create({ model: "gpt-4o", ... });
 *
 *   const log = chain.getAuditLog();    // All calls, decrypted
 *   const stats = chain.getStats();     // Summary counts
 */

import { EncryptedStore } from "./memory/encrypted-store.js";
import { JtiCache } from "./memory/jti-cache.js";
import { AgentIdentity } from "./identity/agent-identity.js";
import { TokenBuilder } from "./auth/token-builder.js";
import { TokenVerifier } from "./auth/token-verifier.js";
import { AuditLog } from "./audit/audit-log.js";
import { wrapOpenAI } from "./wrappers/openai-wrapper.js";
import { wrapAnthropic } from "./wrappers/anthropic-wrapper.js";
import type { AgentConfig, ChainStats, AuditSnapshot } from "./types/chain.js";
import type { AuditEntry } from "./types/audit.js";

export class AgentsChain {
    private readonly store: EncryptedStore;
    private readonly identity: AgentIdentity;
    private readonly builder: TokenBuilder;
    private readonly verifier: TokenVerifier;
    private readonly log: AuditLog;

    private constructor(
        store: EncryptedStore,
        identity: AgentIdentity,
        builder: TokenBuilder,
        verifier: TokenVerifier,
        log: AuditLog
    ) {
        this.store = store;
        this.identity = identity;
        this.builder = builder;
        this.verifier = verifier;
        this.log = log;
    }

    static async create(config: AgentConfig): Promise<AgentsChain> {
        const store = EncryptedStore.create(config.encryptionKey);
        const jtiCache = new JtiCache();
        const identity = await AgentIdentity.create(config, store);
        const builder = new TokenBuilder(identity);
        const verifier = new TokenVerifier(identity, jtiCache);
        const log = new AuditLog(store);

        return new AgentsChain(store, identity, builder, verifier, log);
    }

    // ─── SDK Wrappers ─────────────────────────────────────────────────────────

    openai<T extends object>(client: T): T {
        return wrapOpenAI(client, {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
        });
    }

    anthropic<T extends object>(client: T): T {
        return wrapAnthropic(client, {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
        });
    }

    get agentId(): string {
        return this.identity.agentId;
    }
    get capabilities(): string[] {
        return this.identity.capabilityNames;
    }
    getAuditLog(): AuditEntry[] {
        return this.log.getAll();
    }
    exportAudit(): AuditSnapshot {
        return {
            agentId: this.identity.agentId,
            entries: this.log.getAll(),
            exportedAt: Date.now(),
        };
    }
    getStats(): ChainStats {
        const entries = this.log.getAll();
        return {
            agentId: this.identity.agentId,
            agentName: this.identity.registration.agentName,
            hostname: this.identity.registration.hostname,
            totalCalls: entries.length,
            successfulCalls: entries.filter((e) => e.result === "success").length,
            deniedCalls: entries.filter((e) => e.result === "denied").length,
            errorCalls: entries.filter((e) => e.result === "error").length,
            registeredAt: this.identity.registration.registeredAt,
        };
    }
}
