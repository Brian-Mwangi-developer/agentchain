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
import { HostIdentity } from "./host/host-identity.js";
import { CapabilityRegistry } from "./app/capability-registry.js";
import { wrapApp, attachRegistry } from "./app/app-wrapper.js";
import type { AgentConfig, ChainStats, AuditSnapshot, AppChainConfig } from "./types/chain.js";
import type { AuditEntry } from "./types/audit.js";
import type { AuditExporter } from "./audit/audit-exporter.js";
import type { ResolvedGrant, AgentConfiguration } from "./types/protocol.js";
import type { AppInterceptContext } from "./app/app-wrapper.js";

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

// ─── AppChain ─────────────────────────────────────────────────────────────────

/**
 * AppChain — wraps any app object with capability-gated security.
 *
 * Unlike AgentsChain (which wraps AI SDKs), AppChain wraps your own service
 * objects or any external app, enforcing agent identity, permission grants,
 * constraint validation, and an audit trail on every capability call.
 *
 * Usage:
 *   const chain = await AppChain.create({
 *     providerName: "billing-service",
 *     issuer: "https://billing.mycompany.com",
 *     capabilities: [invoiceCapability, refundCapability],
 *   });
 *
 *   // Wrap your service — every call is identity-bound and audited
 *   const secured = chain.wrap(billingService, agentGrants);
 *   const invoice = await secured.createInvoice({ customerId: "c1", amount: 500 });
 *
 *   // Serve well-known for agent discovery
 *   app.get("/.well-known/agent-configuration", (req, res) => res.json(chain.getWellKnownConfig()));
 *
 *   // Flush audit on shutdown
 *   process.on("SIGTERM", () => chain.drain());
 */
export class AppChain {
    readonly host: HostIdentity;

    private readonly registry: CapabilityRegistry;
    private readonly identity: AgentIdentity;
    private readonly builder: TokenBuilder;
    private readonly verifier: TokenVerifier;
    private readonly log: AuditLog;
    private readonly exporter?: AuditExporter;

    private constructor(
        host: HostIdentity,
        registry: CapabilityRegistry,
        identity: AgentIdentity,
        builder: TokenBuilder,
        verifier: TokenVerifier,
        log: AuditLog,
        exporter?: AuditExporter
    ) {
        this.host = host;
        this.registry = registry;
        this.identity = identity;
        this.builder = builder;
        this.verifier = verifier;
        this.log = log;
        this.exporter = exporter;
    }

    static async create(config: AppChainConfig): Promise<AppChain> {
        const store = EncryptedStore.create(config.encryptionKey);
        const jtiCache = new JtiCache(config.jtiAdapter);

        // Create a synthetic agent identity for this app chain instance
        const identity = await AgentIdentity.create(
            {
                agentName: config.providerName,
                hostname: config.providerName,
                capabilities: config.capabilities.map((c) => c.name),
                encryptionKey: config.encryptionKey,
            },
            store
        );

        const builder = new TokenBuilder(identity);
        const verifier = new TokenVerifier(identity, jtiCache, {
            grantResolver: config.grantResolver,
        });
        const log = new AuditLog(store);

        // Build capability registry
        const registry = new CapabilityRegistry();
        for (const cap of config.capabilities) {
            registry.register(cap);
        }

        // Create Host identity for signing agent registration JWTs
        const host = await HostIdentity.create({
            name: config.host?.name ?? config.providerName,
            issuerUrl: config.host?.issuerUrl ?? config.issuer,
            encryptionKey: config.encryptionKey,
        });

        return new AppChain(host, registry, identity, builder, verifier, log, config.auditExporter);
    }

    /**
     * Wrap any object with capability-gated security.
     *
     * @param target  The service object to wrap
     * @param grants  The resolved grants for the agent making calls
     * @returns       A Proxy with the same type as target
     */
    wrap<T extends object>(target: T, grants: ResolvedGrant[]): T {
        const ctx: AppInterceptContext = {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
            grants,
        };
        attachRegistry(ctx, this.registry);
        return wrapApp(target, this.registry, ctx);
    }

    /**
     * Get the well-known configuration object.
     * Serve this at GET /.well-known/agent-configuration.
     */
    getWellKnownConfig(endpointPrefix?: string): AgentConfiguration {
        return this.registry.buildWellKnownConfig(
            this.host.getRegistration().issuerUrl,
            this.host.getRegistration().name,
            endpointPrefix
        );
    }

    getAuditLog(): AuditEntry[] {
        return this.log.getAll();
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

    /**
     * Export all audit entries via the configured exporter, then clear the log.
     * If no exporter configured, the log is just cleared.
     */
    async drain(exporter?: AuditExporter): Promise<void> {
        return this.log.drain(exporter ?? this.exporter);
    }
}
