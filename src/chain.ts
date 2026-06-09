/**
 * AgentsChain — the main entry point for wrapping AI SDK clients.
 *
 * Creates a Host identity first, then an Agent identity that is cryptographically
 * linked to that Host. Every token signed by the agent carries the host's
 * thumbprint, enabling verifiers to confirm the delegation chain:
 *   HostIdentity (Ed25519) → signs AgentIdentity registration → Agent tokens
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
 *   const stats = chain.getStats();     // Summary counts + auth overhead
 *   await chain.drain(exporter);        // Flush audit log to exporter
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
    readonly host: HostIdentity;
    private readonly defaultExporter?: AuditExporter;

    private constructor(
        store: EncryptedStore,
        host: HostIdentity,
        identity: AgentIdentity,
        builder: TokenBuilder,
        verifier: TokenVerifier,
        log: AuditLog,
        defaultExporter?: AuditExporter
    ) {
        this.store = store;
        this.host = host;
        this.identity = identity;
        this.builder = builder;
        this.verifier = verifier;
        this.log = log;
        this.defaultExporter = defaultExporter;
    }

    /**
     * Create an AgentsChain instance.
     *
     * Internally this:
     * 1. Creates a shared EncryptedStore
     * 2. Creates a HostIdentity (Ed25519 keypair)
     * 3. Creates an AgentIdentity linked to that Host
     * 4. Wires up TokenBuilder, TokenVerifier, JtiCache, AuditLog
     *
     * The agent's JWT tokens carry the host's thumbprint, enabling any verifier
     * to confirm the Host → Agent delegation chain without an external call.
     */
    static async create(config: AgentConfig): Promise<AgentsChain> {
        const store = EncryptedStore.create(config.encryptionKey);
        const jtiCache = new JtiCache(config.jtiAdapter);

        // Create the Host first — the agent registration must reference it
        const host = await HostIdentity.create(
            {
                name: config.agentName,
                issuerUrl: config.hostname,
            },
            store
        );

        // Create agent identity linked to this host
        const identity = await AgentIdentity.create(
            {
                ...config,
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );

        const builder = new TokenBuilder(identity);
        const verifier = new TokenVerifier(identity, jtiCache);
        const log = new AuditLog(store);

        return new AgentsChain(store, host, identity, builder, verifier, log, config.auditExporter);
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

    // ─── Accessors ────────────────────────────────────────────────────────────

    get agentId(): string {
        return this.identity.agentId;
    }

    get hostId(): string {
        return this.host.hostId;
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
        const successEntries = entries.filter((e) => e.result === "success");
        const totalAuthMs = entries.reduce((sum, e) => sum + e.authOverheadMs, 0);
        const avgAuthMs = entries.length > 0 ? Math.round(totalAuthMs / entries.length) : 0;
        const maxAuthMs = entries.length > 0 ? Math.max(...entries.map((e) => e.authOverheadMs)) : 0;

        return {
            agentId: this.identity.agentId,
            hostId: this.host.hostId,
            agentName: this.identity.registration.agentName,
            hostname: this.identity.registration.hostname,
            totalCalls: entries.length,
            successfulCalls: successEntries.length,
            deniedCalls: entries.filter((e) => e.result === "denied").length,
            errorCalls: entries.filter((e) => e.result === "error").length,
            registeredAt: this.identity.registration.registeredAt,
            authOverhead: { avgMs: avgAuthMs, maxMs: maxAuthMs },
        };
    }

    /**
     * Export all audit entries via the configured exporter, then clear the log.
     * If no exporter is provided and none was configured at create time, the log
     * is simply cleared.
     *
     * Call this on SIGTERM/SIGINT or periodically to prevent the audit log from
     * growing unboundedly (it is capped at 10,000 entries internally, but drain
     * ensures no entries are lost before the cap is hit in high-throughput use).
     */
    async drain(exporter?: AuditExporter): Promise<void> {
        return this.log.drain(exporter ?? this.defaultExporter);
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
        // Single shared EncryptedStore for all chain state (host, agent, audit log)
        const store = EncryptedStore.create(config.encryptionKey);
        const jtiCache = new JtiCache(config.jtiAdapter);

        // Create Host identity FIRST — agent registration references it.
        // Uses the shared store (not its own isolated store as it did before).
        const host = await HostIdentity.create(
            {
                name: config.host?.name ?? config.providerName,
                issuerUrl: config.host?.issuerUrl ?? config.issuer,
            },
            store
        );

        // Create the app's own agent identity, linked to the Host above.
        // hostThumbprint + hostPublicKeyJwk are embedded in every token this
        // agent signs, closing the rogue-agent gap.
        const identity = await AgentIdentity.create(
            {
                agentName: config.providerName,
                hostname: config.providerName,
                capabilities: config.capabilities.map((c) => c.name),
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
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
     *
     * @param endpointPrefix Optional path prefix for all endpoint URLs
     * @param opts           Optional description and jwks_uri for the discovery doc
     */
    getWellKnownConfig(
        endpointPrefix?: string,
        opts?: { description?: string; jwks_uri?: string }
    ): AgentConfiguration {
        return this.registry.buildWellKnownConfig(
            this.host.getRegistration().issuerUrl,
            this.host.getRegistration().name,
            endpointPrefix,
            opts
        );
    }

    getAuditLog(): AuditEntry[] {
        return this.log.getAll();
    }

    getStats(): ChainStats {
        const entries = this.log.getAll();
        const totalAuthMs = entries.reduce((sum, e) => sum + e.authOverheadMs, 0);
        const avgAuthMs = entries.length > 0 ? Math.round(totalAuthMs / entries.length) : 0;
        const maxAuthMs = entries.length > 0 ? Math.max(...entries.map((e) => e.authOverheadMs)) : 0;

        return {
            agentId: this.identity.agentId,
            hostId: this.host.hostId,
            agentName: this.identity.registration.agentName,
            hostname: this.identity.registration.hostname,
            totalCalls: entries.length,
            successfulCalls: entries.filter((e) => e.result === "success").length,
            deniedCalls: entries.filter((e) => e.result === "denied").length,
            errorCalls: entries.filter((e) => e.result === "error").length,
            registeredAt: this.identity.registration.registeredAt,
            authOverhead: { avgMs: avgAuthMs, maxMs: maxAuthMs },
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
