/** AgentsChain — wraps OpenAI/Anthropic SDK clients with auth, identity, and audit. */

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
import { AccessRequestManager } from "./access/access-request-manager.js";
import { ApprovalStore } from "./access/approval-store.js";
import type { AgentConfig, ChainStats, AuditSnapshot, AppChainConfig } from "./types/chain.js";
import type { AuditEntry } from "./types/audit.js";
import type { AuditExporter } from "./audit/audit-exporter.js";
import type { ResolvedGrant, AgentConfiguration } from "./types/protocol.js";
import type { AppInterceptContext } from "./app/app-wrapper.js";
import type { ApprovalDecision, DenialDecision, AccessRequest, ApprovalRule } from "./types/access-request.js";

export class AgentsChain {
    private readonly store: EncryptedStore;
    private readonly identity: AgentIdentity;
    private readonly builder: TokenBuilder;
    private readonly verifier: TokenVerifier;
    private readonly log: AuditLog;
    private readonly jtiCache: JtiCache;
    readonly host: HostIdentity;
    private readonly defaultExporter?: AuditExporter;

    private constructor(
        store: EncryptedStore,
        host: HostIdentity,
        identity: AgentIdentity,
        builder: TokenBuilder,
        verifier: TokenVerifier,
        log: AuditLog,
        jtiCache: JtiCache,
        defaultExporter?: AuditExporter
    ) {
        this.store = store;
        this.host = host;
        this.identity = identity;
        this.builder = builder;
        this.verifier = verifier;
        this.log = log;
        this.jtiCache = jtiCache;
        this.defaultExporter = defaultExporter;
    }

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

        return new AgentsChain(store, host, identity, builder, verifier, log, jtiCache, config.auditExporter);
    }

    destroy(): void {
        this.jtiCache.destroy();
    }

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

    async drain(exporter?: AuditExporter): Promise<void> {
        return this.log.drain(exporter ?? this.defaultExporter);
    }
}

// ─── AppChain ─────────────────────────────────────────────────────────────────

/** AppChain — wraps any service object with capability-gated auth, constraints, and audit. */
export class AppChain {
    readonly host: HostIdentity;

    private readonly registry: CapabilityRegistry;
    private readonly identity: AgentIdentity;
    private readonly builder: TokenBuilder;
    private readonly verifier: TokenVerifier;
    private readonly log: AuditLog;
    private readonly jtiCache: JtiCache;
    private readonly exporter?: AuditExporter;
    private readonly accessRequestManager?: AccessRequestManager;
    private readonly approvalStore?: ApprovalStore;

    private constructor(
        host: HostIdentity,
        registry: CapabilityRegistry,
        identity: AgentIdentity,
        builder: TokenBuilder,
        verifier: TokenVerifier,
        log: AuditLog,
        jtiCache: JtiCache,
        exporter?: AuditExporter,
        accessRequestManager?: AccessRequestManager,
        approvalStore?: ApprovalStore
    ) {
        this.host = host;
        this.registry = registry;
        this.identity = identity;
        this.builder = builder;
        this.verifier = verifier;
        this.log = log;
        this.jtiCache = jtiCache;
        this.exporter = exporter;
        this.accessRequestManager = accessRequestManager;
        this.approvalStore = approvalStore;
    }

    static async create(config: AppChainConfig): Promise<AppChain> {
        const issuerUrl = config.host?.issuerUrl ?? config.issuer;
        if (!issuerUrl) {
            throw new Error("AppChain.create: either `issuer` or `host.issuerUrl` must be provided");
        }
        if (config.issuer && config.host?.issuerUrl && config.issuer !== config.host.issuerUrl) {
            throw new Error(
                `AppChain.create: \`issuer\` ("${config.issuer}") and \`host.issuerUrl\` ("${config.host.issuerUrl}") ` +
                `are both set but differ. Use one or the other, not both.`
            );
        }

        // Single shared EncryptedStore for all chain state (host, agent, audit log)
        const store = EncryptedStore.create(config.encryptionKey);
        const jtiCache = new JtiCache(config.jtiAdapter);

        const hostConfig = {
            name: config.host?.name ?? config.providerName,
            issuerUrl,
        };

        // Restore or create Host identity
        const host = (config.host?.privateKeyJwk && config.host?.publicKeyJwk)
            ? await HostIdentity.fromKeyPair(
                  config.host.privateKeyJwk,
                  config.host.publicKeyJwk,
                  hostConfig,
                  store
              )
            : await HostIdentity.create(hostConfig, store);

        // Restore or create Agent identity, linked to the Host above.
        let identity: AgentIdentity;
        if (config.agent?.privateKeyJwk && config.agent?.publicKeyJwk) {
            if (!config.agent.agentId) {
                throw new Error("AppChain.create: `agent.agentId` is required when restoring from JWKs");
            }
            // Restoring persisted agent — rebuild registration from config + host
            const registration: import("./types/identity.js").RegisteredAgent = {
                agentId: config.agent.agentId,
                agentName: config.providerName,
                hostname: config.providerName,
                publicKeyJwk: config.agent.publicKeyJwk,
                thumbprint: "", // will be overwritten
                capabilities: config.capabilities.map((c) => ({
                    capability: c.name,
                    grantedAt: Date.now(),
                })),
                registeredAt: Date.now(),
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            };
            identity = await AgentIdentity.fromKeyPair(
                config.agent.privateKeyJwk,
                config.agent.publicKeyJwk,
                registration,
                store
            );
        } else {
            identity = await AgentIdentity.create(
                {
                    agentName: config.providerName,
                    hostname: config.providerName,
                    capabilities: config.capabilities.map((c) => c.name),
                    hostThumbprint: host.thumbprint,
                    hostPublicKeyJwk: host.getPublicKeyJwk(),
                },
                store
            );
        }

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

        // Access request system (optional)
        let accessRequestManager: AccessRequestManager | undefined;
        let approvalStoreInstance: ApprovalStore | undefined;
        if (config.accessRequests) {
            accessRequestManager = new AccessRequestManager(config.accessRequests);
            // The approval secret must match between manager and store for integrity checks.
            approvalStoreInstance = new ApprovalStore(store, accessRequestManager.approvalSecret);
        }

        return new AppChain(
            host, registry, identity, builder, verifier, log, jtiCache,
            config.auditExporter, accessRequestManager, approvalStoreInstance
        );
    }

    destroy(): void {
        this.jtiCache.destroy();
        this.accessRequestManager?.destroy();
    }

    wrap<T extends object>(target: T, grants: ResolvedGrant[]): T {
        const ctx: AppInterceptContext = {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
            grants,
            accessRequestManager: this.accessRequestManager,
            approvalStore: this.approvalStore,
        };
        attachRegistry(ctx, this.registry);
        return wrapApp(target, this.registry, ctx);
    }

    // ─── Access Request API ──────────────────────────────────────────────────

    /**
     * Approve a pending access request. Called by the server when a human
     * submits their verification code (via webhook, API endpoint, UI, etc.).
     *
     * The verification code was sent out-of-band to the human — the agent
     * cannot forge it because it doesn't have the HMAC secret.
     */
    approve(decision: ApprovalDecision): AccessRequest {
        if (!this.accessRequestManager) {
            throw new Error("Access requests are not enabled on this AppChain");
        }
        return this.accessRequestManager.approve(decision);
    }

    /**
     * Deny a pending access request.
     */
    deny(decision: DenialDecision): AccessRequest {
        if (!this.accessRequestManager) {
            throw new Error("Access requests are not enabled on this AppChain");
        }
        return this.accessRequestManager.deny(decision);
    }

    /**
     * Get all pending access requests (for building a dashboard/UI).
     */
    getPendingRequests(): AccessRequest[] {
        return this.accessRequestManager?.getAllPending() ?? [];
    }

    /**
     * Get all active approval rules.
     */
    getApprovalRules(): ApprovalRule[] {
        return this.approvalStore?.getAll() ?? [];
    }

    /**
     * Revoke a specific approval rule.
     */
    revokeApproval(ruleId: string): boolean {
        return this.approvalStore?.revokeRule(ruleId) ?? false;
    }

    /**
     * Revoke all approval rules for a capability.
     */
    revokeApprovalsForCapability(capability: string): number {
        return this.approvalStore?.revokeAllForCapability(capability) ?? 0;
    }

    /**
     * Revoke all approval rules (nuclear option).
     */
    revokeAllApprovals(): number {
        return this.approvalStore?.revokeAll() ?? 0;
    }

    /** Whether access requests are enabled on this chain. */
    get accessRequestsEnabled(): boolean {
        return this.accessRequestManager !== undefined;
    }

    // ─── Existing API ────────────────────────────────────────────────────────

    /** Serve this at GET /.well-known/agent-configuration for agent discovery. */
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

    async drain(exporter?: AuditExporter): Promise<void> {
        return this.log.drain(exporter ?? this.exporter);
    }
}
