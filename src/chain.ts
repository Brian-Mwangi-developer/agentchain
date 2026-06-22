/** AgentsChain — wraps OpenAI/Anthropic SDK clients with auth, identity, and audit. */

import { AccessRequestManager } from "./access/access-request-manager.js";
import { ApprovalStore } from "./access/approval-store.js";
import type { AppInterceptContext } from "./app/app-wrapper.js";
import { attachRegistry, wrapApp } from "./app/app-wrapper.js";
import { CapabilityRegistry } from "./app/capability-registry.js";
import { createRequestPermissionCapability } from "./app/request-permission-capability.js";
import type { AuditExporter } from "./audit/audit-exporter.js";
import type { TraceExporter } from "./audit/trace-exporter.js";
import { AuditLog } from "./audit/audit-log.js";
import { TokenBuilder } from "./auth/token-builder.js";
import { TokenVerifier } from "./auth/token-verifier.js";
import { HostIdentity } from "./host/host-identity.js";
import { AgentIdentity } from "./identity/agent-identity.js";
import { EncryptedStore } from "./memory/encrypted-store.js";
import { JtiCache } from "./memory/jti-cache.js";
import type { AccessRequest, ApprovalDecision, ApprovalRule, DenialDecision } from "./types/access-request.js";
import type { AuditEntry } from "./types/audit.js";
import type { TraceRun, TraceRunStatus } from "./types/trace.js";
import type { AgentConfig, AppChainConfig, AuditSnapshot, ChainStats } from "./types/chain.js";
import type { AgentConfiguration, ResolvedGrant } from "./types/protocol.js";
import { wrapAnthropic } from "./wrappers/anthropic-wrapper.js";
import { wrapOpenAI } from "./wrappers/openai-wrapper.js";

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

    openai<T extends object>(client: T, traceId?: string): T {
        return wrapOpenAI(client, {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
            traceId,
        });
    }

    anthropic<T extends object>(client: T, traceId?: string): T {
        return wrapAnthropic(client, {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
            traceId,
        });
    }

    /**
     * Open a new trace run. Call this at the start of an agent session.
     * Pass the returned traceId to openai()/anthropic() so LLM calls are grouped.
     * Call closeTrace() when the session ends to export the completed TraceRun.
     */
    openTrace(): string {
        return this.log.openTrace(
            this.identity.agentId,
            this.identity.registration.agentName,
            this.identity.registration.hostThumbprint
        );
    }

    /**
     * Close the trace run and optionally export it.
     * @param traceId - The ID returned by openTrace()
     * @param status - Overall outcome of the agent session
     * @param traceExporter - Where to ship the completed TraceRun (overrides default)
     */
    async closeTrace(
        traceId: string,
        status: TraceRunStatus,
        traceExporter?: TraceExporter
    ): Promise<TraceRun | undefined> {
        return this.log.closeTrace(traceId, status, traceExporter);
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
    private readonly _traceExporter?: TraceExporter;
    private readonly accessRequestManager?: AccessRequestManager;
    private readonly approvalStore?: ApprovalStore;
    private readonly _constraintAware: boolean;

    private constructor(
        host: HostIdentity,
        registry: CapabilityRegistry,
        identity: AgentIdentity,
        builder: TokenBuilder,
        verifier: TokenVerifier,
        log: AuditLog,
        jtiCache: JtiCache,
        constraintAware: boolean,
        exporter?: AuditExporter,
        accessRequestManager?: AccessRequestManager,
        approvalStore?: ApprovalStore,
        traceExporter?: TraceExporter
    ) {
        this.host = host;
        this.registry = registry;
        this.identity = identity;
        this.builder = builder;
        this.verifier = verifier;
        this.log = log;
        this.jtiCache = jtiCache;
        this._constraintAware = constraintAware;
        this.exporter = exporter;
        this._traceExporter = traceExporter;
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

        const constraintAware = config.constraintAware ?? false;

        // Auto-register the built-in request_permission capability when both
        // constraintAware and accessRequests are enabled. This gives AI agents
        // an explicit tool to request human approval.
        if (constraintAware && accessRequestManager && approvalStoreInstance) {
            // grants will be provided at wrap() time, so we create a placeholder
            // that gets updated on each wrap() call. The capability is registered
            // once at init; the grants reference is updated via closure.
            const rpGrantsRef: { current: ResolvedGrant[] } = { current: [] };
            const requestPermissionCap = createRequestPermissionCapability({
                identity,
                builder,
                verifier,
                log,
                get grants() { return rpGrantsRef.current; },
                registry,
                accessRequestManager,
                approvalStore: approvalStoreInstance,
            });
            registry.register(requestPermissionCap);

            // Store the grants ref so wrap() can update it
            (registry as unknown as Record<string, unknown>).__rpGrantsRef = rpGrantsRef;
        }

        return new AppChain(
            host, registry, identity, builder, verifier, log, jtiCache,
            constraintAware, config.auditExporter, accessRequestManager, approvalStoreInstance,
            config.traceExporter
        );
    }

    destroy(): void {
        this.jtiCache.destroy();
        this.accessRequestManager?.destroy();
    }

    wrap<T extends object>(target: T, grants: ResolvedGrant[], traceId?: string): T {
        // Auto-include grant for the built-in request_permission capability when
        // constraintAware mode is active. The caller's grants only cover their own
        // capabilities (e.g. send_sms) — request_permission is a system capability
        // that is always available when the feature is enabled.
        const effectiveGrants: ResolvedGrant[] = this._constraintAware
            ? [
                ...grants,
                { capability: "request_permission", status: "active" as const },
              ]
            : grants;

        // Update the grants reference for the request_permission capability
        const rpGrantsRef = (this.registry as unknown as Record<string, unknown>).__rpGrantsRef as
            { current: ResolvedGrant[] } | undefined;
        if (rpGrantsRef) {
            rpGrantsRef.current = effectiveGrants;
        }

        const ctx: AppInterceptContext = {
            identity: this.identity,
            builder: this.builder,
            verifier: this.verifier,
            log: this.log,
            grants: effectiveGrants,
            accessRequestManager: this.accessRequestManager,
            approvalStore: this.approvalStore,
            constraintAware: this._constraintAware,
            traceId,
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

    get agentId(): string {
        return this.identity.agentId;
    }

    get hostId(): string {
        return this.host.hostId;
    }

    /** Whether access requests are enabled on this chain. */
    get accessRequestsEnabled(): boolean {
        return this.accessRequestManager !== undefined;
    }

    /** Whether constraint-aware mode is enabled. */
    get constraintAware(): boolean {
        return this._constraintAware;
    }

    /**
     * Generate an AI-system-prompt-ready description of all active constraints.
     * Include this in your AI agent's system prompt so it knows the rules upfront.
     */
    getConstraintContext(grants: ResolvedGrant[]): string {
        const lines: string[] = [
            "You are operating under capability constraints enforced by the agents-chain protocol.",
            "When a call violates a constraint, you will receive a structured violation result.",
        ];

        if (this._constraintAware && this.accessRequestManager) {
            lines.push(
                'You have access to a "request_permission" tool that lets you request human approval for blocked calls.',
                ""
            );
        }

        lines.push("Active constraints:");

        const activeGrants = grants.filter((g) => g.status === "active");
        if (activeGrants.length === 0) {
            lines.push("  (no active grants)");
            return lines.join("\n");
        }

        for (const grant of activeGrants) {
            if (!grant.constraints || Object.keys(grant.constraints).length === 0) {
                lines.push(`  - ${grant.capability}: no constraints (unrestricted)`);
                continue;
            }

            lines.push(`  - ${grant.capability}:`);
            for (const [field, constraint] of Object.entries(grant.constraints as Record<string, unknown>)) {
                lines.push(`      ${field}: ${formatConstraintForPrompt(constraint)}`);
            }
        }

        if (this._constraintAware && this.accessRequestManager) {
            lines.push(
                "",
                "If you need to use a value outside these constraints, call request_permission with the capability name, args, and reason.",
                "A human operator will review your request."
            );
        }

        return lines.join("\n");
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

    /**
     * Open a new trace run for this AppChain session.
     * Returns a traceId to pass into wrap() so all capability calls are grouped.
     */
    openTrace(): string {
        return this.log.openTrace(
            this.identity.agentId,
            this.identity.registration.agentName,
            this.identity.registration.hostThumbprint
        );
    }

    /**
     * Close the trace run and optionally export it.
     * @param traceId - The ID returned by openTrace()
     * @param status - Overall outcome of the agent session
     * @param traceExporter - Where to ship the completed TraceRun (overrides default)
     */
    async closeTrace(
        traceId: string,
        status: TraceRunStatus,
        traceExporter?: TraceExporter
    ): Promise<TraceRun | undefined> {
        return this.log.closeTrace(traceId, status, traceExporter ?? this._traceExporter);
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

// ─── Module-level helpers ────────────────────────────────────────────────────

function formatConstraintForPrompt(constraint: unknown): string {
    if (typeof constraint === "string" || typeof constraint === "number" || typeof constraint === "boolean") {
        return `must be exactly ${JSON.stringify(constraint)}`;
    }

    if (typeof constraint === "object" && constraint !== null) {
        const op = constraint as Record<string, unknown>;
        const parts: string[] = [];

        if (op.in && Array.isArray(op.in)) {
            parts.push(`must be one of [${(op.in as unknown[]).map((v) => JSON.stringify(v)).join(", ")}]`);
        }
        if (op.not_in && Array.isArray(op.not_in)) {
            parts.push(`must NOT be [${(op.not_in as unknown[]).map((v) => JSON.stringify(v)).join(", ")}]`);
        }
        if (typeof op.max === "number") {
            parts.push(`maximum ${op.max}`);
        }
        if (typeof op.min === "number") {
            parts.push(`minimum ${op.min}`);
        }

        return parts.length > 0 ? parts.join(", ") : JSON.stringify(constraint);
    }

    return String(constraint);
}
