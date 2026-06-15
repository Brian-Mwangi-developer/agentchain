/**
 * Proxy wrapper for arbitrary service objects. Registered methods are auth-gated via CapabilityRegistry.
 * If a Capability has an `execute` function, it is called. Otherwise, the target's own method is called.
 * When constraintAware is enabled, violations return structured results instead of throwing.
 */

import { ChainAuthError } from "../errors/chain-error.js";
import { enforceConstraints } from "../auth/constraints.js";
import type { CapabilityRegistry } from "./capability-registry.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { ResolvedGrant } from "../types/protocol.js";
import type { AgentContext, GrantConstraints, ConstraintAwareResult } from "../types/capabilities.js";
import type { AccessRequestManager } from "../access/access-request-manager.js";
import type { ApprovalStore } from "../access/approval-store.js";
import type { ApprovalDecision } from "../types/access-request.js";

export type AppInterceptContext = {
    identity: AgentIdentity;
    builder: TokenBuilder;
    verifier: TokenVerifier;
    log: AuditLog;
    grants: ResolvedGrant[];
    /** If set, denied calls will suspend and wait for human approval. */
    accessRequestManager?: AccessRequestManager;
    /** Stores approved rules so future calls don't re-prompt. */
    approvalStore?: ApprovalStore;
    /** When true, return ConstraintAwareResult envelopes instead of raw results/errors. */
    constraintAware?: boolean;
};

export function wrapApp<T extends object>(
    target: T,
    registry: CapabilityRegistry,
    ctx: AppInterceptContext
): T {
    return new Proxy(target, {
        get(obj, prop) {
            if (typeof prop !== "string") return Reflect.get(obj, prop);

            const capability = registry.get(prop);
            const value = Reflect.get(obj, prop);

            if (capability === undefined) {
                return value;
            }

            const targetFn = typeof value === "function" ? (value as Function).bind(obj) : undefined;
            return createInterceptedMethod(capability.name, ctx, targetFn);
        },
    }) as T;
}

function createInterceptedMethod(
    capabilityName: string,
    ctx: AppInterceptContext,
    targetFn?: (...args: unknown[]) => unknown
): (...args: unknown[]) => Promise<unknown> {
    return async (...args: unknown[]) => {
        const callArgs = (args[0] ?? {}) as Record<string, unknown>;
        return executeWithAccessRequest(capabilityName, callArgs, ctx, targetFn);
    };
}

/**
 * Core execution logic with auth, constraints, and optional access request flow.
 * When constraintAware mode is enabled, returns ConstraintAwareResult envelopes
 * instead of raw results/errors.
 */
async function executeWithAccessRequest(
    capabilityName: string,
    callArgs: Record<string, unknown>,
    ctx: AppInterceptContext,
    targetFn?: (...args: unknown[]) => unknown
): Promise<unknown> {
    let jti = "unknown";
    const authStart = Date.now();
    try {
        const { token, claims } = await ctx.builder.build(capabilityName);
        jti = claims.jti;
        const verified = await ctx.verifier.verify(token, capabilityName, ctx.grants);
        const authOverheadMs = Date.now() - authStart;

        const registryEntry = getCapabilityFromCtx(capabilityName, ctx);
        if (!registryEntry) {
            throw new ChainAuthError(
                "capability_denied",
                `Capability "${capabilityName}" not found in registry`
            );
        }

        const grant = ctx.grants.find(
            (g) => g.capability === capabilityName && g.status === "active"
        );

        if (grant?.constraints) {
            const effectiveConstraints = getEffectiveConstraints(
                capabilityName, grant.constraints, ctx.approvalStore
            );
            if (effectiveConstraints) {
                enforceConstraints(effectiveConstraints, callArgs, registryEntry.inputSchema);
            }
        }

        const agentContext: AgentContext = {
            agentId: verified.agentId,
            hostId: verified.hostThumbprint,
            permissions: ctx.grants
                .filter((g) => g.status === "active")
                .map((g) => g.capability),
        };

        const executeFn = registryEntry.execute
            ? (a: unknown) => registryEntry.execute!(a, agentContext)
            : targetFn
                ? (...a: unknown[]) => Promise.resolve(targetFn(...a))
                : null;

        if (!executeFn) {
            throw new ChainAuthError(
                "capability_denied",
                `Capability "${capabilityName}" has no execute function and no target method to delegate to`
            );
        }

        const callStart = Date.now();
        let result: unknown;
        try {
            result = await executeFn(callArgs);
        } catch (execErr) {
            ctx.log.recordCall({
                context: verified,
                args: callArgs,
                result: "error",
                durationMs: Date.now() - callStart,
                errorMessage: execErr instanceof Error ? execErr.message : String(execErr),
                authOverheadMs,
            });
            throw execErr;
        }

        ctx.log.recordCall({
            context: verified,
            args: callArgs,
            result: "success",
            durationMs: Date.now() - callStart,
            authOverheadMs,
        });

        if (ctx.constraintAware) {
            return {
                success: true,
                result,
                permission: "not_required",
                guidance: "Call succeeded. No constraint violations.",
                capability: capabilityName,
            } satisfies ConstraintAwareResult;
        }

        return result;
    } catch (err) {
        if (err instanceof ChainAuthError) {
            if (ctx.constraintAware && isRequestableError(err)) {
                const grant = ctx.grants.find(
                    (g) => g.capability === capabilityName && g.status === "active"
                );

                ctx.log.recordDenied({
                    agentId: ctx.identity.agentId,
                    agentName: ctx.identity.registration.agentName,
                    hostname: ctx.identity.registration.hostname,
                    hostThumbprint: ctx.identity.registration.hostThumbprint,
                    capability: capabilityName,
                    args: callArgs,
                    reason: `[constraint_aware] ${err.message}`,
                    jti,
                    authOverheadMs: Date.now() - authStart,
                });

                const hasAccessRequests = !!ctx.accessRequestManager;
                const guidance = hasAccessRequests
                    ? `Constraint violated on capability "${capabilityName}". You may call the "request_permission" tool with { capability: "${capabilityName}", args: <your original args>, reason: "<why you need this>" } to request human approval. The request will be reviewed by a human operator.`
                    : `Constraint violated on capability "${capabilityName}". The access request system is not available. Adjust your parameters to match the active constraints.`;

                return {
                    success: false,
                    permission: "constraint_violated",
                    violations: err.structuredViolations,
                    guidance,
                    capability: capabilityName,
                    activeConstraints: grant?.constraints as Record<string, unknown> | undefined,
                } satisfies ConstraintAwareResult;
            }

            // Legacy access request flow (constraintAware=false)
            if (ctx.accessRequestManager && isRequestableError(err)) {
                const { violatedField, violatedValue } = extractViolationDetails(err);

                if (ctx.approvalStore) {
                    const existingRule = ctx.approvalStore.findMatchingRule(
                        ctx.identity.agentId,
                        capabilityName,
                        callArgs,
                        violatedField,
                        violatedValue
                    );
                    if (existingRule) {
                        return executeWithAccessRequest(capabilityName, callArgs, ctx, targetFn);
                    }
                }

                ctx.log.recordDenied({
                    agentId: ctx.identity.agentId,
                    agentName: ctx.identity.registration.agentName,
                    hostname: ctx.identity.registration.hostname,
                    hostThumbprint: ctx.identity.registration.hostThumbprint,
                    capability: capabilityName,
                    args: callArgs,
                    reason: `[access_request] ${err.message}`,
                    jti,
                    authOverheadMs: Date.now() - authStart,
                });

                const { request, waitForApproval } = await ctx.accessRequestManager.createRequest({
                    agentId: ctx.identity.agentId,
                    agentName: ctx.identity.registration.agentName,
                    hostId: ctx.identity.registration.hostThumbprint,
                    capability: capabilityName,
                    args: callArgs,
                    reason: err.message,
                    errorCode: err.code as "constraint_violated" | "capability_denied",
                    violatedField,
                    violatedValue,
                });

                const approvalResult = await waitForApproval as {
                    approved: boolean;
                    decision: ApprovalDecision;
                };

                if (approvalResult.approved && ctx.approvalStore) {
                    const rule = ctx.approvalStore.createRule(request, approvalResult.decision);

                    if (approvalResult.decision.scope === "call") {
                        const result = await executeWithAccessRequest(
                            capabilityName, callArgs, ctx, targetFn
                        );
                        ctx.approvalStore.revokeRule(rule.ruleId);
                        return result;
                    }
                }

                return executeWithAccessRequest(capabilityName, callArgs, ctx, targetFn);
            }

            ctx.log.recordDenied({
                agentId: ctx.identity.agentId,
                agentName: ctx.identity.registration.agentName,
                hostname: ctx.identity.registration.hostname,
                hostThumbprint: ctx.identity.registration.hostThumbprint,
                capability: capabilityName,
                args: callArgs,
                reason: err.message,
                jti,
                authOverheadMs: Date.now() - authStart,
            });
            throw err;
        }
        throw err;
    }
}

function isRequestableError(err: ChainAuthError): boolean {
    return err.code === "constraint_violated" || err.code === "capability_denied";
}

function extractViolationDetails(err: ChainAuthError): {
    violatedField?: string;
    violatedValue?: unknown;
} {
    if (err.code !== "constraint_violated") return {};

    const fieldMatch = err.message.match(/field "([^"]+)"/);
    const valueMatch = err.message.match(/field "[^"]+": "([^"]*)"/) ??
                       err.message.match(/field "[^"]+": (\S+)/);

    return {
        violatedField: fieldMatch?.[1],
        violatedValue: valueMatch?.[1],
    };
}

/**
 * Merge approval-store expansions into the grant constraints.
 * Returns null if a capability/global rule removes all constraints.
 * Returns the original constraints if no expansions apply.
 */
export function getEffectiveConstraints(
    capability: string,
    grantConstraints: GrantConstraints,
    approvalStore?: ApprovalStore
): GrantConstraints | null {
    if (!approvalStore) return grantConstraints;

    const expansions = approvalStore.getExpandedConstraints(capability);
    if (expansions === null) return null;
    if (expansions === undefined) return grantConstraints;

    const merged = { ...grantConstraints };
    for (const [field, expansion] of Object.entries(expansions)) {
        const existing = merged[field];
        if (!existing) continue;

        if (typeof existing === "object" && !Array.isArray(existing) &&
            typeof expansion === "object" && !Array.isArray(expansion)) {
            const existingOp = existing as import("../types/capabilities.js").ConstraintOperator;
            const expOp = expansion as import("../types/capabilities.js").ConstraintOperator;

            const mergedOp = { ...existingOp };

            if (expOp.in && mergedOp.in) {
                mergedOp.in = [...new Set([...mergedOp.in, ...expOp.in])];
            }

            if (expOp.in && mergedOp.not_in) {
                mergedOp.not_in = mergedOp.not_in.filter(
                    (v) => !expOp.in!.includes(v)
                );
                if (mergedOp.not_in.length === 0) delete mergedOp.not_in;
            }

            if (expOp.max !== undefined && mergedOp.max !== undefined) {
                mergedOp.max = Math.max(mergedOp.max, expOp.max);
            }
            if (expOp.min !== undefined && mergedOp.min !== undefined) {
                mergedOp.min = Math.min(mergedOp.min, expOp.min);
            }

            merged[field] = mergedOp;
        }
    }

    return merged;
}

const REGISTRY_SYM = Symbol("registry");

export function attachRegistry(ctx: AppInterceptContext, registry: CapabilityRegistry): void {
    (ctx as Record<symbol, unknown>)[REGISTRY_SYM] = registry;
}

function getCapabilityFromCtx(name: string, ctx: AppInterceptContext) {
    const registry = (ctx as Record<symbol, unknown>)[REGISTRY_SYM] as CapabilityRegistry | undefined;
    return registry?.get(name);
}
