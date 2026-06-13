/** Proxy wrapper for arbitrary service objects. Registered methods are auth-gated via CapabilityRegistry.
 *  If a Capability has an `execute` function, it is called. Otherwise, the target's own method is called.
 *  When access requests are enabled, denied calls suspend and wait for human approval. */

import { ChainAuthError } from "../errors/chain-error.js";
import { enforceConstraints } from "../auth/constraints.js";
import type { CapabilityRegistry } from "./capability-registry.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { ResolvedGrant } from "../types/protocol.js";
import type { AgentContext, GrantConstraints } from "../types/capabilities.js";
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

            // Gate through auth. If capability has execute, use it; otherwise fall through to target method.
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
 * Core execution logic. Separated so it can be re-invoked after approval
 * without losing context — the callArgs, capability, and targetFn are all
 * captured in the closure.
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
            // Check if any approval rules expand these constraints
            const effectiveConstraints = getEffectiveConstraints(
                capabilityName, grant.constraints, ctx.approvalStore
            );

            if (effectiveConstraints) {
                enforceConstraints(effectiveConstraints, callArgs, registryEntry.inputSchema);
            }
            // effectiveConstraints === null means a "capability"/"global" rule removed all constraints
        }

        const agentContext: AgentContext = {
            agentId: verified.agentId,
            hostId: verified.hostThumbprint,
            permissions: ctx.grants
                .filter((g) => g.status === "active")
                .map((g) => g.capability),
        };

        // If Capability defines execute, use it. Otherwise, delegate to the target's method.
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

        return result;
    } catch (err) {
        if (err instanceof ChainAuthError) {
            // ── Access Request Flow ──────────────────────────────────────
            // If access requests are enabled, instead of throwing immediately,
            // we suspend the call and wait for human approval.
            if (ctx.accessRequestManager && isRequestableError(err)) {
                const { violatedField, violatedValue } = extractViolationDetails(err);

                // Check if there's already an approval rule that covers this
                if (ctx.approvalStore) {
                    const existingRule = ctx.approvalStore.findMatchingRule(
                        ctx.identity.agentId,
                        capabilityName,
                        callArgs,
                        violatedField,
                        violatedValue
                    );
                    if (existingRule) {
                        // Rule exists but constraint enforcement still failed —
                        // this shouldn't happen if getEffectiveConstraints worked.
                        // Re-execute with fresh auth token (the approval rule
                        // will take effect via getEffectiveConstraints).
                        return executeWithAccessRequest(capabilityName, callArgs, ctx, targetFn);
                    }
                }

                // Log the denial before suspending
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

                // Create the access request and SUSPEND — the promise won't
                // resolve until the human approves/denies/expires.
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

                // Block here — the agent's call is suspended.
                // Context is preserved: capabilityName, callArgs, ctx, targetFn
                // are all in the closure. When the promise resolves, we re-execute.
                const approvalResult = await waitForApproval as {
                    approved: boolean;
                    decision: ApprovalDecision;
                };

                // Human approved — create the approval rule
                if (approvalResult.approved && ctx.approvalStore) {
                    const rule = ctx.approvalStore.createRule(request, approvalResult.decision);

                    // For "call" scope, execute once then remove the rule
                    if (approvalResult.decision.scope === "call") {
                        const result = await executeWithAccessRequest(
                            capabilityName, callArgs, ctx, targetFn
                        );
                        ctx.approvalStore.revokeRule(rule.ruleId);
                        return result;
                    }
                }

                // Re-execute with the new approval rule in place
                return executeWithAccessRequest(capabilityName, callArgs, ctx, targetFn);
            }

            // No access request manager — throw as before
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Only constraint_violated and capability_denied can trigger access requests. */
function isRequestableError(err: ChainAuthError): boolean {
    return err.code === "constraint_violated" || err.code === "capability_denied";
}

/** Extract which field/value was violated from the error message. */
function extractViolationDetails(err: ChainAuthError): {
    violatedField?: string;
    violatedValue?: unknown;
} {
    if (err.code !== "constraint_violated") return {};

    // Parse field name from messages like: field "to": "..." is not in allowed list [...]
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
function getEffectiveConstraints(
    capability: string,
    grantConstraints: GrantConstraints,
    approvalStore?: ApprovalStore
): GrantConstraints | null {
    if (!approvalStore) return grantConstraints;

    const expansions = approvalStore.getExpandedConstraints(capability);
    if (expansions === null) {
        // A capability/global rule removed all constraints
        return null;
    }

    if (expansions === undefined) return grantConstraints; // No rules found — keep original

    // Merge expansions into a copy of the grant constraints
    const merged = { ...grantConstraints };
    for (const [field, expansion] of Object.entries(expansions)) {
        const existing = merged[field];
        if (!existing) continue; // Don't add new constraints, only expand existing ones

        if (typeof existing === "object" && !Array.isArray(existing) &&
            typeof expansion === "object" && !Array.isArray(expansion)) {
            const existingOp = existing as import("../types/capabilities.js").ConstraintOperator;
            const expOp = expansion as import("../types/capabilities.js").ConstraintOperator;

            const mergedOp = { ...existingOp };

            // Expand `in` lists
            if (expOp.in && mergedOp.in) {
                mergedOp.in = [...new Set([...mergedOp.in, ...expOp.in])];
            }

            // Remove approved values from `not_in`
            if (expOp.in && mergedOp.not_in) {
                mergedOp.not_in = mergedOp.not_in.filter(
                    (v) => !expOp.in!.includes(v)
                );
                if (mergedOp.not_in.length === 0) delete mergedOp.not_in;
            }

            // Expand max/min bounds
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

// Helper — we need registry access at intercept time.
// We store it on the context via a symbol to keep the type clean.
const REGISTRY_SYM = Symbol("registry");

export function attachRegistry(ctx: AppInterceptContext, registry: CapabilityRegistry): void {
    (ctx as Record<symbol, unknown>)[REGISTRY_SYM] = registry;
}

function getCapabilityFromCtx(name: string, ctx: AppInterceptContext) {
    const registry = (ctx as Record<symbol, unknown>)[REGISTRY_SYM] as CapabilityRegistry | undefined;
    return registry?.get(name);
}
