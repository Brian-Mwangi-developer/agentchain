/** Proxy wrapper for arbitrary service objects. Registered methods are auth-gated via CapabilityRegistry.
 *  If a Capability has an `execute` function, it is called. Otherwise, the target's own method is called. */

import { ChainAuthError } from "../errors/chain-error.js";
import { enforceConstraints } from "../auth/constraints.js";
import type { CapabilityRegistry } from "./capability-registry.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { ResolvedGrant } from "../types/protocol.js";
import type { AgentContext } from "../types/capabilities.js";

export type AppInterceptContext = {
    identity: AgentIdentity;
    builder: TokenBuilder;
    verifier: TokenVerifier;
    log: AuditLog;
    grants: ResolvedGrant[];
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
                enforceConstraints(grant.constraints, callArgs, registryEntry.inputSchema);
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
    };
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
