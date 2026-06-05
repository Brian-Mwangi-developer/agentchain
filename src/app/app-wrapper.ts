/**
 * wrapApp — wraps any object with capability-gated security.
 *
 * This is the generic version of the AI SDK wrappers (openai-wrapper, anthropic-wrapper).
 * Instead of a hardcoded path→capability map, it uses a CapabilityRegistry.
 *
 * For every method call on the wrapped object:
 *   1. Look up capability by method name in the registry
 *   2. If not in registry → call through without any gating (pass-through)
 *   3. If in registry:
 *      a. Verify the agent holds an active grant for this capability
 *      b. Enforce any constraints on the call arguments
 *      c. Call capability.execute(args, agentContext) — NOT the raw target method
 *      d. Record in audit log (success / denied / error)
 *
 * Note: The Proxy only intercepts direct method calls (not nested paths).
 * Use the AI SDK wrappers for nested path interception (e.g. client.chat.completions.create).
 * This wrapper is designed for flat service objects where method names are unique.
 */

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

/**
 * Wrap any object with capability-gated security.
 *
 * @param target    The object to wrap (e.g. a service instance)
 * @param registry  Capability registry — defines what methods are gated
 * @param ctx       Intercept context — identity, auth, audit, grants
 * @returns         A Proxy with the same type as target
 */
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

            // Not a registered capability — pass through without gating
            if (capability === undefined || typeof value !== "function") {
                return value;
            }

            return createInterceptedMethod(capability.name, ctx);
        },
    }) as T;
}

function createInterceptedMethod(
    capabilityName: string,
    ctx: AppInterceptContext
): (...args: unknown[]) => Promise<unknown> {
    return async (...args: unknown[]) => {
        const callArgs = (args[0] ?? {}) as Record<string, unknown>;

        let jti = "unknown";
        try {
            // Build + verify the single-use JWT
            const { token, claims } = await ctx.builder.build(capabilityName);
            jti = claims.jti;
            const verified = await ctx.verifier.verify(token, capabilityName, ctx.grants);

            // Enforce grant constraints against call arguments
            const grant = ctx.grants.find(
                (g) => g.capability === capabilityName && g.status === "active"
            );
            if (grant?.constraints) {
                enforceConstraints(grant.constraints, callArgs);
            }

            // Build agent context for capability.execute()
            const agentContext: AgentContext = {
                agentId: verified.agentId,
                hostId: verified.hostId ?? "",
                permissions: ctx.grants
                    .filter((g) => g.status === "active")
                    .map((g) => g.capability),
            };

            // Get the registered capability and execute it
            const registryEntry = getCapabilityFromCtx(capabilityName, ctx);
            if (!registryEntry) {
                throw new ChainAuthError(
                    "capability_denied",
                    `Capability "${capabilityName}" not found in registry`
                );
            }

            const start = Date.now();
            let result: unknown;
            try {
                result = await registryEntry.execute(callArgs, agentContext);
            } catch (execErr) {
                ctx.log.recordCall({
                    context: verified,
                    args: callArgs,
                    result: "error",
                    durationMs: Date.now() - start,
                    errorMessage: execErr instanceof Error ? execErr.message : String(execErr),
                });
                throw execErr;
            }

            ctx.log.recordCall({
                context: verified,
                args: callArgs,
                result: "success",
                durationMs: Date.now() - start,
            });

            return result;
        } catch (err) {
            if (err instanceof ChainAuthError) {
                ctx.log.recordDenied({
                    agentId: ctx.identity.agentId,
                    agentName: ctx.identity.registration.agentName,
                    hostname: ctx.identity.registration.hostname,
                    capability: capabilityName,
                    args: callArgs,
                    reason: err.message,
                    jti,
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
