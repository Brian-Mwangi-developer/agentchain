/** Anthropic SDK Proxy wrapper. Intercepts known method paths and gates them through auth + audit. */

import { ChainAuthError } from "../errors/chain-error.js";
import { enforceConstraints } from "../auth/constraints.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { ResolvedGrant } from "../types/protocol.js";

const METHOD_CAPABILITY_MAP: Record<string, string> = {
    "messages.create": "message",
    "messages.stream": "message.stream",
    "messages.countTokens": "message.count_tokens",
    "completions.create": "completion",
    "beta.messages.create": "message.beta",
};

type InterceptContext = {
    identity: AgentIdentity;
    builder: TokenBuilder;
    verifier: TokenVerifier;
    log: AuditLog;
    grants?: ResolvedGrant[];
};

export function wrapAnthropic<T extends object>(client: T, ctx: InterceptContext): T {
    return buildProxy(client, ctx, []);
}

function buildProxy<T extends object>(
    target: T,
    ctx: InterceptContext,
    path: string[]
): T {
    return new Proxy(target, {
        get(obj, prop) {
            if (typeof prop !== "string") return Reflect.get(obj, prop);

            const nextPath = [...path, prop];
            const pathKey = nextPath.join(".");
            const capability = METHOD_CAPABILITY_MAP[pathKey];

            const value = Reflect.get(obj, prop);

            if (capability !== undefined && typeof value === "function") {
                return createInterceptedMethod(value.bind(obj), capability, ctx);
            }

            if (typeof value === "object" && value !== null) {
                return buildProxy(value as object, ctx, nextPath);
            }

            return value;
        },
    }) as T;
}

function createInterceptedMethod(
    originalFn: (...args: unknown[]) => unknown,
    capability: string,
    ctx: InterceptContext
): (...args: unknown[]) => Promise<unknown> {
    return async (...args: unknown[]) => {
        const callArgs = (args[0] ?? {}) as Record<string, unknown>;

        let jti = "unknown";
        const authStart = Date.now();
        try {
            const { token, claims } = await ctx.builder.build(capability);
            jti = claims.jti;
            const verified = await ctx.verifier.verify(token, capability);
            const authOverheadMs = Date.now() - authStart;

            if (ctx.grants) {
                const grant = ctx.grants.find(
                    (g) => g.capability === capability && g.status === "active"
                );
                if (grant?.constraints) {
                    enforceConstraints(grant.constraints, callArgs);
                }
            }

            const callStart = Date.now();
            let result: unknown;
            try {
                result = await Promise.resolve(originalFn(...args));
            } catch (sdkErr) {
                ctx.log.recordCall({
                    context: verified,
                    args: callArgs,
                    result: "error",
                    durationMs: Date.now() - callStart,
                    errorMessage: sdkErr instanceof Error ? sdkErr.message : String(sdkErr),
                    authOverheadMs,
                });
                throw sdkErr;
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
                    capability,
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
