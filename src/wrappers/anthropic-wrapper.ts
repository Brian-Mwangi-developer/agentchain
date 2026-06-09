/**
 * Anthropic SDK wrapper — intercepts calls and runs the auth + audit pipeline.
 *
 * Intercepted capability names (mapped from SDK method paths):
 *   client.messages.create       → "message"
 *   client.messages.stream       → "message.stream"
 *   client.messages.countTokens  → "message.count_tokens"
 *   client.completions.create    → "completion"  (legacy)
 *   client.beta.messages.create  → "message.beta"
 *
 * Any other method path passes through without interception.
 *
 * Same Proxy approach as the OpenAI wrapper — no SDK monkey-patching.
 */

import { ChainAuthError } from "../errors/chain-error.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { AgentIdentity } from "../identity/agent-identity.js";

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
};

/**
 * Wrap an Anthropic client instance.
 * Returns a Proxy that enforces agent auth on every intercepted method.
 */
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
