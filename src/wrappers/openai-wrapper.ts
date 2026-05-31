/**
 * OpenAI SDK wrapper — intercepts calls and runs the auth + audit pipeline.
 *
 * Intercepted capability names (mapped from SDK method paths):
 *   client.chat.completions.create  → "chat.completion"
 *   client.embeddings.create        → "embedding"
 *   client.images.generate          → "image.generation"
 *   client.audio.transcriptions.create → "audio.transcription"
 *   client.audio.speech.create      → "audio.speech"
 *   client.moderations.create       → "moderation"
 *   client.responses.create         → "response"  (Responses API)
 *
 * Any other method path passes through without interception.
 *
 * The wrapper uses JavaScript Proxy so it does not modify the original
 * client object and works with any OpenAI SDK version.
 */

import { ChainAuthError } from "../errors/chain-error.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { AgentIdentity } from "../identity/agent-identity.js";

/** Map from SDK method path (dot-joined) to capability name */
const METHOD_CAPABILITY_MAP: Record<string, string> = {
    "chat.completions.create": "chat.completion",
    "embeddings.create": "embedding",
    "images.generate": "image.generation",
    "audio.transcriptions.create": "audio.transcription",
    "audio.speech.create": "audio.speech",
    "moderations.create": "moderation",
    "responses.create": "response",
};

type InterceptContext = {
    identity: AgentIdentity;
    builder: TokenBuilder;
    verifier: TokenVerifier;
    log: AuditLog;
};

/**
 * Wrap an OpenAI client instance.
 * Returns a Proxy that enforces agent auth on every intercepted method.
 */
export function wrapOpenAI<T extends object>(client: T, ctx: InterceptContext): T {
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

            // If this exact path maps to a known capability, intercept the function
            if (capability !== undefined && typeof value === "function") {
                return createInterceptedMethod(value.bind(obj), capability, ctx);
            }

            // If it's an object (namespace like client.chat), proxy it deeper
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

        // Build + verify a fresh single-use token
        let jti = "unknown";
        try {
            const { token, claims } = await ctx.builder.build(capability);
            jti = claims.jti;
            const verified = await ctx.verifier.verify(token, capability);

            const start = Date.now();
            let result: unknown;
            try {
                result = await Promise.resolve(originalFn(...args));
            } catch (sdkErr) {
                ctx.log.recordCall({
                    context: verified,
                    args: callArgs,
                    result: "error",
                    durationMs: Date.now() - start,
                    errorMessage: sdkErr instanceof Error ? sdkErr.message : String(sdkErr),
                });
                throw sdkErr;
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
                    capability,
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
