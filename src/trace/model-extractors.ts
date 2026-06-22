/**
 * Built-in ModelMetadataExtractor implementations for Anthropic and OpenAI.
 * A global registry lets third parties register custom extractors for other providers.
 *
 * Both built-ins automatically detect:
 *  - model name
 *  - input/output/total tokens
 *  - sampling temperature (from request args)
 *  - tool calls made by the model (tool_use blocks / tool_calls array)
 *  - stop/finish reason
 *  - provider-specific extras (cache tokens, token details, etc.)
 */

import type { ModelMetadata, ModelMetadataExtractor, DetectedToolCall } from "../types/trace.js";

const SECRET_KEY_PATTERN = /(?:key|secret|token|password|auth|credential|bearer)/i;

function sanitizeToolInput(input: unknown): Record<string, unknown> {
    if (typeof input !== "object" || input === null || Array.isArray(input)) {
        return {};
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(input as Record<string, unknown>)) {
        out[k] = SECRET_KEY_PATTERN.test(k) ? "[REDACTED]" : v;
    }
    return out;
}

// ─── Anthropic ────────────────────────────────────────────────────────────────

/**
 * Handles responses from @anthropic-ai/sdk messages.create and beta.messages.create.
 *
 * Response shape:
 * {
 *   model: string,
 *   stop_reason: "end_turn" | "tool_use" | "max_tokens" | "stop_sequence",
 *   usage: { input_tokens, output_tokens, cache_read_input_tokens?, cache_creation_input_tokens? },
 *   content: Array<
 *     | { type: "text", text: string }
 *     | { type: "tool_use", id: string, name: string, input: object }
 *   >
 * }
 */
export const anthropicExtractor: ModelMetadataExtractor = {
    provider: "anthropic",

    canExtract(response: unknown): boolean {
        if (typeof response !== "object" || response === null) return false;
        const r = response as Record<string, unknown>;
        return (
            typeof r["model"] === "string" &&
            typeof r["usage"] === "object" &&
            r["usage"] !== null &&
            "input_tokens" in (r["usage"] as object)
        );
    },

    extract(response: unknown, requestArgs?: Record<string, unknown>): ModelMetadata {
        const r = response as Record<string, unknown>;
        const usage = (r["usage"] ?? {}) as Record<string, unknown>;

        const inputTokens = (usage["input_tokens"] as number | undefined) ?? 0;
        const outputTokens = (usage["output_tokens"] as number | undefined) ?? 0;

        const extra: Record<string, unknown> = {};
        if (typeof usage["cache_read_input_tokens"] === "number") {
            extra["cache_read_input_tokens"] = usage["cache_read_input_tokens"];
        }
        if (typeof usage["cache_creation_input_tokens"] === "number") {
            extra["cache_creation_input_tokens"] = usage["cache_creation_input_tokens"];
        }

        // Detect tool_use content blocks
        const toolCalls: DetectedToolCall[] = [];
        const content = r["content"];
        if (Array.isArray(content)) {
            for (const block of content) {
                if (
                    typeof block === "object" &&
                    block !== null &&
                    (block as Record<string, unknown>)["type"] === "tool_use"
                ) {
                    const b = block as Record<string, unknown>;
                    toolCalls.push({
                        name: typeof b["name"] === "string" ? b["name"] : "unknown",
                        input: sanitizeToolInput(b["input"]),
                        id: typeof b["id"] === "string" ? b["id"] : undefined,
                    });
                }
            }
        }

        return {
            model: (r["model"] as string) ?? "unknown",
            provider: "anthropic",
            inputTokens,
            outputTokens,
            totalTokens: inputTokens + outputTokens,
            temperature: typeof requestArgs?.["temperature"] === "number"
                ? requestArgs["temperature"]
                : undefined,
            toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
            stopReason: typeof r["stop_reason"] === "string" ? r["stop_reason"] : undefined,
            extra: Object.keys(extra).length > 0 ? extra : undefined,
        };
    },
};

// ─── OpenAI ───────────────────────────────────────────────────────────────────

/**
 * Handles responses from openai chat.completions.create and responses.create.
 *
 * Chat Completions shape:
 * {
 *   model: string,
 *   choices: Array<{
 *     finish_reason: string,
 *     message: {
 *       tool_calls?: Array<{ id, type, function: { name, arguments } }>
 *     }
 *   }>,
 *   usage: { prompt_tokens, completion_tokens, total_tokens, prompt_tokens_details?, completion_tokens_details? }
 * }
 *
 * Responses API shape:
 * {
 *   model: string,
 *   status: string,
 *   usage: { input_tokens, output_tokens },
 *   output: Array<{ type: "function_call", name, arguments, call_id? }>
 * }
 */
export const openaiExtractor: ModelMetadataExtractor = {
    provider: "openai",

    canExtract(response: unknown): boolean {
        if (typeof response !== "object" || response === null) return false;
        const r = response as Record<string, unknown>;
        if (typeof r["model"] !== "string") return false;
        const usage = r["usage"] as Record<string, unknown> | undefined;
        return (
            typeof usage === "object" &&
            usage !== null &&
            ("prompt_tokens" in usage || "input_tokens" in usage)
        );
    },

    extract(response: unknown, requestArgs?: Record<string, unknown>): ModelMetadata {
        const r = response as Record<string, unknown>;
        const usage = (r["usage"] ?? {}) as Record<string, unknown>;

        const inputTokens =
            (usage["prompt_tokens"] as number | undefined) ??
            (usage["input_tokens"] as number | undefined) ??
            0;
        const outputTokens =
            (usage["completion_tokens"] as number | undefined) ??
            (usage["output_tokens"] as number | undefined) ??
            0;
        const totalTokens =
            (usage["total_tokens"] as number | undefined) ?? inputTokens + outputTokens;

        const extra: Record<string, unknown> = {};
        if (typeof usage["prompt_tokens_details"] === "object") {
            extra["prompt_tokens_details"] = usage["prompt_tokens_details"];
        }
        if (typeof usage["completion_tokens_details"] === "object") {
            extra["completion_tokens_details"] = usage["completion_tokens_details"];
        }

        // Detect tool calls — Chat Completions API
        const toolCalls: DetectedToolCall[] = [];
        const choices = r["choices"];
        let stopReason: string | undefined;

        if (Array.isArray(choices) && choices.length > 0) {
            const first = choices[0] as Record<string, unknown>;
            stopReason = typeof first["finish_reason"] === "string"
                ? first["finish_reason"]
                : undefined;

            const message = first["message"] as Record<string, unknown> | undefined;
            const rawToolCalls = message?.["tool_calls"];
            if (Array.isArray(rawToolCalls)) {
                for (const tc of rawToolCalls) {
                    if (typeof tc !== "object" || tc === null) continue;
                    const t = tc as Record<string, unknown>;
                    const fn = t["function"] as Record<string, unknown> | undefined;
                    if (!fn) continue;

                    let parsedArgs: Record<string, unknown> = {};
                    if (typeof fn["arguments"] === "string") {
                        try { parsedArgs = JSON.parse(fn["arguments"]); } catch { /* leave empty */ }
                    } else if (typeof fn["arguments"] === "object") {
                        parsedArgs = fn["arguments"] as Record<string, unknown>;
                    }

                    toolCalls.push({
                        name: typeof fn["name"] === "string" ? fn["name"] : "unknown",
                        input: sanitizeToolInput(parsedArgs),
                        id: typeof t["id"] === "string" ? t["id"] : undefined,
                    });
                }
            }
        }

        // Detect tool calls — Responses API (output array with function_call items)
        const output = r["output"];
        if (Array.isArray(output)) {
            for (const item of output) {
                if (typeof item !== "object" || item === null) continue;
                const it = item as Record<string, unknown>;
                if (it["type"] !== "function_call") continue;

                let parsedArgs: Record<string, unknown> = {};
                if (typeof it["arguments"] === "string") {
                    try { parsedArgs = JSON.parse(it["arguments"]); } catch { /* leave empty */ }
                } else if (typeof it["arguments"] === "object") {
                    parsedArgs = it["arguments"] as Record<string, unknown>;
                }

                toolCalls.push({
                    name: typeof it["name"] === "string" ? it["name"] : "unknown",
                    input: sanitizeToolInput(parsedArgs),
                    id: typeof it["call_id"] === "string" ? it["call_id"] : undefined,
                });
            }
            if (!stopReason && typeof r["status"] === "string") {
                stopReason = r["status"];
            }
        }

        return {
            model: (r["model"] as string) ?? "unknown",
            provider: "openai",
            inputTokens,
            outputTokens,
            totalTokens,
            temperature: typeof requestArgs?.["temperature"] === "number"
                ? requestArgs["temperature"]
                : undefined,
            toolCalls: toolCalls.length > 0 ? toolCalls : undefined,
            stopReason,
            extra: Object.keys(extra).length > 0 ? extra : undefined,
        };
    },
};

// ─── Registry ─────────────────────────────────────────────────────────────────

const customExtractors: ModelMetadataExtractor[] = [];
const builtInExtractors: ModelMetadataExtractor[] = [anthropicExtractor, openaiExtractor];

/**
 * Register a custom ModelMetadataExtractor for a provider not natively supported.
 * Custom extractors are checked before the built-in Anthropic/OpenAI ones.
 *
 * @example
 * registerExtractor({
 *   provider: "google",
 *   canExtract(res) { return "usageMetadata" in res; },
 *   extract(res, reqArgs) {
 *     const r = res as any;
 *     // Detect function calls from Google's response
 *     const toolCalls = r.candidates?.[0]?.content?.parts
 *       ?.filter((p: any) => p.functionCall)
 *       ?.map((p: any) => ({ name: p.functionCall.name, input: p.functionCall.args }));
 *     return {
 *       model: r.modelVersion ?? reqArgs?.model ?? "unknown",
 *       provider: "google",
 *       inputTokens: r.usageMetadata?.promptTokenCount,
 *       outputTokens: r.usageMetadata?.candidatesTokenCount,
 *       totalTokens: r.usageMetadata?.totalTokenCount,
 *       temperature: reqArgs?.generationConfig?.temperature,
 *       toolCalls: toolCalls?.length > 0 ? toolCalls : undefined,
 *       stopReason: r.candidates?.[0]?.finishReason,
 *     };
 *   },
 * });
 */
export function registerExtractor(extractor: ModelMetadataExtractor): void {
    customExtractors.unshift(extractor);
}

/**
 * Try every registered extractor in order and return the first match.
 * Returns undefined if no extractor recognises the response.
 */
export function extractModelMetadata(
    response: unknown,
    requestArgs?: Record<string, unknown>
): ModelMetadata | undefined {
    const all = [...customExtractors, ...builtInExtractors];
    for (const extractor of all) {
        if (extractor.canExtract(response)) {
            return extractor.extract(response, requestArgs);
        }
    }
    return undefined;
}
