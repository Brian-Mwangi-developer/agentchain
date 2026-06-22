
/**
 * Trace types for agents-chain.
 *
 * One TraceRun = one agent session start-to-finish.
 * It contains N TraceSpans — one per capability call.
 * ModelMetadata is attached to each span that goes through an LLM call.
 */

// ─── Model metadata ───────────────────────────────────────────────────────────

/**
 * Normalized LLM call metadata extracted from provider responses.
 * Built-in extractors handle Anthropic and OpenAI.
 * Third parties can supply a custom ModelMetadataExtractor.
 */
export type ModelMetadata = {
    /** Model identifier, e.g. "claude-sonnet-4-6", "gpt-4o" */
    model: string;
    /** Provider label, e.g. "anthropic", "openai", or any custom string */
    provider: string;
    /** Tokens consumed by the prompt / input */
    inputTokens?: number;
    /** Tokens produced in the completion / output */
    outputTokens?: number;
    /** Sum of inputTokens + outputTokens, if available */
    totalTokens?: number;
    /** Sampling temperature sent in the request, if present */
    temperature?: number;
    /**
     * Tool/function calls the model requested in this response.
     * Populated automatically by the built-in Anthropic/OpenAI extractors.
     * Custom extractors should populate this when their provider supports tool use.
     */
    toolCalls?: DetectedToolCall[];
    /**
     * The stop/finish reason from the provider, e.g. "end_turn", "tool_use",
     * "stop", "length", "content_filter".
     */
    stopReason?: string;
    /** Any provider-specific extras (cache tokens, reasoning tokens, etc.) */
    extra?: Record<string, unknown>;
};

/**
 * Implement this interface to teach agents-chain how to extract model metadata
 * from an LLM provider response that is not Anthropic or OpenAI.
 *
 * @example
 * const myExtractor: ModelMetadataExtractor = {
 *   provider: "google",
 *   canExtract(response) { return "usageMetadata" in response; },
 *   extract(response, requestArgs) {
 *     const r = response as any;
 *     return {
 *       model: r.modelVersion ?? requestArgs?.model ?? "unknown",
 *       provider: "google",
 *       inputTokens: r.usageMetadata?.promptTokenCount,
 *       outputTokens: r.usageMetadata?.candidatesTokenCount,
 *       totalTokens: r.usageMetadata?.totalTokenCount,
 *       temperature: requestArgs?.generationConfig?.temperature,
 *     };
 *   },
 * };
 */
export interface ModelMetadataExtractor {
    /** Short label identifying the provider, e.g. "google", "cohere" */
    provider: string;
    /**
     * Return true if this extractor can handle the given response object.
     * The first extractor whose canExtract() returns true is used.
     */
    canExtract(response: unknown): boolean;
    /**
     * Extract normalized metadata from the response.
     * @param response - The raw LLM response object.
     * @param requestArgs - The args passed to the original SDK call (contains model, temperature, etc.)
     */
    extract(response: unknown, requestArgs?: Record<string, unknown>): ModelMetadata;
}

// ─── Trace span ───────────────────────────────────────────────────────────────

/** Result of a single capability call within an agent run. */
export type TraceSpanResult =
    | "success"
    | "denied"
    | "error"
    | "access_requested"
    | "access_approved"
    | "access_denied";

/**
 * A tool call detected inside an LLM response.
 * Anthropic: content blocks with type="tool_use"
 * OpenAI: choices[].message.tool_calls
 */
export type DetectedToolCall = {
    /** Tool/function name the model invoked */
    name: string;
    /** The arguments the model passed (sanitized) */
    input: Record<string, unknown>;
    /** Provider-assigned tool call ID, if present */
    id?: string;
};

/** One capability call inside an agent run. */
export type TraceSpan = {
    /** Unique span ID */
    spanId: string;
    /** The capability that was called, e.g. "send_sms", "message" */
    capability: string;
    /** Outcome of the call */
    result: TraceSpanResult;
    /** Wall-clock time the call started (Unix ms) */
    startedAt: number;
    /** How long the actual capability execution took */
    durationMs: number;
    /** How long token auth overhead took */
    authOverheadMs: number;
    /** JWT ID for this call */
    jti: string;
    /** Sanitized call arguments (secrets redacted) */
    args: Record<string, unknown>;
    /** If result is "denied" or "error", the reason */
    denialReason?: string;
    /** If result is "error", the error message */
    errorMessage?: string;
    /** Access request ID, present when the call triggered a human-approval flow */
    accessRequestId?: string;
    /** Approval scope granted (call | value | capability | global), present on access_approved spans */
    approvalScope?: "call" | "value" | "capability" | "global";
    /**
     * LLM metadata for this span, populated by the wrapper when an LLM SDK call
     * was intercepted (Anthropic, OpenAI, or a custom extractor).
     */
    modelMetadata?: ModelMetadata;
    /**
     * Tool calls the model requested in its response.
     * Automatically detected from Anthropic/OpenAI response shapes by the wrappers.
     * Custom extractors can populate this via ModelMetadata.extra["toolCalls"] or
     * by returning it directly if the extractor interface is extended.
     */
    toolCalls?: DetectedToolCall[];
    /**
     * The stop/finish reason from the LLM, e.g. "end_turn", "tool_use",
     * "stop", "length", "content_filter".
     */
    stopReason?: string;
};

// ─── Trace run ────────────────────────────────────────────────────────────────

/** Status of the overall agent run */
export type TraceRunStatus = "success" | "failed" | "partial";

/**
 * One complete agent session — from the first capability call to the last.
 * This is what gets exported to the gateway and stored as a single row.
 */
export type TraceRun = {
    /** Unique trace ID, generated when openTrace() is called */
    traceId: string;
    /** Agent identifier from the chain identity */
    agentId: string;
    /** Human-readable agent name */
    agentName: string;
    /** Host thumbprint */
    hostThumbprint: string;
    /** Overall outcome of the run */
    status: TraceRunStatus;
    /** Unix ms when the trace was opened */
    startedAt: number;
    /** Unix ms when the trace was closed */
    endedAt: number;
    /** endedAt - startedAt */
    totalDurationMs: number;
    /** All capability calls in chronological order */
    spans: TraceSpan[];
    /** Rolled-up counters computed from spans */
    summary: TraceRunSummary;
};

/** Rolled-up statistics derived from all spans in the run. */
export type TraceRunSummary = {
    totalSpans: number;
    successSpans: number;
    deniedSpans: number;
    errorSpans: number;
    totalInputTokens: number;
    totalOutputTokens: number;
    totalTokens: number;
    /** Unique models used across all spans, e.g. ["claude-sonnet-4-6"] */
    modelsUsed: string[];
    /** Unique providers used across all spans, e.g. ["anthropic"] */
    providersUsed: string[];
};
