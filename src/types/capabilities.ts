/**
 * Capability types — define what an app exposes and how agents interact with it.
 *
 * A Capability is a named, schema-described, executable function.
 * When agents-chain wraps an app, every method call is mapped to a Capability
 * and gated by the agent's CapabilityGrants.
 */

// ─── JSON Schema subset (for input/output schemas) ───────────────────────────

export type JsonSchemaType = "object" | "array" | "string" | "number" | "boolean" | "null";

export type JsonSchemaObject = {
    type?: JsonSchemaType | JsonSchemaType[];
    properties?: Record<string, JsonSchemaObject>;
    items?: JsonSchemaObject;
    required?: string[];
    description?: string;
    enum?: unknown[];
    [key: string]: unknown;
};

// ─── Constraints ─────────────────────────────────────────────────────────────

export type ConstraintPrimitive = string | number | boolean;

export type ConstraintOperator = {
    max?: number;
    min?: number;
    in?: ConstraintPrimitive[];
    not_in?: ConstraintPrimitive[];
};

export type ConstraintValue = ConstraintPrimitive | ConstraintOperator;

/**
 * Per-capability argument constraints.
 * Key = argument field name.
 * Value = primitive (exact match) or operator (range/whitelist/blacklist).
 *
 * Example:
 *   { amount: { max: 1000 }, currency: { in: ["USD", "EUR"] } }
 */
export type GrantConstraints = Record<string, ConstraintValue>;

// ─── Agent Context ────────────────────────────────────────────────────────────

/**
 * Context passed to every Capability.execute() call.
 * Tells the capability who is calling and what they are allowed to do.
 */
export type AgentContext = {
    agentId: string;
    hostId: string;
    permissions: string[];    // Active granted capability names
    metadata?: Record<string, string[]>;
};

// ─── Capability ───────────────────────────────────────────────────────────────

/**
 * A named, schema-described, executable function exposed by an app.
 *
 * Usage:
 *   const cap: Capability<{ userId: string }, { balance: number }> = {
 *     name: "get_balance",
 *     description: "Get the current account balance for a user",
 *     inputSchema: { type: "object", required: ["userId"], properties: { userId: { type: "string" } } },
 *     outputSchema: { type: "object", properties: { balance: { type: "number" } } },
 *     execute: async ({ userId }, ctx) => accountService.getBalance(userId),
 *   };
 */
export type Capability<TInput = unknown, TOutput = unknown> = {
    name: string;
    description: string;
    inputSchema: JsonSchemaObject;
    outputSchema: JsonSchemaObject;
    execute: (params: TInput, context: AgentContext) => Promise<TOutput>;
};
