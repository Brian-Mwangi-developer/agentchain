/** Capability types: schema-described named functions, constraints, and agent context. */

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


export type ConstraintPrimitive = string | number | boolean;

export type ConstraintOperator = {
    max?: number;
    min?: number;
    in?: ConstraintPrimitive[];
    not_in?: ConstraintPrimitive[];
};

export type ConstraintValue = ConstraintPrimitive | ConstraintOperator;

export type GrantConstraints = Record<string, ConstraintValue>;

export type AgentContext = {
    agentId: string;
    hostId: string;
    permissions: string[];    // Active granted capability names
    metadata?: Record<string, string[]>;
};

export type Capability<TInput = unknown, TOutput = unknown> = {
    name: string;
    description: string;
    inputSchema: JsonSchemaObject;
    outputSchema: JsonSchemaObject;
    /** The implementation. If omitted, wrap() delegates to the target object's method of the same name. */
    execute?: (params: TInput, context: AgentContext) => Promise<TOutput>;
};

// ─── Constraint-Aware Result Types ──────────────────────────────────────────
// When constraintAware mode is enabled, capability calls return these structured
// envelopes so AI agents can understand and participate in the permission flow.

/** Structured detail about a single constraint violation. */
export type ConstraintViolationDetail = {
    /** The input field that violated a constraint. */
    field: string;
    /** The type of constraint that was violated. */
    constraint: "in" | "not_in" | "max" | "min" | "exact";
    /** The constraint definition (e.g., the allowed list, the max value). */
    expected: unknown;
    /** The value the agent actually provided. */
    actual: unknown;
    /** Human/AI-readable explanation of the violation. */
    message: string;
};

/** The permission status of a capability call. */
export type PermissionStatus =
    | "not_required"            // call passed all constraints normally
    | "constraint_violated"     // constraint failed — agent should decide next step
    | "approved"                // human approved via request_permission
    | "denied"                  // human denied the request
    | "expired";                // approval request timed out

/** Details about a permission grant after human approval. */
export type PermissionGrant = {
    /** How broadly the approval applies. */
    scope: "call" | "value" | "capability" | "global";
    /** The specific field that was approved (for "value" scope). */
    field?: string;
    /** The specific value that was approved. */
    value?: unknown;
    /** AI-readable explanation of what was approved. */
    note: string;
};

/**
 * Structured result envelope returned by capability calls when constraintAware
 * mode is enabled. Gives AI agents full visibility into the permission lifecycle.
 */
export type ConstraintAwareResult<T = unknown> = {
    /** Whether the capability call ultimately succeeded. */
    success: boolean;
    /** The actual capability result (present when success=true). */
    result?: T;
    /** The permission/constraint status of this call. */
    permission: PermissionStatus;
    /** Structured details about constraint violations (when permission !== "not_required"). */
    violations?: ConstraintViolationDetail[];
    /** Details about the permission grant (when permission === "approved"). */
    grant?: PermissionGrant;
    /** AI-readable guidance on what to do next. */
    guidance: string;
    /** The capability that was called. */
    capability: string;
    /** The active constraints on this capability (so the agent knows what IS allowed). */
    activeConstraints?: Record<string, unknown>;
};
