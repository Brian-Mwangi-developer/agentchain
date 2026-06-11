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
