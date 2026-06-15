/** Validates call args against grant constraints (max/min/in/not_in/exact). Throws constraint_violated on failure. */

import { ChainAuthError } from "../errors/chain-error.js";
import type { GrantConstraints, ConstraintValue, ConstraintOperator, ConstraintPrimitive, JsonSchemaObject, ConstraintViolationDetail } from "../types/capabilities.js";

type ViolationPair = {
    message: string;
    detail: ConstraintViolationDetail;
};

export function enforceConstraints(
    constraints: GrantConstraints,
    args: Record<string, unknown>,
    inputSchema?: JsonSchemaObject
): void {
    const violations: ViolationPair[] = [];
    const requiredFields = inputSchema?.required ?? [];

    for (const [field, constraint] of Object.entries(constraints)) {
        const value = args[field];

        if (value === undefined) {
            if (requiredFields.includes(field)) {
                const msg = `field "${field}" is required but was not provided`;
                violations.push({
                    message: msg,
                    detail: { field, constraint: "exact", expected: "(required)", actual: undefined, message: msg },
                });
            }
            continue;
        }

        const violation = checkConstraint(field, value, constraint);
        if (violation) violations.push(violation);
    }

    if (violations.length > 0) {
        throw new ChainAuthError(
            "constraint_violated",
            `Capability argument constraints violated: ${violations.map((v) => v.message).join("; ")}`,
            violations.map((v) => v.message),
            violations.map((v) => v.detail)
        );
    }
}

function checkConstraint(
    field: string,
    value: unknown,
    constraint: ConstraintValue
): ViolationPair | null {
    // Operator constraint
    if (isConstraintOperator(constraint)) {
        return checkOperator(field, value, constraint);
    }

    // Primitive constraint — exact equality
    if (value !== constraint) {
        const msg = `field "${field}": expected exactly ${JSON.stringify(constraint)}, got ${JSON.stringify(value)}`;
        return {
            message: msg,
            detail: { field, constraint: "exact", expected: constraint, actual: value, message: msg },
        };
    }

    return null;
}

function isConstraintOperator(value: ConstraintValue): value is ConstraintOperator {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkOperator(
    field: string,
    value: unknown,
    op: ConstraintOperator
): ViolationPair | null {
    if (op.max !== undefined) {
        if (typeof value !== "number") {
            const msg = `field "${field}": max constraint requires a number, got ${typeof value}`;
            return { message: msg, detail: { field, constraint: "max", expected: op.max, actual: value, message: msg } };
        }
        if (value > op.max) {
            const msg = `field "${field}": ${value} exceeds maximum of ${op.max}`;
            return { message: msg, detail: { field, constraint: "max", expected: op.max, actual: value, message: msg } };
        }
    }

    if (op.min !== undefined) {
        if (typeof value !== "number") {
            const msg = `field "${field}": min constraint requires a number, got ${typeof value}`;
            return { message: msg, detail: { field, constraint: "min", expected: op.min, actual: value, message: msg } };
        }
        if (value < op.min) {
            const msg = `field "${field}": ${value} is below minimum of ${op.min}`;
            return { message: msg, detail: { field, constraint: "min", expected: op.min, actual: value, message: msg } };
        }
    }

    if (op.in !== undefined) {
        if (!isPrimitive(value)) {
            const msg = `field "${field}": in constraint requires a primitive value, got ${typeof value}`;
            return { message: msg, detail: { field, constraint: "in", expected: op.in, actual: value, message: msg } };
        }
        if (!op.in.includes(value as ConstraintPrimitive)) {
            const msg = `field "${field}": "${value}" is not in allowed list [${op.in.map((v) => JSON.stringify(v)).join(", ")}]`;
            return { message: msg, detail: { field, constraint: "in", expected: op.in, actual: value, message: msg } };
        }
    }

    if (op.not_in !== undefined) {
        if (!isPrimitive(value)) {
            const msg = `field "${field}": not_in constraint requires a primitive value, got ${typeof value}`;
            return { message: msg, detail: { field, constraint: "not_in", expected: op.not_in, actual: value, message: msg } };
        }
        if (op.not_in.includes(value as ConstraintPrimitive)) {
            const msg = `field "${field}": "${value}" is in blocked list [${op.not_in.map((v) => JSON.stringify(v)).join(", ")}]`;
            return { message: msg, detail: { field, constraint: "not_in", expected: op.not_in, actual: value, message: msg } };
        }
    }

    return null;
}

function isPrimitive(value: unknown): value is ConstraintPrimitive {
    return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}
