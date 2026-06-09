/** Validates call args against grant constraints (max/min/in/not_in/exact). Throws constraint_violated on failure. */

import { ChainAuthError } from "../errors/chain-error.js";
import type { GrantConstraints, ConstraintValue, ConstraintOperator, ConstraintPrimitive } from "../types/capabilities.js";

export function enforceConstraints(
    constraints: GrantConstraints,
    args: Record<string, unknown>
): void {
    const violations: string[] = [];

    for (const [field, constraint] of Object.entries(constraints)) {
        const value = args[field];

        // Field not present in args — skip (constraint only applies when field is provided)
        if (value === undefined) continue;

        const violation = checkConstraint(field, value, constraint);
        if (violation) violations.push(violation);
    }

    if (violations.length > 0) {
        throw new ChainAuthError(
            "constraint_violated",
            `Capability argument constraints violated: ${violations.join("; ")}`
        );
    }
}

function checkConstraint(
    field: string,
    value: unknown,
    constraint: ConstraintValue
): string | null {
    // Operator constraint
    if (isConstraintOperator(constraint)) {
        return checkOperator(field, value, constraint);
    }

    // Primitive constraint — exact equality
    if (value !== constraint) {
        return `field "${field}": expected exactly ${JSON.stringify(constraint)}, got ${JSON.stringify(value)}`;
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
): string | null {
    if (op.max !== undefined) {
        if (typeof value !== "number") {
            return `field "${field}": max constraint requires a number, got ${typeof value}`;
        }
        if (value > op.max) {
            return `field "${field}": ${value} exceeds maximum of ${op.max}`;
        }
    }

    if (op.min !== undefined) {
        if (typeof value !== "number") {
            return `field "${field}": min constraint requires a number, got ${typeof value}`;
        }
        if (value < op.min) {
            return `field "${field}": ${value} is below minimum of ${op.min}`;
        }
    }

    if (op.in !== undefined) {
        if (!isPrimitive(value)) {
            return `field "${field}": in constraint requires a primitive value, got ${typeof value}`;
        }
        if (!op.in.includes(value as ConstraintPrimitive)) {
            return `field "${field}": "${value}" is not in allowed list [${op.in.map((v) => JSON.stringify(v)).join(", ")}]`;
        }
    }

    if (op.not_in !== undefined) {
        if (!isPrimitive(value)) {
            return `field "${field}": not_in constraint requires a primitive value, got ${typeof value}`;
        }
        if (op.not_in.includes(value as ConstraintPrimitive)) {
            return `field "${field}": "${value}" is in blocked list [${op.not_in.map((v) => JSON.stringify(v)).join(", ")}]`;
        }
    }

    return null;
}

function isPrimitive(value: unknown): value is ConstraintPrimitive {
    return typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}
