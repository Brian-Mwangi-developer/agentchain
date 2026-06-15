/**
 * ChainAuthError — thrown when an agent call is blocked by agents-chain.
 *
 * error codes:
 *   "capability_denied"   — agent does not hold a grant for this capability
 *   "constraint_violated" — capability args violate a constraint
 *   "token_replayed"      — JWT ID has already been used (replay attack)
 *   "token_expired"       — JWT exp has passed
 *   "token_invalid"       — JWT is structurally or cryptographically invalid
 *   "agent_not_found"     — agentId in the JWT does not match registered agent
 */

import type { ConstraintViolationDetail } from "../types/capabilities.js";

export type ChainErrorCode =
    | "capability_denied"
    | "constraint_violated"
    | "token_replayed"
    | "token_expired"
    | "token_invalid"
    | "agent_not_found"
    | "access_request_pending"
    | "access_request_denied"
    | "access_request_expired";

export class ChainAuthError extends Error {
    readonly code: ChainErrorCode;
    readonly violations?: string[];
    /** Structured violation details for constraint-aware mode. */
    readonly structuredViolations?: ConstraintViolationDetail[];

    constructor(code: ChainErrorCode, message: string, violations?: string[], structuredViolations?: ConstraintViolationDetail[]) {
        super(message);
        this.name = "ChainAuthError";
        this.code = code;
        this.violations = violations;
        this.structuredViolations = structuredViolations;
        // Maintain proper prototype chain for instanceof checks
        Object.setPrototypeOf(this, ChainAuthError.prototype);
    }
}

export function isChainAuthError(e: unknown): e is ChainAuthError {
    if (e instanceof ChainAuthError) return true;
    return (
        typeof e === "object" &&
        e !== null &&
        (e as Record<string, unknown>)["name"] === "ChainAuthError" &&
        typeof (e as Record<string, unknown>)["code"] === "string" &&
        typeof (e as Record<string, unknown>)["message"] === "string"
    );
}
