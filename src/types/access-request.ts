/** Access Request types — agent-initiated permission escalation with out-of-band human verification. */

import type { GrantConstraints } from "./capabilities.js";

// ─── Approval Scope ──────────────────────────────────────────────────────────

/**
 * Controls how broadly an approval applies:
 *
 * - "call"       → one-time: approve this exact call only, then discard.
 * - "value"      → session: approve this specific constraint value for the session
 *                   (e.g. allow "+1234567890" for the rest of the session).
 * - "capability" → session: approve the entire capability with relaxed constraints
 *                   for the session.
 * - "global"     → persistent: approve for ALL agents that hit this constraint,
 *                   stored encrypted and survives restart.
 */
export type ApprovalScope = "call" | "value" | "capability" | "global";

/**
 * Optional TTL for approvals. If not provided:
 * - "call" scope: expires after a single use.
 * - "value"/"capability" scope: expires when the session ends.
 * - "global" scope: never expires (until explicitly revoked).
 */
export type ApprovalTTL = {
    /** Duration in milliseconds. */
    durationMs?: number;
    /** Absolute expiry timestamp (Unix ms). Takes precedence over durationMs. */
    expiresAt?: number;
};

// ─── Access Request ──────────────────────────────────────────────────────────

export type AccessRequestStatus = "pending" | "approved" | "denied" | "expired";

export type AccessRequest = {
    /** Unique request ID — used to correlate notification → approval. */
    requestId: string;
    /** Agent that triggered the request. */
    agentId: string;
    agentName: string;
    /** Host that owns this chain. */
    hostId: string;
    /** The capability the agent tried to use. */
    capability: string;
    /** The args that triggered the violation. */
    args: Record<string, unknown>;
    /** Why the request was created (constraint violation message, denial reason). */
    reason: string;
    /** The specific constraint field that was violated (if applicable). */
    violatedField?: string;
    /** The violated constraint value (e.g. the number not in the whitelist). */
    violatedValue?: unknown;
    /** The error code that triggered this request. */
    errorCode: "constraint_violated" | "capability_denied";
    /** When the request was created. */
    createdAt: number;
    /** When the request expires (pending requests auto-expire). */
    expiresAt: number;
    /** Current status. */
    status: AccessRequestStatus;
    /**
     * HMAC of (requestId + agentId + capability + createdAt) using the host's
     * approval secret. The agent never sees this secret, so it cannot forge
     * an approval code. This is sent to the human via the notification channel.
     */
    verificationCode: string;
};

// ─── Approval Decision ───────────────────────────────────────────────────────

export type ApprovalDecision = {
    requestId: string;
    /** The verification code the human received out-of-band. */
    code: string;
    /** How broadly to apply this approval. */
    scope: ApprovalScope;
    /** Optional TTL override. */
    ttl?: ApprovalTTL;
    /** Optional: expand constraints instead of removing them.
     *  e.g. { "to": { in: ["+1234567890"] } } — adds this value to the whitelist. */
    expandConstraints?: GrantConstraints;
};

export type DenialDecision = {
    requestId: string;
    /** The verification code. */
    code: string;
    /** Optional reason for denial (recorded in audit). */
    reason?: string;
};

// ─── Stored Approval Rule ────────────────────────────────────────────────────

/** A rule stored in the ApprovalStore that allows future calls without re-prompting. */
export type ApprovalRule = {
    ruleId: string;
    /** Which capability this rule applies to. */
    capability: string;
    scope: ApprovalScope;
    /** The specific field + value approved (for "value" scope). */
    field?: string;
    value?: unknown;
    /** Expanded constraints (merged into the grant's constraints). */
    expandedConstraints?: GrantConstraints;
    /** Who approved this. */
    approvedBy: string; // requestId that created this rule
    /** When this rule was created. */
    createdAt: number;
    /** When this rule expires (undefined = session-scoped or never). */
    expiresAt?: number;
    /** If true, this rule applies to all agents, not just the one that requested it. */
    global: boolean;
};

// ─── Notification Adapter ────────────────────────────────────────────────────

/**
 * Pluggable notification channel — implement this to send access requests
 * via email, SMS, push notification, webhook, Slack, etc.
 *
 * The adapter is ONLY responsible for delivering the notification.
 * It does NOT handle approval — that comes back through AppChain.approve().
 */
export interface AccessRequestNotifier {
    /**
     * Send a notification to the human operator.
     * The `request` contains the `verificationCode` that the human must
     * submit back to approve.
     */
    notify(request: AccessRequest): Promise<void>;

    /**
     * Optional: called when a request is resolved (approved/denied/expired).
     * Useful for updating a UI or closing a notification.
     */
    onResolved?(request: AccessRequest, outcome: "approved" | "denied" | "expired"): Promise<void>;
}

// ─── Suspended Call Context ──────────────────────────────────────────────────

/**
 * Captured when a call is suspended waiting for approval.
 * Contains everything needed to resume the call exactly where it left off.
 */
export type SuspendedCall = {
    requestId: string;
    capability: string;
    args: Record<string, unknown>;
    /** Timestamp when the call was suspended. */
    suspendedAt: number;
    /** Resolve the suspended promise (call resumes). */
    resolve: (result: unknown) => void;
    /** Reject the suspended promise (call fails). */
    reject: (error: Error) => void;
};

// ─── Access Request Config ───────────────────────────────────────────────────

export type AccessRequestConfig = {
    /** The notification adapter (email, SMS, webhook, etc.). */
    notifier: AccessRequestNotifier;
    /**
     * The approval secret — HMAC key used to sign verification codes.
     * MUST be kept outside the agent's reach (env var, KMS, separate service).
     * 32+ bytes recommended. If not provided, a random one is generated.
     */
    approvalSecret?: string;
    /** How long a pending request stays valid before expiring (ms). Default: 5 minutes. */
    requestTTLMs?: number;
    /** Maximum number of pending requests per agent. Default: 10. */
    maxPendingPerAgent?: number;
    /** Whether to auto-block agents that exceed maxPending (potential abuse). Default: false. */
    blockOnExcessRequests?: boolean;
};
