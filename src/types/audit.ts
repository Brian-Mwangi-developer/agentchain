
export type AuditResult = "success" | "denied" | "error" | "access_requested" | "access_approved" | "access_denied";

export type AuditEntry = {
    id: string;
    agentId: string;
    agentName: string;
    hostname: string;
    hostThumbprint: string;
    capability: string;
    args: Record<string, unknown>;
    result: AuditResult;
    denialReason?: string;
    errorMessage?: string;
    jti: string;
    timestamp: number;
    durationMs: number;
    authOverheadMs: number;
    /** Set when result is access_requested/access_approved/access_denied. */
    accessRequestId?: string;
    /** The approval scope that was applied (for access_approved). */
    approvalScope?: import("./access-request.js").ApprovalScope;
};
