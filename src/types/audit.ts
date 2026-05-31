
export type AuditResult = "success" | "denied" | "error";

export type AuditEntry = {
    id: string;
    agentId: string;
    agentName: string;
    hostname: string;
    capability: string;
    args: Record<string, unknown>;
    result: AuditResult;
    denialReason?: string;
    errorMessage?: string;
    jti: string;
    timestamp: number;
    durationMs: number;
};
