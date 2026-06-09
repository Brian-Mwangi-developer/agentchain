
export type AuditResult = "success" | "denied" | "error";

export type AuditEntry = {
    id: string;
    agentId: string;
    agentName: string;
    hostname: string;
    /**
     * The thumbprint of the Host that registered this agent.
     * Enables per-host audit attribution in multi-host deployments.
     * Previously absent — audit entries could not be traced to a specific Host.
     */
    hostThumbprint: string;
    capability: string;
    args: Record<string, unknown>;
    result: AuditResult;
    denialReason?: string;
    errorMessage?: string;
    jti: string;
    timestamp: number;
    durationMs: number;
    /** Auth pipeline overhead in milliseconds (build + verify JWT). */
    authOverheadMs: number;
};
