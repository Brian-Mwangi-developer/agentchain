import type { AgentConfig } from "./identity.js";
import type { AuditEntry } from "./audit.js";

export type { AgentConfig };

export type ChainStats = {
    agentId: string;
    agentName: string;
    hostname: string;
    totalCalls: number;
    successfulCalls: number;
    deniedCalls: number;
    errorCalls: number;
    registeredAt: number;
};

export type AuditSnapshot = {
    agentId: string;
    entries: AuditEntry[];
    exportedAt: number;
};
