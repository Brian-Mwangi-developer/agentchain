/** AccessRequestManager — creates HMAC-signed access requests, tracks pending calls, verifies approval codes. */

import { createHmac, randomBytes } from "node:crypto";
import { generateId } from "../crypto/utils.js";
import type {
    AccessRequest,
    AccessRequestConfig,
    AccessRequestNotifier,
    ApprovalDecision,
    DenialDecision,
    SuspendedCall,
} from "../types/access-request.js";

const DEFAULT_REQUEST_TTL_MS = 5 * 60 * 1000;
const DEFAULT_MAX_PENDING = 10;
const HMAC_ALGORITHM = "sha256";
const CODE_LENGTH = 8;

export class AccessRequestManager {
    private readonly secret: Buffer;
    private readonly notifier: AccessRequestNotifier;
    private readonly requestTTLMs: number;
    private readonly maxPendingPerAgent: number;
    private readonly blockOnExcess: boolean;

    readonly approvalSecret: Buffer;
    private readonly pending = new Map<string, AccessRequest>();
    private readonly suspended = new Map<string, SuspendedCall>();
    private readonly expiryTimer: ReturnType<typeof setInterval>;

    constructor(config: AccessRequestConfig) {
        this.notifier = config.notifier;
        this.requestTTLMs = config.requestTTLMs ?? DEFAULT_REQUEST_TTL_MS;
        this.maxPendingPerAgent = config.maxPendingPerAgent ?? DEFAULT_MAX_PENDING;
        this.blockOnExcess = config.blockOnExcessRequests ?? false;

        this.secret = config.approvalSecret
            ? Buffer.from(config.approvalSecret, "utf8")
            : randomBytes(32);
        this.approvalSecret = this.secret;

        this.expiryTimer = setInterval(() => this.sweepExpired(), 30_000);
        if (this.expiryTimer.unref) this.expiryTimer.unref();
    }

    destroy(): void {
        clearInterval(this.expiryTimer);
        for (const [, suspended] of this.suspended) {
            suspended.reject(new Error("AccessRequestManager destroyed — pending request cancelled"));
        }
        this.suspended.clear();
        this.pending.clear();
    }

    /**
     * Create an access request and notify the human.
     * Returns a Promise that resolves when the human approves, or rejects on deny/expire.
     */
    async createRequest(params: {
        agentId: string;
        agentName: string;
        hostId: string;
        capability: string;
        args: Record<string, unknown>;
        reason: string;
        errorCode: "constraint_violated" | "capability_denied";
        violatedField?: string;
        violatedValue?: unknown;
    }): Promise<{ request: AccessRequest; waitForApproval: Promise<unknown> }> {
        const agentPending = this.getPendingForAgent(params.agentId);
        if (agentPending.length >= this.maxPendingPerAgent) {
            if (this.blockOnExcess) {
                throw new Error(
                    `Agent "${params.agentId}" has too many pending access requests (${agentPending.length}).`
                );
            }
            const oldest = agentPending[0]!;
            this.expireRequest(oldest.requestId);
        }

        const requestId = generateId("areq");
        const createdAt = Date.now();
        const expiresAt = createdAt + this.requestTTLMs;
        const verificationCode = this.generateCode(requestId, params.agentId, params.capability, createdAt);

        const request: AccessRequest = {
            requestId,
            agentId: params.agentId,
            agentName: params.agentName,
            hostId: params.hostId,
            capability: params.capability,
            args: params.args,
            reason: params.reason,
            violatedField: params.violatedField,
            violatedValue: params.violatedValue,
            errorCode: params.errorCode,
            createdAt,
            expiresAt,
            status: "pending",
            verificationCode,
        };

        this.pending.set(requestId, request);

        const waitForApproval = new Promise<unknown>((resolve, reject) => {
            this.suspended.set(requestId, {
                requestId,
                capability: params.capability,
                args: params.args,
                suspendedAt: Date.now(),
                resolve,
                reject,
            });
        });

        this.notifier.notify(request).catch((err) => {
            console.error(`[agents-chain] Failed to send access request notification: ${err}`);
        });

        return { request, waitForApproval };
    }

    /**
     * Approve a pending access request after HMAC verification.
     * Returns the original request (now marked approved).
     */
    approve(decision: ApprovalDecision): AccessRequest {
        const request = this.pending.get(decision.requestId);
        if (!request) {
            throw new Error(`Access request "${decision.requestId}" not found or already resolved`);
        }
        if (request.status !== "pending") {
            throw new Error(`Access request "${decision.requestId}" is already ${request.status}`);
        }
        if (Date.now() > request.expiresAt) {
            this.expireRequest(decision.requestId);
            throw new Error(`Access request "${decision.requestId}" has expired`);
        }
        if (!this.verifyCode(decision.code, request)) {
            throw new Error("Invalid verification code — approval denied");
        }

        request.status = "approved";

        const suspended = this.suspended.get(decision.requestId);
        if (suspended) {
            suspended.resolve({ approved: true, decision });
        }

        this.pending.delete(decision.requestId);
        this.suspended.delete(decision.requestId);
        this.notifier.onResolved?.(request, "approved").catch(() => {});

        return request;
    }

    /** Deny a pending access request after HMAC verification. */
    deny(decision: DenialDecision): AccessRequest {
        const request = this.pending.get(decision.requestId);
        if (!request) {
            throw new Error(`Access request "${decision.requestId}" not found or already resolved`);
        }
        if (request.status !== "pending") {
            throw new Error(`Access request "${decision.requestId}" is already ${request.status}`);
        }
        if (!this.verifyCode(decision.code, request)) {
            throw new Error("Invalid verification code — denial rejected");
        }

        request.status = "denied";

        const suspended = this.suspended.get(decision.requestId);
        if (suspended) {
            suspended.reject(
                new Error(`Access request denied${decision.reason ? `: ${decision.reason}` : ""}`)
            );
        }

        this.pending.delete(decision.requestId);
        this.suspended.delete(decision.requestId);
        this.notifier.onResolved?.(request, "denied").catch(() => {});

        return request;
    }

    getPending(requestId: string): AccessRequest | undefined {
        return this.pending.get(requestId);
    }

    getPendingForAgent(agentId: string): AccessRequest[] {
        return [...this.pending.values()].filter((r) => r.agentId === agentId && r.status === "pending");
    }

    getAllPending(): AccessRequest[] {
        return [...this.pending.values()].filter((r) => r.status === "pending");
    }

    private generateCode(requestId: string, agentId: string, capability: string, createdAt: number): string {
        const input = `${requestId}:${agentId}:${capability}:${createdAt}`;
        const hmac = createHmac(HMAC_ALGORITHM, this.secret).update(input).digest("hex");
        return hmac.slice(0, CODE_LENGTH).toUpperCase();
    }

    private verifyCode(submittedCode: string, request: AccessRequest): boolean {
        const expected = this.generateCode(
            request.requestId,
            request.agentId,
            request.capability,
            request.createdAt
        );
        if (submittedCode.length !== expected.length) return false;
        let diff = 0;
        for (let i = 0; i < expected.length; i++) {
            diff |= submittedCode.charCodeAt(i) ^ expected.charCodeAt(i);
        }
        return diff === 0;
    }

    private sweepExpired(): void {
        const now = Date.now();
        for (const [id, request] of this.pending) {
            if (request.status === "pending" && now > request.expiresAt) {
                this.expireRequest(id);
            }
        }
    }

    private expireRequest(requestId: string): void {
        const request = this.pending.get(requestId);
        if (!request) return;

        request.status = "expired";

        const suspended = this.suspended.get(requestId);
        if (suspended) {
            suspended.reject(new Error(`Access request "${requestId}" expired — no approval received in time`));
        }

        this.pending.delete(requestId);
        this.suspended.delete(requestId);
        this.notifier.onResolved?.(request, "expired").catch(() => {});
    }
}
