/**
 * Built-in `request_permission` capability — auto-registered when both
 * `constraintAware` and `accessRequests` are enabled on AppChain.
 *
 * Flow:
 *   1. Agent calls a capability → receives ConstraintAwareResult with violation
 *   2. Agent calls request_permission({ capability, args, reason })
 *   3. This suspends until human approves/denies
 *   4. On approval: creates approval rule, re-executes the original capability
 *   5. Returns ConstraintAwareResult with the outcome
 */

import { ChainAuthError } from "../errors/chain-error.js";
import { enforceConstraints } from "../auth/constraints.js";
import { getEffectiveConstraints } from "./app-wrapper.js";
import type { Capability, ConstraintAwareResult, PermissionGrant, AgentContext } from "../types/capabilities.js";
import type { CapabilityRegistry } from "./capability-registry.js";
import type { AccessRequestManager } from "../access/access-request-manager.js";
import type { ApprovalStore } from "../access/approval-store.js";
import type { AuditLog } from "../audit/audit-log.js";
import type { TokenBuilder } from "../auth/token-builder.js";
import type { TokenVerifier } from "../auth/token-verifier.js";
import type { AgentIdentity } from "../identity/agent-identity.js";
import type { ResolvedGrant } from "../types/protocol.js";
import type { ApprovalDecision } from "../types/access-request.js";

export type RequestPermissionInput = {
    /** The capability the agent wants permission to call. */
    capability: string;
    /** The exact args to execute if approved. */
    args: Record<string, unknown>;
    /** Why the agent needs this permission (shown to the human operator). */
    reason?: string;
};

export type RequestPermissionContext = {
    identity: AgentIdentity;
    builder: TokenBuilder;
    verifier: TokenVerifier;
    log: AuditLog;
    grants: ResolvedGrant[];
    registry: CapabilityRegistry;
    accessRequestManager: AccessRequestManager;
    approvalStore: ApprovalStore;
};

/** Creates the built-in request_permission Capability. */
export function createRequestPermissionCapability(
    rpCtx: RequestPermissionContext
): Capability<RequestPermissionInput, ConstraintAwareResult> {
    return {
        name: "request_permission",
        description:
            "Request human approval to execute a capability that was blocked by a constraint violation. " +
            "Call this after receiving a constraint_violated result. Provide the capability name, the exact " +
            "args you want to execute, and optionally a reason explaining why you need this permission. " +
            "The request will be sent to a human operator for review. This call will wait until the human " +
            "approves or denies the request.",
        inputSchema: {
            type: "object",
            properties: {
                capability: {
                    type: "string",
                    description: "The name of the capability to request permission for (e.g. 'send_sms')",
                },
                args: {
                    type: "object",
                    description: "The exact arguments to pass to the capability if approved",
                },
                reason: {
                    type: "string",
                    description: "Why you need this permission — shown to the human operator",
                },
            },
            required: ["capability", "args"],
        },
        outputSchema: {
            type: "object",
            properties: {
                success: { type: "boolean" },
                permission: { type: "string" },
                result: {},
                violations: { type: "array" },
                grant: { type: "object" },
                guidance: { type: "string" },
                capability: { type: "string" },
            },
        },
        execute: async (params: RequestPermissionInput, _agentContext: AgentContext): Promise<ConstraintAwareResult> => {
            const { capability: targetCapability, args: targetArgs, reason } = params;

            const registryEntry = rpCtx.registry.get(targetCapability);
            if (!registryEntry) {
                return {
                    success: false,
                    permission: "denied",
                    guidance: `Capability "${targetCapability}" does not exist. Check the available capabilities and try again.`,
                    capability: targetCapability,
                };
            }

            if (targetCapability === "request_permission") {
                return {
                    success: false,
                    permission: "denied",
                    guidance: `Cannot request permission for "request_permission" — this is a system capability.`,
                    capability: targetCapability,
                };
            }

            const grant = rpCtx.grants.find(
                (g) => g.capability === targetCapability && g.status === "active"
            );

            let violatedField: string | undefined;
            let violatedValue: unknown;
            let errorCode: "constraint_violated" | "capability_denied" = "constraint_violated";
            let violationReason = reason ?? `Agent requested permission for ${targetCapability}`;

            if (grant?.constraints) {
                const effectiveConstraints = getEffectiveConstraints(
                    targetCapability, grant.constraints, rpCtx.approvalStore
                );

                if (effectiveConstraints) {
                    try {
                        enforceConstraints(effectiveConstraints, targetArgs, registryEntry.inputSchema);
                        return await executeAndReturnResult(targetCapability, targetArgs, rpCtx, registryEntry);
                    } catch (constraintErr) {
                        if (constraintErr instanceof ChainAuthError && constraintErr.structuredViolations?.length) {
                            const firstViolation = constraintErr.structuredViolations[0]!;
                            violatedField = firstViolation.field;
                            violatedValue = firstViolation.actual;
                            violationReason = constraintErr.message;
                        }
                    }
                } else {
                    return await executeAndReturnResult(targetCapability, targetArgs, rpCtx, registryEntry);
                }
            } else if (!grant) {
                errorCode = "capability_denied";
                violationReason = `Agent does not have an active grant for "${targetCapability}"`;
            }

            const { request, waitForApproval } = await rpCtx.accessRequestManager.createRequest({
                agentId: rpCtx.identity.agentId,
                agentName: rpCtx.identity.registration.agentName,
                hostId: rpCtx.identity.registration.hostThumbprint,
                capability: targetCapability,
                args: targetArgs,
                reason: violationReason,
                errorCode,
                violatedField,
                violatedValue,
            });

            rpCtx.log.recordAccessRequested({
                agentId: rpCtx.identity.agentId,
                agentName: rpCtx.identity.registration.agentName,
                hostname: rpCtx.identity.registration.hostname,
                hostThumbprint: rpCtx.identity.registration.hostThumbprint,
                capability: targetCapability,
                args: targetArgs,
                reason: violationReason,
                accessRequestId: request.requestId,
            });

            try {
                const approvalResult = await waitForApproval as {
                    approved: boolean;
                    decision: ApprovalDecision;
                };

                if (!approvalResult.approved) {
                    rpCtx.log.recordAccessResolved({
                        agentId: rpCtx.identity.agentId,
                        agentName: rpCtx.identity.registration.agentName,
                        hostname: rpCtx.identity.registration.hostname,
                        hostThumbprint: rpCtx.identity.registration.hostThumbprint,
                        capability: targetCapability,
                        args: targetArgs,
                        accessRequestId: request.requestId,
                        resolution: "access_denied",
                    });

                    return {
                        success: false,
                        permission: "denied",
                        guidance: `Permission request for "${targetCapability}" was denied. Do not retry with the same parameters unless you have reason to believe the decision may change.`,
                        capability: targetCapability,
                    };
                }

                const rule = rpCtx.approvalStore.createRule(request, approvalResult.decision);

                let result: unknown;
                try {
                    result = await executeCapabilityDirect(targetCapability, targetArgs, rpCtx, registryEntry);
                } catch (execErr) {
                    if (approvalResult.decision.scope === "call") {
                        rpCtx.approvalStore.revokeRule(rule.ruleId);
                    }
                    return {
                        success: false,
                        permission: "approved",
                        guidance: `Permission was granted but the capability execution failed: ${execErr instanceof Error ? execErr.message : String(execErr)}`,
                        capability: targetCapability,
                    };
                }

                if (approvalResult.decision.scope === "call") {
                    rpCtx.approvalStore.revokeRule(rule.ruleId);
                }

                rpCtx.log.recordAccessResolved({
                    agentId: rpCtx.identity.agentId,
                    agentName: rpCtx.identity.registration.agentName,
                    hostname: rpCtx.identity.registration.hostname,
                    hostThumbprint: rpCtx.identity.registration.hostThumbprint,
                    capability: targetCapability,
                    args: targetArgs,
                    accessRequestId: request.requestId,
                    resolution: "access_approved",
                    approvalScope: approvalResult.decision.scope,
                });

                const permGrant: PermissionGrant = {
                    scope: approvalResult.decision.scope,
                    field: violatedField,
                    value: violatedValue,
                    note: buildGrantNote(approvalResult.decision.scope, targetCapability, violatedField, violatedValue),
                };

                return {
                    success: true,
                    result,
                    permission: "approved",
                    grant: permGrant,
                    guidance: buildApprovedGuidance(approvalResult.decision.scope, targetCapability, violatedField, violatedValue),
                    capability: targetCapability,
                };
            } catch (waitErr) {
                const errMsg = waitErr instanceof Error ? waitErr.message : String(waitErr);

                rpCtx.log.recordAccessResolved({
                    agentId: rpCtx.identity.agentId,
                    agentName: rpCtx.identity.registration.agentName,
                    hostname: rpCtx.identity.registration.hostname,
                    hostThumbprint: rpCtx.identity.registration.hostThumbprint,
                    capability: targetCapability,
                    args: targetArgs,
                    accessRequestId: request.requestId,
                    resolution: errMsg.includes("expired") ? "access_denied" : "access_denied",
                });

                if (errMsg.includes("expired")) {
                    return {
                        success: false,
                        permission: "expired",
                        guidance: `The permission request for "${targetCapability}" expired without a response. You may call request_permission again to create a new request.`,
                        capability: targetCapability,
                    };
                }

                return {
                    success: false,
                    permission: "denied",
                    guidance: `Permission request for "${targetCapability}" was denied: ${errMsg}. Do not retry with the same parameters unless instructed by the user.`,
                    capability: targetCapability,
                };
            }
        },
    };
}

/** Execute a capability directly and return a ConstraintAwareResult. */
async function executeAndReturnResult(
    capabilityName: string,
    args: Record<string, unknown>,
    rpCtx: RequestPermissionContext,
    registryEntry: Capability
): Promise<ConstraintAwareResult> {
    const result = await executeCapabilityDirect(capabilityName, args, rpCtx, registryEntry);
    return {
        success: true,
        result,
        permission: "approved",
        guidance: `The call to "${capabilityName}" succeeded — the constraints were already satisfied (possibly by a prior approval).`,
        capability: capabilityName,
    };
}

/**
 * Execute a capability directly, bypassing the proxy wrapper.
 * Used after approval to run the actual capability with the approved args.
 */
async function executeCapabilityDirect(
    capabilityName: string,
    args: Record<string, unknown>,
    rpCtx: RequestPermissionContext,
    registryEntry: Capability
): Promise<unknown> {
    const { token } = await rpCtx.builder.build(capabilityName);
    const verified = await rpCtx.verifier.verify(token, capabilityName, rpCtx.grants);

    const agentContext: AgentContext = {
        agentId: verified.agentId,
        hostId: verified.hostThumbprint,
        permissions: rpCtx.grants
            .filter((g) => g.status === "active")
            .map((g) => g.capability),
    };

    const grant = rpCtx.grants.find(
        (g) => g.capability === capabilityName && g.status === "active"
    );
    if (grant?.constraints) {
        const effectiveConstraints = getEffectiveConstraints(
            capabilityName, grant.constraints, rpCtx.approvalStore
        );
        if (effectiveConstraints) {
            enforceConstraints(effectiveConstraints, args, registryEntry.inputSchema);
        }
    }

    if (!registryEntry.execute) {
        throw new Error(`Capability "${capabilityName}" has no execute function`);
    }

    const callStart = Date.now();
    const result = await registryEntry.execute(args, agentContext);

    rpCtx.log.recordCall({
        context: verified,
        args,
        result: "success",
        durationMs: Date.now() - callStart,
        authOverheadMs: 0,
    });

    return result;
}

function buildGrantNote(scope: string, capability: string, field?: string, value?: unknown): string {
    switch (scope) {
        case "call":
            return `This single call to "${capability}" was approved. The approval has been consumed and will not apply to future calls.`;
        case "value":
            return `The value ${JSON.stringify(value)} for field "${field}" on "${capability}" has been approved for this session.`;
        case "capability":
            return `All constraint restrictions on "${capability}" have been lifted for this session.`;
        case "global":
            return `All constraint restrictions on "${capability}" have been permanently lifted.`;
        default:
            return `Permission granted for "${capability}" with scope "${scope}".`;
    }
}

function buildApprovedGuidance(scope: string, capability: string, field?: string, value?: unknown): string {
    switch (scope) {
        case "call":
            return `Human operator approved this specific call to "${capability}". The approval was single-use and has been consumed. If you need to make another call that violates constraints, you must request permission again.`;
        case "value":
            return `Human operator approved the value ${JSON.stringify(value)} for field "${field}" on "${capability}" for this session. You can now make additional calls with this value without requesting permission again.`;
        case "capability":
            return `Human operator approved unrestricted access to "${capability}" for this session. All constraints have been lifted.`;
        case "global":
            return `Human operator granted permanent unrestricted access to "${capability}". All constraints have been permanently lifted.`;
        default:
            return `Permission granted for "${capability}".`;
    }
}
