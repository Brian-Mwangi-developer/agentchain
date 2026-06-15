/** ApprovalStore — encrypted store for approval rules. Only the AccessRequestManager (via verified HMAC codes) can create rules. */

import { createHmac } from "node:crypto";
import { generateId } from "../crypto/utils.js";
import type { EncryptedStore } from "../memory/encrypted-store.js";
import type { AccessRequest, ApprovalDecision, ApprovalRule } from "../types/access-request.js";
import type { ConstraintOperator, ConstraintPrimitive, GrantConstraints } from "../types/capabilities.js";

const STORE_KEY = "approval_rules";
const INTEGRITY_KEY = "approval_rules_integrity";

export class ApprovalStore {
    private readonly store: EncryptedStore;
    private readonly secret: Buffer;
    private rules: ApprovalRule[] = [];

    constructor(store: EncryptedStore, secret: Buffer) {
        this.store = store;
        this.secret = secret;
        this.load();
    }

    /** Called after HMAC-verified approval. Creates the appropriate rule based on the approval scope. */
    createRule(request: AccessRequest, decision: ApprovalDecision): ApprovalRule {
        const now = Date.now();
        let expiresAt: number | undefined;

        if (decision.ttl?.expiresAt) {
            expiresAt = decision.ttl.expiresAt;
        } else if (decision.ttl?.durationMs) {
            expiresAt = now + decision.ttl.durationMs;
        }

        const rule: ApprovalRule = {
            ruleId: generateId("arule"),
            capability: request.capability,
            scope: decision.scope,
            approvedBy: request.requestId,
            createdAt: now,
            expiresAt,
            global: decision.scope === "global",
        };

        if ((decision.scope === "value" || decision.scope === "call") && request.violatedField != null) {
            rule.field = request.violatedField;
            rule.value = request.violatedValue;
        }

        if (decision.expandConstraints) {
            rule.expandedConstraints = decision.expandConstraints;
        }

        this.rules.push(rule);
        this.persist();

        return rule;
    }

    /** Check if there's an active approval rule that covers this capability + args. */
    findMatchingRule(
        agentId: string,
        capability: string,
        args: Record<string, unknown>,
        violatedField?: string,
        violatedValue?: unknown
    ): ApprovalRule | null {
        this.sweepExpired();

        for (const rule of this.rules) {
            if (rule.capability !== capability) continue;

            switch (rule.scope) {
                case "call":
                    continue;
                case "value":
                    if (rule.field === violatedField && this.valueMatches(rule.value, violatedValue)) {
                        return rule;
                    }
                    break;
                case "capability":
                    return rule;
                case "global":
                    return rule;
            }
        }

        return null;
    }

    /**
     * Get the expanded constraints from all active rules for a capability.
     *
     * Returns:
     * - `null` — a capability/global rule bypasses ALL constraints
     * - `undefined` — no matching rules found (use original constraints)
     * - `GrantConstraints` — merged expansions to apply on top of the grant constraints
     */
    getExpandedConstraints(capability: string): GrantConstraints | null | undefined {
        this.sweepExpired();

        const merged: GrantConstraints = {};
        let hasExpansions = false;

        for (const rule of this.rules) {
            if (rule.capability !== capability) continue;

            if (rule.scope === "capability" || rule.scope === "global") {
                return null;
            }

            if (rule.expandedConstraints) {
                for (const [field, constraint] of Object.entries(rule.expandedConstraints)) {
                    merged[field] = this.mergeConstraintValue(merged[field], constraint);
                    hasExpansions = true;
                }
            }

            if ((rule.scope === "value" || rule.scope === "call") && rule.field && rule.value !== undefined) {
                const existing = merged[rule.field];
                if (existing && typeof existing === "object" && !Array.isArray(existing)) {
                    const op = existing as ConstraintOperator;
                    if (op.in && !op.in.includes(rule.value as ConstraintPrimitive)) {
                        op.in.push(rule.value as ConstraintPrimitive);
                    }
                } else {
                    merged[rule.field] = { in: [rule.value as ConstraintPrimitive] };
                }
                hasExpansions = true;
            }
        }

        return hasExpansions ? merged : undefined;
    }

    revokeRule(ruleId: string): boolean {
        const idx = this.rules.findIndex((r) => r.ruleId === ruleId);
        if (idx === -1) return false;
        this.rules.splice(idx, 1);
        this.persist();
        return true;
    }

    revokeAllForCapability(capability: string): number {
        const before = this.rules.length;
        this.rules = this.rules.filter((r) => r.capability !== capability);
        this.persist();
        return before - this.rules.length;
    }

    revokeAll(): number {
        const count = this.rules.length;
        this.rules = [];
        this.persist();
        return count;
    }

    getAll(): ApprovalRule[] {
        this.sweepExpired();
        return [...this.rules];
    }

    private persist(): void {
        this.store.set(STORE_KEY, this.rules);
        const integrity = this.computeIntegrity(this.rules);
        this.store.set(INTEGRITY_KEY, integrity);
    }

    private load(): void {
        const rules = this.store.get<ApprovalRule[]>(STORE_KEY);
        if (!rules) {
            this.rules = [];
            return;
        }

        const storedIntegrity = this.store.get<string>(INTEGRITY_KEY);
        const computed = this.computeIntegrity(rules);
        if (storedIntegrity !== computed) {
            console.error("[agents-chain] ApprovalStore integrity check FAILED — possible tampering. All rules cleared.");
            this.rules = [];
            this.persist();
            return;
        }

        this.rules = rules;
    }

    private computeIntegrity(rules: ApprovalRule[]): string {
        const payload = JSON.stringify(rules);
        return createHmac("sha256", this.secret).update(payload).digest("hex");
    }

    private sweepExpired(): void {
        const now = Date.now();
        const before = this.rules.length;
        this.rules = this.rules.filter((r) => !r.expiresAt || r.expiresAt > now);
        if (this.rules.length !== before) {
            this.persist();
        }
    }

    private valueMatches(ruleValue: unknown, actual: unknown): boolean {
        if (ruleValue === actual) return true;
        return JSON.stringify(ruleValue) === JSON.stringify(actual);
    }

    private mergeConstraintValue(
        existing: import("../types/capabilities.js").ConstraintValue | undefined,
        incoming: import("../types/capabilities.js").ConstraintValue
    ): import("../types/capabilities.js").ConstraintValue {
        if (!existing) return incoming;

        if (typeof existing === "object" && typeof incoming === "object") {
            const merged = { ...existing } as ConstraintOperator;
            const inc = incoming as ConstraintOperator;
            if (inc.in) {
                merged.in = [...new Set([...(merged.in ?? []), ...inc.in])];
            }
            if (inc.not_in) {
                merged.not_in = (merged.not_in ?? []).filter(
                    (v) => !inc.in?.includes(v)
                );
                if (merged.not_in.length === 0) delete merged.not_in;
            }
            if (inc.max !== undefined) merged.max = Math.max(merged.max ?? -Infinity, inc.max);
            if (inc.min !== undefined) merged.min = Math.min(merged.min ?? Infinity, inc.min);
            return merged;
        }

        return incoming;
    }
}
