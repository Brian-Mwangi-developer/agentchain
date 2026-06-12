/** ApprovalStore — encrypted store for approval rules. Agent cannot write directly;
 *  only the AccessRequestManager (via verified HMAC codes) can create rules. */

import { createHmac } from "node:crypto";
import { generateId } from "../crypto/utils.js";
import type { EncryptedStore } from "../memory/encrypted-store.js";
import type { AccessRequest, ApprovalDecision, ApprovalRule } from "../types/access-request.js";
import type { ConstraintOperator, ConstraintPrimitive, GrantConstraints } from "../types/capabilities.js";

const STORE_KEY = "approval_rules";
const INTEGRITY_KEY = "approval_rules_integrity";

export class ApprovalStore {
    private readonly store: EncryptedStore;
    /** HMAC secret for integrity — same secret as AccessRequestManager. */
    private readonly secret: Buffer;
    /** In-memory cache of rules (source of truth is the encrypted store). */
    private rules: ApprovalRule[] = [];

    constructor(store: EncryptedStore, secret: Buffer) {
        this.store = store;
        this.secret = secret;
        this.load();
    }

    // ─── Create Rule from Approved Request ───────────────────────────────────

    /**
     * Called ONLY after HMAC-verified approval. Creates the appropriate rule
     * based on the approval scope.
     */
    createRule(request: AccessRequest, decision: ApprovalDecision): ApprovalRule {
        const now = Date.now();
        let expiresAt: number | undefined;

        if (decision.ttl?.expiresAt) {
            expiresAt = decision.ttl.expiresAt;
        } else if (decision.ttl?.durationMs) {
            expiresAt = now + decision.ttl.durationMs;
        }
        // No TTL + session scope = no expiresAt (lives for the session)
        // No TTL + global scope = no expiresAt (lives forever until revoked)

        const rule: ApprovalRule = {
            ruleId: generateId("arule"),
            capability: request.capability,
            scope: decision.scope,
            approvedBy: request.requestId,
            createdAt: now,
            expiresAt,
            global: decision.scope === "global",
        };

        // For "value" scope — record the specific field/value that was approved
        if (decision.scope === "value" && request.violatedField != null) {
            rule.field = request.violatedField;
            rule.value = request.violatedValue;
        }

        // For constraint expansion
        if (decision.expandConstraints) {
            rule.expandedConstraints = decision.expandConstraints;
        }

        this.rules.push(rule);
        this.persist();

        return rule;
    }

    // ─── Query Rules ─────────────────────────────────────────────────────────

    /**
     * Check if there's an active approval rule that covers this capability + args.
     * Returns the matching rule, or null if none found.
     */
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

            // Global rules apply to any agent
            // Non-global rules only apply via the approval flow (we don't store agentId
            // on the rule because session rules are per-chain, not per-agent)

            switch (rule.scope) {
                case "call":
                    // One-time rules are consumed immediately — they shouldn't be in the store
                    // after use. If somehow one is here, skip it.
                    continue;

                case "value":
                    // Match if the violated field+value matches this rule
                    if (rule.field === violatedField && this.valueMatches(rule.value, violatedValue)) {
                        return rule;
                    }
                    break;

                case "capability":
                    // Blanket approval for this capability — always matches
                    return rule;

                case "global":
                    // Blanket approval for all agents on this capability
                    return rule;
            }
        }

        return null;
    }

    /**
     * Get the expanded constraints from all active rules for a capability.
     * These get merged into the grant constraints before enforcement.
     */
    /**
     * Get the expanded constraints from all active rules for a capability.
     * These get merged into the grant constraints before enforcement.
     *
     * Returns:
     * - `null`      → a capability/global rule bypasses ALL constraints
     * - `undefined`  → no matching rules found, no expansions (use original constraints)
     * - `GrantConstraints` → merged expansions to apply on top of the grant constraints
     */
    getExpandedConstraints(capability: string): GrantConstraints | null | undefined {
        this.sweepExpired();

        const merged: GrantConstraints = {};
        let hasExpansions = false;

        for (const rule of this.rules) {
            if (rule.capability !== capability) continue;

            // "capability" and "global" scopes bypass constraints entirely
            if (rule.scope === "capability" || rule.scope === "global") {
                return null; // null = no constraints (all allowed)
            }

            // Merge expanded constraints
            if (rule.expandedConstraints) {
                for (const [field, constraint] of Object.entries(rule.expandedConstraints)) {
                    merged[field] = this.mergeConstraintValue(merged[field], constraint);
                    hasExpansions = true;
                }
            }

            // For "value" scope, expand the `in` list for that field
            if (rule.scope === "value" && rule.field && rule.value !== undefined) {
                const existing = merged[rule.field];
                if (existing && typeof existing === "object" && !Array.isArray(existing)) {
                    const op = existing as ConstraintOperator;
                    if (op.in && !op.in.includes(rule.value as ConstraintPrimitive)) {
                        op.in.push(rule.value as ConstraintPrimitive);
                    }
                } else {
                    // Create a new `in` constraint with just this value
                    merged[rule.field] = { in: [rule.value as ConstraintPrimitive] };
                }
                hasExpansions = true;
            }
        }

        return hasExpansions ? merged : undefined;
    }

    // ─── Revoke ──────────────────────────────────────────────────────────────

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

    // ─── Persistence (tamper-proof) ──────────────────────────────────────────

    private persist(): void {
        this.store.set(STORE_KEY, this.rules);
        // Write HMAC integrity tag so we can detect tampering
        const integrity = this.computeIntegrity(this.rules);
        this.store.set(INTEGRITY_KEY, integrity);
    }

    private load(): void {
        const rules = this.store.get<ApprovalRule[]>(STORE_KEY);
        if (!rules) {
            this.rules = [];
            return;
        }

        // Verify integrity — if the agent somehow wrote to the store directly,
        // the HMAC won't match and we reject all rules.
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

    // ─── Helpers ─────────────────────────────────────────────────────────────

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
        // Deep comparison for objects
        return JSON.stringify(ruleValue) === JSON.stringify(actual);
    }

    private mergeConstraintValue(
        existing: import("../types/capabilities.js").ConstraintValue | undefined,
        incoming: import("../types/capabilities.js").ConstraintValue
    ): import("../types/capabilities.js").ConstraintValue {
        if (!existing) return incoming;

        // If both are operators, merge their lists
        if (typeof existing === "object" && typeof incoming === "object") {
            const merged = { ...existing } as ConstraintOperator;
            const inc = incoming as ConstraintOperator;
            if (inc.in) {
                merged.in = [...new Set([...(merged.in ?? []), ...inc.in])];
            }
            if (inc.not_in) {
                // Remove from not_in if we're approving it
                merged.not_in = (merged.not_in ?? []).filter(
                    (v) => !inc.in?.includes(v)
                );
                if (merged.not_in.length === 0) delete merged.not_in;
            }
            if (inc.max !== undefined) merged.max = Math.max(merged.max ?? -Infinity, inc.max);
            if (inc.min !== undefined) merged.min = Math.min(merged.min ?? Infinity, inc.min);
            return merged;
        }

        // Incoming takes precedence for primitives
        return incoming;
    }
}
