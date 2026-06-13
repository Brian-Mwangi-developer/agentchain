/**
 * Access Request System — test suite
 *
 * Covers:
 *   12. AccessRequestManager — HMAC codes, approve, deny, expire, rate limit
 *   13. ApprovalStore — rule creation, all 4 scopes, tamper detection, revocation, TTL
 *   14. AppChain + access requests — suspend/resume, all scopes, constraint expansion, e2e
 *
 * Run with: pnpm test  (builds then runs from dist/esm)
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { EncryptedStore } from "../memory/encrypted-store.js";
import { AccessRequestManager } from "../access/access-request-manager.js";
import { ApprovalStore } from "../access/approval-store.js";
import { AppChain } from "../chain.js";
import { ChainAuthError } from "../errors/chain-error.js";
import type { AccessRequest } from "../types/access-request.js";

// ─── Shared helpers ────────────────────────────────────────────────────────

/** Builds a notifier that captures all notifications in an array. */
function makeNotifier() {
    const received: AccessRequest[] = [];
    const resolved: Array<{ request: AccessRequest; outcome: string }> = [];
    return {
        notifier: {
            async notify(request: AccessRequest) {
                received.push(request);
            },
            async onResolved(request: AccessRequest, outcome: string) {
                resolved.push({ request, outcome });
            },
        },
        received,
        resolved,
    };
}

/** Waits for `n` items to appear in the array, polling up to timeoutMs. */
async function waitFor<T>(arr: T[], n: number, timeoutMs = 500): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (arr.length < n && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
    }
    assert.ok(arr.length >= n, `Expected ${n} items, got ${arr.length} after ${timeoutMs}ms`);
}

/** Minimal SMS capability for AppChain tests. */
function makeSmsCapability() {
    return {
        name: "send_sms",
        description: "Send an SMS message",
        inputSchema: {
            type: "object" as const,
            required: ["to", "body"] as string[],
            properties: {
                to: { type: "string" as const },
                body: { type: "string" as const },
            },
        },
        outputSchema: { type: "object" as const },
        execute: async (params: unknown) => {
            const { to, body } = params as { to: string; body: string };
            return { sent: true, to, body };
        },
    };
}

/** Creates an AppChain with access requests enabled, returns chain + notifier internals. */
async function makeChainWithAccessRequests(approvalSecret = "test-secret-32-bytes-long-enough") {
    const { notifier, received, resolved } = makeNotifier();
    const chain = await AppChain.create({
        providerName: "sms-service",
        issuer: "https://sms.example.com",
        capabilities: [makeSmsCapability()],
        accessRequests: {
            approvalSecret,
            requestTTLMs: 60_000,
            notifier,
        },
    });
    return { chain, received, resolved };
}

// ─────────────────────────────────────────────────────────────────────────────
// 12. AccessRequestManager
// ─────────────────────────────────────────────────────────────────────────────

describe("AccessRequestManager", () => {
    it("createRequest() generates a non-empty verificationCode", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({
            approvalSecret: "test-secret",
            notifier,
        });

        const { request } = await manager.createRequest({
            agentId: "agent-1",
            agentName: "Test Agent",
            hostId: "host-thumb",
            capability: "send_sms",
            args: { to: "+9999999", body: "hi" },
            reason: "number not in whitelist",
            errorCode: "constraint_violated",
            violatedField: "to",
            violatedValue: "+9999999",
        });

        assert.ok(request.requestId.startsWith("areq_"), "requestId must have areq_ prefix");
        assert.equal(request.status, "pending");
        assert.ok(request.verificationCode.length === 8, "code must be 8 chars");
        assert.ok(/^[0-9A-F]{8}$/.test(request.verificationCode), "code must be uppercase hex");
        manager.destroy();
    });

    it("createRequest() calls notifier.notify() with the request", async () => {
        const { notifier, received } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "test-secret", notifier });

        await manager.createRequest({
            agentId: "agent-1",
            agentName: "Agent",
            hostId: "host",
            capability: "send_sms",
            args: { to: "+9999" },
            reason: "denied",
            errorCode: "capability_denied",
        });

        await waitFor(received, 1);
        assert.equal(received[0]!.capability, "send_sms");
        assert.equal(received[0]!.agentId, "agent-1");
        manager.destroy();
    });

    it("getPendingForAgent() returns all pending requests for that agent", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "s", notifier });

        await manager.createRequest({
            agentId: "agent-A",
            agentName: "A",
            hostId: "h",
            capability: "cap1",
            args: {},
            reason: "r",
            errorCode: "capability_denied",
        });
        await manager.createRequest({
            agentId: "agent-A",
            agentName: "A",
            hostId: "h",
            capability: "cap2",
            args: {},
            reason: "r",
            errorCode: "capability_denied",
        });
        await manager.createRequest({
            agentId: "agent-B",
            agentName: "B",
            hostId: "h",
            capability: "cap1",
            args: {},
            reason: "r",
            errorCode: "capability_denied",
        });

        assert.equal(manager.getPendingForAgent("agent-A").length, 2);
        assert.equal(manager.getPendingForAgent("agent-B").length, 1);
        assert.equal(manager.getAllPending().length, 3);
        manager.destroy();
    });

    it("approve() with correct code resolves the waitForApproval promise", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "test-secret", notifier });

        const { request, waitForApproval } = await manager.createRequest({
            agentId: "agent-1",
            agentName: "A",
            hostId: "h",
            capability: "send_sms",
            args: { to: "+9999" },
            reason: "denied",
            errorCode: "constraint_violated",
            violatedField: "to",
            violatedValue: "+9999",
        });

        // Approve asynchronously
        setTimeout(() => {
            manager.approve({
                requestId: request.requestId,
                code: request.verificationCode,
                scope: "value",
            });
        }, 10);

        const result = await waitForApproval as { approved: boolean };
        assert.equal(result.approved, true);
        assert.equal(manager.getAllPending().length, 0, "request removed after approval");
        manager.destroy();
    });

    it("approve() with wrong code throws and leaves request pending", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "test-secret", notifier });

        const { request } = await manager.createRequest({
            agentId: "agent-1",
            agentName: "A",
            hostId: "h",
            capability: "send_sms",
            args: {},
            reason: "denied",
            errorCode: "capability_denied",
        });

        assert.throws(
            () => manager.approve({ requestId: request.requestId, code: "WRONGCOD", scope: "call" }),
            /Invalid verification code/
        );

        // Request is still pending — not consumed
        assert.equal(manager.getAllPending().length, 1);
        manager.destroy();
    });

    it("deny() with correct code rejects the waitForApproval promise", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "test-secret", notifier });

        const { request, waitForApproval } = await manager.createRequest({
            agentId: "agent-1",
            agentName: "A",
            hostId: "h",
            capability: "send_sms",
            args: {},
            reason: "denied",
            errorCode: "capability_denied",
        });

        setTimeout(() => {
            manager.deny({
                requestId: request.requestId,
                code: request.verificationCode,
                reason: "Not allowed",
            });
        }, 10);

        await assert.rejects(waitForApproval, /Access request denied.*Not allowed/);
        assert.equal(manager.getAllPending().length, 0);
        manager.destroy();
    });

    it("approve() throws for unknown requestId", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "s", notifier });

        assert.throws(
            () => manager.approve({ requestId: "areq_nonexistent", code: "XXXXXXXX", scope: "call" }),
            /not found or already resolved/
        );
        manager.destroy();
    });

    it("destroy() rejects all suspended calls", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "s", notifier });

        const { waitForApproval } = await manager.createRequest({
            agentId: "a",
            agentName: "A",
            hostId: "h",
            capability: "cap",
            args: {},
            reason: "r",
            errorCode: "capability_denied",
        });

        const rejectionPromise = assert.rejects(waitForApproval, /destroyed/);
        manager.destroy();
        await rejectionPromise;
    });

    it("approvalSecret is exposed as a Buffer on the manager", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "my-secret", notifier });

        assert.ok(Buffer.isBuffer(manager.approvalSecret));
        assert.ok(manager.approvalSecret.length > 0);
        manager.destroy();
    });

    it("two different requests for the same capability produce different codes", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "test-secret", notifier });

        const { request: r1, waitForApproval: w1 } = await manager.createRequest({
            agentId: "agent-1",
            agentName: "A",
            hostId: "h",
            capability: "send_sms",
            args: { to: "+1111" },
            reason: "r",
            errorCode: "constraint_violated",
        });
        const { request: r2, waitForApproval: w2 } = await manager.createRequest({
            agentId: "agent-1",
            agentName: "A",
            hostId: "h",
            capability: "send_sms",
            args: { to: "+2222" },
            reason: "r",
            errorCode: "constraint_violated",
        });

        // Codes must differ (tied to different requestId + createdAt)
        assert.notEqual(r1.verificationCode, r2.verificationCode);

        // Drain pending promises before destroy to avoid unhandledRejection warnings
        const drain = Promise.allSettled([w1, w2]);
        manager.destroy();
        await drain;
    });

    it("rate limit: oldest pending is expired when maxPendingPerAgent is exceeded", async () => {
        const { notifier } = makeNotifier();
        const manager = new AccessRequestManager({
            approvalSecret: "s",
            notifier,
            maxPendingPerAgent: 2,
        });

        const { request: r1, waitForApproval: w1 } = await manager.createRequest({
            agentId: "agent-1", agentName: "A", hostId: "h",
            capability: "c", args: {}, reason: "r", errorCode: "capability_denied",
        });
        const { waitForApproval: w2 } = await manager.createRequest({
            agentId: "agent-1", agentName: "A", hostId: "h",
            capability: "c", args: {}, reason: "r", errorCode: "capability_denied",
        });

        // Third request — should expire the first one
        const rejectionPromise = assert.rejects(w1, /expired/);
        const { waitForApproval: w3 } = await manager.createRequest({
            agentId: "agent-1", agentName: "A", hostId: "h",
            capability: "c", args: {}, reason: "r", errorCode: "capability_denied",
        });

        await rejectionPromise;
        // First request is gone — only 2 remain
        assert.equal(manager.getPendingForAgent("agent-1").length, 2);
        assert.equal(manager.getPending(r1.requestId), undefined);

        // Drain w2, w3 before destroy
        const drain = Promise.allSettled([w2, w3]);
        manager.destroy();
        await drain;
    });

    it("onResolved is called with 'approved' after approval", async () => {
        const { notifier, resolved } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "s", notifier });

        const { request } = await manager.createRequest({
            agentId: "a", agentName: "A", hostId: "h",
            capability: "c", args: {}, reason: "r", errorCode: "capability_denied",
        });

        manager.approve({
            requestId: request.requestId,
            code: request.verificationCode,
            scope: "call",
        });

        await waitFor(resolved, 1);
        assert.equal(resolved[0]!.outcome, "approved");
        manager.destroy();
    });

    it("onResolved is called with 'denied' after denial", async () => {
        const { notifier, resolved } = makeNotifier();
        const manager = new AccessRequestManager({ approvalSecret: "s", notifier });

        const { request, waitForApproval } = await manager.createRequest({
            agentId: "a", agentName: "A", hostId: "h",
            capability: "c", args: {}, reason: "r", errorCode: "capability_denied",
        });

        // Catch the rejection before it becomes unhandled
        waitForApproval.catch(() => {});

        manager.deny({ requestId: request.requestId, code: request.verificationCode });

        await waitFor(resolved, 1);
        assert.equal(resolved[0]!.outcome, "denied");
        manager.destroy();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 13. ApprovalStore
// ─────────────────────────────────────────────────────────────────────────────

describe("ApprovalStore", () => {
    function makeStore() {
        const secret = Buffer.from("test-integrity-secret", "utf8");
        const store = EncryptedStore.create();
        const approvalStore = new ApprovalStore(store, secret);
        return { store, approvalStore, secret };
    }

    function fakeRequest(overrides: Partial<AccessRequest> = {}): AccessRequest {
        return {
            requestId: "areq_test001",
            agentId: "agent-1",
            agentName: "Agent",
            hostId: "host-thumb",
            capability: "send_sms",
            args: { to: "+9999", body: "hi" },
            reason: "number not in whitelist",
            violatedField: "to",
            violatedValue: "+9999",
            errorCode: "constraint_violated",
            createdAt: Date.now(),
            expiresAt: Date.now() + 60_000,
            status: "approved",
            verificationCode: "TESTCODE",
            ...overrides,
        };
    }

    it("starts empty", () => {
        const { approvalStore } = makeStore();
        assert.equal(approvalStore.getAll().length, 0);
    });

    it("createRule() creates a 'value' scope rule with field+value set", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "value" });

        assert.equal(rule.scope, "value");
        assert.equal(rule.capability, "send_sms");
        assert.equal(rule.field, "to");
        assert.equal(rule.value, "+9999");
        assert.equal(rule.global, false);
        assert.equal(approvalStore.getAll().length, 1);
    });

    it("createRule() creates a 'capability' scope rule with no field", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "capability" });

        assert.equal(rule.scope, "capability");
        assert.equal(rule.field, undefined);
        assert.equal(rule.global, false);
    });

    it("createRule() creates a 'global' scope rule with global=true", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "global" });

        assert.equal(rule.global, true);
    });

    it("createRule() with TTL sets expiresAt", () => {
        const { approvalStore } = makeStore();
        const now = Date.now();
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, {
            requestId: request.requestId,
            code: "X",
            scope: "value",
            ttl: { durationMs: 5 * 60 * 1000 },
        });

        assert.ok(rule.expiresAt !== undefined);
        assert.ok(rule.expiresAt! > now + 4 * 60 * 1000);
    });

    it("createRule() with explicit expiresAt uses it directly", () => {
        const { approvalStore } = makeStore();
        const expiresAt = Date.now() + 99_999;
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, {
            requestId: request.requestId,
            code: "X",
            scope: "value",
            ttl: { expiresAt },
        });

        assert.equal(rule.expiresAt, expiresAt);
    });

    it("findMatchingRule() finds 'value' scope rule by field+value", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "value" });

        const match = approvalStore.findMatchingRule("agent-1", "send_sms", { to: "+9999" }, "to", "+9999");
        assert.ok(match !== null);
        assert.equal(match!.scope, "value");
    });

    it("findMatchingRule() returns null for wrong field value", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "value" });

        const match = approvalStore.findMatchingRule("agent-1", "send_sms", { to: "+8888" }, "to", "+8888");
        assert.equal(match, null);
    });

    it("findMatchingRule() finds 'capability' scope rule for any value", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "capability" });

        const match1 = approvalStore.findMatchingRule("agent-1", "send_sms", { to: "+1111" });
        const match2 = approvalStore.findMatchingRule("agent-2", "send_sms", { to: "+2222" });
        assert.ok(match1 !== null);
        assert.ok(match2 !== null);
    });

    it("findMatchingRule() finds 'global' scope rule for any agent", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "global" });

        assert.ok(approvalStore.findMatchingRule("agent-A", "send_sms", {}) !== null);
        assert.ok(approvalStore.findMatchingRule("agent-B", "send_sms", {}) !== null);
    });

    it("findMatchingRule() skips 'call' scope rules", () => {
        const { approvalStore } = makeStore();
        // Manually push a call-scope rule (bypassing createRule to simulate stale state)
        (approvalStore as any).rules.push({
            ruleId: "arule_call_test",
            capability: "send_sms",
            scope: "call",
            approvedBy: "areq_test",
            createdAt: Date.now(),
            global: false,
        });

        const match = approvalStore.findMatchingRule("agent-1", "send_sms", {});
        assert.equal(match, null, "call-scope rules should be skipped by findMatchingRule");
    });

    it("getExpandedConstraints() returns null for 'capability' scope (bypass all constraints)", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "capability" });

        const expanded = approvalStore.getExpandedConstraints("send_sms");
        assert.equal(expanded, null);
    });

    it("getExpandedConstraints() returns null for 'global' scope", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "global" });

        assert.equal(approvalStore.getExpandedConstraints("send_sms"), null);
    });

    it("getExpandedConstraints() expands 'in' list for 'value' scope", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "value" });

        const expanded = approvalStore.getExpandedConstraints("send_sms");
        assert.ok(expanded !== null);
        const toConstraint = expanded!["to"] as { in: string[] };
        assert.ok(Array.isArray(toConstraint.in));
        assert.ok(toConstraint.in.includes("+9999"));
    });

    it("getExpandedConstraints() returns undefined for different capability", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "value" });

        const expanded = approvalStore.getExpandedConstraints("other_capability");
        assert.equal(expanded, undefined);
    });

    it("revokeRule() removes the rule and returns true", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "value" });

        assert.equal(approvalStore.revokeRule(rule.ruleId), true);
        assert.equal(approvalStore.getAll().length, 0);
    });

    it("revokeRule() returns false for unknown ruleId", () => {
        const { approvalStore } = makeStore();
        assert.equal(approvalStore.revokeRule("arule_nonexistent"), false);
    });

    it("revokeAllForCapability() removes only matching rules", () => {
        const { approvalStore } = makeStore();
        approvalStore.createRule(fakeRequest({ requestId: "r1", capability: "send_sms" }), {
            requestId: "r1", code: "X", scope: "value",
        });
        approvalStore.createRule(fakeRequest({ requestId: "r2", capability: "send_email", violatedField: "to" }), {
            requestId: "r2", code: "X", scope: "value",
        });

        const count = approvalStore.revokeAllForCapability("send_sms");
        assert.equal(count, 1);
        assert.equal(approvalStore.getAll().length, 1);
        assert.equal(approvalStore.getAll()[0]!.capability, "send_email");
    });

    it("revokeAll() removes all rules and returns count", () => {
        const { approvalStore } = makeStore();
        approvalStore.createRule(fakeRequest({ requestId: "r1" }), { requestId: "r1", code: "X", scope: "value" });
        approvalStore.createRule(fakeRequest({ requestId: "r2" }), { requestId: "r2", code: "X", scope: "capability" });

        const count = approvalStore.revokeAll();
        assert.equal(count, 2);
        assert.equal(approvalStore.getAll().length, 0);
    });

    it("expired rules are swept automatically by getAll()", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        const rule = approvalStore.createRule(request, {
            requestId: request.requestId, code: "X", scope: "value",
            ttl: { expiresAt: Date.now() - 1 }, // already expired
        });

        // getAll() triggers sweepExpired
        assert.equal(approvalStore.getAll().length, 0);
    });

    it("expired rules are ignored by findMatchingRule()", () => {
        const { approvalStore } = makeStore();
        const request = fakeRequest();
        approvalStore.createRule(request, {
            requestId: request.requestId, code: "X", scope: "value",
            ttl: { expiresAt: Date.now() - 1 },
        });

        const match = approvalStore.findMatchingRule("agent-1", "send_sms", { to: "+9999" }, "to", "+9999");
        assert.equal(match, null);
    });

    it("tamper detection: corrupting rules in the store wipes all rules on reload", () => {
        const secret = Buffer.from("integrity-secret", "utf8");
        const encStore = EncryptedStore.create();
        const approvalStore = new ApprovalStore(encStore, secret);

        const request = fakeRequest();
        approvalStore.createRule(request, { requestId: request.requestId, code: "X", scope: "global" });
        assert.equal(approvalStore.getAll().length, 1);

        // Tamper: write rules directly to the store bypassing ApprovalStore
        // (simulates an agent writing to EncryptedStore directly)
        encStore.set("approval_rules", [{ ruleId: "injected", capability: "send_sms", scope: "global", global: true, approvedBy: "fake", createdAt: 0 }]);
        // The integrity tag now mismatches

        // Load a fresh ApprovalStore from the same tampered EncryptedStore
        const reloaded = new ApprovalStore(encStore, secret);
        assert.equal(
            reloaded.getAll().length, 0,
            "tampered rules should be wiped on reload"
        );
    });

    it("rules survive a clean reload when not tampered", () => {
        const secret = Buffer.from("integrity-secret", "utf8");
        const encStore = EncryptedStore.create();
        const store1 = new ApprovalStore(encStore, secret);

        const request = fakeRequest();
        store1.createRule(request, { requestId: request.requestId, code: "X", scope: "global" });

        // Reload from the same EncryptedStore — same secret, same data
        const store2 = new ApprovalStore(encStore, secret);
        assert.equal(store2.getAll().length, 1, "rules should survive clean reload");
        assert.equal(store2.getAll()[0]!.scope, "global");
    });

    it("wrong secret on reload wipes all rules", () => {
        const secret1 = Buffer.from("correct-secret", "utf8");
        const secret2 = Buffer.from("wrong-secret-xx", "utf8");
        const encStore = EncryptedStore.create();
        const store1 = new ApprovalStore(encStore, secret1);

        const request = fakeRequest();
        store1.createRule(request, { requestId: request.requestId, code: "X", scope: "global" });

        // Try to load with wrong secret
        const store2 = new ApprovalStore(encStore, secret2);
        assert.equal(store2.getAll().length, 0, "rules should be wiped when loaded with wrong secret");
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 14. AppChain + access requests (integration)
// ─────────────────────────────────────────────────────────────────────────────

describe("AppChain — access requests disabled (default behavior unchanged)", () => {
    it("throws ChainAuthError immediately when access requests not configured", async () => {
        const chain = await AppChain.create({
            providerName: "sms-service",
            issuer: "https://sms.example.com",
            capabilities: [makeSmsCapability()],
        });

        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        await assert.rejects(
            () => secured["send_sms"]!({ to: "+9999999", body: "hi" }),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "constraint_violated");
                return true;
            }
        );
    });

    it("accessRequestsEnabled is false when not configured", async () => {
        const chain = await AppChain.create({
            providerName: "test",
            issuer: "https://test.com",
            capabilities: [makeSmsCapability()],
        });
        assert.equal(chain.accessRequestsEnabled, false);
    });

    it("chain.approve() throws when access requests not enabled", async () => {
        const chain = await AppChain.create({
            providerName: "test",
            issuer: "https://test.com",
            capabilities: [makeSmsCapability()],
        });
        assert.throws(
            () => chain.approve({ requestId: "r", code: "c", scope: "call" }),
            /not enabled/
        );
    });

    it("chain.deny() throws when access requests not enabled", async () => {
        const chain = await AppChain.create({
            providerName: "test",
            issuer: "https://test.com",
            capabilities: [makeSmsCapability()],
        });
        assert.throws(
            () => chain.deny({ requestId: "r", code: "c" }),
            /not enabled/
        );
    });
});

describe("AppChain — access requests enabled", () => {
    it("accessRequestsEnabled is true when configured", async () => {
        const { chain } = await makeChainWithAccessRequests();
        assert.equal(chain.accessRequestsEnabled, true);
        chain.destroy();
    });

    it("getPendingRequests() returns empty array initially", async () => {
        const { chain } = await makeChainWithAccessRequests();
        assert.equal(chain.getPendingRequests().length, 0);
        chain.destroy();
    });

    it("getApprovalRules() returns empty array initially", async () => {
        const { chain } = await makeChainWithAccessRequests();
        assert.equal(chain.getApprovalRules().length, 0);
        chain.destroy();
    });

    it("suspended call creates a pending request visible via getPendingRequests()", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // Start a call that will be suspended — don't await it yet
        const callPromise = secured["send_sms"]!({ to: "+9999999", body: "hello" });

        // Wait for the notifier to receive the request
        await waitFor(received, 1);

        assert.equal(chain.getPendingRequests().length, 1);
        const pending = chain.getPendingRequests()[0]!;
        assert.equal(pending.capability, "send_sms");
        assert.equal(pending.violatedField, "to");
        assert.equal(pending.violatedValue, "+9999999");

        // Deny to clean up
        chain.deny({ requestId: pending.requestId, code: pending.verificationCode });
        await assert.rejects(callPromise);
        chain.destroy();
    });

    it("SCOPE 'call': call succeeds once then the rule is removed", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const callPromise = secured["send_sms"]!({ to: "+9999999", body: "test" });
        await waitFor(received, 1);

        const pending = chain.getPendingRequests()[0]!;
        chain.approve({
            requestId: pending.requestId,
            code: pending.verificationCode,
            scope: "call",
        });

        const result = await callPromise as { sent: boolean };
        assert.equal(result.sent, true);

        // Rule should be gone after single use
        assert.equal(chain.getApprovalRules().length, 0);
        chain.destroy();
    });

    it("SCOPE 'value': subsequent calls to approved value succeed without re-prompting", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // First call — will be suspended
        const callPromise = secured["send_sms"]!({ to: "+9999999", body: "first" });
        await waitFor(received, 1);

        const pending = chain.getPendingRequests()[0]!;
        chain.approve({
            requestId: pending.requestId,
            code: pending.verificationCode,
            scope: "value",
        });

        const result1 = await callPromise as { sent: boolean };
        assert.equal(result1.sent, true);
        assert.equal(chain.getApprovalRules().length, 1, "value rule should persist");

        // Second call — same number, should pass without triggering a new request
        const result2 = await secured["send_sms"]!({ to: "+9999999", body: "second" }) as { sent: boolean };
        assert.equal(result2.sent, true);
        // Still only 1 notification (not 2)
        assert.equal(received.length, 1, "second call should not trigger a new notification");

        chain.destroy();
    });

    it("SCOPE 'value': different unapproved value still triggers a new request", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // Approve +9999999
        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({ requestId: p1.requestId, code: p1.verificationCode, scope: "value" });
        await call1;

        // Now try a different unapproved number
        const call2 = secured["send_sms"]!({ to: "+8888888", body: "b" });
        await waitFor(received, 2);

        assert.equal(chain.getPendingRequests().length, 1);
        const p2 = chain.getPendingRequests()[0]!;
        assert.equal(p2.violatedValue, "+8888888");

        chain.deny({ requestId: p2.requestId, code: p2.verificationCode });
        await assert.rejects(call2);
        chain.destroy();
    });

    it("SCOPE 'capability': all values for the capability are allowed without constraint", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // Approve at capability scope
        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({ requestId: p1.requestId, code: p1.verificationCode, scope: "capability" });
        await call1;

        // Any subsequent number works — no new requests
        const r2 = await secured["send_sms"]!({ to: "+1111111", body: "b" }) as { sent: boolean };
        const r3 = await secured["send_sms"]!({ to: "+2222222", body: "c" }) as { sent: boolean };
        assert.equal(r2.sent, true);
        assert.equal(r3.sent, true);
        assert.equal(received.length, 1, "only 1 notification should have been sent");

        chain.destroy();
    });

    it("SCOPE 'global': approval rule shows global=true and applies to all agents", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({ requestId: p1.requestId, code: p1.verificationCode, scope: "global" });
        await call1;

        const rules = chain.getApprovalRules();
        assert.equal(rules.length, 1);
        assert.equal(rules[0]!.global, true);
        assert.equal(rules[0]!.scope, "global");
        chain.destroy();
    });

    it("SCOPE 'global' with TTL: rule disappears after expiry", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({
            requestId: p1.requestId,
            code: p1.verificationCode,
            scope: "global",
            ttl: { expiresAt: Date.now() - 1 }, // already expired
        });
        await call1;

        // Rule was created but already expired
        assert.equal(chain.getApprovalRules().length, 0, "expired rule should be swept on getAll()");
        chain.destroy();
    });

    it("denial rejects the suspended call with an error", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const callPromise = secured["send_sms"]!({ to: "+9999999", body: "hi" });
        await waitFor(received, 1);

        const pending = chain.getPendingRequests()[0]!;
        chain.deny({
            requestId: pending.requestId,
            code: pending.verificationCode,
            reason: "Administrator declined",
        });

        await assert.rejects(
            callPromise,
            /Access request denied.*Administrator declined/
        );
        chain.destroy();
    });

    it("wrong verification code on chain.approve() throws without resuming call", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const callPromise = secured["send_sms"]!({ to: "+9999999", body: "hi" });
        await waitFor(received, 1);

        const pending = chain.getPendingRequests()[0]!;
        assert.throws(
            () => chain.approve({ requestId: pending.requestId, code: "WRONGCOD", scope: "call" }),
            /Invalid verification code/
        );

        // Call is still suspended
        assert.equal(chain.getPendingRequests().length, 1);

        // Clean up
        chain.deny({ requestId: pending.requestId, code: pending.verificationCode });
        await assert.rejects(callPromise);
        chain.destroy();
    });

    it("revokeApproval() removes a rule and subsequent calls re-trigger access request", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // Approve with 'value' scope
        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({ requestId: p1.requestId, code: p1.verificationCode, scope: "value" });
        await call1;

        const rules = chain.getApprovalRules();
        assert.equal(rules.length, 1);

        // Revoke the rule
        assert.equal(chain.revokeApproval(rules[0]!.ruleId), true);
        assert.equal(chain.getApprovalRules().length, 0);

        // Next call triggers a new access request
        const call2 = secured["send_sms"]!({ to: "+9999999", body: "b" });
        await waitFor(received, 2);
        assert.equal(chain.getPendingRequests().length, 1);

        const p2 = chain.getPendingRequests()[0]!;
        chain.deny({ requestId: p2.requestId, code: p2.verificationCode });
        await assert.rejects(call2);
        chain.destroy();
    });

    it("revokeApprovalsForCapability() removes rules for that capability only", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({ requestId: p1.requestId, code: p1.verificationCode, scope: "capability" });
        await call1;

        assert.equal(chain.getApprovalRules().length, 1);
        const removed = chain.revokeApprovalsForCapability("send_sms");
        assert.equal(removed, 1);
        assert.equal(chain.getApprovalRules().length, 0);
        chain.destroy();
    });

    it("revokeAllApprovals() removes everything", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const call1 = secured["send_sms"]!({ to: "+9999999", body: "a" });
        await waitFor(received, 1);
        const p1 = chain.getPendingRequests()[0]!;
        chain.approve({ requestId: p1.requestId, code: p1.verificationCode, scope: "global" });
        await call1;

        assert.equal(chain.getApprovalRules().length, 1);
        const removed = chain.revokeAllApprovals();
        assert.equal(removed, 1);
        assert.equal(chain.getApprovalRules().length, 0);
        chain.destroy();
    });

    it("allowed calls still pass through normally (not affected by access request layer)", async () => {
        const { chain } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // Whitelisted number — should pass immediately without any access request
        const result = await secured["send_sms"]!({ to: "+254700000001", body: "hi" }) as { sent: boolean };
        assert.equal(result.sent, true);
        assert.equal(chain.getPendingRequests().length, 0);
        chain.destroy();
    });

    it("audit log records denied entry when call is suspended", async () => {
        const { chain, received } = await makeChainWithAccessRequests();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const callPromise = secured["send_sms"]!({ to: "+9999999", body: "test" });
        await waitFor(received, 1);

        // Audit should have recorded the initial denial
        const log = chain.getAuditLog();
        const deniedEntry = log.find((e) => e.result === "denied");
        assert.ok(deniedEntry !== undefined, "audit log should have a denied entry");
        assert.ok(deniedEntry!.denialReason?.includes("[access_request]"), "denial reason should mention access_request");

        const pending = chain.getPendingRequests()[0]!;
        chain.deny({ requestId: pending.requestId, code: pending.verificationCode });
        await assert.rejects(callPromise);
        chain.destroy();
    });

    it("destroy() cleans up access request manager without error", async () => {
        const { chain } = await makeChainWithAccessRequests();
        assert.doesNotThrow(() => chain.destroy());
    });
});
