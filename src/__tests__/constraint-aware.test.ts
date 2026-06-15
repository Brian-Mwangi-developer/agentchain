/**
 * Constraint-Aware Mode — test suite
 *
 * Covers the two-step agent-driven permission flow:
 *   1. constraintAware: false — existing behavior unchanged (regression guard)
 *   2. constraintAware: true, allowed call → ConstraintAwareResult envelope
 *   3. constraintAware: true, violation → structured violation returned (no auto-suspend)
 *   4. constraintAware: true, request_permission → approved → result with grant
 *   5. constraintAware: true, request_permission → denied → denied result
 *   6. constraintAware: true, request_permission for unknown capability → error
 *   7. getConstraintContext() returns well-formed string
 *
 * Run with: pnpm test
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { AppChain } from "../chain.js";
import { ChainAuthError } from "../errors/chain-error.js";
import type { ConstraintAwareResult } from "../types/capabilities.js";
import type { AccessRequest } from "../types/access-request.js";

// ─── Shared helpers ────────────────────────────────────────────────────────

function makeNotifier() {
    const received: AccessRequest[] = [];
    const resolved: Array<{ request: AccessRequest; outcome: string }> = [];
    return {
        notifier: {
            async notify(request: AccessRequest) { received.push(request); },
            async onResolved(request: AccessRequest, outcome: string) { resolved.push({ request, outcome }); },
        },
        received,
        resolved,
    };
}

async function waitFor<T>(arr: T[], n: number, timeoutMs = 500): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (arr.length < n && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
    }
    assert.ok(arr.length >= n, `Expected ${n} items, got ${arr.length} after ${timeoutMs}ms`);
}

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

async function makeConstraintAwareChain(approvalSecret = "test-secret-32-bytes-long-enough") {
    const { notifier, received, resolved } = makeNotifier();
    const chain = await AppChain.create({
        providerName: "sms-service",
        issuer: "https://sms.example.com",
        capabilities: [makeSmsCapability()],
        constraintAware: true,
        accessRequests: {
            approvalSecret,
            requestTTLMs: 60_000,
            notifier,
        },
    });
    return { chain, received, resolved };
}

// ─────────────────────────────────────────────────────────────────────────────
// 15. Constraint-Aware Mode — regression guard
// ─────────────────────────────────────────────────────────────────────────────

describe("Constraint-Aware: backwards compatibility (constraintAware=false)", () => {
    it("throws ChainAuthError when constraintAware is false (default)", async () => {
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

    it("constraintAware getter returns false by default", async () => {
        const chain = await AppChain.create({
            providerName: "test",
            issuer: "https://test.com",
            capabilities: [makeSmsCapability()],
        });
        assert.equal(chain.constraintAware, false);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 16. Constraint-Aware Mode — structured results
// ─────────────────────────────────────────────────────────────────────────────

describe("Constraint-Aware: structured results", () => {
    it("constraintAware getter returns true when configured", async () => {
        const { chain } = await makeConstraintAwareChain();
        assert.equal(chain.constraintAware, true);
        chain.destroy();
    });

    it("allowed call returns ConstraintAwareResult with permission=not_required", async () => {
        const { chain } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const result = await secured["send_sms"]!({ to: "+254700000001", body: "hi" }) as ConstraintAwareResult;

        assert.equal(result.success, true);
        assert.equal(result.permission, "not_required");
        assert.equal(result.capability, "send_sms");
        assert.ok(result.result);
        assert.equal((result.result as { sent: boolean }).sent, true);
        assert.ok(result.guidance.includes("succeeded"));

        chain.destroy();
    });

    it("constraint violation returns structured result (does NOT auto-suspend)", async () => {
        const { chain, received } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // This should return immediately — NOT suspend
        const result = await secured["send_sms"]!({ to: "+9999999", body: "hi" }) as ConstraintAwareResult;

        assert.equal(result.success, false);
        assert.equal(result.permission, "constraint_violated");
        assert.equal(result.capability, "send_sms");
        assert.ok(result.violations);
        assert.ok(result.violations!.length > 0);
        assert.equal(result.violations![0]!.field, "to");
        assert.equal(result.violations![0]!.constraint, "in");
        assert.equal(result.violations![0]!.actual, "+9999999");
        assert.ok(Array.isArray(result.violations![0]!.expected));
        assert.ok((result.violations![0]!.expected as string[]).includes("+254700000001"));
        assert.ok(result.guidance.includes("request_permission"));

        // Active constraints should be included
        assert.ok(result.activeConstraints);
        assert.ok(result.activeConstraints!["to"]);

        // No access request should have been created (agent must do this explicitly)
        assert.equal(received.length, 0, "should NOT auto-create access request");
        assert.equal(chain.getPendingRequests().length, 0);

        chain.destroy();
    });

    it("constraint violation without access requests says 'not available'", async () => {
        const chain = await AppChain.create({
            providerName: "sms-service",
            issuer: "https://sms.example.com",
            capabilities: [makeSmsCapability()],
            constraintAware: true,
            // No accessRequests configured
        });

        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const result = await secured["send_sms"]!({ to: "+9999999", body: "hi" }) as ConstraintAwareResult;

        assert.equal(result.success, false);
        assert.equal(result.permission, "constraint_violated");
        assert.ok(result.guidance.includes("not available"));

        chain.destroy();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 17. Constraint-Aware: request_permission flow
// ─────────────────────────────────────────────────────────────────────────────

describe("Constraint-Aware: request_permission capability", () => {
    it("request_permission is auto-registered when constraintAware + accessRequests enabled", async () => {
        const { chain } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } },
            { capability: "request_permission", status: "active" as const },
        ];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // request_permission should be a callable method on the secured proxy
        assert.equal(typeof secured["request_permission"], "function");
        chain.destroy();
    });

    it("request_permission → approved → returns result with grant", async () => {
        const { chain, received } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } },
            { capability: "request_permission", status: "active" as const },
        ];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // Agent calls request_permission — this suspends until human approves
        const reqPromise = secured["request_permission"]!({
            capability: "send_sms",
            args: { to: "+9999999", body: "hello" },
            reason: "User asked me to notify this number",
        }) as Promise<ConstraintAwareResult>;

        // Wait for the notification to arrive
        await waitFor(received, 1);

        // Human approves
        const pending = chain.getPendingRequests()[0]!;
        chain.approve({
            requestId: pending.requestId,
            code: pending.verificationCode,
            scope: "value",
        });

        const result = await reqPromise;

        // The result should be wrapped in a ConstraintAwareResult from the capability's execute
        // Since request_permission returns a ConstraintAwareResult, and constraintAware wraps
        // it again, we might get a double-wrap. Let's check both levels.
        const innerResult = result.permission === "not_required" && result.result
            ? result.result as ConstraintAwareResult
            : result;

        assert.equal(innerResult.success, true);
        assert.equal(innerResult.permission, "approved");
        assert.ok(innerResult.result);
        assert.equal((innerResult.result as { sent: boolean }).sent, true);
        assert.ok(innerResult.grant);
        assert.equal(innerResult.grant!.scope, "value");
        assert.ok(innerResult.guidance.includes("approved"));

        chain.destroy();
    });

    it("request_permission → denied → returns denied result", async () => {
        const { chain, received } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } },
            { capability: "request_permission", status: "active" as const },
        ];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const reqPromise = secured["request_permission"]!({
            capability: "send_sms",
            args: { to: "+9999999", body: "hello" },
            reason: "need to notify",
        }) as Promise<ConstraintAwareResult>;

        await waitFor(received, 1);

        const pending = chain.getPendingRequests()[0]!;
        chain.deny({
            requestId: pending.requestId,
            code: pending.verificationCode,
            reason: "Not authorized",
        });

        const result = await reqPromise;

        // Unwrap if double-wrapped
        const innerResult = result.permission === "not_required" && result.result
            ? result.result as ConstraintAwareResult
            : result;

        assert.equal(innerResult.success, false);
        assert.equal(innerResult.permission, "denied");
        assert.ok(innerResult.guidance.includes("denied"));

        chain.destroy();
    });

    it("request_permission for unknown capability returns error result", async () => {
        const { chain } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [
            { capability: "send_sms", status: "active" as const },
            { capability: "request_permission", status: "active" as const },
        ];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const result = await secured["request_permission"]!({
            capability: "nonexistent_capability",
            args: {},
        }) as ConstraintAwareResult;

        // Unwrap
        const innerResult = result.permission === "not_required" && result.result
            ? result.result as ConstraintAwareResult
            : result;

        assert.equal(innerResult.success, false);
        assert.ok(innerResult.guidance.includes("does not exist"));

        chain.destroy();
    });

    it("request_permission for request_permission itself is rejected", async () => {
        const { chain } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [
            { capability: "send_sms", status: "active" as const },
            { capability: "request_permission", status: "active" as const },
        ];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        const result = await secured["request_permission"]!({
            capability: "request_permission",
            args: {},
        }) as ConstraintAwareResult;

        const innerResult = result.permission === "not_required" && result.result
            ? result.result as ConstraintAwareResult
            : result;

        assert.equal(innerResult.success, false);
        assert.ok(innerResult.guidance.includes("system capability"));

        chain.destroy();
    });

    it("after value-scope approval, subsequent calls pass without re-requesting", async () => {
        const { chain, received } = await makeConstraintAwareChain();
        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } },
            { capability: "request_permission", status: "active" as const },
        ];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        // First: get violation
        const violationResult = await secured["send_sms"]!({ to: "+9999999", body: "first" }) as ConstraintAwareResult;
        assert.equal(violationResult.success, false);
        assert.equal(violationResult.permission, "constraint_violated");

        // Second: request permission
        const reqPromise = secured["request_permission"]!({
            capability: "send_sms",
            args: { to: "+9999999", body: "first" },
            reason: "User needs this",
        }) as Promise<ConstraintAwareResult>;

        await waitFor(received, 1);
        const pending = chain.getPendingRequests()[0]!;
        chain.approve({
            requestId: pending.requestId,
            code: pending.verificationCode,
            scope: "value",
        });
        await reqPromise;

        // Third: same number should now pass directly
        const result = await secured["send_sms"]!({ to: "+9999999", body: "second" }) as ConstraintAwareResult;
        assert.equal(result.success, true);
        assert.equal(result.permission, "not_required");

        // Only 1 notification total
        assert.equal(received.length, 1);

        chain.destroy();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 18. getConstraintContext()
// ─────────────────────────────────────────────────────────────────────────────

describe("Constraint-Aware: getConstraintContext()", () => {
    it("returns a well-formed string describing constraints", async () => {
        const { chain } = await makeConstraintAwareChain();
        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001", "+254700000002"] } } },
        ];

        const context = chain.getConstraintContext(grants);

        assert.ok(context.includes("agents-chain protocol"));
        assert.ok(context.includes("send_sms"));
        assert.ok(context.includes("+254700000001"));
        assert.ok(context.includes("+254700000002"));
        assert.ok(context.includes("request_permission"));

        chain.destroy();
    });

    it("includes max/min constraints", async () => {
        const { chain } = await makeConstraintAwareChain();
        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { amount: { max: 1000, min: 1 } } },
        ];

        const context = chain.getConstraintContext(grants);
        assert.ok(context.includes("maximum 1000"));
        assert.ok(context.includes("minimum 1"));

        chain.destroy();
    });

    it("handles unrestricted grants", async () => {
        const { chain } = await makeConstraintAwareChain();
        const grants = [
            { capability: "send_sms", status: "active" as const },
        ];

        const context = chain.getConstraintContext(grants);
        assert.ok(context.includes("unrestricted"));

        chain.destroy();
    });

    it("without accessRequests, does not mention request_permission", async () => {
        const chain = await AppChain.create({
            providerName: "test",
            issuer: "https://test.com",
            capabilities: [makeSmsCapability()],
            constraintAware: true,
        });

        const grants = [
            { capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254"] } } },
        ];

        const context = chain.getConstraintContext(grants);
        assert.ok(!context.includes("request_permission"));

        chain.destroy();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 19. Structured violations on ChainAuthError
// ─────────────────────────────────────────────────────────────────────────────

describe("Constraint-Aware: structuredViolations on ChainAuthError", () => {
    it("ChainAuthError carries structuredViolations when thrown by enforceConstraints", async () => {
        // Use non-constraintAware mode to get a thrown error
        const chain = await AppChain.create({
            providerName: "sms-service",
            issuer: "https://sms.example.com",
            capabilities: [makeSmsCapability()],
        });

        const service = { send_sms: async () => ({ sent: true }) };
        const grants = [{ capability: "send_sms", status: "active" as const, constraints: { to: { in: ["+254700000001"] } } }];
        const secured = chain.wrap(service, grants) as Record<string, Function>;

        try {
            await secured["send_sms"]!({ to: "+9999999", body: "hi" });
            assert.fail("should have thrown");
        } catch (err) {
            assert.ok(err instanceof ChainAuthError);
            assert.ok(err.structuredViolations);
            assert.equal(err.structuredViolations!.length, 1);
            assert.equal(err.structuredViolations![0]!.field, "to");
            assert.equal(err.structuredViolations![0]!.constraint, "in");
            assert.equal(err.structuredViolations![0]!.actual, "+9999999");
            assert.ok(Array.isArray(err.structuredViolations![0]!.expected));
        }
    });
});
