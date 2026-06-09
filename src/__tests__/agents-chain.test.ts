/**
 * agents-chain — comprehensive test suite
 *
 * Run with: node --experimental-strip-types --test src/__tests__/agents-chain.test.ts
 *
 * Uses Node.js built-in test runner (no external deps).
 * Each section mirrors a distinct module; the final section runs an end-to-end
 * build → verify round-trip and measures auth overhead.
 */

import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";

// ── Source imports (relative, .js extension required by NodeNext resolution) ──
import { EncryptedStore } from "../memory/encrypted-store.js";
import { JtiCache } from "../memory/jti-cache.js";
import { ChainAuthError } from "../errors/chain-error.js";
import { AgentIdentity } from "../identity/agent-identity.js";
import { HostIdentity } from "../host/host-identity.js";
import { TokenBuilder } from "../auth/token-builder.js";
import { TokenVerifier } from "../auth/token-verifier.js";
import { AuditLog } from "../audit/audit-log.js";
import { enforceConstraints } from "../auth/constraints.js";
import { CapabilityRegistry } from "../app/capability-registry.js";
import { AgentsChain, AppChain } from "../chain.js";

// ─────────────────────────────────────────────────────────────────────────────
// 1. EncryptedStore
// ─────────────────────────────────────────────────────────────────────────────

describe("EncryptedStore", () => {
    it("stores and retrieves a value correctly", () => {
        const store = EncryptedStore.create();
        store.set("key1", { hello: "world", n: 42 });
        const v = store.get<{ hello: string; n: number }>("key1");
        assert.deepEqual(v, { hello: "world", n: 42 });
    });

    it("returns undefined for missing keys", () => {
        const store = EncryptedStore.create();
        assert.equal(store.get("nonexistent"), undefined);
    });

    it("has() reflects store state", () => {
        const store = EncryptedStore.create();
        assert.equal(store.has("k"), false);
        store.set("k", 1);
        assert.equal(store.has("k"), true);
    });

    it("delete() removes a key", () => {
        const store = EncryptedStore.create();
        store.set("k", "v");
        store.delete("k");
        assert.equal(store.has("k"), false);
    });

    it("size tracks number of entries", () => {
        const store = EncryptedStore.create();
        assert.equal(store.size, 0);
        store.set("a", 1);
        store.set("b", 2);
        assert.equal(store.size, 2);
    });

    it("clear() empties the store", () => {
        const store = EncryptedStore.create();
        store.set("a", 1);
        store.clear();
        assert.equal(store.size, 0);
    });

    it("append() pushes items into an array", () => {
        const store = EncryptedStore.create();
        store.append("list", "first");
        store.append("list", "second");
        const list = store.get<string[]>("list");
        assert.deepEqual(list, ["first", "second"]);
    });

    it("accepts an explicit 64-char hex key", () => {
        const hexKey = "a".repeat(64);
        const store = EncryptedStore.create(hexKey);
        store.set("x", 99);
        assert.equal(store.get<number>("x"), 99);
    });

    it("throws on a malformed hex key", () => {
        assert.throws(() => EncryptedStore.create("tooshort"), /64-character/);
    });

    it("decryption fails (throws) when ciphertext is tampered", () => {
        const store = EncryptedStore.create();
        store.set("secret", "plaintext");

        // Reach into private store map and corrupt the ciphertext part
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const internalMap: Map<string, string> = (store as any).store;
        const encoded = internalMap.get("secret")!;
        const parts = encoded.split(":");
        // Flip a byte in the ciphertext (base64 index 3 → 4)
        parts[2] = parts[2]!.split("").reverse().join("");
        internalMap.set("secret", parts.join(":"));

        assert.throws(
            () => store.get("secret"),
            (err: unknown) => {
                assert.ok(err instanceof Error);
                // Either auth failure or base64 decode corruption
                return true;
            }
        );
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. JtiCache
// ─────────────────────────────────────────────────────────────────────────────

describe("JtiCache", () => {
    it("allows the first use of a jti", async () => {
        const cache = new JtiCache();
        await assert.doesNotReject(() => cache.assert("agent-1", "jti-abc"));
        cache.destroy();
    });

    it("throws token_replayed on second use of same jti", async () => {
        const cache = new JtiCache();
        await cache.assert("agent-1", "jti-xyz");
        await assert.rejects(
            () => cache.assert("agent-1", "jti-xyz"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "token_replayed");
                return true;
            }
        );
        cache.destroy();
    });

    it("allows same jti for different agents", async () => {
        const cache = new JtiCache();
        await cache.assert("agent-1", "shared-jti");
        await assert.doesNotReject(() => cache.assert("agent-2", "shared-jti"));
        cache.destroy();
    });

    it("allows same agent reuse after entry expires (simulated)", async () => {
        const cache = new JtiCache();
        await cache.assert("agent-1", "expiring-jti");

        // Manually backdate the expiry so evictExpired() removes it
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const map: Map<string, number> = (cache as any).inMemory;
        map.set("agent-1:expiring-jti", Date.now() - 1); // expired 1 ms ago

        // Trigger lazy eviction by calling assert() (which calls evictExpired first)
        await assert.doesNotReject(() => cache.assert("agent-1", "expiring-jti"));
        cache.destroy();
    });

    it("size reflects live entries", async () => {
        const cache = new JtiCache();
        assert.equal(cache.size, 0);
        await cache.assert("a", "j1");
        await cache.assert("a", "j2");
        assert.equal(cache.size, 2);
        cache.destroy();
    });

    it("destroy() clears map and stops timer", () => {
        const cache = new JtiCache();
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        assert.ok((cache as any).gcTimer !== undefined, "timer should exist in in-memory mode");
        cache.destroy();
        assert.equal(cache.size, 0);
    });

    it("adapter path: delegates has/set and throws on replay", async () => {
        const store = new Map<string, number>();
        const adapter = {
            has: async (key: string) => store.has(key) && store.get(key)! > Date.now(),
            set: async (key: string, ttlMs: number) => {
                store.set(key, Date.now() + ttlMs);
            },
        };
        const cache = new JtiCache(adapter);

        // No GC timer in adapter mode
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        assert.equal((cache as any).gcTimer, undefined, "no timer in adapter mode");

        await cache.assert("agent-1", "jti-adapter-1");
        await assert.rejects(
            () => cache.assert("agent-1", "jti-adapter-1"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "token_replayed");
                return true;
            }
        );
        // No destroy() call needed — no timer
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. HostIdentity
// ─────────────────────────────────────────────────────────────────────────────

describe("HostIdentity", () => {
    it("creates a host with a thumbprint", async () => {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "test-host", issuerUrl: "https://test.example.com" },
            store
        );
        assert.ok(host.thumbprint.length > 0, "thumbprint must be non-empty");
        assert.equal(host.hostId, host.thumbprint);
    });

    it("stores registration in the shared store", async () => {
        const store = EncryptedStore.create();
        await HostIdentity.create(
            { name: "test-host", issuerUrl: "https://test.example.com" },
            store
        );
        assert.ok(store.has("host:identity"), "host registration should be in shared store");
    });

    it("getPublicKeyJwk() returns a JWK with crv=Ed25519", async () => {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "test-host", issuerUrl: "https://test.example.com" },
            store
        );
        const jwk = host.getPublicKeyJwk();
        assert.equal(jwk.kty, "OKP");
        assert.equal(jwk.crv, "Ed25519");
    });

    it("signHostJwt() returns a valid 3-part JWT", async () => {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "test-host", issuerUrl: "https://test.example.com" },
            store
        );
        const token = await host.signHostJwt();
        const parts = token.split(".");
        assert.equal(parts.length, 3, "JWT must have header.payload.signature");
    });

    it("fromKeyPair() restores stable identity with the same thumbprint", async () => {
        const store1 = EncryptedStore.create();
        const original = await HostIdentity.create(
            { name: "test-host", issuerUrl: "https://test.example.com" },
            store1
        );
        const privateJwk = await original.exportPrivateKeyJwk();
        const publicJwk = original.getPublicKeyJwk();

        const store2 = EncryptedStore.create();
        const restored = await HostIdentity.fromKeyPair(
            privateJwk,
            publicJwk,
            { name: "test-host", issuerUrl: "https://test.example.com" },
            store2
        );
        assert.equal(restored.thumbprint, original.thumbprint);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. AgentIdentity
// ─────────────────────────────────────────────────────────────────────────────

describe("AgentIdentity", () => {
    async function makeHost() {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "app", issuerUrl: "https://app.example.com" },
            store
        );
        return { store, host };
    }

    it("create() succeeds with hostThumbprint + hostPublicKeyJwk", async () => {
        const { store, host } = await makeHost();
        const identity = await AgentIdentity.create(
            {
                agentName: "test-agent",
                hostname: "test-host",
                capabilities: ["read", "write"],
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );
        assert.ok(identity.agentId.includes("test-host"));
        assert.equal(identity.hostThumbprint, host.thumbprint);
    });

    it("create() throws without hostThumbprint", async () => {
        const { store } = await makeHost();
        await assert.rejects(
            () =>
                AgentIdentity.create(
                    {
                        agentName: "rogue",
                        hostname: "rogue-host",
                        capabilities: ["read"],
                        // no hostThumbprint
                    } as Parameters<typeof AgentIdentity.create>[0],
                    store
                ),
            /hostThumbprint/
        );
    });

    it("hasCapability() returns correct boolean", async () => {
        const { store, host } = await makeHost();
        const identity = await AgentIdentity.create(
            {
                agentName: "agent",
                hostname: "h",
                capabilities: ["read", "write"],
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );
        assert.ok(identity.hasCapability("read"));
        assert.ok(identity.hasCapability("write"));
        assert.ok(!identity.hasCapability("delete"));
    });

    it("agentId has expected format: <hostname>-agent-<32hex>", async () => {
        const { store, host } = await makeHost();
        const identity = await AgentIdentity.create(
            {
                agentName: "agent",
                hostname: "myapp",
                capabilities: [],
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );
        assert.match(identity.agentId, /^myapp-agent-[0-9a-f]{32}$/);
    });

    it("restore() retrieves identity from store", async () => {
        const { store, host } = await makeHost();
        const original = await AgentIdentity.create(
            {
                agentName: "agent",
                hostname: "h",
                capabilities: ["read"],
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );
        const restored = await AgentIdentity.restore(original.privateKey, store);
        assert.equal(restored.agentId, original.agentId);
        assert.equal(restored.hostThumbprint, original.hostThumbprint);
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. TokenBuilder + TokenVerifier (round-trip)
// ─────────────────────────────────────────────────────────────────────────────

describe("TokenBuilder + TokenVerifier", () => {
    async function makeChain(capabilities: string[] = ["chat.completion"]) {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "app", issuerUrl: "https://app.example.com" },
            store
        );
        const identity = await AgentIdentity.create(
            {
                agentName: "test-agent",
                hostname: "test-host",
                capabilities,
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );
        const jtiCache = new JtiCache();
        const builder = new TokenBuilder(identity);
        const verifier = new TokenVerifier(identity, jtiCache);
        return { identity, builder, verifier, jtiCache };
    }

    it("build() returns a 3-part JWT with correct claims", async () => {
        const { builder } = await makeChain();
        const { token, claims } = await builder.build("chat.completion");
        const parts = token.split(".");
        assert.equal(parts.length, 3);
        assert.equal(claims.aud, "chat.completion");
        assert.ok(typeof claims.jti === "string" && claims.jti.length > 0);
        assert.ok(typeof claims.hostThumbprint === "string" && claims.hostThumbprint.length > 0);
    });

    it("verify() passes for a freshly built token", async () => {
        const { builder, verifier, jtiCache } = await makeChain();
        const { token } = await builder.build("chat.completion");
        const ctx = await verifier.verify(token, "chat.completion");
        assert.equal(ctx.capability, "chat.completion");
        assert.ok(ctx.agentId.length > 0);
        assert.ok(ctx.hostThumbprint.length > 0);
        jtiCache.destroy();
    });

    it("verify() rejects wrong capability (aud mismatch)", async () => {
        const { builder, verifier, jtiCache } = await makeChain(["read", "write"]);
        const { token } = await builder.build("read");
        await assert.rejects(
            () => verifier.verify(token, "write"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "capability_denied");
                return true;
            }
        );
        jtiCache.destroy();
    });

    it("verify() rejects a replayed token", async () => {
        const { builder, verifier, jtiCache } = await makeChain();
        const { token } = await builder.build("chat.completion");
        await verifier.verify(token, "chat.completion");
        await assert.rejects(
            () => verifier.verify(token, "chat.completion"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "token_replayed");
                return true;
            }
        );
        jtiCache.destroy();
    });

    it("verify() rejects a token for an unregistered capability", async () => {
        const { builder, verifier, jtiCache } = await makeChain(["read"]);

        // Build a token for a capability the agent doesn't hold.
        // We need to build it — but the verifier checks grants AFTER signature.
        // So we build "read" but tell verifier we want "admin".
        const { token } = await builder.build("read");
        // aud = "read" != requested "admin" → capability_denied from aud check
        await assert.rejects(
            () => verifier.verify(token, "admin"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "capability_denied");
                return true;
            }
        );
        jtiCache.destroy();
    });

    it("verify() rejects a malformed token", async () => {
        const { verifier, jtiCache } = await makeChain();
        await assert.rejects(
            () => verifier.verify("not.a.jwt", "chat.completion"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "token_invalid");
                return true;
            }
        );
        jtiCache.destroy();
    });

    it("verify() rejects an expired token", async () => {
        const { identity, jtiCache } = await makeChain();

        // Build a token with exp in the past
        const { signJwt } = await import("../crypto/ed25519.js");
        const { base64UrlEncode } = await import("../crypto/utils.js");
        const { randomBytes } = await import("node:crypto");

        const nowSeconds = Math.floor(Date.now() / 1000);
        const expiredClaims = {
            iss: identity.thumbprint,
            sub: identity.agentId,
            aud: "chat.completion",
            iat: nowSeconds - 120,
            exp: nowSeconds - 60,   // expired 60 seconds ago
            jti: base64UrlEncode(randomBytes(16)),
            hostname: identity.registration.hostname,
            agentName: identity.registration.agentName,
            hostThumbprint: identity.registration.hostThumbprint,
        };
        const expiredToken = await signJwt(expiredClaims, identity.privateKey, "agent+jwt");
        const verifier = new TokenVerifier(identity, jtiCache, { clockSkew: 0 });

        await assert.rejects(
            () => verifier.verify(expiredToken, "chat.completion"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "token_expired");
                return true;
            }
        );
        jtiCache.destroy();
    });

    it("verify() rejects a token with wrong hostThumbprint", async () => {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "app", issuerUrl: "https://app.example.com" },
            store
        );
        const identity = await AgentIdentity.create(
            {
                agentName: "agent",
                hostname: "h",
                capabilities: ["read"],
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );

        // Build a token but inject a different hostThumbprint
        const { signJwt } = await import("../crypto/ed25519.js");
        const { base64UrlEncode } = await import("../crypto/utils.js");
        const { randomBytes } = await import("node:crypto");

        const nowSeconds = Math.floor(Date.now() / 1000);
        const tamperedClaims = {
            iss: identity.thumbprint,
            sub: identity.agentId,
            aud: "read",
            iat: nowSeconds,
            exp: nowSeconds + 60,
            jti: base64UrlEncode(randomBytes(16)),
            hostname: identity.registration.hostname,
            agentName: identity.registration.agentName,
            hostThumbprint: "rogue-thumbprint-injected",
        };
        const tamperedToken = await signJwt(tamperedClaims, identity.privateKey, "agent+jwt");

        const jtiCache = new JtiCache();
        const verifier = new TokenVerifier(identity, jtiCache);
        await assert.rejects(
            () => verifier.verify(tamperedToken, "read"),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "token_invalid");
                return true;
            }
        );
        jtiCache.destroy();
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. AuditLog
// ─────────────────────────────────────────────────────────────────────────────

describe("AuditLog", () => {
    function makeStore() {
        return EncryptedStore.create();
    }

    const baseCtx = {
        agentId: "test-agent-001",
        agentName: "test-agent",
        hostname: "test-host",
        hostThumbprint: "thumb-abc",
        capability: "read",
        jti: "jti-001",
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 60,
    };

    it("recordCall() appends a success entry", () => {
        const store = makeStore();
        const log = new AuditLog(store);
        log.recordCall({
            context: baseCtx,
            args: { query: "hello" },
            result: "success",
            durationMs: 10,
            authOverheadMs: 2,
        });
        assert.equal(log.count, 1);
        const [entry] = log.getAll();
        assert.equal(entry!.result, "success");
        assert.equal(entry!.capability, "read");
        assert.equal(entry!.authOverheadMs, 2);
        assert.equal(entry!.hostThumbprint, "thumb-abc");
    });

    it("recordDenied() appends a denied entry with reason", () => {
        const store = makeStore();
        const log = new AuditLog(store);
        log.recordDenied({
            agentId: "a1",
            agentName: "ag",
            hostname: "h",
            hostThumbprint: "thumb-xyz",
            capability: "write",
            args: {},
            reason: "no grant",
            jti: "j1",
            authOverheadMs: 3,
        });
        const entries = log.getAll();
        assert.equal(entries.length, 1);
        assert.equal(entries[0]!.result, "denied");
        assert.equal(entries[0]!.denialReason, "no grant");
    });

    it("sanitizes secret keys in args (key, token, password)", () => {
        const store = makeStore();
        const log = new AuditLog(store);
        log.recordCall({
            context: baseCtx,
            args: {
                apiKey: "sk-secret123",
                password: "hunter2",
                normalField: "visible",
            },
            result: "success",
            durationMs: 5,
            authOverheadMs: 1,
        });
        const [entry] = log.getAll();
        assert.equal(entry!.args["apiKey"], "[REDACTED]");
        assert.equal(entry!.args["password"], "[REDACTED]");
        assert.equal(entry!.args["normalField"], "visible");
    });

    it("getByResult() filters entries correctly", () => {
        const store = makeStore();
        const log = new AuditLog(store);
        log.recordCall({
            context: baseCtx,
            args: {},
            result: "success",
            durationMs: 1,
            authOverheadMs: 1,
        });
        log.recordDenied({
            agentId: "a",
            agentName: "ag",
            hostname: "h",
            hostThumbprint: "t",
            capability: "write",
            args: {},
            reason: "no grant",
            jti: "j2",
            authOverheadMs: 1,
        });
        assert.equal(log.getByResult("success").length, 1);
        assert.equal(log.getByResult("denied").length, 1);
    });

    it("capped at MAX_ENTRIES=1000 — oldest entry is evicted", () => {
        const store = makeStore();
        const log = new AuditLog(store);

        // Fill to exactly 1000
        for (let i = 0; i < 1000; i++) {
            log.recordCall({
                context: { ...baseCtx, jti: `jti-${i}` },
                args: {},
                result: "success",
                durationMs: 1,
                authOverheadMs: 1,
            });
        }
        assert.equal(log.count, 1000);

        const firstJti = log.getAll()[0]!.jti;

        // Add one more — oldest should be evicted
        log.recordCall({
            context: { ...baseCtx, jti: "jti-overflow" },
            args: {},
            result: "success",
            durationMs: 1,
            authOverheadMs: 1,
        });
        assert.equal(log.count, 1000, "should remain at cap after eviction");

        const newFirst = log.getAll()[0]!.jti;
        assert.notEqual(newFirst, firstJti, "oldest entry should have been evicted");
        const entries = log.getAll();
        assert.equal(entries[entries.length - 1]!.jti, "jti-overflow");
    });

    it("drain() calls exporter and clears the log", async () => {
        const store = makeStore();
        const log = new AuditLog(store);
        log.recordCall({
            context: baseCtx,
            args: {},
            result: "success",
            durationMs: 1,
            authOverheadMs: 1,
        });

        let exportedCount = 0;
        const exporter = {
            export: async (entries: unknown[]) => {
                exportedCount = entries.length;
            },
        };

        await log.drain(exporter);
        assert.equal(exportedCount, 1);
        assert.equal(log.count, 0, "log should be cleared after drain");
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. Constraint enforcement
// ─────────────────────────────────────────────────────────────────────────────

describe("enforceConstraints", () => {
    it("passes when args satisfy all constraints", () => {
        assert.doesNotThrow(() =>
            enforceConstraints(
                { amount: { max: 1000 }, currency: { in: ["USD", "EUR"] } },
                { amount: 500, currency: "USD" }
            )
        );
    });

    it("throws constraint_violated when max is exceeded", () => {
        assert.throws(
            () => enforceConstraints({ amount: { max: 100 } }, { amount: 200 }),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "constraint_violated");
                return true;
            }
        );
    });

    it("throws when below min", () => {
        assert.throws(
            () => enforceConstraints({ quantity: { min: 1 } }, { quantity: 0 }),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "constraint_violated");
                return true;
            }
        );
    });

    it("throws when value not in allowed list", () => {
        assert.throws(
            () =>
                enforceConstraints(
                    { currency: { in: ["USD", "EUR"] } },
                    { currency: "GBP" }
                ),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "constraint_violated");
                return true;
            }
        );
    });

    it("throws when value is in blocked list", () => {
        assert.throws(
            () =>
                enforceConstraints(
                    { region: { not_in: ["CN", "RU"] } },
                    { region: "CN" }
                ),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "constraint_violated");
                return true;
            }
        );
    });

    it("throws on exact primitive mismatch", () => {
        assert.throws(
            () => enforceConstraints({ mode: "strict" as const }, { mode: "lenient" }),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "constraint_violated");
                return true;
            }
        );
    });

    it("allows absent fields (constraint only applies when field is present)", () => {
        assert.doesNotThrow(() =>
            enforceConstraints({ amount: { max: 100 } }, { currency: "USD" })
        );
    });

    it("allows unconstrained fields in args", () => {
        assert.doesNotThrow(() =>
            enforceConstraints({ amount: { max: 100 } }, { amount: 50, extraField: "anything" })
        );
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. CapabilityRegistry
// ─────────────────────────────────────────────────────────────────────────────

describe("CapabilityRegistry", () => {
    function makeCap(name: string) {
        return {
            name,
            description: `${name} capability`,
            inputSchema: { type: "object" as const },
            outputSchema: { type: "object" as const },
            execute: async () => ({ ok: true }),
        };
    }

    it("register() adds a capability", () => {
        const reg = new CapabilityRegistry();
        reg.register(makeCap("read"));
        assert.equal(reg.has("read"), true);
        assert.equal(reg.size, 1);
    });

    it("register() throws on duplicate name", () => {
        const reg = new CapabilityRegistry();
        reg.register(makeCap("read"));
        assert.throws(() => reg.register(makeCap("read")), /already registered/);
    });

    it("list() returns all registered caps", () => {
        const reg = new CapabilityRegistry();
        reg.register(makeCap("read"));
        reg.register(makeCap("write"));
        assert.equal(reg.list().length, 2);
    });

    it("buildWellKnownConfig() has required protocol fields", () => {
        const reg = new CapabilityRegistry();
        reg.register(makeCap("read"));
        const config = reg.buildWellKnownConfig("https://example.com", "test-app");
        assert.equal(config.version, "1.0-draft");
        assert.equal(config.issuer, "https://example.com");
        assert.ok(Array.isArray(config.default_capabilities));
        assert.ok(config.default_capabilities.includes("read"));
        assert.ok(config.endpoints.register);
        assert.ok(config.endpoints.execute);
        assert.ok(config.endpoints.revoke);
    });

    it("buildWellKnownConfig() includes optional fields when provided", () => {
        const reg = new CapabilityRegistry();
        const config = reg.buildWellKnownConfig(
            "https://example.com",
            "test-app",
            "/api",
            { description: "Test app", jwks_uri: "https://example.com/.well-known/jwks" }
        );
        assert.equal(config.description, "Test app");
        assert.equal(config.jwks_uri, "https://example.com/.well-known/jwks");
        assert.ok(config.endpoints.register!.startsWith("/api/"));
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. AgentsChain (integration)
// ─────────────────────────────────────────────────────────────────────────────

describe("AgentsChain", () => {
    it("create() returns an instance with hostId and agentId", async () => {
        const chain = await AgentsChain.create({
            agentName: "test-agent",
            hostname: "test-app",
            capabilities: ["chat.completion"],
        });
        assert.ok(chain.agentId.startsWith("test-app-agent-"));
        assert.ok(chain.hostId.length > 0);
    });

    it("getStats() initialises with zero calls and valid authOverhead shape", async () => {
        const chain = await AgentsChain.create({
            agentName: "agent",
            hostname: "app",
            capabilities: ["chat.completion"],
        });
        const stats = chain.getStats();
        assert.equal(stats.totalCalls, 0);
        assert.equal(stats.successfulCalls, 0);
        assert.equal(stats.deniedCalls, 0);
        assert.equal(typeof stats.authOverhead.avgMs, "number");
        assert.equal(typeof stats.authOverhead.maxMs, "number");
    });

    it("capabilities() returns registered capability names", async () => {
        const chain = await AgentsChain.create({
            agentName: "agent",
            hostname: "app",
            capabilities: ["read", "write", "delete"],
        });
        const caps = chain.capabilities;
        assert.ok(caps.includes("read"));
        assert.ok(caps.includes("write"));
        assert.ok(caps.includes("delete"));
    });

    it("drain() with no exporter clears the log without throwing", async () => {
        const chain = await AgentsChain.create({
            agentName: "agent",
            hostname: "app",
            capabilities: [],
        });
        await assert.doesNotReject(() => chain.drain());
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. AppChain (integration)
// ─────────────────────────────────────────────────────────────────────────────

describe("AppChain", () => {
    function makeReadCap() {
        return {
            name: "read_data",
            description: "Read data records",
            inputSchema: { type: "object" as const, properties: { id: { type: "string" as const } } },
            outputSchema: { type: "object" as const },
            execute: async (params: unknown) => {
                const { id } = params as { id: string };
                return { data: `record-${id}` };
            },
        };
    }

    it("create() sets up host, agent, registry", async () => {
        const chain = await AppChain.create({
            providerName: "data-service",
            issuer: "https://data.example.com",
            capabilities: [makeReadCap()],
        });
        assert.ok(chain.host.thumbprint.length > 0);
    });

    it("getWellKnownConfig() returns protocol-compliant config", async () => {
        const chain = await AppChain.create({
            providerName: "billing-service",
            issuer: "https://billing.example.com",
            capabilities: [makeReadCap()],
        });
        const config = chain.getWellKnownConfig();
        assert.equal(config.version, "1.0-draft");
        assert.equal(config.issuer, "https://billing.example.com");
        assert.ok(config.default_capabilities.includes("read_data"));
    });

    it("wrap() returns a Proxy that executes the capability with valid grant", async () => {
        // Service methods are bypassed by the Proxy — Capability.execute() is called instead.
        // Type as Record so TypeScript doesn't complain about the call args.
        const service: Record<string, (...args: unknown[]) => Promise<unknown>> = {
            read_data: async (params) => {
                const { id } = params as { id: string };
                return { data: `record-${id}` };
            },
        };

        const chain = await AppChain.create({
            providerName: "data-service",
            issuer: "https://data.example.com",
            capabilities: [makeReadCap()],
        });

        const grants = [{ capability: "read_data", status: "active" as const }];
        const secured = chain.wrap(service, grants);

        const result = await secured["read_data"]!({ id: "42" });
        assert.deepEqual(result, { data: "record-42" });

        const stats = chain.getStats();
        assert.equal(stats.successfulCalls, 1);
    });

    it("wrap() denies calls for capabilities not in grants", async () => {
        const service: Record<string, (...args: unknown[]) => Promise<unknown>> = {
            read_data: async () => ({ data: "x" }),
        };

        const chain = await AppChain.create({
            providerName: "data-service",
            issuer: "https://data.example.com",
            capabilities: [makeReadCap()],
        });

        // Empty grants list — no active grants
        const secured = chain.wrap(service, []);

        await assert.rejects(
            () => secured["read_data"]!({ id: "1" }),
            (err: unknown) => {
                assert.ok(err instanceof ChainAuthError);
                assert.equal(err.code, "capability_denied");
                return true;
            }
        );

        const stats = chain.getStats();
        assert.equal(stats.deniedCalls, 1);
    });

    it("getStats() authOverhead is populated after calls", async () => {
        const service: Record<string, (...args: unknown[]) => Promise<unknown>> = {
            read_data: async () => ({ data: "x" }),
        };

        const chain = await AppChain.create({
            providerName: "data-service",
            issuer: "https://data.example.com",
            capabilities: [makeReadCap()],
        });

        const grants = [{ capability: "read_data", status: "active" as const }];
        const secured = chain.wrap(service, grants);
        await secured["read_data"]!({ id: "1" });

        const stats = chain.getStats();
        assert.equal(stats.successfulCalls, 1);
        assert.ok(stats.authOverhead.maxMs >= 0, "maxMs must be non-negative");
        assert.ok(stats.authOverhead.avgMs >= 0, "avgMs must be non-negative");
    });
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. Auth latency overhead measurement
// ─────────────────────────────────────────────────────────────────────────────

describe("Auth latency overhead", () => {
    it("measures build()+verify() overhead and stays under 50ms on warm path", async () => {
        const store = EncryptedStore.create();
        const host = await HostIdentity.create(
            { name: "perf-app", issuerUrl: "https://perf.example.com" },
            store
        );
        const identity = await AgentIdentity.create(
            {
                agentName: "perf-agent",
                hostname: "perf",
                capabilities: ["benchmark"],
                hostThumbprint: host.thumbprint,
                hostPublicKeyJwk: host.getPublicKeyJwk(),
            },
            store
        );
        const jtiCache = new JtiCache();
        const builder = new TokenBuilder(identity);
        const verifier = new TokenVerifier(identity, jtiCache);

        const ITERATIONS = 10;
        const times: number[] = [];

        for (let i = 0; i < ITERATIONS; i++) {
            const start = performance.now();
            const { token } = await builder.build("benchmark");
            await verifier.verify(token, "benchmark");
            times.push(performance.now() - start);
        }

        jtiCache.destroy();

        const avg = times.reduce((s, t) => s + t, 0) / times.length;
        const max = Math.max(...times);

        // Log results — visible in test output
        console.log(`  Auth overhead — avg: ${avg.toFixed(2)}ms  max: ${max.toFixed(2)}ms`);

        // Generous upper bound to accommodate slow CI environments
        assert.ok(avg < 50, `Average auth overhead ${avg.toFixed(2)}ms should be under 50ms`);
    });
});
