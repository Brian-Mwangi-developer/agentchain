/**
 * ESM interop smoke test.
 * Verifies that the ESM build can be imported and that all public exports are
 * present and have the correct types.
 *
 * Run: node scripts/test-esm.mjs
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
    AgentsChain,
    AppChain,
    HostIdentity,
    CapabilityRegistry,
    wrapApp,
    ChainAuthError,
    isChainAuthError,
    ConsoleAuditExporter,
    HttpAuditExporter,
    generateKeyPair,
    exportPublicKeyJwk,
    exportPrivateKeyJwk,
    importPublicKeyJwk,
    computeJwkThumbprint,
    signJwt,
    verifyJwtSignature,
    decodeJwtUnsafe,
    generateId,
    generateAgentId,
    base64UrlEncode,
    base64UrlDecode,
} from "../dist/esm/index.js";

const expectedFunctions = {
    AgentsChain,
    AppChain,
    HostIdentity,
    CapabilityRegistry,
    wrapApp,
    ChainAuthError,
    isChainAuthError,
    ConsoleAuditExporter,
    HttpAuditExporter,
    generateKeyPair,
    exportPublicKeyJwk,
    exportPrivateKeyJwk,
    importPublicKeyJwk,
    computeJwkThumbprint,
    signJwt,
    verifyJwtSignature,
    decodeJwtUnsafe,
    generateId,
    generateAgentId,
    base64UrlEncode,
    base64UrlDecode,
};

describe("ESM interop — import from 'agents-chain'", () => {
    for (const [name, value] of Object.entries(expectedFunctions)) {
        it(`exports "${name}" as a function`, () => {
            assert.equal(typeof value, "function", `Expected "${name}" to be a function`);
        });
    }

    it("ChainAuthError instances satisfy isChainAuthError()", () => {
        const err = new ChainAuthError("token_invalid", "test");
        assert.ok(isChainAuthError(err));
    });

    it("ChainAuthError is instanceof Error", () => {
        const err = new ChainAuthError("token_invalid", "test");
        assert.ok(err instanceof Error);
        assert.equal(err.name, "ChainAuthError");
        assert.equal(err.code, "token_invalid");
    });

    it("CapabilityRegistry can register and retrieve a capability", () => {
        const registry = new CapabilityRegistry();
        const cap = {
            name: "doSomething",
            description: "A test capability",
            inputSchema: { type: "object", properties: {} },
            outputSchema: { type: "object", properties: {} },
        };
        registry.register(cap);
        const retrieved = registry.get("doSomething");
        assert.equal(retrieved.name, "doSomething");
    });

    it("isChainAuthError returns false for plain errors", () => {
        assert.equal(isChainAuthError(new Error("plain")), false);
        assert.equal(isChainAuthError(null), false);
        assert.equal(isChainAuthError("string"), false);
    });

    it("generateId returns a non-empty string", async () => {
        const id = await generateId();
        assert.equal(typeof id, "string");
        assert.ok(id.length > 0);
    });

    it("base64UrlEncode / base64UrlDecode round-trips correctly", () => {
        const input = "hello world 123 !@#";
        const encoded = base64UrlEncode(Buffer.from(input));
        const decoded = base64UrlDecode(encoded);
        assert.equal(Buffer.from(decoded).toString(), input);
    });

    it("named exports are stable across re-import (ESM singleton)", async () => {
        // Re-importing the same module should return the same references
        const mod2 = await import("../dist/esm/index.js");
        assert.equal(mod2.ChainAuthError, ChainAuthError);
        assert.equal(mod2.isChainAuthError, isChainAuthError);
    });
});
