/**
 * CJS interop smoke test.
 * Verifies that the CommonJS build can be require()'d and that all public
 * exports are present and have the correct types.
 *
 * Run: node scripts/test-cjs.cjs
 */

"use strict";

const assert = require("node:assert/strict");
const { describe, it, run } = require("node:test");

describe("CJS interop — require('agents-chain')", () => {
    const pkg = require("../dist/cjs/index.js");

    const expectedFunctions = [
        "AgentsChain",
        "AppChain",
        "HostIdentity",
        "CapabilityRegistry",
        "wrapApp",
        "ChainAuthError",
        "isChainAuthError",
        "ConsoleAuditExporter",
        "HttpAuditExporter",
        "generateKeyPair",
        "exportPublicKeyJwk",
        "exportPrivateKeyJwk",
        "importPublicKeyJwk",
        "computeJwkThumbprint",
        "signJwt",
        "verifyJwtSignature",
        "decodeJwtUnsafe",
        "generateId",
        "generateAgentId",
        "base64UrlEncode",
        "base64UrlDecode",
    ];

    for (const name of expectedFunctions) {
        it(`exports "${name}" as a function`, () => {
            assert.equal(typeof pkg[name], "function", `Expected "${name}" to be a function`);
        });
    }

    it("ChainAuthError instances satisfy isChainAuthError()", () => {
        const err = new pkg.ChainAuthError("token_invalid", "test");
        assert.ok(pkg.isChainAuthError(err));
    });

    it("ChainAuthError is instanceof Error", () => {
        const err = new pkg.ChainAuthError("token_invalid", "test");
        assert.ok(err instanceof Error);
        assert.equal(err.name, "ChainAuthError");
        assert.equal(err.code, "token_invalid");
    });

    it("CapabilityRegistry can register and retrieve a capability", () => {
        const registry = new pkg.CapabilityRegistry();
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
        assert.equal(pkg.isChainAuthError(new Error("plain")), false);
        assert.equal(pkg.isChainAuthError(null), false);
        assert.equal(pkg.isChainAuthError("string"), false);
    });

    it("generateId returns a non-empty string", async () => {
        const id = await pkg.generateId();
        assert.equal(typeof id, "string");
        assert.ok(id.length > 0);
    });

    it("base64UrlEncode / base64UrlDecode round-trips correctly", () => {
        const input = "hello world 123 !@#";
        const encoded = pkg.base64UrlEncode(Buffer.from(input));
        const decoded = pkg.base64UrlDecode(encoded);
        assert.equal(Buffer.from(decoded).toString(), input);
    });
});
