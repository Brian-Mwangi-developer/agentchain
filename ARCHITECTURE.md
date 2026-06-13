# agents-chain — Architecture

This document describes the internal structure and data flows of the `agents-chain` package as of v0.0.55.

---

## Module map

```
agents-chain/
├── chain.ts                  AgentsChain, AppChain (main entry points)
├── index.ts                  Public re-exports
│
├── host/
│   └── host-identity.ts      HostIdentity — Ed25519 keypair, thumbprint, signs host/registration JWTs
│
├── identity/
│   └── agent-identity.ts     AgentIdentity — Ed25519 keypair, agent registration, capability names
│
├── auth/
│   ├── token-builder.ts      TokenBuilder — mints signed 60s capability JWTs
│   ├── token-verifier.ts     TokenVerifier — 11-step pipeline (decode → sig → chain → JTI → grant)
│   └── constraints.ts        enforceConstraints() — field-level validation against GrantConstraints
│
├── app/
│   ├── capability-registry.ts  CapabilityRegistry — name → Capability map, well-known config builder
│   └── app-wrapper.ts          wrapApp() — JavaScript Proxy interceptor, dispatches to execute or target method
│
├── audit/
│   ├── audit-log.ts           AuditLog — in-memory buffer (O(1) append, cap 1000), AES-256-GCM flush
│   └── audit-exporter.ts      AuditExporter interface, ConsoleAuditExporter, HttpAuditExporter
│
├── memory/
│   ├── encrypted-store.ts     EncryptedStore — AES-256-GCM Map<string,string>, optional persistence adapter
│   └── jti-cache.ts           JtiCache — 90s replay window, background GC, optional Redis adapter
│
├── crypto/
│   ├── ed25519.ts             generateKeyPair, sign/verify JWT, JWK import/export, thumbprint
│   └── utils.ts               generateId, generateAgentId, base64UrlEncode/Decode
│
├── errors/
│   └── chain-error.ts         ChainAuthError, isChainAuthError(), ChainErrorCode enum
│
├── wrappers/
│   ├── openai-wrapper.ts      wrapOpenAI() — Proxy over OpenAI SDK, maps method paths → capability strings
│   └── anthropic-wrapper.ts   wrapAnthropic() — Proxy over Anthropic SDK, maps method paths → capability strings
│
├── access/
│   ├── access-request-manager.ts  AccessRequestManager — HMAC code generation, pending request
│   │                               tracking, approve/deny/expire, suspended Promise map
│   └── approval-store.ts           ApprovalStore — encrypted + HMAC-integrity rule storage,
│                                   constraint expansion and merging
│
└── types/
    ├── capabilities.ts        Capability, AgentContext, GrantConstraints, JsonSchemaObject
    ├── chain.ts               AgentConfig, AppChainConfig, ChainStats, AuditSnapshot
    ├── identity.ts            RegisteredAgent, CapabilityGrant, CapabilityConstraints
    ├── audit.ts               AuditEntry, AuditResult
    ├── protocol.ts            HostJwtClaims, AgentJwtClaims, ResolvedGrant, AgentConfiguration
    └── access-request.ts      AccessRequest, ApprovalScope, ApprovalDecision, DenialDecision,
                               ApprovalRule, SuspendedCall, AccessRequestNotifier, AccessRequestConfig
```

---

## Shared state — EncryptedStore

All chain state flows through one shared `EncryptedStore` instance created in `AppChain.create()` or `AgentsChain.create()`. Nothing is siloed.

```
AppChain.create()
    │
    └─► EncryptedStore.create(encryptionKey?)
            │
            ├─► HostIdentity    (persists host registration under "host:*" keys)
            ├─► AgentIdentity   (persists agent registration under "agent:*" keys)
            └─► AuditLog        (persists encrypted audit buffer under "audit:log" key)
```

An optional `StorePersistenceAdapter` (Redis, SQLite, etc.) can be injected — `EncryptedStore` delegates `get/set/delete` to it so state survives process restarts.

---

## AppChain creation flow

```
AppChain.create(config)
    │
    ├── 1. EncryptedStore.create()           — AES-256-GCM in-memory store (+ optional adapter)
    ├── 2. JtiCache(jtiAdapter?)             — 90s replay window (+ optional Redis adapter)
    │
    ├── 3a. HostIdentity.fromKeyPair()       — if config.host.privateKeyJwk provided
    │   OR
    │   3b. HostIdentity.create()            — generates new Ed25519 keypair
    │
    ├── 4a. AgentIdentity.fromKeyPair()      — if config.agent.privateKeyJwk provided
    │   OR
    │   4b. AgentIdentity.create()           — generates new Ed25519 keypair, links to host thumbprint
    │
    ├── 5. TokenBuilder(identity)            — builds signed JWTs using agent private key
    ├── 6. TokenVerifier(identity, jtiCache) — runs 11-step verification pipeline
    ├── 7. AuditLog(store)                   — in-memory buffer backed by EncryptedStore
    │
    ├── 8. CapabilityRegistry
    │       └── registry.register(cap) for each capability in config.capabilities
    │
    └── 9. (optional) AccessRequestManager + ApprovalStore
            └── created when config.accessRequests is set
                AccessRequestManager(approvalSecret, requestTTLMs, notifier)
                ApprovalStore(store, approvalSecret)   ← shares same secret for HMAC integrity
```

---

## Per-call security pipeline — `chain.wrap(service, grants)`

```
caller → secured.someMethod(args)
    │
    │   [JavaScript Proxy — app-wrapper.ts]
    │
    ├── TokenBuilder.build(capabilityName)
    │       └── signJwt({ sub: agentId, iss: thumbprint, aud: capability, hostThumbprint, jti, exp })
    │
    ├── TokenVerifier.verify(token, capability, grants)
    │       │
    │       │   Step 1–2  decode JWT, confirm typ = "agent+jwt"
    │       │   Step 3    sub === identity.agentId
    │       │   Step 4    iss === identity.thumbprint
    │       │   Step 5    aud === capability
    │       │   Step 6    token.hostThumbprint === identity.registration.hostThumbprint
    │       │   Step 7    verifyJwtSignature(token, agent public key)
    │       │   Step 8    exp/iat temporal check (±30s clock skew)
    │       │   Step 9    JtiCache.has(jti) → throw token_replayed; else JtiCache.set(jti, 90s)
    │       │   Step 10   grants.find(g => g.capability === cap && g.status === "active")
    │       │   Step 11   grant.expiresAt > Date.now()
    │       │
    │       └── returns VerifiedCallContext { agentId, thumbprint, hostThumbprint, capability, jti }
    │
    ├── ApprovalStore.getExpandedConstraints(capability)
    │       └── merges any active approval rules into grant constraints
    │           returns: null (bypass all) | undefined (no rules) | GrantConstraints (merged)
    │
    ├── enforceConstraints(effectiveConstraints, args, capability.inputSchema)
    │       └── for each constrained field:
    │               - if field in inputSchema.required and value === undefined → constraint_violated
    │               - max/min/in/not_in/exact equality checks on present values
    │
    ├── resolve executeFn
    │       ├── if capability.execute defined  → capability.execute(args, agentContext)
    │       └── if target has method of same name → target[methodName](args)   [after auth gate]
    │
    ├── executeFn(args)
    │
    ├── AuditLog.recordCall({ context, args, result, durationMs, authOverheadMs })
    │
    └── on ChainAuthError (constraint_violated | capability_denied):
            │
            ├── [no accessRequestManager] → AuditLog.recordDenied(...) → throw
            │
            └── [accessRequestManager present]
                    │
                    ├── ApprovalStore.findMatchingRule() → existing rule?
                    │       └── yes → re-execute (rule expands constraints)
                    │
                    ├── AuditLog.recordDenied(reason: "[access_request] ...")
                    │
                    ├── AccessRequestManager.createRequest(...)
                    │       └── generates HMAC code, stores SuspendedCall { resolve, reject }
                    │           notifier.notify(request)   ← sends code to human out-of-band
                    │
                    ├── await waitForApproval   ← SUSPENDED — agent call blocks here
                    │
                    ├── [approved] → ApprovalStore.createRule(request, decision)
                    │       ├── scope "call"       → re-execute once, then revokeRule()
                    │       └── scope "value/capability/global" → re-execute (rule persists)
                    │
                    └── [denied/expired] → throw ChainAuthError(access_request_denied/expired)
```

---

## Host JWT flow

The `HostIdentity` keypair is the cryptographic anchor. Its thumbprint (JWK SHA-256) is embedded in every agent registration and every capability JWT so the verifier can trace the full delegation chain.

```
HostIdentity
    │
    ├── getPublicKeyJwk()           → raw JWK (embedded in agent registration)
    ├── thumbprint                  → SHA-256 of JWK (stable hostId)
    ├── signHostJwt()               → host+jwt signed with host private key
    └── signAgentRegistrationJwt(agentPublicKeyJwk)
            └── { typ: "host+jwt", sub: hostThumbprint, aud: agentThumbprint,
                  hostPublicKeyJwk, exp: +24h }

AgentIdentity.registration
    ├── agentId                     → agent's JWK thumbprint
    ├── publicKeyJwk                → agent's Ed25519 public key
    ├── hostThumbprint              → copied from HostIdentity at registration time
    └── hostPublicKeyJwk            → copied from HostIdentity at registration time

Capability JWT (agent+jwt)
    ├── sub: agentId
    ├── iss: agentThumbprint
    ├── aud: capabilityName
    ├── hostThumbprint              → verified in Step 6
    ├── jti                         → random ID, cached 90s for replay protection
    └── exp: now + 60s
```

---

## Identity restore flow (across restarts)

```
First boot
    AppChain.create({ providerName, issuer, capabilities })
        → HostIdentity.create()    → generates { privateKey, publicKey }
        → AgentIdentity.create()   → generates { privateKey, publicKey }

    Export for persistence:
        host.exportPrivateKeyJwk() → hostPrivateKeyJwk  (store in secrets manager)
        host.getPublicKeyJwk()     → hostPublicKeyJwk

Subsequent boots
    AppChain.create({
        ...,
        host:  { privateKeyJwk, publicKeyJwk },
        agent: { agentId, privateKeyJwk, publicKeyJwk }
    })
        → HostIdentity.fromKeyPair()    → restores same thumbprint / hostId
        → AgentIdentity.fromKeyPair()   → restores same agentId
```

---

## AuditLog internals

```
AuditLog
    ├── buffer: AuditEntry[]         ← in-memory, never encrypted individually
    ├── loaded: boolean              ← lazy-load flag
    │
    ├── ensureLoaded()               ← decrypts from EncryptedStore once on first read
    ├── appendCapped(entry)          ← O(1) push, evicts oldest when buffer.length > 1000
    ├── getAll()                     ← returns buffer (always in-memory, no I/O)
    ├── flush()                      ← encrypts entire buffer to EncryptedStore
    └── drain(exporter?)             ← calls exporter.export(entries), then clears buffer
```

Every `recordCall()` / `recordDenied()` appends to `this.buffer` directly — there is no per-append encrypt/decrypt cycle. The buffer is flushed to `EncryptedStore` only when `flush()` or `drain()` is called.

Argument sanitization runs before any entry is stored:

```
sanitizeArgs(args)
    └── for each key in args:
            if key matches /key|secret|token|password|auth|credential|bearer/ (case-insensitive)
                → replace value with "[REDACTED]"
```

---

## JTI cache internals

```
JtiCache
    ├── cache: Map<jti, expiresAt>
    ├── GC timer: setInterval(evictExpired, 45s).unref()   ← does not block process exit
    │
    ├── has(jti)       → checks local cache + optional adapter.has(jti)
    ├── set(jti, ttl)  → cache.set(jti, now+ttl) + optional adapter.set(jti, ttl)
    ├── evictExpired() → removes entries where expiresAt < now
    └── destroy()      → clearInterval(timer), cache.clear()
```

`destroy()` must be called on graceful shutdown (and in tests) to stop the GC timer.

---

## Capability registry internals

```
CapabilityRegistry
    ├── caps: Map<name, Capability>
    │
    ├── register(cap)        → throws if name already exists
    ├── upsert(cap)          → replaces silently (runtime hot-reload)
    ├── get(name)            → returns Capability or undefined
    ├── unregister(name)     → removes, returns true if existed
    ├── list()               → returns all Capability values
    └── buildWellKnownConfig(issuerUrl, providerName, prefix?, opts?)
            └── returns AgentConfiguration for /.well-known/agent-configuration
```

---

## Access request internals

```
AccessRequestManager
    ├── pendingRequests: Map<requestId, AccessRequest>
    ├── suspendedCalls:  Map<requestId, SuspendedCall { resolve, reject }>
    ├── readonly secret: Buffer          ← agent can never reach this
    │
    ├── createRequest(params)
    │       ├── generateId("areq")       → requestId
    │       ├── generateCode()           → HMAC-SHA256(secret, requestId:agentId:capability:createdAt)
    │       │                               truncated to 8 uppercase hex chars → "A3F7C209"
    │       ├── stores request + new Promise in suspendedCalls
    │       ├── schedules expiry timer (requestTTLMs)
    │       ├── notifier.notify(request) ← sends code out-of-band
    │       └── returns { request, waitForApproval: Promise }
    │
    ├── approve(decision)
    │       ├── verifyCode() — constant-time HMAC compare (prevents timing attacks)
    │       └── suspendedCalls.get(requestId).resolve({ approved: true, decision })
    │
    ├── deny(decision)
    │       └── suspendedCalls.get(requestId).resolve({ approved: false, decision })
    │
    └── destroy()   → clears all expiry timers

ApprovalStore
    ├── rules: ApprovalRule[]            ← in-memory cache
    ├── readonly secret: Buffer          ← same secret as AccessRequestManager
    │
    ├── createRule(request, decision)
    │       └── builds ApprovalRule from scope, field, value, TTL → persist()
    │
    ├── findMatchingRule(agentId, capability, args, violatedField, violatedValue)
    │       └── sweepExpired() → iterate rules → match by scope:
    │               "call"       → skip (consumed immediately)
    │               "value"      → match if field + value match
    │               "capability" → always match
    │               "global"     → always match
    │
    ├── getExpandedConstraints(capability)
    │       └── returns null (capability/global rule found — bypass all constraints)
    │               undefined (no matching rules — use original constraints)
    │               GrantConstraints (value/call rules — merged in list expansions)
    │
    ├── persist()   → store.set(rules) + store.set(HMAC over rules JSON)
    └── load()      → recompute HMAC; if mismatch → wipe all rules + warn
```

---

## Persistence adapter injection points

```
AppChain.create(config)
    │
    ├── config.encryptionKey      → AES-256-GCM key for EncryptedStore (hex or base64)
    │
    ├── config.storeAdapter       → StorePersistenceAdapter
    │       interface StorePersistenceAdapter {
    │           get(key: string): Promise<string | undefined>
    │           set(key: string, value: string): Promise<void>
    │           delete(key: string): Promise<void>
    │       }
    │
    ├── config.jtiAdapter         → JtiPersistenceAdapter
    │       interface JtiPersistenceAdapter {
    │           has(key: string): Promise<boolean>
    │           set(key: string, ttlMs: number): Promise<void>
    │       }
    │
    └── config.grantResolver      → async (agentId, capability) => ResolvedGrant | undefined
            used by TokenVerifier to fetch grants from your DB instead of from the passed-in array
```

---

## Build outputs

The package ships two compiled outputs selected automatically by Node.js via the `exports` map:

```
dist/
├── esm/
│   ├── index.js          ESM (import / type: "module" consumers)
│   └── index.d.ts        TypeScript declarations
└── cjs/
    ├── package.json      { "type": "commonjs" }  ← required for .js to load as CJS
    ├── index.js          CommonJS (require() consumers)
    └── index.d.ts
```

```json
"exports": {
  ".": {
    "import":  { "types": "./dist/esm/index.d.ts", "default": "./dist/esm/index.js" },
    "require": { "types": "./dist/cjs/index.d.ts", "default": "./dist/cjs/index.js" }
  }
}
```

---

## Test structure

```
src/__tests__/agents-chain.test.ts      20 suites, 87 unit + integration tests
src/__tests__/access-requests.test.ts   4 suites, 57 access request tests
scripts/test-cjs.cjs                    27 CJS artifact tests  (require from dist/cjs)
scripts/test-esm.mjs                    28 ESM artifact tests  (import from dist/esm)

pnpm test             build + unit suites (130 tests)
pnpm test:interop     CJS + ESM artifact tests (55 tests, no rebuild)
pnpm test:all         both of the above
```
