# agents-chain — Architecture & Gap Analysis

## Overview

`agents-chain` (v0.0.3) is a zero-dependency TypeScript library that adds identity, authentication, and audit to AI agent SDK calls (OpenAI, Anthropic) and to arbitrary app service objects. It operates as a transparent proxy layer — no modification to existing SDK clients or service classes is needed.

---

## How It Works

### Two Entry Points

#### 1. `AgentsChain` — AI SDK Wrapper
Used to wrap OpenAI or Anthropic SDK clients. Every intercepted method call goes through a full auth pipeline before hitting the real API.

```
AgentsChain.create(config)
  ├── EncryptedStore     (AES-256-GCM in-memory store for keys + audit log)
  ├── AgentIdentity      (Ed25519 keypair + registration record)
  ├── TokenBuilder       (builds per-call signed agent+jwt tokens)
  ├── TokenVerifier      (verifies tokens, checks grants, enforces expiry + replay)
  └── AuditLog           (append-only encrypted log of all calls)
```

**Per-call flow (openai/anthropic wrapper):**
1. `client.chat.completions.create(...)` is intercepted by a `Proxy`
2. Path `"chat.completions.create"` → mapped to capability name `"chat.completion"`
3. `TokenBuilder.build("chat.completion")` → signs a fresh `agent+jwt` (60s TTL, unique `jti`)
4. `TokenVerifier.verify(token, "chat.completion")` → validates signature, claims, expiry, replay, and grant
5. On success: original SDK method is called, result + duration recorded in AuditLog
6. On failure: `ChainAuthError` is thrown and a "denied" entry is recorded in AuditLog

#### 2. `AppChain` — App Service Wrapper
Used to wrap your own service objects. Instead of a hardcoded path→capability map, it uses a `CapabilityRegistry` with user-defined `Capability` objects.

```
AppChain.create(config)
  ├── EncryptedStore
  ├── AgentIdentity      (synthetic — provider name used as agent identity)
  ├── TokenBuilder
  ├── TokenVerifier      (optional external grantResolver)
  ├── AuditLog
  ├── CapabilityRegistry (user-registered Capability objects)
  └── HostIdentity       (signs host+jwt for agent registration operations)
```

**Per-call flow (app-wrapper):**
1. `securedService.createInvoice(args)` is intercepted by a `Proxy`
2. Method name `"createInvoice"` looked up in `CapabilityRegistry`
3. If not registered: pass-through, no gating
4. If registered: same JWT build → verify pipeline as above
5. Grant constraints (max/min/in/not_in) enforced on `args` after JWT verification
6. `capability.execute(args, agentContext)` is called — the user's own logic, NOT the raw method
7. Result recorded in AuditLog

---

## Module Map

| Module | Responsibility |
|---|---|
| `src/chain.ts` | `AgentsChain` and `AppChain` entry classes |
| `src/identity/agent-identity.ts` | Ed25519 keypair + registration; stored encrypted |
| `src/host/host-identity.ts` | Host keypair; signs management JWTs (registration, revocation) |
| `src/auth/token-builder.ts` | Builds signed `agent+jwt` per capability call |
| `src/auth/token-verifier.ts` | Verifies JWT: signature, claims, expiry, JTI replay, grant |
| `src/auth/constraints.ts` | Enforces `GrantConstraints` (max/min/in/not_in) on call args |
| `src/memory/encrypted-store.ts` | AES-256-GCM in-memory KV store; no disk persistence |
| `src/memory/jti-cache.ts` | Replay protection; in-memory or pluggable adapter (Redis etc.) |
| `src/audit/audit-log.ts` | Append-only encrypted audit log; per-session |
| `src/audit/audit-exporter.ts` | `ConsoleAuditExporter` and `HttpAuditExporter` for draining |
| `src/app/capability-registry.ts` | Registers `Capability` objects; generates well-known config |
| `src/app/app-wrapper.ts` | Proxy wrapper for arbitrary service objects |
| `src/wrappers/openai-wrapper.ts` | Proxy wrapper for OpenAI SDK clients |
| `src/wrappers/anthropic-wrapper.ts` | Proxy wrapper for Anthropic SDK clients |
| `src/crypto/ed25519.ts` | Ed25519 keygen, sign, verify; JWT encode/decode |
| `src/crypto/utils.ts` | ID generation, base64url helpers |
| `src/types/` | `identity`, `chain`, `audit`, `protocol`, `capabilities` types |
| `src/errors/chain-error.ts` | `ChainAuthError` with typed error codes |

---

## Security Model

- **Identity**: Every agent has an Ed25519 keypair. The `iss` JWT claim is the public key thumbprint — not a mutable name — making key substitution attacks detectable.
- **Tokens**: Single-use, 60-second TTL, scope-bound (`aud` = capability name). A token for `"chat.completion"` cannot authorize `"embedding"`.
- **Replay protection**: `JtiCache` stores every seen `jti` for 90 seconds (covers 60s TTL + 30s clock skew). Reusing a token throws immediately.
- **Grants**: Every call checks the agent holds an active grant for the capability. External `grantResolver` can delegate to Redis / DB.
- **Constraints**: Per-grant argument constraints (`max`, `min`, `in`, `not_in`) enforced before execution.
- **Audit log**: All calls (success, denied, error) written to `EncryptedStore`. Sensitive arg keys (token, key, secret, password, etc.) are redacted before logging.
- **Storage**: All sensitive state (keys, audit log) is held in AES-256-GCM encrypted in-memory store. No disk persistence.

---

## Known Issues & Architecture Gaps

### CONFIRMED BUGS

#### BUG 1 — JTI Replay False Positive (in-memory path)
**File:** [src/memory/jti-cache.ts](src/memory/jti-cache.ts#L97)

The `evictExpired()` call happens before checking existence, which is correct. However, the comment at the bottom of the file (`BUG: If we dont have an adapter then the system always says token Replay Detected`) indicates the author has observed this in practice. The root cause: `AgentsChain.create()` and `AppChain.create()` both call `AgentIdentity.create()`, which generates a **new** keypair on every call. But they both also share a **single** `JtiCache` instance and a **single** `TokenVerifier` — meaning if `verify()` is called twice for the same capability in the same session, the second call will have a different `jti` and should not collide. The real issue is likely that `AppChain` builds both an `AgentIdentity` and a `HostIdentity` using separate `EncryptedStore` instances, and the `TokenVerifier` tied to `AgentIdentity` is self-verifying (it builds the token AND verifies it against the same identity). Self-issue + self-verify is architecturally circular and means the agent is authenticating itself to itself — there is no external party involved in `AgentsChain` or `AppChain` by default.

---

#### BUG 2 — `HostIdentity` creates its own `EncryptedStore`, ignores `AppChain`'s store
**File:** [src/host/host-identity.ts](src/host/host-identity.ts#L63), [src/chain.ts](src/chain.ts#L201)

`HostIdentity.create()` internally calls `EncryptedStore.create(config.encryptionKey)`, creating a **second isolated store**. `AppChain` already has its own store passed to `AgentIdentity` and `AuditLog`. Host registration data is therefore in a separate encrypted store with no shared lifetime or cleanup path.

---

#### BUG 3 — `AgentJwtClaims` type duplication and mismatch
**Files:** [src/auth/token-builder.ts](src/auth/token-builder.ts#L19), [src/types/protocol.ts](src/types/protocol.ts#L32)

`AgentJwtClaims` is defined **twice** with different shapes:
- `token-builder.ts` defines: `{ iss, sub, aud, iat, exp, jti, hostname, agentName }`
- `protocol.ts` defines: `{ iss, sub, aud, iat, exp, jti, capabilities? }`

`TokenVerifier` imports from `token-builder.ts`. The `protocol.ts` version is a dead type never used by the verifier. This creates a divergence between what the wire protocol spec says and what is actually signed/verified. The `hostname` and `agentName` custom claims are not part of any declared protocol spec.

---

### ARCHITECTURE GAPS

#### GAP 1 — Self-issuance: Agent builds and verifies its own tokens
**Files:** [src/chain.ts](src/chain.ts), [src/app/app-wrapper.ts](src/app/app-wrapper.ts)

In both `AgentsChain` and `AppChain`, the same `AgentIdentity` is used to **build** the token (via `TokenBuilder`) and to **verify** it (via `TokenVerifier`). This means the library is authenticating an agent to itself — there is no external verifier. This is secure for audit purposes (the log is trustworthy) but provides no actual access control against a third party. A real deployment needs either:
- A remote server that holds the verification keys (the referenced `agent-auth` server)
- Or cross-agent verification where Agent A's token is verified by Agent B's verifier

The architecture describes endpoints (`/agent/register`, `/capability/execute`, etc.) in `AgentConfiguration` but none of them are implemented or called anywhere in this library.

---

#### GAP 2 — `RegisteredAgent` has no Host linkage
**Files:** [src/types/identity.ts](src/types/identity.ts#L38), [src/identity/agent-identity.ts](src/identity/agent-identity.ts)

`RegisteredAgent` has no `hostId` or `hostThumbprint` field. The code has a comment: `// NOTE: a Registered Agent needs its parents HostKeys`. Without this, there is no cryptographic chain from Host → Agent, which means:
- The well-known config cannot express which Host vouches for which agents
- `VerifiedCallContext.hostId` is always `undefined` (it is populated as `verified.hostId ?? ""` in app-wrapper, but `verify()` never sets it because the agent token has no host claim)

---

#### GAP 3 — `AgentJwtClaims.iss` is the agent thumbprint, not the host thumbprint
**File:** [src/auth/token-builder.ts](src/auth/token-builder.ts#L40), [src/types/protocol.ts](src/types/protocol.ts#L33)

`TokenBuilder` sets `iss = identity.thumbprint` (the **agent's** public key thumbprint). The comment in `protocol.ts` says `iss` should be "Host thumbprint (who delegated this agent)". These are semantically opposite. If `iss` should identify the delegating host, the agent needs to know its host's thumbprint at token build time — but `AgentIdentity` has no host reference.

---

#### GAP 4 — `AppChain.wrap()` requires pre-resolved `grants` at wrap time
**File:** [src/chain.ts](src/chain.ts#L217)

`AppChain.wrap(target, grants)` takes `grants` at the moment of wrapping. This means:
- All calls on the wrapped object use the **same static grants** regardless of who is calling
- If multiple agents call the same wrapped service with different permissions, a new wrapped proxy must be created per agent per request
- There is no per-call grant resolution at the proxy level (only at the `TokenVerifier` level via `grantResolver`)

---

#### GAP 5 — `CapabilityRegistry` well-known config lists endpoints that don't exist
**File:** [src/app/capability-registry.ts](src/app/capability-registry.ts#L51)

`buildWellKnownConfig()` returns hardcoded endpoint paths (`/agent/register`, `/capability/execute`, etc.). These routes are not implemented by this library. Consumers serving `/.well-known/agent-configuration` will advertise endpoints that do nothing unless they build all those routes themselves. There is no HTTP server, no route handler, and no middleware provided.

---

#### GAP 6 — `AuditLog` entries contain no Host identity
**File:** [src/audit/audit-log.ts](src/audit/audit-log.ts#L55)

`AuditEntry` records `agentId`, `agentName`, `hostname`, `capability` — but no `hostId`. The comment in the source (`NOTE: Fix this since it does not Contain Hosts credentials`) confirms this is a known gap. In a multi-host deployment, audit logs cannot be attributed to a specific Host.

---

#### GAP 7 — Constraint types are duplicated across two type files
**Files:** [src/types/identity.ts](src/types/identity.ts#L25), [src/types/capabilities.ts](src/types/capabilities.ts#L25)

`ConstraintPrimitive`, `ConstraintOperator`, and `ConstraintValue` are defined identically in both `types/identity.ts` and `types/capabilities.ts`. `CapabilityConstraints` (identity.ts) and `GrantConstraints` (capabilities.ts) are structurally identical but separate types. `index.ts` re-exports both sets under different aliases, creating confusion about which is canonical.

---

#### GAP 8 — No tests
**File:** [package.json](package.json#L24)

`"test": "echo \"Error: no test specified\" && exit 1"` — there are zero tests. For a security-critical library (JWT signing/verification, replay protection, constraint enforcement), this is a significant gap. None of the auth pipeline, crypto, or audit logic has test coverage.

---

#### GAP 9 — `EncryptedStore` grows unboundedly
**File:** [src/memory/encrypted-store.ts](src/memory/encrypted-store.ts)

The audit log uses `store.append()` which reads, pushes, and re-encrypts the full array on every call. For long-running processes with many AI calls, this array grows indefinitely in memory. `drain()` clears it, but only if called explicitly. There is no automatic eviction or size limit.

---

#### GAP 10 — `AgentsChain` has no `drain()` method
**File:** [src/chain.ts](src/chain.ts#L36)

`AppChain` exposes `drain(exporter?)` for flushing the audit log. `AgentsChain` does not. Users wrapping OpenAI/Anthropic have no way to export or clear the audit log other than reading all entries and managing them manually.

---

## Summary Table

| # | Type | Severity | Description |
|---|---|---|---|
| BUG 1 | Bug | High | JTI in-memory path may false-positive on replay detection |
| BUG 2 | Bug | Medium | `HostIdentity` creates a second isolated `EncryptedStore` |
| BUG 3 | Bug | Medium | `AgentJwtClaims` defined twice with incompatible shapes |
| GAP 1 | Architecture | High | Agent self-issues and self-verifies — no external auth party |
| GAP 2 | Architecture | High | `RegisteredAgent` missing host linkage (`hostId`) |
| GAP 3 | Architecture | High | `iss` claim semantics inverted (agent vs host thumbprint) |
| GAP 4 | Design | Medium | Grants are static at wrap time, not dynamic per caller |
| GAP 5 | Design | Medium | Well-known config advertises unimplemented endpoints |
| GAP 6 | Design | Medium | Audit entries missing host identity |
| GAP 7 | Design | Low | Constraint types duplicated across two type files |
| GAP 8 | Quality | High | Zero tests for security-critical code paths |
| GAP 9 | Design | Medium | `EncryptedStore` / audit log grows unboundedly without explicit drain |
| GAP 10 | Design | Low | `AgentsChain` missing `drain()` for audit export |
