# agents-chain

**v0.0.55** — A zero-dependency security layer for AI agent systems. Gives every service a **Host identity**, every agent an **Ed25519 keypair**, and gates every capability call through a signed JWT pipeline with constraint enforcement, an encrypted audit trail, and a **human-in-the-loop access request system** for denied calls.

Built for the pattern where a **Host** registers capabilities that **Agents** are granted permission to call — with full cryptographic accountability at every step.

---

## What it does

- **Host + Agent identity** — Ed25519 keypairs with JWK thumbprints as stable IDs. A Host signs agent registration JWTs; agents sign scoped capability tokens tied back to that Host. No rogue agent can impersonate a registered one.
- **11-step JWT verification** — Every capability call mints a fresh 60-second single-use token. Sub, iss, aud, Host delegation chain, Ed25519 signature, expiry, JTI replay, grant existence, grant expiry, and constraint check — all verified before execution proceeds.
- **Capability registry** — Register named capabilities on any service object with input/output schemas. Each capability can define its own `execute` function, or delegate to the target object's own method.
- **Proxy-based call interception** — `chain.wrap(service, grants)` returns a JavaScript Proxy. Method calls are intercepted by name and gated through the full auth pipeline transparently.
- **Grant constraints** — Active grants carry field-level constraints (`max`, `min`, `in`, `not_in`, exact equality). Required fields from the capability's `inputSchema` are enforced — a missing required field is a violation, not a pass.
- **Encrypted audit log** — AES-256-GCM in-memory ring buffer (capped at 1000 entries) of every call, denial, and error. Auth overhead is recorded per entry. Drain to any HTTP endpoint or custom exporter.
- **Stable identity across restarts** — Export host and agent keypairs as JWK; restore them on next boot via `fromKeyPair()`. Your `agentId` and `hostId` stay the same.
- **Persistent JTI replay protection** — In-memory by default; swap in your own Redis/database adapter for cross-process protection.
- **Persistent store adapter** — Plug in Redis or any key-value store for `EncryptedStore` to survive restarts.
- **Well-known discovery** — Serve `GET /.well-known/agent-configuration` with one call so other agents can discover your capabilities automatically.
- **Zero mandatory dependencies** — Everything defaults to in-memory. External systems are adapter-injected by you.
- **Human-in-the-loop access requests** — When an agent is denied, instead of throwing, the call suspends and waits for human approval out-of-band. A pluggable notifier sends the verification code via email, SMS, push, or webhook. The agent's call resumes exactly where it left off when approved.

---

## Installation

```bash
npm install agents-chain
# or
pnpm add agents-chain
```

> Requires Node.js 18+. Ships both ESM and CommonJS builds.

---

## Core concepts

### Host

A `HostIdentity` holds an Ed25519 keypair and acts as the cryptographic anchor for the system. It signs agent registration JWTs that bind an agent's public key to a specific host. Its `thumbprint` (SHA-256 of the JWK) is the stable `hostId` embedded in every capability token.

### Agent

An `AgentIdentity` holds its own Ed25519 keypair, is registered under a Host (carrying the host's `thumbprint`), and is granted a set of capabilities. Every capability call mints a JWT signed with the agent's private key — the verifier checks the full delegation chain back to the Host.

### Capability

A `Capability` is a named, schema-described function. It declares `inputSchema` and `outputSchema` (JSON Schema objects) and optionally an `execute` function. If `execute` is omitted, `wrap()` delegates to the target object's own method of the same name.

### Grant

A `ResolvedGrant` says "this agent is allowed to call this capability". Grants carry `status: "active"`, an optional `expiresAt`, and optional `constraints` that restrict what argument values are allowed.

### AppChain

`AppChain` is the main entry point for any service that registers capabilities and serves them to agents. It owns the Host identity, the capability registry, the token builder/verifier, and the audit log. You call `chain.wrap(service, grants)` to get a secured Proxy of your service object.

---

## Quick start — wrapping a service

```ts
import { AppChain, ConsoleAuditExporter } from 'agents-chain';

// 1. Create the chain — generates Host + Agent keypairs, builds the registry
const chain = await AppChain.create({
  providerName: 'billing-service',
  issuer: 'https://billing.mycompany.com',
  capabilities: [
    {
      name: 'createInvoice',
      description: 'Create a new invoice for a customer',
      inputSchema: {
        type: 'object',
        required: ['customerId', 'amount'],
        properties: {
          customerId: { type: 'string' },
          amount: { type: 'number' },
        },
      },
      outputSchema: { type: 'object' },
      // execute receives (args, agentContext) — agentContext carries agentId, hostId, permissions
      execute: async (args, ctx) => {
        console.log(`Agent ${ctx.agentId} creating invoice`);
        return billingDb.createInvoice(args.customerId, args.amount);
      },
    },
  ],
  auditExporter: new ConsoleAuditExporter(),
});

// 2. Define which grants this agent holds
const grants = [
  {
    capability: 'createInvoice',
    status: 'active',
    constraints: {
      amount: { max: 5000 },
    },
    expiresAt: Date.now() + 86_400_000, // 24h
  },
];

// 3. Wrap your service — returns a Proxy with the auth gate in front
const secured = chain.wrap(billingService, grants);

// 4. Call it — the full 11-step pipeline runs before your execute function
const invoice = await secured.createInvoice({ customerId: 'c1', amount: 500 });

// 5. Flush audit log on shutdown
process.on('SIGTERM', () => chain.drain());
```

---

## Delegating to target object methods

If a capability does not define `execute`, the call is forwarded to the target object's own method after the auth gate passes. This lets you wrap an existing service without rewriting its methods:

```ts
const myService = {
  async sendNotification(args) {
    return notificationApi.send(args.userId, args.message);
  },
};

const chain = await AppChain.create({
  providerName: 'notification-service',
  issuer: 'https://notify.mycompany.com',
  capabilities: [
    {
      name: 'sendNotification',
      description: 'Send a notification to a user',
      inputSchema: {
        type: 'object',
        required: ['userId', 'message'],
        properties: {
          userId: { type: 'string' },
          message: { type: 'string' },
        },
      },
      outputSchema: { type: 'object' },
      // No execute — delegates to myService.sendNotification after auth passes
    },
  ],
});

const secured = chain.wrap(myService, grants);
await secured.sendNotification({ userId: 'u1', message: 'Hello' });
// → myService.sendNotification is called after the auth gate
```

---

## Stable identity across restarts

By default, `AppChain.create()` generates fresh Ed25519 keypairs on every boot. To keep the same `hostId` and `agentId` across restarts, export the keys after first creation and pass them back in on subsequent boots:

```ts
// First boot — generate and save
const chain = await AppChain.create({ providerName: 'my-service', issuer: '...', capabilities: [...] });

const hostPrivateKeyJwk = await chain.host.exportPrivateKeyJwk();
const hostPublicKeyJwk = chain.host.getPublicKeyJwk();
// Persist these securely (e.g. to your secrets manager or encrypted config)

// Subsequent boots — restore
const chain = await AppChain.create({
  providerName: 'my-service',
  issuer: '...',
  capabilities: [...],
  host: {
    privateKeyJwk: hostPrivateKeyJwk,   // restored from persistence
    publicKeyJwk: hostPublicKeyJwk,
  },
  agent: {
    agentId: savedAgentId,
    privateKeyJwk: agentPrivateKeyJwk,
    publicKeyJwk: agentPublicKeyJwk,
  },
});
// chain.host.hostId and chain.agentId are now identical to the first boot
```

---

## Grant constraints

Constrain what argument values an agent is allowed to pass. Constraints are checked against the capability's `inputSchema.required` — a missing required field is a violation even if no constraint value is defined for it.

```ts
const grants = [
  {
    capability: 'createInvoice',
    status: 'active',
    constraints: {
      amount: { max: 1000 },              // amount must be <= 1000
      currency: { in: ['USD', 'EUR'] },   // currency must be one of these
      discount: { min: 0 },               // discount must be >= 0
      category: 'standard',               // exact equality
    },
    expiresAt: Date.now() + 86_400_000,
  },
];

// Passes
await secured.createInvoice({ customerId: 'c1', amount: 500, currency: 'USD' });

// Throws ChainAuthError("constraint_violated") — amount exceeds max
await secured.createInvoice({ customerId: 'c1', amount: 2000, currency: 'USD' });

// Throws ChainAuthError("constraint_violated") — customerId is required but missing
await secured.createInvoice({ amount: 500 });
```

Supported operators: `max`, `min`, `in`, `not_in`, exact primitive equality.

---

## 11-step verification pipeline

Every intercepted call goes through this pipeline before your code runs.

| Step | What is checked | Error on failure |
|------|----------------|-----------------|
| 1–2 | Decode JWT header + payload, confirm `typ = "agent+jwt"` | `token_invalid` |
| 3 | `sub` matches registered `agentId` | `agent_not_found` |
| 4 | `iss` matches registered public key thumbprint | `token_invalid` |
| 5 | `aud` matches the requested capability name | `capability_denied` |
| 6 | `hostThumbprint` in token matches agent's registered Host | `token_invalid` |
| 7 | Ed25519 signature is valid | `token_invalid` |
| 8 | `exp`/`iat` temporal check (30s clock skew tolerance) | `token_expired` / `token_invalid` |
| 9 | JTI not seen in the 90-second replay window | `token_replayed` |
| 10 | Agent holds an `active` grant for this capability | `capability_denied` |
| 11 | Grant has not expired (`expiresAt`) | `capability_denied` |
| 11b | Call arguments satisfy all grant constraints + required fields | `constraint_violated` |

All failures throw `ChainAuthError` and are written to the audit log as `result: "denied"`.

---

## Audit log

Every call is recorded in an AES-256-GCM encrypted in-memory buffer (capped at 1000 entries, O(1) appends).

```ts
// Read all entries (decrypted in-memory, no I/O)
const entries = chain.getAuditLog();

// Summary stats including auth overhead
const stats = chain.getStats();
// {
//   agentId, hostId, agentName, hostname,
//   totalCalls, successfulCalls, deniedCalls, errorCalls,
//   registeredAt,
//   authOverhead: { avgMs, maxMs }
// }

// Drain and clear — call on shutdown or periodically
await chain.drain();                               // uses auditExporter from config
await chain.drain(new ConsoleAuditExporter());     // override exporter ad-hoc
```

Each `AuditEntry` contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique entry ID |
| `agentId` | `string` | Agent that made the call |
| `agentName` | `string` | Human-readable agent name |
| `capability` | `string` | Capability requested |
| `args` | `object` | Sanitized call arguments |
| `result` | `"success" \| "denied" \| "error"` | Outcome |
| `denialReason` | `string?` | Set when `result === "denied"` |
| `jti` | `string` | JWT ID (replay protection key) |
| `timestamp` | `number` | Unix ms |
| `durationMs` | `number` | Execution time in ms |
| `authOverheadMs` | `number` | Time spent in build+verify |

Argument keys matching `key`, `secret`, `token`, `password`, `auth`, `credential`, or `bearer` are automatically replaced with `"[REDACTED]"` before logging.

---

## Host identity

`HostIdentity` is the cryptographic anchor of the system. Its `thumbprint` (JWK SHA-256) is the stable `hostId`.

```ts
// Access the host from a chain
const { host } = chain;

console.log(host.hostId);          // stable thumbprint
console.log(host.thumbprint);      // same as hostId

// Export keypair for persistence
const privateKeyJwk = await host.exportPrivateKeyJwk();
const publicKeyJwk = host.getPublicKeyJwk();

// Sign a host JWT (for agent registration flows)
const hostJwt = await host.signHostJwt();

// Sign an agent registration JWT (binds agent public key to this host)
const registrationJwt = await host.signAgentRegistrationJwt(agentPublicKeyJwk);
```

---

## JTI replay protection

By default, JTI replay protection is in-memory and resets on restart. For multi-process or multi-instance deployments, inject your own adapter:

```ts
import { AppChain } from 'agents-chain';

const redisAdapter = {
  has: (key) => redis.exists(key).then(Boolean),
  set: (key, ttlMs) => redis.set(key, '1', 'PX', ttlMs).then(() => {}),
};

const chain = await AppChain.create({
  providerName: 'my-service',
  issuer: 'https://myservice.com',
  capabilities: [...],
  jtiAdapter: redisAdapter,
});
```

The `JtiPersistenceAdapter` interface:

```ts
interface JtiPersistenceAdapter {
  has(key: string): Promise<boolean>;
  set(key: string, ttlMs: number): Promise<void>;
}
```

---

## Store persistence adapter

`EncryptedStore` is in-memory by default. Inject a `StorePersistenceAdapter` to back it with Redis, SQLite, or a file:

```ts
import { AppChain } from 'agents-chain';

const sqliteAdapter = {
  get: (key) => db.get('SELECT value FROM store WHERE key = ?', key).then(r => r?.value),
  set: (key, value) => db.run('INSERT OR REPLACE INTO store VALUES (?, ?)', key, value),
  delete: (key) => db.run('DELETE FROM store WHERE key = ?', key),
};

const chain = await AppChain.create({
  providerName: 'my-service',
  issuer: '...',
  capabilities: [...],
  storeAdapter: sqliteAdapter,
});
```

The `StorePersistenceAdapter` interface:

```ts
interface StorePersistenceAdapter {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```

---

## Well-known discovery

Serve `GET /.well-known/agent-configuration` so other agents and systems can discover your capabilities automatically:

```ts
// Express / Fastify / any framework
app.get('/.well-known/agent-configuration', (req, res) =>
  res.json(chain.getWellKnownConfig())
);

// With optional endpoint prefix and JWKS URI
chain.getWellKnownConfig('/api/v1', { jwks_uri: 'https://myservice.com/.well-known/jwks.json' });
```

The response shape:

```json
{
  "version": "1.0-draft",
  "provider_name": "billing-service",
  "issuer": "https://billing.mycompany.com",
  "algorithms": ["Ed25519"],
  "modes": ["delegated", "autonomous"],
  "approval_methods": ["device_authorization"],
  "endpoints": {
    "register": "/agent/register",
    "capabilities": "/capability/list",
    "execute": "/capability/execute",
    "status": "/agent/status",
    "revoke": "/agent/revoke"
  },
  "default_capabilities": ["createInvoice"]
}
```

---

## Lifecycle management

```ts
// Destroy cleans up the JTI GC timer — important in tests and Lambda
chain.destroy();

// Drain the audit log before shutdown
await chain.drain();
```

Always call `chain.destroy()` in tests to prevent timer handles from keeping the process alive.

---

## Error handling

All auth failures throw `ChainAuthError`. Use `isChainAuthError()` to detect them safely across module boundaries:

```ts
import { isChainAuthError } from 'agents-chain';

try {
  await secured.createInvoice({ customerId: 'c1', amount: 99999 });
} catch (err) {
  if (isChainAuthError(err)) {
    console.error(err.code);    // "constraint_violated" | "capability_denied" | "token_invalid" | ...
    console.error(err.message); // human-readable reason
  }
}
```

Error codes:

| Code | Meaning |
|------|---------|
| `token_invalid` | JWT malformed, wrong type, bad signature, or delegation chain mismatch |
| `token_expired` | JWT is outside its validity window |
| `token_replayed` | JTI already seen within the 90-second replay window |
| `agent_not_found` | `sub` claim does not match a registered agent |
| `capability_denied` | No active grant for the requested capability, or grant has expired |
| `constraint_violated` | Call arguments violated a grant constraint or a required field was missing |
| `access_request_denied` | A pending access request was explicitly denied by the human operator |
| `access_request_expired` | A pending access request timed out before the human responded |

---

## Access request system

When `accessRequests` is configured, denied calls **suspend** instead of throwing. The agent's call blocks on a Promise while a human reviews it out-of-band. When approved, the call resumes exactly where it left off.

### Setup

```ts
const chain = await AppChain.create({
  providerName: 'my-service',
  issuer: 'https://myservice.com',
  capabilities: [...],
  accessRequests: {
    approvalSecret: process.env.APPROVAL_SECRET, // keep outside agent reach
    requestTTLMs: 5 * 60 * 1000,                // requests expire after 5 min
    notifier: {
      async notify(request) {
        // send via email, SMS, push, webhook — your choice
        await sendEmail({
          to: 'admin@myservice.com',
          subject: `Agent access request: ${request.capability}`,
          body: `Agent "${request.agentName}" wants to call ${request.capability}\n` +
                `Args: ${JSON.stringify(request.args)}\n` +
                `Code: ${request.verificationCode}\n` +
                `Approve: POST /approve { requestId: "${request.requestId}", code, scope }`,
        });
      },
      async onResolved(request, outcome) {
        // optional: update your UI when the request is approved/denied/expired
      },
    },
  },
});
```

### Approval endpoint

```ts
app.post('/approve', (req, res) => {
  const { requestId, code, scope, ttl } = req.body;
  try {
    const result = chain.approve({ requestId, code, scope, ttl });
    // The suspended agent call resumes automatically here
    res.json({ ok: true, capability: result.capability });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/deny', (req, res) => {
  const { requestId, code, reason } = req.body;
  try {
    chain.deny({ requestId, code, reason });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

### Approval scopes

| Scope | What it approves | Duration |
|-------|-----------------|----------|
| `call` | This exact call only — rule is revoked immediately after | One-time |
| `value` | The specific field value (e.g. `+254799999999` added to the `to` whitelist) | Session |
| `capability` | All calls to this capability — constraints bypassed | Session |
| `global` | All calls to this capability — encrypted, survives restart | Persistent |

### Dashboard API

```ts
chain.getPendingRequests()                    // AccessRequest[] — what's waiting
chain.getApprovalRules()                      // ApprovalRule[] — what's been approved
chain.revokeApproval(ruleId)                  // revoke a specific rule
chain.revokeApprovalsForCapability(capability) // revoke all rules for a capability
chain.revokeAllApprovals()                    // wipe all approval rules
chain.accessRequestsEnabled                   // boolean
```

### Security model

The verification code is an HMAC-SHA256 digest of `requestId + agentId + capability + createdAt`, truncated to 8 uppercase hex characters. The secret is a `private readonly Buffer` inside `AccessRequestManager` — never reachable from agent execution context. A code from one request cannot be replayed on a different one.

Approval rules are stored AES-256-GCM encrypted with an HMAC integrity tag. If the store is modified directly, the HMAC check fails on load and all rules are wiped.

---

## `AppChainConfig` reference

```ts
type AppChainConfig = {
  providerName: string;             // Human name for this service
  issuer: string;                   // Canonical URL (e.g. https://myservice.com)
  capabilities: Capability[];       // Registered capability definitions

  // Optional — stable keypairs for identity across restarts
  host?: {
    name?: string;
    issuerUrl?: string;             // Overrides top-level issuer if set
    privateKeyJwk?: JsonWebKey;     // If provided, restores instead of generating
    publicKeyJwk?: JsonWebKey;
  };
  agent?: {
    agentId?: string;               // Required when restoring from JWKs
    privateKeyJwk?: JsonWebKey;
    publicKeyJwk?: JsonWebKey;
  };

  encryptionKey?: string;           // AES-256-GCM key for EncryptedStore (hex or base64)
  jtiAdapter?: JtiPersistenceAdapter;
  storeAdapter?: StorePersistenceAdapter;
  grantResolver?: (agentId: string, capability: string) => Promise<ResolvedGrant | undefined>;
  auditExporter?: AuditExporter;

  // Access request system — enables suspend/resume for denied calls
  accessRequests?: {
    approvalSecret: string;           // HMAC secret — keep outside agent reach
    requestTTLMs?: number;            // How long a pending request stays open (default: 5 min)
    notifier: AccessRequestNotifier;  // Delivery channel (email, SMS, push, webhook)
  };
};
```

---

## `Capability` type reference

```ts
type Capability<TInput = unknown, TOutput = unknown> = {
  name: string;
  description: string;
  inputSchema: JsonSchemaObject;    // JSON Schema; `required` array is enforced
  outputSchema: JsonSchemaObject;
  execute?: (params: TInput, context: AgentContext) => Promise<TOutput>;
  // If omitted, wrap() delegates to the target object's method of the same name
};

type AgentContext = {
  agentId: string;
  hostId: string;
  permissions: string[];            // All active capability names for this agent
};
```

---

## `ResolvedGrant` type reference

```ts
type ResolvedGrant = {
  capability: string;               // Must match a registered capability name
  status: 'active' | 'revoked' | 'expired';  // Only 'active' grants are enforced
  constraints?: GrantConstraints;   // Field-level constraints on call arguments
  expiresAt?: number;               // Unix ms — grant is denied after this point
};

type GrantConstraints = Record<string, ConstraintValue>;

type ConstraintValue =
  | string | number | boolean       // Exact equality
  | { max?: number; min?: number; in?: Primitive[]; not_in?: Primitive[] };
```

---

## CapabilityRegistry

`CapabilityRegistry` is used internally by `AppChain` but can be used standalone:

```ts
import { CapabilityRegistry } from 'agents-chain';

const registry = new CapabilityRegistry();

registry.register(capability);          // Throws if already registered
registry.upsert(capability);            // Replaces without throwing
registry.get('capabilityName');         // Returns Capability or undefined
registry.unregister('capabilityName'); // Removes, returns true if it existed
registry.list();                        // Returns all registered capabilities
```

---

## Crypto utilities

Low-level Ed25519 utilities are exported if you need them directly:

```ts
import {
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
} from 'agents-chain';
```

All crypto runs through the Node.js `node:crypto` Web Crypto API — no third-party crypto library is used.

---

## Module compatibility

The package ships two builds:

| Format | Path | When used |
|--------|------|-----------|
| ESM | `dist/esm/index.js` | `import` / `type: "module"` projects |
| CommonJS | `dist/cjs/index.js` | `require()` / TypeScript `module: "CommonJS"` |

Both are selected automatically via the `exports` map in `package.json`. No configuration needed.

---

## Auth overhead

Ed25519 signing and verification happen in-process via Node.js Web Crypto. Typical warm-path overhead is **under 1ms per call**.

```ts
const stats = chain.getStats();
// stats.authOverhead → { avgMs: number, maxMs: number }
```

`authOverheadMs` is recorded on every audit entry — you can see the cost of the auth pipeline per capability call.

---

## Changelog

### v0.0.55

**Access request system — human-in-the-loop approval for denied agent calls:**

- **`AccessRequestManager`** — generates HMAC-SHA256 verification codes, tracks pending requests with configurable TTL, handles approve/deny/expire. The secret is a `private readonly Buffer` — the agent has no path to it.
- **`ApprovalStore`** — tamper-proof encrypted rule storage. AES-256-GCM via `EncryptedStore` + HMAC integrity tag over the full rule list. If the store is modified directly, all rules are wiped on next load.
- **4 approval scopes** — `call` (one-time), `value` (session whitelist expansion), `capability` (session bypass), `global` (persistent across restarts).
- **Suspend/resume** — a denied agent call blocks on a `Promise` inside the Proxy interceptor. The closure preserves capability name, args, and auth context. When the human approves, the Promise resolves and the exact same call re-executes with expanded constraints.
- **Pluggable notifier** — implement `AccessRequestNotifier.notify(request)` to deliver verification codes via any channel (email, SMS, push, webhook).
- **`AppChain` API additions** — `approve()`, `deny()`, `getPendingRequests()`, `getApprovalRules()`, `revokeApproval()`, `revokeApprovalsForCapability()`, `revokeAllApprovals()`, `accessRequestsEnabled`.
- **Bug fix** — `call` scope approval now correctly expands the `in` constraint list before re-execution, preventing an infinite access-request loop.
- **Package size** — stripped test files from the npm bundle. Packed: 136.8 kB → 55.2 kB (60% reduction).

### v0.0.45

**Fixes and improvements across all 15 documented issues:**

- **Dual ESM + CJS build** — Package now ships `dist/esm/` and `dist/cjs/` with proper conditional exports. CommonJS consumers using `require()` no longer hit `ERR_REQUIRE_ESM`.
- **Required field constraint enforcement** — A missing field listed in `inputSchema.required` now throws `constraint_violated`. Previously it was silently skipped.
- **Stable identity across restarts** — `AppChainConfig` accepts `host.privateKeyJwk` / `agent.privateKeyJwk`. `AppChain.create()` calls `fromKeyPair()` when keys are provided, `create()` when not.
- **`StorePersistenceAdapter`** — New interface on `EncryptedStore`. Plug in Redis, SQLite, or any key-value store.
- **`AppChain.destroy()` / `AgentsChain.destroy()`** — Propagates to the internal `JtiCache` GC timer. Prevents timer leaks in tests and Lambda.
- **`wrap()` delegates to target methods** — If a `Capability` omits `execute`, `wrapApp()` now calls the target object's own bound method after auth. Previously the target was silently ignored.
- **`CapabilityRegistry.upsert()` / `unregister()`** — Runtime capability replacement without recreating the chain.
- **`isChainAuthError()`** — Safe type guard that works across module boundaries (checking `name` + `code` properties, not prototype).
- **Issuer conflict detection** — `AppChain.create()` throws if `issuer` and `host.issuerUrl` are both set and differ.
- **`AgentIdentity.fromKeyPair()`** — Restore a persisted agent identity from JWKs across restarts.
- **AuditLog O(1) appends** — Switched to an in-memory buffer with lazy load. 1000-entry benchmark improved from ~2000ms to ~11ms.
- **`AgentIdentity` key caching** — `getPublicKey()` and `getHostPublicKey()` cache the imported `CryptoKey` on first call.
- **Constraint enforcement in SDK wrappers** — `wrapOpenAI()` and `wrapAnthropic()` now call `enforceConstraints()` when grants are provided.
- **CJS + ESM interop test suite** — `pnpm run test:interop` runs 55 artifact-level tests against both built outputs.

### v0.0.4

- Host → Agent delegation chain with `hostThumbprint` embedded in every token
- 11-step verification pipeline
- JTI cache background GC with `unref()`
- Audit log capped at 1000 entries
- `authOverheadMs` recorded per audit entry
- `HostIdentity` uses the shared `EncryptedStore`
- `AgentsChain.drain()`

### v0.0.3

Initial public release with `AgentsChain`, `AppChain`, `HostIdentity`, `AgentIdentity`, `TokenBuilder`, `TokenVerifier`, `AuditLog`, `CapabilityRegistry`, and `EncryptedStore`.

---

## Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full data-flow diagrams covering the package internals, per-call security pipeline, Host JWT flow, and persistence adapter integration points.

---

## License

MIT — [brianmwangidev](https://www.npmjs.com/~brianmwangidev)
