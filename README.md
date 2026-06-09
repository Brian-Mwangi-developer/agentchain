# agents-chain

**v0.0.4** — A zero-dependency security layer that wraps any app, service object, or AI SDK with Ed25519 identity, JWT-gated capability enforcement, constraint validation, and an encrypted audit trail.

Drop it in front of your billing service, a third-party API client, or an OpenAI/Anthropic SDK — every call is signed, verified, scoped, and logged without touching your existing code.

---

## What it does

- **Host + Agent identity** — Ed25519 keypairs with JWK thumbprints as stable IDs. Hosts sign agent registration JWTs; agents sign scoped capability tokens.
- **11-step JWT verification** — Every capability call mints a fresh 60-second single-use token. Sub, iss, aud, Host delegation chain, signature, expiry, JTI replay, and capability grant are all verified before the call proceeds.
- **Capability registry + app wrapper** — Register named capabilities on any service object. A JavaScript Proxy intercepts method calls by name and gates them through the full auth pipeline.
- **Constraint enforcement** — Grants can carry `max`, `min`, `in`, `not_in`, or exact-equality constraints on call arguments, enforced before execution.
- **Encrypted audit log** — AES-256-GCM in-memory log of every call (success, denied, error). Drain to any HTTP endpoint or custom exporter on a schedule or at shutdown.
- **Adapter interfaces** — Plug in your own Redis client for JTI replay protection across restarts. Plug in your own grant resolver to read active grants from your DB. The package ships no Redis client.
- **Well-known discovery** — Serve `GET /.well-known/agent-configuration` with one call. Agents discover your capabilities, endpoints, and supported algorithms automatically.
- **Zero mandatory dependencies** — In-memory defaults for everything. Redis, databases, and HTTP clients are injected by you.

---

## Package overview

![Package overview — all modules and how they connect](https://raw.githubusercontent.com/Brian-Mwangi-developer/agentchain/main/docs/overview1.jpeg)

The package has six layers. **HostIdentity** and **AgentIdentity** hold Ed25519 keypairs — agents are cryptographically linked to their Host so no rogue agent can impersonate a registered one. **TokenBuilder** mints scoped JWTs; **TokenVerifier** runs the 11-step verification pipeline including delegation chain checks. **CapabilityRegistry** maps method names to capability definitions; **wrapApp()** turns any object into a secured Proxy using that registry. **AuditLog** records every call (with auth overhead timing) into an AES-256-GCM encrypted store, capped at 1000 entries, and drains to any **AuditExporter**. All state lives in one shared **EncryptedStore** — there is no network I/O by default.

---

## Installation

```bash
npm install agents-chain
# or
pnpm add agents-chain
```

> Requires Node.js 18+

---

## Wrapping any app — AppChain

`AppChain` is the main entry point for wrapping your own services or third-party clients.

### Integration flow

![Integration flow — AppChain.create() through chain.wrap() to a secured Proxy](https://raw.githubusercontent.com/Brian-Mwangi-developer/agentchain/main/docs/flow1.jpeg)

```ts
import { AppChain, HttpAuditExporter } from 'agents-chain';

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
      execute: async (args, ctx) => {
        // ctx carries agentId, hostId, and active permissions
        return billingDb.createInvoice(args.customerId, args.amount);
      },
    },
  ],

  // Optional: resolve grants from your DB instead of in-memory
  grantResolver: async (agentId, capability) => myDb.getGrant(agentId, capability),

  // Optional: drain audit log to a hosted endpoint
  auditExporter: new HttpAuditExporter({
    endpoint: 'https://audit.yourservice.com/ingest',
    apiKey: process.env.AUDIT_API_KEY,
  }),
});

// Serve capability discovery
app.get('/.well-known/agent-configuration', (req, res) =>
  res.json(chain.getWellKnownConfig())
);

// Wrap any object — every registered method is now capability-gated
const secured = chain.wrap(billingService, agentGrants);
const invoice = await secured.createInvoice({ customerId: 'c1', amount: 500 });

// Flush audit log on shutdown
process.on('SIGTERM', () => chain.drain());
```

---

## Per-call security pipeline

Every intercepted call goes through this verification pipeline before your code runs.

![Per-call security flow — 9-step JWT verification pipeline](https://raw.githubusercontent.com/Brian-Mwangi-developer/agentchain/main/docs/agent-flow1.jpeg)

| Step | Check | Error on failure |
|------|-------|-----------------|
| 1–2 | Decode JWT header + payload, confirm `typ = "agent+jwt"` | `token_invalid` |
| 3 | `sub` matches registered `agentId` | `agent_not_found` |
| 4 | `iss` matches registered public key thumbprint | `token_invalid` |
| 5 | `aud` matches the requested capability name | `capability_denied` |
| 6 | `hostThumbprint` claim matches the agent's registered Host | `token_invalid` |
| 7 | Ed25519 signature is valid | `token_invalid` |
| 8 | `exp`/`iat` temporal check + 30s clock skew tolerance | `token_expired` / `token_invalid` |
| 9 | JTI not seen in 90-second replay window | `token_replayed` |
| 10 | Agent holds an `active` grant for the capability | `capability_denied` |
| 11 | Grant has not expired (`expiresAt`) | `capability_denied` |
| 11b | Call arguments satisfy all grant constraints | `constraint_violated` |

All failures throw `ChainAuthError` and are recorded in the audit log as `result: "denied"`.

---

## Wrapping AI SDKs — AgentsChain

For OpenAI and Anthropic clients, use `AgentsChain` instead. It maps SDK method paths to capability strings automatically.

### OpenAI

```ts
import { AgentsChain } from 'agents-chain';
import OpenAI from 'openai';

const chain = await AgentsChain.create({
  agentName: 'summarizer',
  hostname: 'my-app',
  capabilities: ['chat.completion'],
});

const ai = chain.openai(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }));

const response = await ai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Summarize the water cycle.' }],
});
```

### Anthropic

```ts
import { AgentsChain } from 'agents-chain';
import Anthropic from '@anthropic-ai/sdk';

const chain = await AgentsChain.create({
  agentName: 'classifier',
  hostname: 'my-app',
  capabilities: ['message'],
});

const ai = chain.anthropic(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));

const response = await ai.messages.create({
  model: 'claude-sonnet-4-6',
  max_tokens: 256,
  messages: [{ role: 'user', content: 'Classify: "I love it!"' }],
});
```

### Capability names

#### OpenAI

| SDK method | Capability string |
|-----------|------------------|
| `ai.chat.completions.create()` | `"chat.completion"` |
| `ai.embeddings.create()` | `"embedding"` |
| `ai.images.generate()` | `"image.generation"` |
| `ai.audio.transcriptions.create()` | `"audio.transcription"` |
| `ai.audio.speech.create()` | `"audio.speech"` |
| `ai.moderations.create()` | `"moderation"` |
| `ai.responses.create()` | `"response"` |

#### Anthropic

| SDK method | Capability string |
|-----------|------------------|
| `ai.messages.create()` | `"message"` |
| `ai.messages.stream()` | `"message.stream"` |
| `ai.messages.countTokens()` | `"message.count_tokens"` |
| `ai.completions.create()` | `"completion"` |
| `ai.beta.messages.create()` | `"message.beta"` |

Any method not in these tables passes through without interception.

---

## Grant constraints

Constrain what an agent is allowed to pass in call arguments:

```ts
const grants = [
  {
    capability: 'createInvoice',
    status: 'active',
    constraints: {
      amount: { max: 1000 },              // amount <= 1000
      currency: { in: ['USD', 'EUR'] },   // currency must be one of these
    },
    expiresAt: Date.now() + 86_400_000,   // expires in 24h
  },
];

const secured = chain.wrap(billingService, grants);

// This passes
await secured.createInvoice({ customerId: 'c1', amount: 500, currency: 'USD' });

// This throws ChainAuthError("constraint_violated")
await secured.createInvoice({ customerId: 'c1', amount: 2000, currency: 'USD' });
```

Supported operators: `max`, `min`, `in`, `not_in`, exact primitive equality.

---

## Persistent JTI replay protection

By default, JTI replay protection is in-memory and resets on restart. For shared deployments, plug in your own Redis client:

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

---

## Audit log

Every call is recorded in an AES-256-GCM encrypted in-memory log.

```ts
// Get all entries (decrypted)
const entries = chain.getAuditLog();

// Summary counts
const stats = chain.getStats();
// { agentId, agentName, hostname, totalCalls, successfulCalls, deniedCalls, errorCalls, registeredAt }

// Export and clear — call periodically or on shutdown
await chain.drain();                               // uses auditExporter from config
await chain.drain(new ConsoleAuditExporter());     // override exporter
```

Each `AuditEntry` contains:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `string` | Unique entry ID |
| `agentId` | `string` | Agent that made the call |
| `agentName` | `string` | Human-readable agent name |
| `capability` | `string` | Capability requested |
| `args` | `object` | Sanitized call arguments (secrets redacted) |
| `result` | `"success" \| "denied" \| "error"` | Outcome |
| `denialReason` | `string?` | Set when `result === "denied"` |
| `jti` | `string` | JWT ID used |
| `timestamp` | `number` | Unix ms |
| `durationMs` | `number` | Execution time in ms |

Argument keys matching `key`, `secret`, `token`, `password`, `auth`, `credential`, or `bearer` are automatically replaced with `"[REDACTED]"` before logging.

---

## Host identity

`HostIdentity` is the user's anchor for signing agent registration JWTs against an agent-auth server.

```ts
// chain.host is a HostIdentity instance
const hostJwt = await chain.host.signHostJwt();
const registrationJwt = await chain.host.signAgentRegistrationJwt(agentPublicKeyJwk);

// Stable identity across restarts — export and reload the private key
const privateKeyJwk = await chain.host.exportPrivateKeyJwk();
// persist privateKeyJwk securely

// On next startup (pass the shared store from your chain):
const host = await HostIdentity.fromKeyPair(savedPrivateKeyJwk, savedPublicKeyJwk, config, store);
```

---

## Well-known discovery

```ts
// Returns AgentConfiguration — serve at GET /.well-known/agent-configuration
chain.getWellKnownConfig();

// {
//   version: "1.0-draft",
//   provider_name: "billing-service",
//   issuer: "https://billing.mycompany.com",
//   algorithms: ["Ed25519"],
//   modes: ["delegated", "autonomous"],
//   approval_methods: ["device_authorization"],
//   endpoints: {
//     register: "/agent/register",
//     capabilities: "/capability/list",
//     execute: "/capability/execute",
//     status: "/agent/status",
//     revoke: "/agent/revoke",
//     ...
//   },
//   default_capabilities: ["createInvoice", ...]
// }
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

---

## Auth latency overhead

The package exposes per-call auth overhead via `getStats()`:

```ts
const stats = chain.getStats();
// stats.authOverhead → { avgMs: number, maxMs: number }
```

`authOverheadMs` is the time spent inside `TokenBuilder.build()` + `TokenVerifier.verify()` for each call. In-process Ed25519 signing is fast — typical warm-path overhead is **< 1ms** per call on modern hardware.

---

## Changelog

### v0.0.4

**Security:**
- **Host → Agent delegation chain** — Every agent registration now embeds `hostThumbprint` + `hostPublicKeyJwk`. Every token carries `hostThumbprint`. Verifier step 6 checks that the token's `hostThumbprint` matches the agent's registered Host. This closes the rogue-agent gap where a self-issued agent was indistinguishable from a registered one.
- **11-step verification pipeline** — Added step 6 (delegation chain check), step 11 (grant expiry), rounding out the pipeline to 11 checks.

**Memory management:**
- **JTI cache background GC** — In-memory JTI replay protection now runs a background `setInterval` (45s interval, unref'd) that evicts expired entries proactively. Previously only lazy-evicted on insert — a burst of traffic followed by silence could leave ~90,000 entries in memory with no cleanup trigger.
- **`JtiCache.destroy()`** — New method to stop the GC timer and clear the cache. Call on graceful shutdown or in tests to avoid timer leaks.
- **Audit log capped at 1000 entries** — `appendCapped()` evicts the oldest entry when the cap is reached. Prevents unbounded memory growth in long-running processes.

**Observability:**
- `authOverheadMs` recorded per audit entry — the time spent in `build()+verify()` for every call.
- `getStats()` returns `authOverhead: { avgMs, maxMs }` across all entries.

**Architecture:**
- `HostIdentity` now uses the **shared** `EncryptedStore` passed in from the chain. Previously it silently created its own isolated store, siloing host data from the audit log.
- `AgentsChain` gains a `drain()` method (previously only `AppChain` had it).
- Duplicate type definitions (`AgentJwtClaims`, constraint types) consolidated to single canonical locations.

**Tests:**
- 64 tests covering all modules via Node.js built-in `node:test` (no new dependencies). Run with `pnpm test`.

### v0.0.3

Initial public release with `AgentsChain`, `AppChain`, `HostIdentity`, `AgentIdentity`, `TokenBuilder`, `TokenVerifier`, `AuditLog`, `CapabilityRegistry`, and `EncryptedStore`.

---

## Full architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for Mermaid diagrams covering the package internals, integration flow, per-call security pipeline, Host JWT flow, well-known discovery, and persistence adapter swap-in points.

---

## License

MIT — [brianmwangidev](https://www.npmjs.com/~brianmwangidev)
