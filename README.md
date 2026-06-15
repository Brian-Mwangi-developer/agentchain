# agents-chain

**v0.0.58** — Zero-dependency security layer for AI agent systems. Ed25519 identity, JWT auth, constraint enforcement, encrypted audit, human-in-the-loop access requests, and constraint-aware agent flows.

[![npm](https://img.shields.io/npm/v/agents-chain)](https://www.npmjs.com/package/agents-chain)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

> **[Full documentation](https://agent-chain.melduo.com/)**

---

## Install

```bash
npm install agents-chain
```

> Requires Node.js 18+. Ships ESM + CommonJS.

## What It Does

- **Host + Agent identity** — Ed25519 keypairs with JWK thumbprints as stable IDs
- **11-step JWT verification** — signature, replay protection, delegation chain, grant + constraint enforcement
- **Grant constraints** — field-level rules: `max`, `min`, `in`, `not_in`, exact equality
- **Access requests** — denied calls suspend and wait for human approval out-of-band (HMAC-verified, 4 scopes)
- **Constraint-aware mode** — returns structured violation envelopes so AI agents can reason about permissions and explicitly request approval
- **Encrypted audit log** — AES-256-GCM ring buffer with auth overhead tracking, access request lifecycle events
- **Zero dependencies** — everything defaults to in-memory, external systems are adapter-injected

## Quick Start

```typescript
import { AppChain, isChainAuthError } from 'agents-chain';

const chain = await AppChain.create({
  providerName: 'billing-service',
  issuer: 'https://billing.example.com',
  capabilities: [{
    name: 'createInvoice',
    description: 'Create an invoice',
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
      return { invoiceId: 'inv_001', amount: args.amount };
    },
  }],
});

const grants = [{
  capability: 'createInvoice',
  status: 'active' as const,
  constraints: { amount: { max: 5000 } },
  expiresAt: Date.now() + 86_400_000,
}];

const secured = chain.wrap({}, grants);

await secured.createInvoice({ customerId: 'c1', amount: 500 });  // ✅
await secured.createInvoice({ customerId: 'c1', amount: 99999 }); // ❌ constraint_violated
```

## Constraint-Aware Mode

When `constraintAware` is enabled, capability calls return structured `ConstraintAwareResult` envelopes instead of throwing errors. This lets AI agents understand violations and decide whether to request human approval.

```typescript
const chain = await AppChain.create({
  // ...capabilities, accessRequests config...
  constraintAware: true,
});

const secured = chain.wrap(service, grants);

// Allowed call — returns success envelope
const result = await secured.sendSms({ to: '+1234', message: 'Hello' });
// { success: true, result: {...}, permission: "not_required", capability: "sendSms" }

// Violation — returns structured error instead of throwing
const denied = await secured.sendSms({ to: '+9999', message: 'Hello' });
// {
//   success: false,
//   permission: "constraint_violated",
//   violations: [{ field: "to", constraint: "in", expected: ["+1234"], actual: "+9999", message: "..." }],
//   guidance: "Call request_permission to request human approval",
//   capability: "sendSms",
//   activeConstraints: { to: { in: ["+1234"] } }
// }
```

### Two-Step Agent-Driven Permission Flow

With `constraintAware: true` and `accessRequests` configured, a built-in `request_permission` capability is auto-registered. The agent explicitly decides when to request human approval:

```
Step 1: Agent calls sendSms(+9999)
        → Returns structured violation (no suspension, no throw)

Step 2: Agent calls request_permission({ capability: "sendSms", args: {...}, reason: "..." })
        → Suspends until human approves/denies
        → Returns: { success: true, permission: "approved", result: {...} }
           OR:    { success: false, permission: "denied", reason: "..." }
```

The agent receives a constraint context string via `chain.getConstraintContext(grants)` that can be injected into its system prompt.

## Access Requests

When `accessRequests` is configured, denied calls **suspend** instead of throwing. The call blocks until a human approves or denies via an HMAC-verified code:

```typescript
const chain = await AppChain.create({
  // ...
  accessRequests: {
    approvalSecret: process.env.APPROVAL_SECRET,
    requestTTLMs: 5 * 60 * 1000,
    notifier: {
      async notify(request) {
        console.log(`Code: ${request.verificationCode}`);
      },
    },
  },
});

// Approve with 4 scopes: call, value, capability, global
chain.approve({ requestId, code, scope: 'value' });
```

[Read more about access requests](https://agent-chain.melduo.com/docs/access-requests/overview)

## Audit Trail

The audit log captures the full lifecycle of capability calls, including access request events:

| Result | Description |
|--------|-------------|
| `success` | Capability executed successfully |
| `denied` | Call rejected by auth or constraints |
| `error` | Capability threw during execution |
| `access_requested` | Agent requested human approval (call suspended) |
| `access_approved` | Human approved the access request |
| `access_denied` | Human denied the access request |

Export audit entries to external systems via `HttpAuditExporter` or implement your own `AuditExporter`.

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](https://agent-chain.melduo.com/docs/getting-started) | Installation, quick start, how it works |
| [Core Concepts](https://agent-chain.melduo.com/docs/concepts/host-and-agent) | Host & Agent, Capabilities, Grants, Verification, Audit |
| [Access Requests](https://agent-chain.melduo.com/docs/access-requests/overview) | Suspend/resume, approval scopes, security model |
| [Examples](https://agent-chain.melduo.com/docs/examples/basic-service) | Basic service, SMS gateway, access request flow |
| [API Reference](https://agent-chain.melduo.com/docs/api/appchain-config) | AppChainConfig, types, error codes |
| [Architecture](https://agent-chain.melduo.com/docs/architecture) | Module map, data flows, internals |

## Sponsored by

[![Sponsored by Melduo](https://raw.githubusercontent.com/Brian-Mwangi-developer/agentchain/main/docs/sponsoredmelduo.png)](https://melduo.com)

## License

MIT — [brianmwangidev](https://www.npmjs.com/~brianmwangidev)
