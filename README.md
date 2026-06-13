# agents-chain

**v0.0.57** — Zero-dependency security layer for AI agent systems. Ed25519 identity, JWT auth, constraint enforcement, encrypted audit, and human-in-the-loop access requests.

[![npm](https://img.shields.io/npm/v/agents-chain)](https://www.npmjs.com/package/agents-chain)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

> **[Full documentation](https://brian-mwangi-developer.github.io/agentchain/)**

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
- **Encrypted audit log** — AES-256-GCM ring buffer with auth overhead tracking
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

[Read more about access requests](https://brian-mwangi-developer.github.io/agentchain/docs/access-requests/overview)

## Documentation

| Section | Description |
|---------|-------------|
| [Getting Started](https://brian-mwangi-developer.github.io/agentchain/docs/getting-started) | Installation, quick start, how it works |
| [Core Concepts](https://brian-mwangi-developer.github.io/agentchain/docs/concepts/host-and-agent) | Host & Agent, Capabilities, Grants, Verification, Audit |
| [Access Requests](https://brian-mwangi-developer.github.io/agentchain/docs/access-requests/overview) | Suspend/resume, approval scopes, security model |
| [Examples](https://brian-mwangi-developer.github.io/agentchain/docs/examples/basic-service) | Basic service, SMS gateway, access request flow |
| [API Reference](https://brian-mwangi-developer.github.io/agentchain/docs/api/appchain-config) | AppChainConfig, types, error codes |
| [Architecture](https://brian-mwangi-developer.github.io/agentchain/docs/architecture) | Module map, data flows, internals |

## Sponsored by

[![Sponsored by Melduo](https://raw.githubusercontent.com/Brian-Mwangi-developer/agentchain/main/docs/sponsoredmelduo.png)](https://melduo.com)

## License

MIT — [brianmwangidev](https://www.npmjs.com/~brianmwangidev)
