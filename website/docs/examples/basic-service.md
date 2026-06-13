---
sidebar_position: 1
title: "Example: Basic Service"
---

# Example: Basic Service

A complete Node.js example showing how to wrap a billing service with agents-chain.

## Full Example

```typescript
import { AppChain, ConsoleAuditExporter, isChainAuthError } from 'agents-chain';

// ── 1. Your service ─────────────────────────────────────────────────
// This is the code you already have. agents-chain doesn't touch it.
const billingService = {
  async createInvoice(args: { customerId: string; amount: number; currency: string }) {
    console.log(`Creating invoice: $${args.amount} ${args.currency} for ${args.customerId}`);
    return {
      invoiceId: `inv_${Date.now()}`,
      customerId: args.customerId,
      amount: args.amount,
      currency: args.currency,
      status: 'created',
    };
  },
};

// ── 2. Create the chain ─────────────────────────────────────────────
const chain = await AppChain.create({
  providerName: 'billing-service',
  issuer: 'https://billing.example.com',
  capabilities: [
    {
      name: 'createInvoice',
      description: 'Create a new invoice for a customer',
      inputSchema: {
        type: 'object',
        required: ['customerId', 'amount', 'currency'],
        properties: {
          customerId: { type: 'string' },
          amount: { type: 'number' },
          currency: { type: 'string' },
        },
      },
      outputSchema: {
        type: 'object',
        properties: {
          invoiceId: { type: 'string' },
          status: { type: 'string' },
        },
      },
      // No execute — delegates to billingService.createInvoice
    },
  ],
  auditExporter: new ConsoleAuditExporter(),
});

console.log('Host ID:', chain.host.hostId);
console.log('Agent ID:', chain.agentId);

// ── 3. Define grants ────────────────────────────────────────────────
// This agent can create invoices up to $5000, USD or EUR only
const grants = [
  {
    capability: 'createInvoice',
    status: 'active' as const,
    constraints: {
      amount: { min: 0, max: 5000 },
      currency: { in: ['USD', 'EUR'] },
    },
    expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24h
  },
];

// ── 4. Wrap the service ─────────────────────────────────────────────
const secured = chain.wrap(billingService, grants);

// ── 5. Call through the secured proxy ───────────────────────────────

// ✅ This works — within constraints
const invoice = await secured.createInvoice({
  customerId: 'customer_001',
  amount: 250,
  currency: 'USD',
});
console.log('Invoice created:', invoice);

// ❌ This is denied — amount exceeds max
try {
  await secured.createInvoice({
    customerId: 'customer_001',
    amount: 99999,
    currency: 'USD',
  });
} catch (err) {
  if (isChainAuthError(err)) {
    console.log('Denied:', err.code, '—', err.message);
    // "constraint_violated — Capability argument constraints violated: ..."
  }
}

// ❌ This is denied — JPY not in allowed currencies
try {
  await secured.createInvoice({
    customerId: 'customer_001',
    amount: 100,
    currency: 'JPY',
  });
} catch (err) {
  if (isChainAuthError(err)) {
    console.log('Denied:', err.code, '—', err.message);
  }
}

// ── 6. Check the audit log ──────────────────────────────────────────
const stats = chain.getStats();
console.log('\nStats:', {
  total: stats.totalCalls,
  success: stats.successfulCalls,
  denied: stats.deniedCalls,
  avgAuthMs: stats.authOverhead.avgMs.toFixed(2),
});

const log = chain.getAuditLog();
for (const entry of log) {
  console.log(`  ${entry.result}: ${entry.capability} (${entry.durationMs}ms)`);
}

// ── 7. Clean up ─────────────────────────────────────────────────────
await chain.drain();
chain.destroy();
```

## Running It

```bash
# Save the above as example.ts
npx tsx example.ts
```

## Expected Output

```
Host ID: a9Mb7qr3k8ZFvJ66imtYZD9rojmmEsy8OhidAeP5OLU
Agent ID: billing-service-agent-abc123
Creating invoice: $250 USD for customer_001
Invoice created: { invoiceId: 'inv_1718...', customerId: 'customer_001', amount: 250, currency: 'USD', status: 'created' }
Denied: constraint_violated — Capability argument constraints violated: field "amount": 99999 exceeds max 5000
Denied: constraint_violated — Capability argument constraints violated: field "currency": "JPY" is not in allowed list ["USD", "EUR"]

Stats: { total: 3, success: 1, denied: 2, avgAuthMs: '0.42' }
  success: createInvoice (1ms)
  denied: createInvoice (0ms)
  denied: createInvoice (0ms)
```
