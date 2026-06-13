---
sidebar_position: 2
title: Capabilities
---

# Capabilities

A **Capability** is a named, schema-described function that an agent can call. Capabilities are registered on an `AppChain` and form the menu of operations available to agents.

## Defining a Capability

```typescript
const sendSmsCapability = {
  name: 'send_sms',
  description: 'Send an SMS message',
  inputSchema: {
    type: 'object',
    required: ['to', 'message'],
    properties: {
      to: { type: 'string', description: 'Phone number in E.164 format' },
      message: { type: 'string', description: 'SMS content' },
    },
  },
  outputSchema: {
    type: 'object',
    properties: {
      messageId: { type: 'string' },
      status: { type: 'string' },
    },
  },
  execute: async (args, ctx) => {
    // ctx.agentId — who called this
    // ctx.hostId  — which host this agent belongs to
    // ctx.permissions — all active capabilities for this agent
    return smsApi.send(args.to, args.message);
  },
};
```

## Key Properties

| Property | Required | Description |
|----------|----------|-------------|
| `name` | Yes | Unique identifier. Must match the method name on the target object (if not using `execute`). |
| `description` | Yes | Human-readable description. |
| `inputSchema` | Yes | JSON Schema for the arguments. The `required` array is enforced. |
| `outputSchema` | Yes | JSON Schema for the return value. |
| `execute` | No | Custom execution function. If omitted, the call delegates to the target object's method. |

## Execute vs. Delegation

There are two modes for running a capability:

### With `execute`

The capability defines its own function. The Proxy calls it directly after auth passes:

```typescript
{
  name: 'createInvoice',
  execute: async (args, ctx) => {
    // This runs after the 11-step auth pipeline passes
    return db.createInvoice(args);
  },
}
```

### Without `execute` (delegation)

The Proxy forwards the call to the target object's method of the same name:

```typescript
const service = {
  async createInvoice(args) {
    return db.createInvoice(args);
  },
};

// The capability has the same name — no execute needed
const capabilities = [{
  name: 'createInvoice',
  description: '...',
  inputSchema: { ... },
  outputSchema: { ... },
  // No execute — delegates to service.createInvoice
}];

const secured = chain.wrap(service, grants);
await secured.createInvoice({ amount: 100 });
// → service.createInvoice is called after auth
```

## Agent Context

When using `execute`, the second argument is an `AgentContext`:

```typescript
type AgentContext = {
  agentId: string;        // Who called this
  hostId: string;         // Which host this agent belongs to
  permissions: string[];  // All active capability names for this agent
};
```

## Capability Registry

Capabilities are stored in a `CapabilityRegistry`. You typically don't interact with it directly, but it's available:

```typescript
import { CapabilityRegistry } from 'agents-chain';

const registry = new CapabilityRegistry();

registry.register(capability);       // Throws if already registered
registry.upsert(capability);         // Replaces without throwing
registry.get('capabilityName');      // Returns Capability or undefined
registry.unregister('capabilityName'); // Removes, returns true if existed
registry.list();                     // Returns all registered capabilities
```
