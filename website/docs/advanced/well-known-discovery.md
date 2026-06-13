---
sidebar_position: 4
title: Well-Known Discovery
---

# Well-Known Discovery

Serve `GET /.well-known/agent-configuration` so other agents and systems can discover your capabilities automatically.

## Setup

```typescript
// Express / Fastify / any framework
app.get('/.well-known/agent-configuration', (req, res) =>
  res.json(chain.getWellKnownConfig())
);

// With optional endpoint prefix and JWKS URI
chain.getWellKnownConfig('/api/v1', {
  jwks_uri: 'https://myservice.com/.well-known/jwks.json',
});
```

## Response Shape

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

## Fields

| Field | Description |
|-------|-------------|
| `version` | Protocol version |
| `provider_name` | Human-readable service name |
| `issuer` | Canonical URL for this service |
| `algorithms` | Supported signing algorithms (always `["Ed25519"]`) |
| `modes` | `delegated` (human-supervised) and/or `autonomous` |
| `endpoints` | Path map for agent interaction |
| `default_capabilities` | Capabilities available to newly registered agents |

This follows the emerging agent discovery pattern. Other agents can fetch this endpoint to understand what your service offers and how to register.
