---
sidebar_position: 8
title: Agent Integration Guide
---

# Agent Integration Guide

This guide is for AI agents that want to call capabilities exposed by a service protected with agents-chain.

## What You Need

1. **An agent identity** — an Ed25519 keypair. The JWK thumbprint is your stable agent ID.
2. **A registration** — your public key must be registered with the service's Host.
3. **An active grant** — the service must have granted you the capability with `status: "active"`.

## Discovering the Service

Services expose a discovery endpoint:

```
GET /.well-known/agent-configuration
```

```json
{
  "version": "1.0-draft",
  "provider_name": "billing-service",
  "issuer": "https://billing.example.com",
  "algorithms": ["Ed25519"],
  "default_capabilities": ["createInvoice", "getBalance"]
}
```

## Token Format

Every call requires a fresh `agent+jwt` token:

- **Signed** with your Ed25519 private key
- **Single-use** — unique `jti` per call
- **Short-lived** — 60-second TTL
- **Scoped** — `aud` must match the capability name exactly

```json
{
  "typ": "agent+jwt",
  "alg": "EdDSA",
  "sub": "<agentId>",
  "iss": "<JWK thumbprint>",
  "aud": "<capability name>",
  "hostThumbprint": "<Host thumbprint>",
  "jti": "<random 128-bit>",
  "iat": 1700000000,
  "exp": 1700000060
}
```

**Never reuse a token.** Build a fresh one for every call.

## Making a Call

```
POST /capability/execute
Authorization: Bearer <agent+jwt>
Content-Type: application/json

{
  "capability": "createInvoice",
  "args": { "customerId": "c1", "amount": 500 }
}
```

## Your Call May Suspend

If the service has [access requests](/docs/access-requests/overview) enabled, a denied call **does not throw immediately**. Instead, your call **suspends** — the Promise blocks — while the human operator reviews the request.

- **No retry logic needed** — if approved, the call resolves normally
- **If denied** → throws `ChainAuthError` with code `access_request_denied`
- **If expired** → throws `ChainAuthError` with code `access_request_expired`
- **Calls can take minutes** — don't set tight timeouts on gated calls

## Grant Constraints

Your grant may carry constraints:

```json
{
  "capability": "createInvoice",
  "status": "active",
  "constraints": {
    "amount": { "max": 1000 },
    "currency": { "in": ["USD", "EUR"] }
  }
}
```

| Constraint | Meaning |
|------------|---------|
| `{ max: N }` | Value must be `<= N` |
| `{ min: N }` | Value must be `>= N` |
| `{ in: [...] }` | Value must be in the list |
| `{ not_in: [...] }` | Value must not be in the list |
| `"exact"` | Value must equal the primitive exactly |

## Error Codes

| Code | Meaning |
|------|---------|
| `token_invalid` | Malformed JWT, bad signature, wrong typ/iss/hostThumbprint |
| `token_expired` | `exp` has passed |
| `token_replayed` | `jti` was already used |
| `agent_not_found` | `sub` does not match the registered agentId |
| `capability_denied` | No active grant or grant expired |
| `constraint_violated` | Arguments violate grant constraints |
| `access_request_denied` | Human operator denied the request |
| `access_request_expired` | Request timed out |
