# agents-chain — Agent Integration Guide

This guide is for AI agents (autonomous or delegated) that want to call capabilities exposed by a service protected with **agents-chain** (v0.0.55).

---

## What you need before calling

To call a capability you need three things:

1. **An agent identity** — an Ed25519 keypair. The JWK thumbprint of the public key is your stable agent ID.
2. **A registration** — your public key must be registered with the service's Host, linking you to a specific Host thumbprint.
3. **An active grant** — the service must have granted you the capability you want to call, with status `"active"`.

---

## Discovering the service

Services using agents-chain expose a discovery endpoint:

```
GET /.well-known/agent-configuration
```

Response:
```json
{
  "version": "1.0-draft",
  "provider_name": "billing-service",
  "issuer": "https://billing.example.com",
  "algorithms": ["Ed25519"],
  "modes": ["delegated", "autonomous"],
  "endpoints": {
    "register": "/agent/register",
    "capabilities": "/capability/list",
    "execute": "/capability/execute",
    "status": "/agent/status",
    "revoke": "/agent/revoke",
    "rotate_key": "/agent/rotate-key",
    "request_capability": "/agent/request-capability",
    "introspect": "/agent/introspect"
  },
  "default_capabilities": ["createInvoice", "getBalance"]
}
```

Parse `issuer` as the base URL and `endpoints` for the paths you need.

---

## Token format

Every capability call requires a fresh **agent+jwt** token. The token is:

- Signed with your Ed25519 **private key**
- Single-use — a unique `jti` (JWT ID) per call
- Short-lived — 60-second TTL
- Scoped — `aud` must exactly equal the capability name

### JWT claims

```json
{
  "iss": "<your JWK thumbprint>",
  "sub": "<your agentId>",
  "aud": "<capability name>",
  "iat": 1700000000,
  "exp": 1700000060,
  "jti": "<random 128-bit base64url>",
  "hostname": "<your hostname>",
  "agentName": "<your agent name>",
  "hostThumbprint": "<thumbprint of the Host that registered you>"
}
```

### JWT header

```json
{
  "alg": "EdDSA",
  "typ": "agent+jwt"
}
```

The compact serialization is `base64url(header).base64url(payload).base64url(signature)`.

---

## What the verifier checks (11 steps)

Your token is rejected if any of these fail:

| Step | Check | Error |
|------|-------|-------|
| 1–2 | `typ = "agent+jwt"`, valid JSON | `token_invalid` |
| 3 | `sub` matches the registered agentId | `agent_not_found` |
| 4 | `iss` matches your registered public key thumbprint | `token_invalid` |
| 5 | `aud` matches the requested capability | `capability_denied` |
| 6 | `hostThumbprint` matches the service's registered Host | `token_invalid` |
| 7 | Ed25519 signature is valid | `token_invalid` |
| 8 | `exp`/`iat` within bounds (±30s clock skew) | `token_expired` / `token_invalid` |
| 9 | `jti` not seen in the last 90 seconds | `token_replayed` |
| 10 | You hold an `active` grant for the capability | `capability_denied` |
| 11 | Grant has not expired, arguments satisfy constraints | `capability_denied` / `constraint_violated` |

**Never reuse a token.** Build a fresh one for every call.

---

## Making a capability call

The call structure depends on the service. For an agents-chain `AppChain`, the service wraps a flat object — call the method directly with the capability name and pass your token.

If the service exposes an HTTP endpoint:

```
POST /capability/execute
Authorization: Bearer <agent+jwt>
Content-Type: application/json

{
  "capability": "createInvoice",
  "args": { "customerId": "c1", "amount": 500 }
}
```

The service verifies the token, checks grants and constraints, executes, and returns the result.

---

## Grant constraints

Your grant may carry constraints that restrict what argument values you can pass:

```json
{
  "capability": "createInvoice",
  "status": "active",
  "constraints": {
    "amount": { "max": 1000 },
    "currency": { "in": ["USD", "EUR"] }
  },
  "expiresAt": 1700086400000
}
```

| Constraint | Meaning |
|------------|---------|
| `{ max: N }` | Value must be `<= N` |
| `{ min: N }` | Value must be `>= N` |
| `{ in: [...] }` | Value must be in the list |
| `{ not_in: [...] }` | Value must not be in the list |
| `"exact"` | Value must equal the primitive exactly |

Violating a constraint throws `constraint_violated` before your call reaches the service.

---

## Access request system — your call may suspend

If the service has enabled the **access request system**, a denied call does **not** throw immediately. Instead your call **suspends** — the Promise blocks — while the human operator reviews the request out-of-band.

When the operator approves, your call **resumes automatically** with expanded constraints and returns a result as if nothing happened. You do not need to retry.

If the operator **denies** the request, your call throws `ChainAuthError` with code `access_request_denied`. If the request **expires** (the operator didn't respond in time), it throws `access_request_expired`.

### What this means for your agent

- **No retry logic needed** — if the service has access requests enabled, your `await secured.someMethod(args)` will eventually resolve (approved) or throw (denied/expired). Just handle the error codes.
- **Calls can take minutes** — don't set tight timeouts on gated calls if access requests are enabled.
- **The constraint that was violated may be expanded** — after approval, the value you passed will be added to the service's whitelist for future calls (depending on the scope the operator chose).

### Error codes added in v0.0.55

| Code | Meaning |
|------|---------|
| `access_request_denied` | The human operator explicitly denied the request |
| `access_request_expired` | The request timed out before the operator responded |

---

## Error codes

| Code | Meaning |
|------|---------|
| `token_invalid` | Malformed JWT, bad signature, wrong typ/iss/hostThumbprint |
| `token_expired` | `exp` has passed |
| `token_replayed` | `jti` was already used |
| `agent_not_found` | `sub` does not match the registered agentId |
| `capability_denied` | No active grant, or grant is pending/denied/expired |
| `constraint_violated` | Call arguments violate grant constraints |
| `access_request_denied` | Human operator denied the access request |
| `access_request_expired` | Access request timed out before operator responded |

---

## Registration (if required)

To register your agent with a Host, sign a `host+jwt` embedding your public key and POST it to `/agent/register`. The Host signs on your behalf if it trusts you.

This library ships `HostIdentity.signAgentRegistrationJwt(agentPublicKeyJwk)` for the Host side. The agent side just needs its Ed25519 keypair — present the public key JWK during registration and keep the private key secret.

---

## Quick-start with agents-chain (Node.js)

If the calling agent is also built with agents-chain:

```ts
import { AgentsChain } from 'agents-chain';

const chain = await AgentsChain.create({
  agentName: 'my-agent',
  hostname: 'my-service',
  capabilities: ['createInvoice'],
});

// chain.host.thumbprint   → Host ID
// chain.agentId           → your stable agent ID
// chain.capabilities      → ['createInvoice']

// Build a token for a single call
const { token } = await chain['builder'].build('createInvoice');

// Or use chain.wrap() / chain.openai() / chain.anthropic() for automatic token management
```

For full API usage see [README.md](./README.md).
