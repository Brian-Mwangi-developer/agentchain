---
sidebar_position: 3
title: Error Codes
---

# Error Codes

All auth failures throw `ChainAuthError`. Use `isChainAuthError()` to detect them safely across module boundaries.

## Usage

```typescript
import { isChainAuthError } from 'agents-chain';

try {
  await secured.createInvoice({ customerId: 'c1', amount: 99999 });
} catch (err) {
  if (isChainAuthError(err)) {
    console.error(err.code);     // "constraint_violated"
    console.error(err.message);  // human-readable reason
  }
}
```

## Error Code Reference

### Token Errors

| Code | Meaning |
|------|---------|
| `token_invalid` | JWT malformed, wrong `typ`, bad signature, or delegation chain mismatch |
| `token_expired` | JWT is outside its validity window (±30s clock skew) |
| `token_replayed` | JTI already seen within the 90-second replay window |

### Auth Errors

| Code | Meaning |
|------|---------|
| `agent_not_found` | `sub` claim does not match a registered agent |
| `capability_denied` | No active grant for the requested capability, or grant has expired |
| `constraint_violated` | Call arguments violated a grant constraint, or a required field was missing |

### Access Request Errors

| Code | Meaning |
|------|---------|
| `access_request_pending` | An access request has been created and is awaiting human approval |
| `access_request_denied` | The human operator explicitly denied the access request |
| `access_request_expired` | The access request timed out before the operator responded |

## `isChainAuthError()`

A safe type guard that works across module boundaries. It checks `name` and `code` properties instead of using `instanceof`:

```typescript
import { isChainAuthError } from 'agents-chain';

// Works even across different module instances
if (isChainAuthError(err)) {
  // err is typed as ChainAuthError
  switch (err.code) {
    case 'constraint_violated':
      // Handle constraint violation
      break;
    case 'access_request_denied':
      // Human denied the request
      break;
    default:
      // Other auth error
  }
}
```
