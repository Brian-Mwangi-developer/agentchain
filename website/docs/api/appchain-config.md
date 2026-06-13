---
sidebar_position: 1
title: AppChainConfig
---

# AppChainConfig

The configuration object passed to `AppChain.create()`.

```typescript
type AppChainConfig = {
  providerName: string;
  issuer: string;
  capabilities: Capability[];

  // Identity persistence
  host?: {
    name?: string;
    issuerUrl?: string;
    privateKeyJwk?: JsonWebKey;
    publicKeyJwk?: JsonWebKey;
  };
  agent?: {
    agentId?: string;
    privateKeyJwk?: JsonWebKey;
    publicKeyJwk?: JsonWebKey;
  };

  // Store & adapters
  encryptionKey?: string;
  jtiAdapter?: JtiPersistenceAdapter;
  storeAdapter?: StorePersistenceAdapter;
  grantResolver?: (agentId: string, capability: string) => Promise<ResolvedGrant | undefined>;
  auditExporter?: AuditExporter;

  // Access request system
  accessRequests?: {
    approvalSecret: string;
    requestTTLMs?: number;
    notifier: AccessRequestNotifier;
  };
};
```

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `providerName` | `string` | Human-readable name for this service |
| `issuer` | `string` | Canonical URL (e.g. `https://myservice.com`) |
| `capabilities` | `Capability[]` | Array of capability definitions |

## Identity Fields

| Field | Description |
|-------|-------------|
| `host.privateKeyJwk` | If provided, restores the host identity instead of generating a new one |
| `host.publicKeyJwk` | Must be provided together with `privateKeyJwk` |
| `host.issuerUrl` | Overrides top-level `issuer` if set (must not conflict) |
| `agent.agentId` | Required when restoring from JWKs |
| `agent.privateKeyJwk` | Restore agent identity |
| `agent.publicKeyJwk` | Must be provided together with `privateKeyJwk` |

## Adapter Fields

| Field | Description |
|-------|-------------|
| `encryptionKey` | AES-256-GCM key for `EncryptedStore` (hex or base64). Auto-generated if omitted. |
| `jtiAdapter` | Redis/database adapter for cross-process JTI replay protection |
| `storeAdapter` | Redis/database adapter for persistent `EncryptedStore` |
| `grantResolver` | Dynamic grant lookup from your database |
| `auditExporter` | Where to drain audit entries (`ConsoleAuditExporter`, `HttpAuditExporter`, or custom) |

## Access Request Fields

| Field | Description |
|-------|-------------|
| `accessRequests.approvalSecret` | HMAC secret for verification codes. **Keep outside agent reach.** |
| `accessRequests.requestTTLMs` | How long a pending request stays open (default: 5 min) |
| `accessRequests.notifier` | Pluggable delivery channel for access request notifications |

## AppChain Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `wrap(target, grants)` | `Proxy<T>` | Wraps a service object with the auth gate |
| `getAuditLog()` | `AuditEntry[]` | All audit entries |
| `getStats()` | `ChainStats` | Summary statistics |
| `drain(exporter?)` | `Promise<void>` | Export and clear audit buffer |
| `destroy()` | `void` | Clean up timers (JTI GC, access request expiry) |
| `getWellKnownConfig()` | `AgentConfiguration` | Discovery endpoint payload |
| `approve(decision)` | `AccessRequest` | Approve a pending access request |
| `deny(decision)` | `AccessRequest` | Deny a pending access request |
| `getPendingRequests()` | `AccessRequest[]` | List pending requests |
| `getApprovalRules()` | `ApprovalRule[]` | List active approval rules |
| `revokeApproval(ruleId)` | `boolean` | Revoke a specific rule |
| `revokeApprovalsForCapability(cap)` | `number` | Revoke all rules for a capability |
| `revokeAllApprovals()` | `number` | Revoke all rules |
| `accessRequestsEnabled` | `boolean` | Whether access requests are configured |

## AppChain Properties

| Property | Type | Description |
|----------|------|-------------|
| `host` | `HostIdentity` | The host identity |
| `agentId` | `string` | The agent's stable ID (JWK thumbprint) |
