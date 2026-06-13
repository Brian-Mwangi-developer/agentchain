---
sidebar_position: 1
title: Host & Agent Identity
---

# Host & Agent Identity

Every agents-chain deployment has two cryptographic identities: a **Host** and an **Agent**. Together they form a delegation chain that ties every capability call back to a trusted authority.

## Host

A `HostIdentity` holds an Ed25519 keypair and acts as the cryptographic anchor. Its JWK thumbprint (SHA-256) is the stable `hostId`. The Host signs agent registration JWTs that bind an agent's public key to a specific host.

```mermaid
flowchart TD
    H[HostIdentity] -->|generates| KP[Ed25519 Keypair]
    KP -->|JWK SHA-256| T[thumbprint = hostId]
    H -->|signs| RJ[Agent Registration JWT]
    RJ -->|binds| A[Agent public key to this Host]
```

```typescript
// Access the host from a chain
const { host } = chain;

console.log(host.hostId);       // stable thumbprint
console.log(host.thumbprint);   // same as hostId

// Export for persistence
const privateKeyJwk = await host.exportPrivateKeyJwk();
const publicKeyJwk = host.getPublicKeyJwk();

// Sign host JWTs
const hostJwt = await host.signHostJwt();
const registrationJwt = await host.signAgentRegistrationJwt(agentPublicKeyJwk);
```

## Agent

An `AgentIdentity` holds its own Ed25519 keypair, is registered under a Host (carrying the host's `thumbprint`), and is granted capabilities. Every capability call mints a JWT signed with the agent's private key — the verifier checks the full delegation chain back to the Host.

```mermaid
flowchart LR
    subgraph Host
        HK[Host Private Key]
        HT[Host Thumbprint]
    end
    subgraph Agent
        AK[Agent Private Key]
        AT[Agent Thumbprint = agentId]
        REG[registration.hostThumbprint]
    end
    HT -->|embedded at registration| REG
    AK -->|signs| JWT[Capability JWT]
    JWT -->|contains| HT2[hostThumbprint claim]
```

## The Delegation Chain

When an agent calls a capability, the JWT contains:

| Claim | Source |
|-------|--------|
| `sub` | Agent's `agentId` (JWK thumbprint) |
| `iss` | Agent's JWK thumbprint |
| `aud` | Capability name |
| `hostThumbprint` | The Host that registered this agent |

The verifier checks that `hostThumbprint` in the token matches the agent's registered Host. A rogue agent cannot impersonate a registered one because it cannot produce a valid signature with the registered agent's private key.

## Stable IDs

Both `hostId` and `agentId` are derived from the public key — they are deterministic. The same keypair always produces the same ID. This means you can:

1. Generate keypairs on first boot
2. Export and persist the JWKs
3. Restore them on subsequent boots
4. Get the exact same `hostId` and `agentId` back

See [Identity Persistence](/docs/advanced/identity-persistence) for details.
