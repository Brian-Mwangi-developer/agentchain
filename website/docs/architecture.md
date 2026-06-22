---
sidebar_position: 7
title: Architecture
---

# Architecture

Internal structure and data flows of the `agents-chain` package.

## Module Map

```
agents-chain/
├── chain.ts                     AppChain (main entry point)
├── index.ts                     Public re-exports
│
├── host/
│   └── host-identity.ts         HostIdentity — Ed25519 keypair, thumbprint
│
├── identity/
│   └── agent-identity.ts        AgentIdentity — Ed25519 keypair, registration
│
├── auth/
│   ├── token-builder.ts         TokenBuilder — mints signed 60s JWTs
│   ├── token-verifier.ts        TokenVerifier — 11-step pipeline
│   └── constraints.ts           enforceConstraints() — field-level validation
│
├── app/
│   ├── capability-registry.ts   CapabilityRegistry — name → Capability map
│   └── app-wrapper.ts           wrapApp() — Proxy interceptor + access requests
│
├── access/
│   ├── access-request-manager.ts  HMAC codes, pending requests, approve/deny
│   └── approval-store.ts          Encrypted + HMAC-integrity rule storage
│
├── audit/
│   ├── audit-log.ts             AuditLog — in-memory buffer, AES-256-GCM, trace lifecycle
│   ├── audit-exporter.ts        Console + HTTP audit exporters
│   └── trace-exporter.ts        ConsoleTraceExporter + HttpTraceExporter
│
├── trace/
│   └── model-extractors.ts      Built-in Anthropic/OpenAI ModelMetadataExtractor, extractor registry
│
├── memory/
│   ├── encrypted-store.ts       EncryptedStore — AES-256-GCM Map
│   └── jti-cache.ts             JtiCache — 90s replay window
│
├── crypto/
│   ├── ed25519.ts               Key generation, sign/verify, JWK
│   └── utils.ts                 generateId, base64url
│
├── errors/
│   └── chain-error.ts           ChainAuthError, isChainAuthError()
│
├── wrappers/
│   ├── openai-wrapper.ts        OpenAI SDK Proxy
│   └── anthropic-wrapper.ts     Anthropic SDK Proxy
│
└── types/
    ├── capabilities.ts          Capability, AgentContext, GrantConstraints
    ├── chain.ts                 AppChainConfig, ChainStats
    ├── identity.ts              RegisteredAgent, CapabilityGrant
    ├── audit.ts                 AuditEntry, AuditResult
    ├── protocol.ts              ResolvedGrant, AgentConfiguration
    ├── access-request.ts        AccessRequest, ApprovalScope, ApprovalRule
    └── trace.ts                 TraceRun, TraceSpan, ModelMetadata, ModelMetadataExtractor
```

## AppChain Creation Flow

```mermaid
flowchart TD
    A[AppChain.create] --> B[EncryptedStore.create]
    A --> C[JtiCache]
    A --> D{Host keys provided?}
    D -->|yes| E[HostIdentity.fromKeyPair]
    D -->|no| F[HostIdentity.create]
    A --> G{Agent keys provided?}
    G -->|yes| H[AgentIdentity.fromKeyPair]
    G -->|no| I[AgentIdentity.create]
    A --> J[TokenBuilder]
    A --> K[TokenVerifier]
    A --> L[AuditLog]
    A --> M[CapabilityRegistry]
    A --> N{accessRequests config?}
    N -->|yes| O[AccessRequestManager + ApprovalStore]
    N -->|no| P[Skip]
```

## Per-Call Pipeline

```mermaid
sequenceDiagram
    participant Agent
    participant Proxy as Proxy Interceptor
    participant TB as TokenBuilder
    participant TV as TokenVerifier
    participant AS as ApprovalStore
    participant EC as enforceConstraints
    participant Cap as Capability.execute

    Agent->>Proxy: secured.method(args)
    Proxy->>TB: build(capabilityName)
    TB-->>Proxy: signed JWT
    Proxy->>TV: verify(token, capability, grants)
    TV-->>Proxy: VerifiedCallContext
    Proxy->>AS: getExpandedConstraints(capability)
    AS-->>Proxy: effective constraints
    Proxy->>EC: enforceConstraints(constraints, args)
    EC-->>Proxy: pass
    Proxy->>Cap: execute(args, agentContext)
    Cap-->>Proxy: result
    Proxy-->>Agent: result
```

## Trace Data Flow

```mermaid
sequenceDiagram
    participant App
    participant Chain as AppChain / AgentsChain
    participant AuditLog
    participant Wrapper as app-wrapper / SDK wrapper

    App->>Chain: openTrace()
    Chain->>AuditLog: openTrace(agentId, agentName, hostThumbprint)
    AuditLog-->>Chain: traceId

    App->>Chain: wrap(service, grants, traceId)
    App->>Wrapper: secured.capability(args)
    Wrapper->>AuditLog: recordCall(..., traceId)
    Note over AuditLog: appendSpan() → stored in activeTraces map

    App->>Chain: closeTrace(traceId, status, exporter?)
    Chain->>AuditLog: closeTrace(traceId, status, exporter)
    Note over AuditLog: buildSummary(spans) → TraceRun assembled
    AuditLog->>App: TraceRun
    Note over AuditLog: if exporter provided → exporter.export(run)
```

## Shared State

All chain state flows through one `EncryptedStore`:

```mermaid
flowchart TD
    A[AppChain.create] --> B[EncryptedStore]
    B --> C[HostIdentity]
    B --> D[AgentIdentity]
    B --> E[AuditLog]
    B --> F[ApprovalStore]
    G[StorePersistenceAdapter] -.->|optional| B
```
