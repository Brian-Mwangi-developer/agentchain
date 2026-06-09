# agents-chain — Architecture

agents-chain is a **security layer** that wraps any app or service object with Ed25519-based identity, JWT-gated capability enforcement, constraint validation, and an encrypted audit trail. It has zero mandatory runtime dependencies — Redis, databases, and HTTP clients are injected by the user via adapter interfaces.

---

## Package Internals

```mermaid
graph TB
    subgraph agents-chain["agents-chain package"]
        direction TB

        subgraph Identity["Identity Layer"]
            HI["HostIdentity\nEd25519 keypair\nSigns host+jwt tokens"]
            AI["AgentIdentity\nEd25519 keypair\nStable agentId (thumbprint)"]
        end

        subgraph Auth["Auth Layer"]
            TB2["TokenBuilder\nMints scoped agent+jwt\n(60s TTL, single-use JTI\nhostThumbprint embedded)"]
            TV["TokenVerifier\n11-step JWT verification\n+ constraint enforcement"]
            CS["enforceConstraints()\nmax / min / in / not_in\nexact equality"]
            JC["JtiCache\nReplay protection\n90-second window\nBackground GC timer (45s)"]
        end

        subgraph AppLayer["App Layer"]
            CR["CapabilityRegistry\nname → Capability map\nBuilds well-known config"]
            WA["wrapApp()\nJS Proxy intercepts\nmethod calls on any object"]
        end

        subgraph Memory["Memory Layer"]
            ES["EncryptedStore\nAES-256-GCM\nin-memory KV"]
        end

        subgraph Audit["Audit Layer"]
            AL["AuditLog\nAppend-only encrypted log\nCapped at 1000 entries\nrecords authOverheadMs"]
            AE["AuditExporter\nConsoleAuditExporter\nHttpAuditExporter"]
        end

        subgraph Chains["Entry Points"]
            AC["AgentsChain\nWraps OpenAI / Anthropic SDKs"]
            APC["AppChain\nWraps any service object"]
        end
    end

    APC --> HI
    APC --> CR
    APC --> WA
    APC --> AI
    APC --> TB2
    APC --> TV
    APC --> AL

    AC --> AI
    AC --> TB2
    AC --> TV
    AC --> AL

    WA --> TB2
    WA --> TV
    WA --> CS
    WA --> AL
    WA --> CR

    TV --> JC
    TV --> CS

    AI --> ES
    HI --> ES
    AL --> ES
    AL --> AE
```

---

## Integration Flow — Wrapping an App

This shows how a developer integrates agents-chain in front of their own service (e.g. a billing service).

```mermaid
sequenceDiagram
    actor Dev as Developer
    participant AC as AppChain.create()
    participant CR as CapabilityRegistry
    participant HI as HostIdentity
    participant WA as wrapApp() Proxy
    participant TV as TokenVerifier
    participant CS as enforceConstraints()
    participant CAP as capability.execute()
    participant LOG as AuditLog

    Dev->>AC: AppChain.create({ providerName, issuer, capabilities[], grantResolver? })
    AC->>HI: HostIdentity.create({ name, issuerUrl })
    Note over HI: Generates Ed25519 keypair\nComputes JWK thumbprint → hostId
    AC->>CR: register(capability) for each capability
    AC-->>Dev: chain (AppChain instance)

    Dev->>AC: chain.wrap(billingService, agentGrants[])
    AC->>WA: wrapApp(target, registry, ctx)
    WA-->>Dev: secured (Proxy of billingService)

    Dev->>WA: secured.createInvoice({ customerId, amount })
    Note over WA: Proxy intercepts method call\nLooks up "createInvoice" in registry
```

---

## Per-Call Security Flow

Every intercepted capability call goes through this 11-step verification pipeline.

```mermaid
flowchart TD
    CALL["secured.createInvoice(args)"]
    BUILD["TokenBuilder.build('createInvoice')\nMint scoped agent+jwt\n{ iss: thumbprint, sub: agentId,\n  aud: 'createInvoice',\n  hostThumbprint: hostId,\n  iat, exp: now+60, jti: random }"]
    D1{{"Step 1-2\nDecode JWT header + payload\nConfirm typ = 'agent+jwt'"}}
    D2{{"Step 3\nsub === registered agentId?"}}
    D3{{"Step 4\niss === public key thumbprint?"}}
    D4{{"Step 5\naud === requested capability?"}}
    D5{{"Step 6 (NEW)\nhostThumbprint claim matches\nagent's registered Host?"}}
    D6{{"Step 7\nEd25519 signature valid?"}}
    D7{{"Step 8\nexp/iat temporal check\n+ clock skew tolerance"}}
    D8{{"Step 9\nJTI not seen in\n90-second window?"}}
    D9{{"Step 10\nAgent holds active grant\nfor this capability?\n(grantResolver or in-memory)"}}
    D10{{"Step 11\nGrant not expired?\n+ Constraints satisfied?"}}
    EXEC["capability.execute(args, agentContext)\nUser-defined execution"]
    LOG_OK["AuditLog.recordCall()\nresult: 'success'\nauthOverheadMs recorded"]
    LOG_ERR["AuditLog.recordCall()\nresult: 'error'"]
    LOG_DENY["AuditLog.recordDenied()\nresult: 'denied'"]
    THROW_AUTH["throw ChainAuthError"]
    THROW_EXEC["re-throw execution error"]

    CALL --> BUILD
    BUILD --> D1
    D1 -->|fail| THROW_AUTH
    D1 -->|pass| D2
    D2 -->|fail: agent_not_found| THROW_AUTH
    D2 -->|pass| D3
    D3 -->|fail: token_invalid| THROW_AUTH
    D3 -->|pass| D4
    D4 -->|fail: capability_denied| THROW_AUTH
    D4 -->|pass| D5
    D5 -->|fail: token_invalid| THROW_AUTH
    D5 -->|pass| D6
    D6 -->|fail: token_invalid| THROW_AUTH
    D6 -->|pass| D7
    D7 -->|fail: token_expired / token_invalid| THROW_AUTH
    D7 -->|pass| D8
    D8 -->|fail: token_replayed| THROW_AUTH
    D8 -->|pass| D9
    D9 -->|fail: capability_denied| THROW_AUTH
    D9 -->|pass| D10
    D10 -->|fail: capability_denied / constraint_violated| THROW_AUTH
    D10 -->|pass| EXEC
    EXEC -->|success| LOG_OK
    EXEC -->|throws| LOG_ERR
    LOG_ERR --> THROW_EXEC
    THROW_AUTH --> LOG_DENY

    style CALL fill:#1e293b,color:#f8fafc
    style D5 fill:#1e40af,color:#eff6ff
    style EXEC fill:#166534,color:#f0fdf4
    style LOG_OK fill:#166534,color:#f0fdf4
    style LOG_ERR fill:#7f1d1d,color:#fef2f2
    style LOG_DENY fill:#7f1d1d,color:#fef2f2
    style THROW_AUTH fill:#7f1d1d,color:#fef2f2
    style THROW_EXEC fill:#7f1d1d,color:#fef2f2
```

---

## Host → Agent Delegation Chain

Every agent is cryptographically linked to its Host. This closes the rogue-agent gap — a self-issued agent cannot impersonate a registered one because the verifier checks `hostThumbprint` at step 6.

```mermaid
flowchart LR
    subgraph HostLayer["Host Layer"]
        HI["HostIdentity\nEd25519 keypair\nhostId = JWK thumbprint"]
    end

    subgraph AgentLayer["Agent Layer"]
        AI["AgentIdentity\nEd25519 keypair\nregistration embeds:\n- hostThumbprint\n- hostPublicKeyJwk"]
    end

    subgraph TokenLayer["Token Layer (per-call)"]
        JWT["agent+jwt\nclaims include:\n- iss: agentThumbprint\n- sub: agentId\n- hostThumbprint: hostId"]
    end

    subgraph VerifyLayer["Verification (step 6)"]
        CHECK["jwt.hostThumbprint\n===\nagentIdentity.hostThumbprint?"]
    end

    HI -->|"thumbprint + publicKeyJwk\nembedded at registration"| AI
    AI -->|"hostThumbprint\nincluded in every token"| JWT
    JWT -->|"checked by TokenVerifier"| CHECK
    CHECK -->|"mismatch → token_invalid"| DENY["ChainAuthError\ntoken_invalid"]
    CHECK -->|"match → proceed"| NEXT["Steps 7-11"]

    style HI fill:#1e40af,color:#eff6ff
    style AI fill:#1e40af,color:#eff6ff
    style JWT fill:#1e293b,color:#f8fafc
    style CHECK fill:#166534,color:#f0fdf4
    style DENY fill:#7f1d1d,color:#fef2f2
```

---

## Host JWT Flow — Agent Registration

The `HostIdentity` is used to sign management JWTs when registering agents against an agent-auth compliant server.

```mermaid
sequenceDiagram
    actor Dev as Developer
    participant HI as HostIdentity
    participant AuthServer as Agent-Auth Server

    Dev->>HI: chain.host.signAgentRegistrationJwt(agentPublicKeyJwk)
    Note over HI: Signs host+jwt\n{ iss: hostId, aud: issuerUrl,\n  agent_public_key: JWK,\n  iat, exp: now+60, jti }
    HI-->>Dev: signed host+jwt (string)

    Dev->>AuthServer: POST /agent/register\nAuthorization: Bearer <host+jwt>
    AuthServer-->>Dev: { agentId, grants[] }

    Note over Dev: Developer now has agentId + grants\nPass grants[] to chain.wrap(service, grants)
```

---

## Well-Known Discovery

```mermaid
sequenceDiagram
    actor Agent as External Agent
    participant App as Developer's App
    participant AC as AppChain
    participant CR as CapabilityRegistry

    Agent->>App: GET /.well-known/agent-configuration
    App->>AC: chain.getWellKnownConfig()
    AC->>CR: buildWellKnownConfig(issuer, providerName)
    CR-->>AC: AgentConfiguration\n{ version, provider_name, issuer,\n  algorithms: ["Ed25519"],\n  endpoints: { register, capabilities,\n    execute, status, revoke, ... },\n  default_capabilities: [...] }
    AC-->>App: AgentConfiguration
    App-->>Agent: 200 OK — JSON
```

---

## Persistence Adapters — Plugging In Redis

agents-chain defaults to in-memory state. For production deployments, plug in your own Redis client via two adapter interfaces — the package never imports a Redis client.

```mermaid
graph LR
    subgraph Default["Default (in-memory)"]
        JC_MEM["JtiCache\nin-memory Map\nresets on restart"]
        LOG_MEM["AuditLog\nEncryptedStore\nin-memory"]
    end

    subgraph WithAdapters["With Adapters (production)"]
        JC_REDIS["JtiCache(redisAdapter)\nJtiPersistenceAdapter\n{ has(key), set(key, ttlMs) }"]
        LOG_HTTP["AuditLog.drain()\nHttpAuditExporter\nPOST /audit/ingest"]
        GR["grantResolver\n(agentId, capability) =>\nPromise<ResolvedGrant | null>"]
    end

    subgraph UserProvided["User provides"]
        REDIS["ioredis / node-redis\nclient instance"]
        DB["Your DB / API\nclient instance"]
        INGEST["Any HTTP endpoint\nor hosted audit service"]
    end

    JC_REDIS -->|implements| REDIS
    LOG_HTTP -->|POSTs to| INGEST
    GR -->|queries| DB
```

---

## Complete Integration Example

```mermaid
graph TD
    subgraph YourApp["Your Application"]
        SVC["billingService\n(your existing object)"]
        ROUTES["Express Routes"]
        WK["Well-Known Endpoint\nGET /.well-known/agent-configuration"]
    end

    subgraph ChainSetup["AppChain Setup"]
        AC["AppChain.create({\n  providerName: 'billing',\n  issuer: 'https://billing.co',\n  capabilities: [...],\n  grantResolver: db.getGrant\n})"]
        SECURED["chain.wrap(billingService, grants)\n→ secured (Proxy)"]
    end

    subgraph Security["agents-chain Security Layer"]
        PROXY["JS Proxy Intercept"]
        JWT_FLOW["11-Step JWT Verification"]
        CONSTRAINT["Constraint Enforcement"]
        AUDIT["Encrypted Audit Log"]
    end

    subgraph Storage["Optional External Storage"]
        REDIS2["Redis\nJTI replay protection"]
        AUDITDB["Audit Ingest\nHttpAuditExporter"]
        GRANTDB["Grant Store\ngrantResolver callback"]
    end

    ROUTES --> SECURED
    SECURED --> PROXY
    PROXY --> JWT_FLOW
    JWT_FLOW --> CONSTRAINT
    CONSTRAINT --> SVC
    SVC --> AUDIT
    AUDIT -->|drain()| AUDITDB
    JWT_FLOW -->|JtiCache| REDIS2
    JWT_FLOW -->|grantResolver| GRANTDB
    WK --> AC

    style PROXY fill:#1e40af,color:#eff6ff
    style JWT_FLOW fill:#1e40af,color:#eff6ff
    style CONSTRAINT fill:#1e40af,color:#eff6ff
    style AUDIT fill:#1e40af,color:#eff6ff
```
