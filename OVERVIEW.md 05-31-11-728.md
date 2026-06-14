# agentchain — Access Request System Overview

This document explains how the access request layer works: how an agent's blocked call turns into a human notification, gets approved with a tamper-proof code, and resumes exactly where it left off.

---

## 1. The Big Picture

```mermaid
flowchart TD
    A([LLM Agent]) -->|calls wrapped service| B[Proxy Interceptor\napp-wrapper.ts]
    B -->|JWT auth + constraint check| C{Allowed?}
    C -->|yes| D([Execute Capability])
    C -->|no — constraint_violated\nor capability_denied| E{Access Requests\nenabled?}
    E -->|no| F([Throw ChainAuthError])
    E -->|yes| G[AccessRequestManager\ncreate request + SUSPEND call]
    G -->|verificationCode sent| H[AccessRequestNotifier\nemail / SMS / push / webhook]
    H -->|out-of-band| I([Human Operator])
    I -->|chain.approve code + scope| J[HMAC Verification\nconstant-time compare]
    J -->|invalid code| K([Throw — approval rejected])
    J -->|valid code| L[ApprovalStore\ncreate rule]
    L --> M[Resume suspended call\nre-execute with new rule]
    M -->|rule covers this call| D
```

---

## 2. The Proxy Intercept — Every Call Goes Through Here

Every method call on a wrapped service object is intercepted by a `Proxy` in [app-wrapper.ts](src/app/app-wrapper.ts). This is where auth, constraints, and the access request flow all live.

```mermaid
sequenceDiagram
    participant Agent
    participant Proxy as Proxy (app-wrapper)
    participant Builder as TokenBuilder
    participant Verifier as TokenVerifier
    participant Constraints as enforceConstraints
    participant ApprovalStore

    Agent->>Proxy: service.sendSMS({ to: "+9999999" })
    Proxy->>Builder: build("sendSMS")
    Builder-->>Proxy: signed JWT
    Proxy->>Verifier: verify(token, "sendSMS", grants)
    Verifier-->>Proxy: VerifiedCallContext
    Proxy->>ApprovalStore: getExpandedConstraints("sendSMS")
    ApprovalStore-->>Proxy: merged constraints (or null = bypass)
    Proxy->>Constraints: enforceConstraints(effectiveConstraints, args)
    Constraints-->>Proxy: throws constraint_violated ❌
    Note over Proxy: Caught — access request flow begins
```

---

## 3. The Suspend & Resume Flow — How Context is Preserved

This is the key mechanism. The agent's call does not throw — it **blocks** on a Promise inside `executeWithAccessRequest`. All context (capability name, args, auth context) lives in the function's closure. When the human approves, the Promise resolves and the exact same call re-runs.

```mermaid
sequenceDiagram
    participant Agent
    participant Wrapper as executeWithAccessRequest
    participant Manager as AccessRequestManager
    participant Notifier as AccessRequestNotifier
    participant Human
    participant Chain as chain.approve()

    Agent->>Wrapper: sendSMS({ to: "+9999999" })
    Note over Wrapper: constraint_violated caught
    Wrapper->>Manager: createRequest({ capability, args, ... })
    Manager->>Manager: generate HMAC code\n(agent never sees secret)
    Manager-->>Wrapper: { request, waitForApproval: Promise }
    Wrapper->>Notifier: notify(request)
    Note over Notifier: sends email/SMS/push with code
    Notifier-->>Human: "Agent wants to SMS +9999999\nCode: A3F7C209"

    Note over Wrapper,Agent: ⏸ SUSPENDED — awaiting waitForApproval Promise
    Note over Agent: agent's await is blocked here\nclosure holds: capabilityName, callArgs, ctx, targetFn

    Human->>Chain: chain.approve({ requestId, code: "A3F7C209", scope: "value" })
    Chain->>Manager: approve(decision)
    Manager->>Manager: verify HMAC code ✅
    Manager->>Manager: suspended.resolve({ approved: true, decision })

    Note over Wrapper: Promise resolves — RESUMED
    Wrapper->>Wrapper: createRule in ApprovalStore
    Wrapper->>Wrapper: re-call executeWithAccessRequest\n(same args, same context)
    Note over Wrapper: This time constraints pass ✅
    Wrapper-->>Agent: result returned
```

---

## 4. The HMAC Security Model — Why Agents Can't Self-Approve

The verification code is a truncated HMAC-SHA256 digest. The agent has no path to the secret — it is a `private readonly Buffer` inside `AccessRequestManager`, never passed to anything the agent's execution context can reach.

```mermaid
flowchart LR
    subgraph config ["AppChain.create(config)"]
        S["approvalSecret\n(env var / KMS)"]
    end

    subgraph manager ["AccessRequestManager\n(private readonly secret)"]
        G["generateCode()\nHMAC-SHA256(secret, requestId:agentId:capability:createdAt)\n→ 'A3F7C209'"]
        V["verifyCode()\nconstant-time compare\nHMAC must match"]
    end

    subgraph store ["ApprovalStore\n(private readonly secret)"]
        I["computeIntegrity()\nHMAC over all stored rules\nif tampered → wipe rules"]
    end

    subgraph agent ["Agent execution context\n(Proxy / capabilities / JWT verifier)"]
        X["❌ No access to secret\n❌ No access to verificationCode\n✅ Sees only: requestId"]
    end

    S -->|"same Buffer"| manager
    S -->|"same Buffer"| store
    agent -.->|"cannot reach"| S
```

**Code generation input:**
```
HMAC-SHA256(
  key: approvalSecret,
  data: "areq_abc123:agent-xyz:sendSMS:1718000000000"
) → "A3F7C209FF..."  →  truncate to 8 chars  →  "A3F7C209"
```

The code is tied to the specific `requestId + agentId + capability + timestamp`. A code from one request cannot be replayed on a different one.

---

## 5. The 4 Approval Scopes

When the human approves, they choose how broadly to grant permission.

```mermaid
flowchart TD
    A([Human approves]) --> B{scope?}

    B -->|"call"| C["One-time only\nRule created, used once,\nthen immediately revoked\nContext: this exact call"]
    B -->|"value"| D["Specific value approved\ne.g. '+9999999' added to\nthe 'to' field whitelist\nContext: session"]
    B -->|"capability"| E["Whole capability unlocked\nAll constraints removed\nfor this session\nContext: session"]
    B -->|"global"| F["Persistent rule\nStored encrypted in EncryptedStore\nApplies to all agents\nSurvives restart"]

    C --> G([Call executes once, rule gone])
    D --> H([Future SMS to '+9999999' allowed])
    E --> I([All SMS calls allowed this session])
    F --> J([All SMS calls allowed forever until revoked])
```

---

## 6. ApprovalStore — Tamper-Proof Rule Storage

Rules are stored encrypted (AES-256-GCM via `EncryptedStore`). On top of that, an HMAC integrity tag covers the entire rule list. If anything modifies the store directly, the HMAC check fails on load and all rules are wiped.

```mermaid
flowchart TD
    A[ApprovalStore.createRule] -->|"encrypt + store"| B[(EncryptedStore\nAES-256-GCM)]
    A -->|"HMAC over rules JSON"| C[Integrity tag stored separately]

    D[Process restart / load] --> E[Read rules from store]
    E --> F[Recompute HMAC over loaded rules]
    F --> G{HMAC matches\nstored tag?}
    G -->|yes| H([Rules restored ✅])
    G -->|no — tampered!| I([Clear all rules ⚠️\nLog warning])

    J([Agent tries to write rules directly]) -->|"goes through EncryptedStore"| K["No integrity tag written\n→ HMAC mismatch on next load\n→ Rules wiped"]
```

---

## 7. How to Use It — API Surface

### Setup

```typescript
const chain = await AppChain.create({
  providerName: "my-service",
  issuer: "https://myapp.com",
  capabilities: [sendSMSCapability],
  accessRequests: {
    approvalSecret: process.env.APPROVAL_SECRET, // keep outside agent reach
    requestTTLMs: 5 * 60 * 1000,                // requests expire in 5 min
    notifier: {
      async notify(request) {
        // send email, SMS, push notification, webhook — your choice
        await sendEmail({
          to: "admin@myapp.com",
          subject: `Agent access request: ${request.capability}`,
          body: `Agent "${request.agentName}" wants to call ${request.capability}\n` +
                `Reason: ${request.reason}\n` +
                `Code: ${request.verificationCode}\n` +
                `Approve at: https://myapp.com/approve?id=${request.requestId}`
        });
      },
      async onResolved(request, outcome) {
        // optional: update your UI or close a notification
      }
    }
  }
});
```

### Approval Endpoint

```typescript
// POST /agent-approvals  (your API — called by human via UI or webhook)
app.post("/agent-approvals", (req, res) => {
  const { requestId, code, scope, ttl } = req.body;
  try {
    const approved = chain.approve({ requestId, code, scope, ttl });
    // The suspended agent call resumes automatically here
    res.json({ ok: true, capability: approved.capability });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
```

### Dashboard / Monitoring

```typescript
// See what's waiting
chain.getPendingRequests();  // AccessRequest[]

// See what's been approved
chain.getApprovalRules();    // ApprovalRule[]

// Revoke a rule
chain.revokeApproval(ruleId);
chain.revokeApprovalsForCapability("sendSMS");
chain.revokeAllApprovals();
```

---

## 8. File Map

```
src/
├── types/
│   ├── access-request.ts      ← All types: AccessRequest, ApprovalScope, ApprovalRule,
│   │                             SuspendedCall, AccessRequestNotifier, ApprovalDecision
│   └── audit.ts               ← Extended: access_requested / access_approved / access_denied
│
├── access/
│   ├── access-request-manager.ts  ← HMAC code generation, pending request tracking,
│   │                                 approve/deny/expire, suspended Promise map
│   └── approval-store.ts          ← Encrypted + HMAC-integrity rule storage,
│                                    constraint expansion and merging
│
├── app/
│   └── app-wrapper.ts         ← Proxy interceptor — suspend/resume integration,
│                                 getEffectiveConstraints, re-execute on approval
│
├── errors/
│   └── chain-error.ts         ← Added: access_request_pending / denied / expired
│
└── chain.ts                   ← AppChain: wires it all together, exposes
                                  approve() / deny() / getPendingRequests() /
                                  getApprovalRules() / revokeApproval()
```
