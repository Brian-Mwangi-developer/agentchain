---
sidebar_position: 2
title: Types
---

# Type Reference

All types exported from `agents-chain`.

## Capability

```typescript
type Capability<TInput = unknown, TOutput = unknown> = {
  name: string;
  description: string;
  inputSchema: JsonSchemaObject;     // JSON Schema; `required` array is enforced
  outputSchema: JsonSchemaObject;
  execute?: (params: TInput, context: AgentContext) => Promise<TOutput>;
};

type AgentContext = {
  agentId: string;
  hostId: string;
  permissions: string[];
};
```

## ResolvedGrant

```typescript
type ResolvedGrant = {
  capability: string;
  status: 'active' | 'revoked' | 'expired';
  constraints?: GrantConstraints;
  expiresAt?: number;
};
```

## GrantConstraints

```typescript
type GrantConstraints = Record<string, ConstraintValue>;

type ConstraintValue =
  | ConstraintPrimitive          // Exact equality
  | ConstraintOperator;          // Operator-based

type ConstraintPrimitive = string | number | boolean;

type ConstraintOperator = {
  max?: number;
  min?: number;
  in?: ConstraintPrimitive[];
  not_in?: ConstraintPrimitive[];
};
```

## AccessRequest

```typescript
type AccessRequest = {
  requestId: string;
  agentId: string;
  agentName: string;
  hostId: string;
  capability: string;
  args: Record<string, unknown>;
  reason: string;
  violatedField?: string;
  violatedValue?: unknown;
  errorCode: 'constraint_violated' | 'capability_denied';
  createdAt: number;
  expiresAt: number;
  status: AccessRequestStatus;
  verificationCode: string;
};

type AccessRequestStatus = 'pending' | 'approved' | 'denied' | 'expired';
```

## ApprovalDecision / DenialDecision

```typescript
type ApprovalDecision = {
  requestId: string;
  code: string;
  scope: ApprovalScope;
  ttl?: ApprovalTTL;
  expandConstraints?: GrantConstraints;
};

type DenialDecision = {
  requestId: string;
  code: string;
  reason?: string;
};

type ApprovalScope = 'call' | 'value' | 'capability' | 'global';

type ApprovalTTL = {
  durationMs?: number;
  expiresAt?: number;
};
```

## ApprovalRule

```typescript
type ApprovalRule = {
  ruleId: string;
  capability: string;
  scope: ApprovalScope;
  field?: string;
  value?: unknown;
  expandedConstraints?: GrantConstraints;
  approvedBy: string;
  createdAt: number;
  expiresAt?: number;
  global: boolean;
};
```

## AccessRequestNotifier

```typescript
type AccessRequestNotifier = {
  notify(request: AccessRequest): Promise<void>;
  onResolved?(request: AccessRequest, outcome: 'approved' | 'denied' | 'expired'): Promise<void>;
};
```

## AuditEntry

```typescript
type AuditEntry = {
  id: string;
  agentId: string;
  agentName: string;
  capability: string;
  args: Record<string, unknown>;
  result: 'success' | 'denied' | 'error';
  denialReason?: string;
  jti: string;
  timestamp: number;
  durationMs: number;
  authOverheadMs: number;
};
```

## ChainStats

```typescript
type ChainStats = {
  agentId: string;
  hostId: string;
  agentName: string;
  hostname: string;
  totalCalls: number;
  successfulCalls: number;
  deniedCalls: number;
  errorCalls: number;
  registeredAt: number;
  authOverhead: { avgMs: number; maxMs: number };
};
```

## Adapter Interfaces

```typescript
interface JtiPersistenceAdapter {
  has(key: string): Promise<boolean>;
  set(key: string, ttlMs: number): Promise<void>;
}

interface StorePersistenceAdapter {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```
