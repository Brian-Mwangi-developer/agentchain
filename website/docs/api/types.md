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
  /** LLM metadata when the call went through an OpenAI/Anthropic wrapper */
  modelMetadata?: ModelMetadata;
};
```

## TraceRun

A complete agent session — from `openTrace()` to `closeTrace()`.

```typescript
type TraceRun = {
  traceId: string;
  agentId: string;
  agentName: string;
  hostThumbprint: string;
  status: TraceRunStatus;       // "success" | "failed" | "partial"
  startedAt: number;            // Unix ms
  endedAt: number;              // Unix ms
  totalDurationMs: number;
  spans: TraceSpan[];
  summary: TraceRunSummary;
};

type TraceRunStatus = 'success' | 'failed' | 'partial';

type TraceRunSummary = {
  totalSpans: number;
  successSpans: number;
  deniedSpans: number;
  errorSpans: number;
  totalInputTokens: number;
  totalOutputTokens: number;
  totalTokens: number;
  modelsUsed: string[];
  providersUsed: string[];
};
```

## TraceSpan

One capability call within a `TraceRun`.

```typescript
type TraceSpan = {
  spanId: string;
  capability: string;
  result: TraceSpanResult;
  startedAt: number;
  durationMs: number;
  authOverheadMs: number;
  jti: string;
  args: Record<string, unknown>;
  denialReason?: string;
  errorMessage?: string;
  accessRequestId?: string;
  approvalScope?: 'call' | 'value' | 'capability' | 'global';
  modelMetadata?: ModelMetadata;
  toolCalls?: DetectedToolCall[];
  stopReason?: string;
};

type TraceSpanResult =
  | 'success'
  | 'denied'
  | 'error'
  | 'access_requested'
  | 'access_approved'
  | 'access_denied';
```

## ModelMetadata

Normalized LLM response metadata, extracted automatically by the Anthropic and OpenAI wrappers.

```typescript
type ModelMetadata = {
  model: string;          // e.g. "claude-sonnet-4-6", "gpt-4o"
  provider: string;       // e.g. "anthropic", "openai"
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  temperature?: number;
  toolCalls?: DetectedToolCall[];
  stopReason?: string;    // e.g. "end_turn", "tool_use", "stop", "length"
  extra?: Record<string, unknown>;  // provider-specific (cache tokens, etc.)
};

type DetectedToolCall = {
  name: string;
  input: Record<string, unknown>;  // sanitized — secrets redacted
  id?: string;                     // provider-assigned call ID
};
```

## ModelMetadataExtractor

Interface for teaching agents-chain how to extract metadata from an unsupported LLM provider.

```typescript
interface ModelMetadataExtractor {
  provider: string;
  canExtract(response: unknown): boolean;
  extract(response: unknown, requestArgs?: Record<string, unknown>): ModelMetadata;
}
```

Register with `registerExtractor(extractor)`. See [Tracing & Observability](../concepts/tracing) for a full example.

## TraceExporter

```typescript
interface TraceExporter {
  export(run: TraceRun): Promise<void>;
}
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
