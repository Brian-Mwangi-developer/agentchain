---
sidebar_position: 3
title: SDK Wrappers
---

# SDK Wrappers

agents-chain ships Proxy wrappers for the OpenAI and Anthropic SDKs. These intercept API calls and gate them through the auth pipeline.

## OpenAI Wrapper

```typescript
import OpenAI from 'openai';
import { AppChain } from 'agents-chain';

const chain = await AppChain.create({
  providerName: 'openai-service',
  issuer: 'https://myservice.com',
  capabilities: [
    {
      name: 'chat.completions.create',
      description: 'Create a chat completion',
      inputSchema: { type: 'object', properties: {} },
      outputSchema: { type: 'object' },
    },
  ],
});

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
const grants = [
  { capability: 'chat.completions.create', status: 'active' },
];

// Wrap the SDK — method paths are mapped to capability names
const secured = chain.openai(openai, grants);

// This goes through the auth pipeline before reaching OpenAI
const response = await secured.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello' }],
});
```

## Anthropic Wrapper

```typescript
import Anthropic from '@anthropic-ai/sdk';
import { AppChain } from 'agents-chain';

const chain = await AppChain.create({
  providerName: 'anthropic-service',
  issuer: 'https://myservice.com',
  capabilities: [
    {
      name: 'messages.create',
      description: 'Create a message',
      inputSchema: { type: 'object', properties: {} },
      outputSchema: { type: 'object' },
    },
  ],
});

const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
const grants = [
  { capability: 'messages.create', status: 'active' },
];

const secured = chain.anthropic(anthropic, grants);

const response = await secured.messages.create({
  model: 'claude-sonnet-4-6',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello' }],
});
```

## Tracing LLM Calls

Pass a `traceId` to `openai()` or `anthropic()` to attach LLM metadata (model name, token counts, tool calls, stop reason) to every span in the active trace:

```typescript
const traceId = chain.openTrace();

const openai = chain.openai(new OpenAI({ apiKey: '...' }), traceId);
await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hello' }],
});

const anthropic = chain.anthropic(new Anthropic({ apiKey: '...' }), traceId);
await anthropic.messages.create({
  model: 'claude-sonnet-4-6',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello' }],
});

const run = await chain.closeTrace(traceId, 'success');
// run.summary.totalTokens    — combined token count
// run.summary.modelsUsed     — ["gpt-4o", "claude-sonnet-4-6"]
// run.spans[0].modelMetadata — { model, provider, inputTokens, outputTokens, toolCalls, ... }
```

See [Tracing & Observability](../concepts/tracing) for the full API.

## How It Works

The wrappers use JavaScript `Proxy` to intercept nested property access. When you call `secured.chat.completions.create(args)`, the wrapper:

1. Maps the path `chat.completions.create` to a capability name
2. Runs the full auth pipeline (token mint → 11-step verify → constraints)
3. Calls the real SDK method if auth passes
4. Extracts `ModelMetadata` from the response (tokens, model, tool calls)
5. Records the call in the audit log, attaching the metadata to the span if a `traceId` is active

Constraint enforcement works on the SDK call arguments. You can restrict which models, parameters, or inputs an agent is allowed to use.
