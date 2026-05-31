# agents-chain

Lightweight identity, authentication, and audit layer for AI agent SDKs.

Wrap your OpenAI or Anthropic client with `agents-chain` to get:

- **Ed25519 key-pair identity** per agent instance
- **JWT-based capability tokens** — every API call is signed and verified
- **Encrypted in-memory audit log** — AES-256-GCM, queryable at runtime
- **Zero network calls** — everything runs locally, no external service required

---

## Installation

```bash
npm install agents-chain
# or
pnpm add agents-chain
```

> Requires Node.js 18+

---

## Quick start

### OpenAI

```ts
import { AgentsChain } from 'agents-chain';
import OpenAI from 'openai';

const chain = await AgentsChain.create({
  agentName: 'summarizer',
  hostname: 'my-app',
  capabilities: ['chat.completion'],
});

const ai = chain.openai(new OpenAI({ apiKey: process.env.OPENAI_API_KEY }));

const response = await ai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Summarize the water cycle in one sentence.' }],
});

console.log(response.choices[0].message.content);
```

### Anthropic

```ts
import { AgentsChain } from 'agents-chain';
import Anthropic from '@anthropic-ai/sdk';

const chain = await AgentsChain.create({
  agentName: 'classifier',
  hostname: 'my-app',
  capabilities: ['messages.create'],
});

const ai = chain.anthropic(new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }));

const response = await ai.messages.create({
  model: 'claude-sonnet-4-6',
  max_tokens: 256,
  messages: [{ role: 'user', content: 'Classify this text as positive or negative: "I love it!"' }],
});

console.log(response.content[0]);
```

---

## Configuration

```ts
const chain = await AgentsChain.create({
  agentName: string;      // Human-readable name for this agent
  hostname: string;       // Used to build the agentId: "<hostname>-agent-<32hex>"
  capabilities: string[]; // List of capability strings this agent is allowed to use
  encryptionKey?: string; // Optional 64-char hex (32-byte) AES-256-GCM key.
                          // Omit to generate a random key per session.
                          // Provide to persist and reload audit logs across restarts.
});
```

---

## Audit log

Every API call through a wrapped client is recorded in an encrypted in-memory log.

```ts
// Get all entries (decrypted)
const entries = chain.getAuditLog();

// Full snapshot with metadata
const snapshot = chain.exportAudit();
// { agentId, entries, exportedAt }

// Summary counts
const stats = chain.getStats();
// { agentId, agentName, hostname, totalCalls, successfulCalls, deniedCalls, errorCalls, registeredAt }
```

Each `AuditEntry` contains:

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique entry ID |
| `agentId` | `string` | The agent that made the call |
| `capability` | `string` | Capability used |
| `result` | `"success" \| "denied" \| "error"` | Outcome |
| `timestamp` | `number` | Unix ms |
| `meta` | `Record<string, unknown>` | Provider-specific metadata |

---

## Identity & crypto utilities

Low-level utilities are exported if you need direct access:

```ts
import {
  generateKeyPair,
  exportPublicKeyJwk,
  exportPrivateKeyJwk,
  importPublicKeyJwk,
  computeJwkThumbprint,
  signJwt,
  verifyJwtSignature,
  decodeJwtUnsafe,
  generateId,
  generateAgentId,
  base64UrlEncode,
  base64UrlDecode,
} from 'agents-chain';
```

---

## License

MIT — [brianmwangidev](https://www.npmjs.com/~brianmwangidev)
