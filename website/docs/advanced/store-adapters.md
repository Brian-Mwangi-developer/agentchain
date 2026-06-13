---
sidebar_position: 2
title: Store Adapters
---

# Store Adapters

Everything defaults to in-memory. For production deployments, inject adapters to persist state across restarts and across processes.

## Store Persistence Adapter

`EncryptedStore` backs all chain state (host registration, agent registration, audit buffer, approval rules). Inject a `StorePersistenceAdapter` to back it with Redis, SQLite, or any key-value store:

```typescript
const redisStoreAdapter = {
  async get(key) {
    return redis.get(key) ?? undefined;
  },
  async set(key, value) {
    await redis.set(key, value);
  },
  async delete(key) {
    await redis.del(key);
  },
};

const chain = await AppChain.create({
  providerName: 'my-service',
  issuer: 'https://myservice.com',
  capabilities: [...],
  storeAdapter: redisStoreAdapter,
});
```

### Interface

```typescript
interface StorePersistenceAdapter {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string): Promise<void>;
  delete(key: string): Promise<void>;
}
```

## JTI Adapter

JTI replay protection is in-memory by default (resets on restart). For multi-process or multi-instance deployments, inject a Redis adapter:

```typescript
const redisJtiAdapter = {
  async has(key) {
    return Boolean(await redis.exists(key));
  },
  async set(key, ttlMs) {
    await redis.set(key, '1', 'PX', ttlMs);
  },
};

const chain = await AppChain.create({
  // ...
  jtiAdapter: redisJtiAdapter,
});
```

### Interface

```typescript
interface JtiPersistenceAdapter {
  has(key: string): Promise<boolean>;
  set(key: string, ttlMs: number): Promise<void>;
}
```

## Grant Resolver

Instead of passing grants as an array to `chain.wrap()`, resolve them dynamically from a database:

```typescript
const chain = await AppChain.create({
  // ...
  grantResolver: async (agentId, capability) => {
    const grant = await db.query(
      'SELECT * FROM grants WHERE agent_id = ? AND capability = ? AND status = ?',
      [agentId, capability, 'active']
    );
    return grant ?? undefined;
  },
});
```

## Encryption Key

By default, `EncryptedStore` generates a random AES-256-GCM key. To persist encrypted data across restarts, provide a stable key:

```typescript
const chain = await AppChain.create({
  // ...
  encryptionKey: process.env.STORE_ENCRYPTION_KEY, // hex or base64
});
```
