/**
 * JtiCache — JWT ID replay protection with optional persistence adapter.
 *
 * Security properties:
 * - Every agent+jwt carries a unique `jti` (JWT ID).
 * - Once seen, the jti is recorded for REPLAY_WINDOW_MS.
 * - Any attempt to reuse the same jti within that window throws ChainAuthError.
 * - This prevents replay attacks: an intercepted token cannot be reused.
 * - TTL eviction is lazy (checked on insert) — no background timer needed.
 *
 * The window is 90 seconds to comfortably cover the 60-second token max TTL
 * plus clock skew tolerance.
 *
 * Persistence adapter (optional):
 * By default, the cache is in-memory and resets on process restart (which is
 * safe — a new keypair = new identity = old tokens invalid anyway).
 *
 * If you need replay protection to survive restarts (e.g. shared deployment),
 * provide a JtiPersistenceAdapter backed by Redis or your DB.
 * The package does NOT ship a Redis client — the user provides it.
 *
 * Example Redis adapter:
 *   const adapter: JtiPersistenceAdapter = {
 *     has: (key) => redis.exists(key).then(Boolean),
 *     set: (key, ttlMs) => redis.set(key, "1", "PX", ttlMs).then(() => {}),
 *   };
 */

import { ChainAuthError } from "../errors/chain-error.js";

const REPLAY_WINDOW_MS = 90_000; // 90 seconds

/**
 * Interface for backing the JTI cache with a persistent store (e.g. Redis).
 * Implement this interface and pass it to JtiCache to survive process restarts.
 */
export interface JtiPersistenceAdapter {
    /** Returns true if the key exists (and has not expired). */
    has(key: string): Promise<boolean>;
    /** Store the key with the given TTL in milliseconds. */
    set(key: string, ttlMs: number): Promise<void>;
}

export class JtiCache {
    /** Map of "<agentId>:<jti>" → expiry timestamp (Unix ms) */
    private readonly inMemory = new Map<string, number>();
    private readonly adapter?: JtiPersistenceAdapter;

    constructor(adapter?: JtiPersistenceAdapter) {
        this.adapter = adapter;
    }

    async assert(agentId: string, jti: string): Promise<void> {
        const cacheKey = `${agentId}:${jti}`;

        if (this.adapter) {
            // Persistent path — delegate to adapter
            const exists = await this.adapter.has(cacheKey);
            if (exists) {
                throw new ChainAuthError(
                    "token_replayed",
                    `JWT has already been used (jti="${jti}") — replay attack detected`
                );
            }
            await this.adapter.set(cacheKey, REPLAY_WINDOW_MS);
            //NOTE:Confirm this Implementation Here.
        } else {
            // In-memory path
            this.evictExpired();
            const existing = this.inMemory.get(cacheKey);
            if (existing !== undefined) {
                throw new ChainAuthError(
                    "token_replayed",
                    `JWT has already been used (jti="${jti}") — replay attack detected`
                );
            }
            this.inMemory.set(cacheKey, Date.now() + REPLAY_WINDOW_MS);
        }
    }

    /** Remove all in-memory entries whose expiry has passed. */
    private evictExpired(): void {
        const now = Date.now();
        for (const [key, expiry] of this.inMemory) {
            if (expiry < now) {
                this.inMemory.delete(key);
            }
        }
    }

    /** Number of in-memory entries (does not reflect persistent store). */
    get size(): number {
        return this.inMemory.size;
    }
}

