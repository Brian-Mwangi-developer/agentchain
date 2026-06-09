/** JTI replay protection: 90-second window, lazy + background GC, optional persistent adapter. */

import { ChainAuthError } from "../errors/chain-error.js";

const REPLAY_WINDOW_MS = 90_000;
const GC_INTERVAL_MS = 45_000;

/** Plug in a persistent store (e.g. Redis) for shared deployments. */
export interface JtiPersistenceAdapter {
    /** Returns true if the key exists and has not expired. */
    has(key: string): Promise<boolean>;
    /** Store the key with the given TTL in milliseconds. */
    set(key: string, ttlMs: number): Promise<void>;
}

export class JtiCache {
    private readonly inMemory = new Map<string, number>();
    private readonly adapter?: JtiPersistenceAdapter;
    private readonly gcTimer?: ReturnType<typeof setInterval>;

    constructor(adapter?: JtiPersistenceAdapter) {
        this.adapter = adapter;
        if (!adapter) {
            const timer = setInterval(() => this.evictExpired(), GC_INTERVAL_MS);
            if (typeof timer.unref === "function") timer.unref();
            this.gcTimer = timer;
        }
    }

    /** Throws token_replayed if this jti was seen within the replay window, then records it. */
    async assert(agentId: string, jti: string): Promise<void> {
        const cacheKey = `${agentId}:${jti}`;

        if (this.adapter) {
            const exists = await this.adapter.has(cacheKey);
            if (exists) {
                throw new ChainAuthError(
                    "token_replayed",
                    `JWT ID "${jti}" has already been used — replay attack detected. ` +
                    `Each capability call must use a freshly-built token.`
                );
            }
            await this.adapter.set(cacheKey, REPLAY_WINDOW_MS);
        } else {
            this.evictExpired();
            if (this.inMemory.has(cacheKey)) {
                throw new ChainAuthError(
                    "token_replayed",
                    `JWT ID "${jti}" has already been used — replay attack detected. ` +
                    `Each capability call must use a freshly-built token (TokenBuilder.build()).`
                );
            }
            this.inMemory.set(cacheKey, Date.now() + REPLAY_WINDOW_MS);
        }
    }

    private evictExpired(): void {
        const now = Date.now();
        for (const [key, expiry] of this.inMemory) {
            if (expiry < now) this.inMemory.delete(key);
        }
    }

    /** Stop the GC timer and clear the cache. Call on shutdown or after tests. */
    destroy(): void {
        if (this.gcTimer !== undefined) {
            clearInterval(this.gcTimer);
        }
        this.inMemory.clear();
    }

    get size(): number {
        return this.inMemory.size;
    }
}