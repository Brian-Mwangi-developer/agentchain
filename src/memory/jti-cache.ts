/**
 * JtiCache — in-memory JWT ID replay protection.
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
 */

import { ChainAuthError } from "../errors/chain-error.js";

const REPLAY_WINDOW_MS = 90_000; // 90 seconds

export class JtiCache {
    /** Map of "<agentId>:<jti>" → expiry timestamp (Unix ms) */
    private readonly cache = new Map<string, number>();

    assert(agentId: string, jti: string): void {
        this.evictExpired();

        const cacheKey = `${agentId}:${jti}`;
        const existing = this.cache.get(cacheKey);

        if (existing !== undefined) {
            throw new ChainAuthError(
                "token_replayed",
                `JWT has already been used (jti="${jti}") — replay attack detected`
            );
        }

        this.cache.set(cacheKey, Date.now() + REPLAY_WINDOW_MS);
    }

    /** Remove all entries whose expiry has passed. */
    private evictExpired(): void {
        const now = Date.now();
        for (const [key, expiry] of this.cache) {
            if (expiry < now) {
                this.cache.delete(key);
            }
        }
    }

    get size(): number {
        return this.cache.size;
    }
}
