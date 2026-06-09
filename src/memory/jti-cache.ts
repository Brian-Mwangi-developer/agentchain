/**
 * JtiCache — JWT ID replay protection with optional persistence adapter.
 *
 * Security properties:
 * - Every agent+jwt carries a unique `jti` (JWT ID), generated fresh per call.
 * - Once seen, the jti is recorded for REPLAY_WINDOW_MS (90 seconds).
 * - Any attempt to reuse the same jti within that window throws ChainAuthError.
 * - TTL eviction is lazy (on insert) — no background timer needed.
 *
 * Why 90 seconds: token TTL is 60s + 30s clock skew tolerance = 90s window.
 * A token cannot be replayed after expiry (exp check in TokenVerifier), but
 * the jti cache provides defence-in-depth for the live 60-second window.
 *
 * In-memory vs persistent:
 * By default, the cache is in-memory and resets on process restart. This is
 * safe for single-process deployments: a new keypair is generated on restart,
 * making all previous tokens invalid regardless of jti state.
 *
 * For multi-process or multi-instance deployments, provide a
 * JtiPersistenceAdapter (e.g. Redis) so the replay window survives restarts
 * and is shared across instances. Pass it via AgentsChain/AppChain jtiAdapter.
 *
 * Example Redis adapter:
 *   const adapter: JtiPersistenceAdapter = {
 *     has: (key) => redis.exists(key).then(Boolean),
 *     set: (key, ttlMs) => redis.set(key, "1", "PX", ttlMs).then(() => {}),
 *   };
 *
 * Previously reported "always replay detected" (no adapter path):
 * The in-memory logic was correct — the issue was test/integration code calling
 * verify() twice on the *same* token (same jti). The fix: always call
 * TokenBuilder.build() before each verify() so a fresh jti is generated.
 * The wrappers (openai-wrapper, anthropic-wrapper, app-wrapper) already do this
 * correctly — they call build() inside every intercepted method call.
 */

import { ChainAuthError } from "../errors/chain-error.js";

const REPLAY_WINDOW_MS = 90_000; // 90 seconds

/**
 * Interface for backing the JTI cache with a persistent store (e.g. Redis).
 * Implement this and pass it to AgentsChain/AppChain via the jtiAdapter option.
 */
export interface JtiPersistenceAdapter {
    /** Returns true if the key exists and has not expired. */
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

    /**
     * Assert that a jti has not been seen before, then record it.
     * Throws ChainAuthError("token_replayed") if the jti is a duplicate.
     *
     * Each call to TokenBuilder.build() generates a cryptographically random
     * jti, so legitimate sequential calls will never collide here.
     */
    async assert(agentId: string, jti: string): Promise<void> {
        const cacheKey = `${agentId}:${jti}`;

        if (this.adapter) {
            // Persistent path — check then set via adapter
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
            // In-memory path: evict stale entries FIRST, then check, then record.
            // Evicting before the check ensures we never reject a legitimately
            // reused jti that was originally seen outside the replay window
            // (edge case: same random jti generated after window closes — vanishingly
            // unlikely with 128-bit entropy, but handled correctly).
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

    /** Remove all in-memory entries whose expiry has passed. */
    private evictExpired(): void {
        const now = Date.now();
        for (const [key, expiry] of this.inMemory) {
            if (expiry < now) {
                this.inMemory.delete(key);
            }
        }
    }

    /** Number of live in-memory entries (does not reflect persistent store size). */
    get size(): number {
        return this.inMemory.size;
    }
}