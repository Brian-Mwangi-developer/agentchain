/** AES-256-GCM key-value store. Each value encrypted with a fresh random IV. Supports optional persistence adapter. */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;      // 96-bit IV — GCM recommended
const TAG_BYTES = 16;     // 128-bit auth tag — maximum GCM strength

/** Plug in a persistent backend (e.g. Redis, SQLite, file-system) for durable storage. */
export interface StorePersistenceAdapter {
    get(key: string): Promise<string | undefined>;
    set(key: string, value: string): Promise<void>;
    delete(key: string): Promise<void>;
}

export class EncryptedStore {
    private readonly key: Buffer;
    private readonly store = new Map<string, string>();
    private readonly adapter?: StorePersistenceAdapter;

    private constructor(key: Buffer, adapter?: StorePersistenceAdapter) {
        this.key = key;
        this.adapter = adapter;
    }

    /** @param hexKey Optional 64-char hex string (32 bytes). Random key generated if omitted. */
    static create(hexKey?: string, adapter?: StorePersistenceAdapter): EncryptedStore {
        let key: Buffer;
        if (hexKey) {
            if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) {
                throw new Error("encryptionKey must be a 64-character hex string (32 bytes)");
            }
            key = Buffer.from(hexKey, "hex");
        } else {
            key = randomBytes(32);
        }
        return new EncryptedStore(key, adapter);
    }

    private encrypt(value: unknown): string {
        const plaintext = JSON.stringify(value);
        const iv = randomBytes(IV_BYTES);
        const cipher = createCipheriv(ALGORITHM, this.key, iv);
        const encrypted = Buffer.concat([
            cipher.update(plaintext, "utf8"),
            cipher.final(),
        ]);
        const tag = cipher.getAuthTag();

        return [
            iv.toString("base64"),
            tag.toString("base64"),
            encrypted.toString("base64"),
        ].join(":");
    }

    private decrypt<T>(key: string, encoded: string): T {
        const parts = encoded.split(":");
        if (parts.length !== 3) {
            throw new Error(`EncryptedStore: corrupted entry at key "${key}"`);
        }

        const iv = Buffer.from(parts[0]!, "base64");
        const tag = Buffer.from(parts[1]!, "base64");
        const ciphertext = Buffer.from(parts[2]!, "base64");

        if (iv.length !== IV_BYTES) {
            throw new Error(`EncryptedStore: invalid IV length for key "${key}"`);
        }
        if (tag.length !== TAG_BYTES) {
            throw new Error(`EncryptedStore: invalid auth tag length for key "${key}"`);
        }

        const decipher = createDecipheriv(ALGORITHM, this.key, iv);
        decipher.setAuthTag(tag);

        let plaintext: string;
        try {
            plaintext = decipher.update(ciphertext, undefined, "utf8") + decipher.final("utf8");
        } catch {
            throw new Error(`EncryptedStore: authentication failed for key "${key}" — possible tampering`);
        }

        return JSON.parse(plaintext) as T;
    }

    set(key: string, value: unknown): void {
        const encoded = this.encrypt(value);
        this.store.set(key, encoded);
        if (this.adapter) {
            // Fire-and-forget for sync API compat; callers needing guarantees use setAsync
            void this.adapter.set(key, encoded);
        }
    }

    async setAsync(key: string, value: unknown): Promise<void> {
        const encoded = this.encrypt(value);
        this.store.set(key, encoded);
        if (this.adapter) {
            await this.adapter.set(key, encoded);
        }
    }

    get<T>(key: string): T | undefined {
        const encoded = this.store.get(key);
        if (!encoded) return undefined;
        return this.decrypt<T>(key, encoded);
    }

    async getAsync<T>(key: string): Promise<T | undefined> {
        // Try in-memory first
        const memEncoded = this.store.get(key);
        if (memEncoded) return this.decrypt<T>(key, memEncoded);

        // Fall through to adapter
        if (this.adapter) {
            const encoded = await this.adapter.get(key);
            if (!encoded) return undefined;
            // Cache in memory
            this.store.set(key, encoded);
            return this.decrypt<T>(key, encoded);
        }

        return undefined;
    }

    append<T>(key: string, item: T): void {
        const existing = this.get<T[]>(key) ?? [];
        existing.push(item);
        this.set(key, existing);
    }

    has(key: string): boolean {
        return this.store.has(key);
    }

    delete(key: string): void {
        this.store.delete(key);
        if (this.adapter) {
            void this.adapter.delete(key);
        }
    }

    async deleteAsync(key: string): Promise<void> {
        this.store.delete(key);
        if (this.adapter) {
            await this.adapter.delete(key);
        }
    }

    get size(): number {
        return this.store.size;
    }

    clear(): void {
        this.store.clear();
    }
}
