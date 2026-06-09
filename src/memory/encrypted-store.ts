/** AES-256-GCM in-memory key-value store. Each value encrypted with a fresh random IV. */

import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;      // 96-bit IV — GCM recommended
const TAG_BYTES = 16;     // 128-bit auth tag — maximum GCM strength

export class EncryptedStore {
    private readonly key: Buffer;
    private readonly store = new Map<string, string>();

    private constructor(key: Buffer) {
        this.key = key;
    }

    /** @param hexKey Optional 64-char hex string (32 bytes). Random key generated if omitted. */
    static create(hexKey?: string): EncryptedStore {
        let key: Buffer;
        if (hexKey) {
            if (!/^[0-9a-fA-F]{64}$/.test(hexKey)) {
                throw new Error("encryptionKey must be a 64-character hex string (32 bytes)");
            }
            key = Buffer.from(hexKey, "hex");
        } else {
            key = randomBytes(32);
        }
        return new EncryptedStore(key);
    }

    set(key: string, value: unknown): void {
        const plaintext = JSON.stringify(value);
        const iv = randomBytes(IV_BYTES);
        const cipher = createCipheriv(ALGORITHM, this.key, iv);
        const encrypted = Buffer.concat([
            cipher.update(plaintext, "utf8"),
            cipher.final(),
        ]);
        const tag = cipher.getAuthTag();

        // Format: base64(iv):base64(tag):base64(ciphertext)
        const encoded = [
            iv.toString("base64"),
            tag.toString("base64"),
            encrypted.toString("base64"),
        ].join(":");

        this.store.set(key, encoded);
    }

    get<T>(key: string): T | undefined {
        const encoded = this.store.get(key);
        if (!encoded) return undefined;

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
            // GCM auth tag mismatch — data has been tampered with
            throw new Error(`EncryptedStore: authentication failed for key "${key}" — possible tampering`);
        }

        return JSON.parse(plaintext) as T;
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
    }

    get size(): number {
        return this.store.size;
    }

    clear(): void {
        this.store.clear();
    }
}
