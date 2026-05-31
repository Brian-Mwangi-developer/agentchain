import { randomBytes } from "node:crypto";

export function base64UrlEncode(buffer: Buffer | Uint8Array): string {
    return Buffer.from(buffer)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}


export function base64UrlDecode(str: string): Buffer {
    // Pad to multiple of 4
    const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}



export function generateId(prefix: string): string {
    // 128-bit random, base64url encoded (~22 chars). Collision risk is negligible.
    const suffix = base64UrlEncode(randomBytes(16));
    return `${prefix}_${suffix}`;
}



export function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null;
}


export function parseJson<T>(value: string): T {
    return JSON.parse(value) as T;
}