import { randomBytes } from "node:crypto";

export type JwtTyp = "agent+jwt";

export function base64UrlEncode(buffer: Buffer | Uint8Array): string {
    return Buffer.from(buffer)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");
}

export function base64UrlDecode(str: string): Buffer {
    const padded = str + "=".repeat((4 - (str.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

/**
 * Generate a cryptographically random ID.
 * Format: <prefix>_<22 base64url chars> (128-bit entropy).
 * When a hostname is provided the format is: <hostname>-<suffix>-<22chars>
 */
export function generateId(prefix: string): string {
    const suffix = base64UrlEncode(randomBytes(16));
    return `${prefix}_${suffix}`;
}

/**
 * Build a host-scoped agent ID.
 * Format: <hostname>-agent-<32 hex chars>
 * The 32 hex chars = 128-bit random, making collision negligible.
 */
export function generateAgentId(hostname: string): string {
    const random = randomBytes(16).toString("hex"); // 32 hex chars
    const safe = hostname.toLowerCase().replace(/[^a-z0-9]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "");
    return `${safe}-agent-${random}`;
}

export function isObject(value: unknown): value is Record<string, unknown> {
    return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseJson<T>(value: string): T {
    return JSON.parse(value) as T;
}
