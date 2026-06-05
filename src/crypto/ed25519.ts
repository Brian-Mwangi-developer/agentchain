/**
 * Ed25519 key operations and JWT construction using only node:crypto.
 *
 * - Zero external JWT library dependency
 * - All signing uses EdDSA (Ed25519) via crypto.subtle
 * - Never pass Buffer directly to crypto.subtle — always Uint8Array
 */

import { createHash } from "node:crypto";
import { base64UrlDecode, base64UrlEncode, isObject, parseJson, type JwtTyp } from "./utils.js";

// ─── Types ────────────────────────────────────────────────────────────────────

export type JwtHeader = {
    alg: "EdDSA";
    typ: JwtTyp;
    kid?: string;
};

export type JwtPayload = {
    iss?: string;
    sub?: string;
    aud?: string;
    exp?: number;
    iat?: number;
    jti?: string;
    [key: string]: unknown;
};

export type DecodedJwt<T extends JwtPayload = JwtPayload> = {
    header: JwtHeader;
    payload: T;
    signingInput: string;
    signature: string;
};

export type VerifyJwtOptions = {
    expectedTyp: JwtTyp;
};

export type JwksResponse = {
    keys: JsonWebKey[];
};

// ─── Key Generation ───────────────────────────────────────────────────────────

export async function generateKeyPair(): Promise<{
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}> {
    const keypair = await crypto.subtle.generateKey(
        "Ed25519" as AlgorithmIdentifier,
        true,
        ["sign", "verify"]
    ) as CryptoKeyPair;
    return { publicKey: keypair.publicKey, privateKey: keypair.privateKey };
}

// ─── JWK Export / Import ──────────────────────────────────────────────────────

export async function exportPublicKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
    return crypto.subtle.exportKey("jwk", key);
}

export async function exportPrivateKeyJwk(key: CryptoKey): Promise<JsonWebKey> {
    return crypto.subtle.exportKey("jwk", key);
}

export async function importPublicKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x) {
        throw new Error("Invalid Ed25519 public JWK: must be OKP/Ed25519 with x field");
    }
    return crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["verify"]
    );
}

export async function importPrivateKeyJwk(jwk: JsonWebKey): Promise<CryptoKey> {
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x || !jwk.d) {
        throw new Error("Invalid Ed25519 private JWK: must be OKP/Ed25519 with x and d fields");
    }
    return crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["sign"]
    );
}

// ─── JWK Thumbprint (RFC 7638) ────────────────────────────────────────────────

/**
 * Compute the SHA-256 JWK thumbprint of an Ed25519 public key.
 * Canonical JSON: only crv, kty, x — sorted lexicographically.
 */
export function computeJwkThumbprint(jwk: JsonWebKey): string {
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.x) {
        throw new Error("Invalid Ed25519 JWK for thumbprint computation");
    }
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
    const hash = createHash("sha256").update(canonical).digest();
    return base64UrlEncode(hash);
}

// ─── JWT Construction ─────────────────────────────────────────────────────────

function encodeJwtPart(obj: object): string {
    return base64UrlEncode(Buffer.from(JSON.stringify(obj)));
}

/**
 * Sign a compact JWT using Ed25519.
 * The private key signs header.payload — signature covers both parts.
 */
export async function signJwt<T extends JwtPayload>(
    payload: T,
    privateKey: CryptoKey,
    typ: JwtTyp
): Promise<string> {
    const header: JwtHeader = { alg: "EdDSA", typ };
    const encodedHeader = encodeJwtPart(header);
    const encodedPayload = encodeJwtPart(payload);
    const signingInput = `${encodedHeader}.${encodedPayload}`;

    const sigBytes = await crypto.subtle.sign(
        "Ed25519" as AlgorithmIdentifier,
        privateKey,
        new TextEncoder().encode(signingInput) // Uint8Array — NOT Buffer
    );

    const sig = base64UrlEncode(new Uint8Array(sigBytes));
    return `${signingInput}.${sig}`;
}

// ─── JWT Decoding (without verification) ─────────────────────────────────────

function isJwtHeader(value: unknown): value is JwtHeader {
    if (!isObject(value)) return false;
    const typ = value["typ"];
    return value["alg"] === "EdDSA" && (typ === "agent+jwt" || typ === "host+jwt");
}

/**
 * Decode a JWT without verifying its signature.
 * Used to extract claims before key lookup. Never trust these claims for auth.
 */
export function decodeJwtUnsafe<T extends JwtPayload = JwtPayload>(
    token: string
): DecodedJwt<T> {
    const parts = token.split(".");
    if (parts.length !== 3) {
        throw new Error("Invalid JWT format: expected 3 dot-separated parts");
    }

    const [headerB64, payloadB64, signature] = parts as [string, string, string];

    const rawHeader = parseJson<unknown>(base64UrlDecode(headerB64).toString("utf8"));
    if (!isJwtHeader(rawHeader)) {
        throw new Error("Invalid JWT header: expected alg=EdDSA, typ=agent+jwt");
    }

    const rawPayload = parseJson<unknown>(base64UrlDecode(payloadB64).toString("utf8"));
    if (!isObject(rawPayload)) {
        throw new Error("Invalid JWT payload: not a JSON object");
    }

    return {
        header: rawHeader,
        payload: rawPayload as T,
        signingInput: `${headerB64}.${payloadB64}`,
        signature,
    };
}

// ─── JWT Verification ─────────────────────────────────────────────────────────

/**
 * Verify an Ed25519 JWT signature and confirm typ matches.
 * Does NOT check exp/iat/jti — TokenVerifier handles those.
 */
export async function verifyJwtSignature<T extends JwtPayload = JwtPayload>(
    token: string,
    publicKey: CryptoKey,
    opts: VerifyJwtOptions
): Promise<DecodedJwt<T>> {
    const decoded = decodeJwtUnsafe<T>(token);

    if (decoded.header.typ !== opts.expectedTyp) {
        throw new Error(`JWT typ mismatch: expected "${opts.expectedTyp}", got "${decoded.header.typ}"`);
    }
    if (decoded.header.alg !== "EdDSA") {
        throw new Error(`JWT alg mismatch: expected "EdDSA", got "${decoded.header.alg}"`);
    }

    const sigBytes = new Uint8Array(base64UrlDecode(decoded.signature));
    const inputBytes = new TextEncoder().encode(decoded.signingInput);

    const valid = await crypto.subtle.verify(
        "Ed25519" as AlgorithmIdentifier,
        publicKey,
        sigBytes,
        inputBytes // Uint8Array — NOT Buffer
    );

    if (!valid) {
        throw new Error("JWT signature verification failed: signature does not match");
    }

    return decoded;
}
