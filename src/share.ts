import { deflateRawSync, inflateRawSync } from "node:zlib";
import type { Engine } from "@culpritsql/plans";

export type ShareStudioMode = "plan" | "compare" | "deadlock";

/**
 * Exact SharePayloadV1 wire contract consumed by https://explain.culpritsql.com/#s=z1.<deflate-raw-base64url>.
 */
export interface SharePayloadV1 {
  v: 1;
  m: ShareStudioMode;
  t?: string;
  e?: Engine;
  q?: string;
  p?: string;
  na?: string;
  pa?: string;
  nb?: string;
  pb?: string;
  d?: string;
}

export const MAX_SHARE_HASH_CHARS = 28_000;
export const DEFAULT_EXPLAIN_BASE_URL = "https://explain.culpritsql.com/";

export function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

export function fromBase64Url(encoded: string): Uint8Array {
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((encoded.length + 3) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

/**
 * Scrub SQL string and numeric literals for non-XML text payloads when sharing redacted links.
 * Matches explain.culpritsql.com's exact literal scrubber.
 */
export function scrubSqlLiterals(text: string): string {
  return text
    .replace(/'(?:''|[^'])*'/g, "'?'")
    .replace(/\b\d+(?:\.\d+)?\b/g, (num) => (num === "0" || num === "1" ? num : "?"));
}

/**
 * Encodes a SharePayloadV1 using RFC 1951 raw deflate (`z1.<base64url>`) compatible with
 * Web CompressionStream/DecompressionStream("deflate-raw") in explain.culpritsql.com.
 */
export function encodeShareHash(
  payload: SharePayloadV1,
): { ok: true; hash: string } | { ok: false; reason: "too_large" } {
  const json = JSON.stringify(payload);
  const rawBytes = Buffer.from(json, "utf8");
  const compressed = deflateRawSync(rawBytes, { level: 9 });
  const encoded = `z1.${toBase64Url(compressed)}`;
  if (encoded.length > MAX_SHARE_HASH_CHARS) {
    return { ok: false, reason: "too_large" };
  }
  return { ok: true, hash: `#s=${encoded}` };
}

/**
 * Decodes a `#s=z1.<base64url>` or `#s=u1.<base64url>` hash fragment or full URL back to SharePayloadV1.
 */
export function decodeShareHash(hashOrUrl: string): SharePayloadV1 | null {
  const hashIndex = hashOrUrl.indexOf("#");
  const fragment = hashIndex >= 0 ? hashOrUrl.slice(hashIndex + 1) : hashOrUrl.replace(/^#/, "");
  const params = new URLSearchParams(fragment);
  const token = params.get("s");
  if (!token) return null;
  try {
    let bytes: Uint8Array;
    if (token.startsWith("z1.")) {
      bytes = new Uint8Array(inflateRawSync(fromBase64Url(token.slice(3))));
    } else if (token.startsWith("u1.")) {
      bytes = fromBase64Url(token.slice(3));
    } else {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(bytes).toString("utf8")) as SharePayloadV1;
    if (parsed?.v !== 1 || !parsed.m) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function buildExplainShareUrl(
  payload: SharePayloadV1,
  baseUrl: string = DEFAULT_EXPLAIN_BASE_URL,
): string | null {
  const res = encodeShareHash(payload);
  if (!res.ok) return null;
  const normalizedBase = baseUrl.endsWith("/") ? baseUrl : `${baseUrl}/`;
  const fullUrl = `${normalizedBase}${res.hash}`;
  if (fullUrl.length > MAX_SHARE_HASH_CHARS) {
    return null;
  }
  return fullUrl;
}
