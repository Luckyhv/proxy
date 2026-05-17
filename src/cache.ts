import {
    MANIFEST_CACHE_TTL_SECONDS,
    PROXY_CACHE_MAX_BYTES,
    PROXY_CACHE_MAX_ENTRY_BYTES,
    SEGMENT_CACHE_TTL_SECONDS,
} from "./constants";

interface CacheEntry {
    body: ArrayBuffer;
    contentType: string;
    createdAt: number;
    expiresAt: number;
    headers: Record<string, string>;
    status: number;
}

interface RangeRequest {
    start: number;
    end: number;
}

const cache = new Map<string, CacheEntry>();
let cacheBytes = 0;
let hits = 0;
let misses = 0;
let bypasses = 0;
let coalesced = 0;
let prefetches = 0;
let prefetchHits = 0;
let prefetchFailures = 0;

const inflight = new Map<string, Promise<void>>();

function nowSeconds(): number {
    return Date.now() / 1000;
}

function byteLength(body: ArrayBuffer): number {
    return body.byteLength;
}

function touch(key: string, entry: CacheEntry): void {
    cache.delete(key);
    cache.set(key, entry);
}

function removeEntry(key: string, entry: CacheEntry): void {
    cache.delete(key);
    cacheBytes -= byteLength(entry.body);
}

function evictExpired(now = nowSeconds()): void {
    for (const [key, entry] of cache) {
        if (entry.expiresAt <= now) removeEntry(key, entry);
    }
}

function evictToBudget(): void {
    evictExpired();
    while (cacheBytes > PROXY_CACHE_MAX_BYTES) {
        const first = cache.entries().next().value as [string, CacheEntry] | undefined;
        if (!first) break;
        removeEntry(first[0], first[1]);
    }
}

function parseRange(rangeHeader: string | null, size: number): RangeRequest | null {
    if (!rangeHeader?.startsWith("bytes=")) return null;

    const [rawStart, rawEnd] = rangeHeader.slice(6).split("-", 2);
    if (rawStart === "" && rawEnd === "") return null;

    let start: number;
    let end: number;

    if (rawStart === "") {
        const suffixLength = Number(rawEnd);
        if (!Number.isInteger(suffixLength) || suffixLength <= 0) return null;
        start = Math.max(size - suffixLength, 0);
        end = size - 1;
    } else {
        start = Number(rawStart);
        end = rawEnd === "" ? size - 1 : Number(rawEnd);
        if (!Number.isInteger(start) || !Number.isInteger(end)) return null;
    }

    if (start < 0 || end < start || start >= size) return null;
    return { start, end: Math.min(end, size - 1) };
}

export function buildCacheKey(method: string, url: URL): string {
    return `${method.toUpperCase()}:${url.href}`;
}

export function getCachedResponse(key: string, rangeHeader: string | null, method: string): Response | null {
    const entry = cache.get(key);
    if (!entry) {
        misses++;
        return null;
    }

    const now = nowSeconds();
    if (entry.expiresAt <= now) {
        removeEntry(key, entry);
        misses++;
        return null;
    }

    hits++;
    touch(key, entry);

    const headers = new Headers(entry.headers);
    headers.set("Age", String(Math.max(0, Math.floor(now - entry.createdAt))));
    headers.set("X-Proxy-Cache", "HIT");
    headers.set("Accept-Ranges", "bytes");

    if (method === "HEAD") {
        headers.set("Content-Length", String(entry.body.byteLength));
        return new Response(null, { status: entry.status, headers });
    }

    const range = parseRange(rangeHeader, entry.body.byteLength);
    if (range) {
        const body = entry.body.slice(range.start, range.end + 1);
        headers.set("Content-Length", String(body.byteLength));
        headers.set("Content-Range", `bytes ${range.start}-${range.end}/${entry.body.byteLength}`);
        return new Response(body, { status: 206, headers });
    }

    headers.set("Content-Length", String(entry.body.byteLength));
    return new Response(entry.body.slice(0), { status: entry.status, headers });
}

export function hasFreshCache(key: string): boolean {
    const entry = cache.get(key);
    if (!entry) return false;

    const now = nowSeconds();
    if (entry.expiresAt <= now) {
        removeEntry(key, entry);
        return false;
    }

    touch(key, entry);
    return true;
}

export async function waitForInflightCache(key: string): Promise<boolean> {
    const pending = inflight.get(key);
    if (!pending) return false;

    coalesced++;
    try {
        await pending;
    } catch {
        // The caller will do its own fetch path after a failed coalesced request.
    }
    return true;
}

export function trackInflightCache(key: string, task: Promise<void>): void {
    if (inflight.has(key)) return;
    inflight.set(key, task.finally(() => inflight.delete(key)));
}

export function putCachedResponse(
    key: string,
    body: ArrayBuffer,
    headers: Record<string, string>,
    status: number,
    kind: "manifest" | "segment",
): void {
    if (PROXY_CACHE_MAX_BYTES === 0 || body.byteLength === 0 || body.byteLength > PROXY_CACHE_MAX_ENTRY_BYTES) {
        bypasses++;
        return;
    }

    const previous = cache.get(key);
    if (previous) removeEntry(key, previous);

    const ttl = kind === "manifest" ? MANIFEST_CACHE_TTL_SECONDS : SEGMENT_CACHE_TTL_SECONDS;
    const now = nowSeconds();
    const entry: CacheEntry = {
        body,
        contentType: headers["Content-Type"] ?? headers["content-type"] ?? "",
        createdAt: now,
        expiresAt: now + ttl,
        headers,
        status,
    };

    cache.set(key, entry);
    cacheBytes += byteLength(body);
    evictToBudget();
}

export function noteCacheBypass(): void {
    bypasses++;
}

export function notePrefetch(result: "queued" | "hit" | "failed"): void {
    if (result === "queued") prefetches++;
    if (result === "hit") prefetchHits++;
    if (result === "failed") prefetchFailures++;
}

export function getCacheStats() {
    evictExpired();
    const total = hits + misses;
    return {
        bytes: cacheBytes,
        entries: cache.size,
        maxBytes: PROXY_CACHE_MAX_BYTES,
        maxEntryBytes: PROXY_CACHE_MAX_ENTRY_BYTES,
        hits,
        misses,
        bypasses,
        coalesced,
        inflight: inflight.size,
        prefetches,
        prefetchHits,
        prefetchFailures,
        hitRate: total === 0 ? 0 : hits / total,
    };
}
