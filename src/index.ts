import { Hono } from 'hono'
import { cors } from "hono/cors";
import { logger } from 'hono/logger'

import {
  buildCacheKey,
  getCachedResponse,
  getCacheStats,
  hasFreshCache,
  noteCacheBypass,
  notePrefetch,
  putCachedResponse,
  trackInflightCache,
  waitForInflightCache,
} from "./cache";
import {
  ALLOWED_ORIGINS,
  BLACKLIST_HEADERS,
  FETCH_TIMEOUT_MS,
  HLS_PREFETCH_CONCURRENCY,
  HLS_PREFETCH_ENABLED,
  HLS_PREFETCH_LIMIT,
  MANIFEST_CACHE_CONTROL,
  MEDIA_CACHE_CONTROL,
  MAX_CONCURRENT_UPSTREAM,
  MAX_MANIFEST_BYTES,
  MAX_POST_BODY_BYTES,
  PROXY_CACHE_MAX_ENTRY_BYTES,
} from "./constants";
import { generateHeadersOriginal } from "./headers";
import { extractM3u8Urls, processM3u8Line, resolveUrl, buildProxyPath } from "./processor";
import { validateTargetUrl } from "./security";

// ─── URL Encryption (XOR + base64url) ────────────────────────────────────────

const XOR_KEY = process.env.XOR_KEY ?? "";
const XOR_KEY_BYTES = new TextEncoder().encode(XOR_KEY);
const SAFE_EXTRA_HEADERS = new Set([
  "accept",
  "accept-language",
  "authorization",
  "cache-control",
  "pragma",
  "user-agent",
  "x-requested-with",
]);
const MEDIA_EXTENSIONS = new Set(["ts", "mp4", "m4s", "aac", "vtt", "webm", "m4v", "mov", "m4a", "mp3", "ogg", "opus", "srt", "ass", "bin", "key"]);
const WARMABLE_EXTENSIONS = new Set([...MEDIA_EXTENSIONS, "m3u8"]);

let activeUpstreamRequests = 0;
let activePrefetches = 0;
const prefetchQueue: URL[] = [];
const queuedPrefetches = new Set<string>();

async function acquireUpstreamSlot(): Promise<() => void> {
  while (activeUpstreamRequests >= MAX_CONCURRENT_UPSTREAM) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  activeUpstreamRequests++;
  return () => {
    activeUpstreamRequests = Math.max(0, activeUpstreamRequests - 1);
  };
}

function releaseOnce(release: () => void): () => void {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    release();
  };
}

function streamWithRelease(stream: ReadableStream<Uint8Array> | null, release: () => void): ReadableStream<Uint8Array> | null {
  if (!stream) {
    release();
    return null;
  }

  const reader = stream.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          release();
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (error) {
        release();
        controller.error(error);
      }
    },
    async cancel(reason) {
      release();
      await reader.cancel(reason);
    },
  });
}

function createDeferred(): { promise: Promise<void>; resolve: () => void; reject: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve, reject: resolve };
}

function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const raw = atob(padded);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decryptUrl(encrypted: string): string | null {
  try {
    const bytes = base64UrlToBytes(encrypted);
    if (XOR_KEY_BYTES.length > 0) {
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = bytes[i] ^ XOR_KEY_BYTES[i % XOR_KEY_BYTES.length];
      }
    }
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

export function encryptUrl(url: string): string {
  const result = new TextEncoder().encode(url);
  if (XOR_KEY_BYTES.length === 0) return bytesToBase64Url(result);

  for (let i = 0; i < result.length; i++) {
    result[i] = result[i] ^ XOR_KEY_BYTES[i % XOR_KEY_BYTES.length];
  }
  return bytesToBase64Url(result);
}

const trustedOrigins: string[] = Array.from(ALLOWED_ORIGINS);


const app = new Hono()

app.use(logger())

app.use(
  cors({
    origin: trustedOrigins.length === 0 ? "*" : trustedOrigins,
    allowHeaders: [
      "Content-Type", "Authorization", "Range", "X-Requested-With",
      "Origin", "Referer", "Accept", "Accept-Encoding", "Accept-Language",
      "Cache-Control", "Pragma", "Sec-Fetch-Dest", "Sec-Fetch-Mode",
      "Sec-Fetch-Site", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
      "Connection",
    ],
    allowMethods: ["GET", "POST", "OPTIONS", "HEAD"],
    exposeHeaders: [
      "Content-Length", "Content-Range", "Accept-Ranges", "Content-Type",
      "Cache-Control", "Expires", "Vary", "ETag", "Last-Modified",
      "Age", "X-Proxy-Cache",
    ],
    maxAge: 86400,
    credentials: trustedOrigins.length > 0,
  })
);

app.get("/", (c) => c.json({ status: "Online" }));
app.get("/api/info", (c) => c.json({
  status: "Online",
  cache: getCacheStats(),
  limits: {
    maxConcurrentUpstream: MAX_CONCURRENT_UPSTREAM,
    maxManifestBytes: MAX_MANIFEST_BYTES,
    maxPostBodyBytes: MAX_POST_BODY_BYTES,
    maxCacheEntryBytes: PROXY_CACHE_MAX_ENTRY_BYTES,
    hlsPrefetchEnabled: HLS_PREFETCH_ENABLED,
    hlsPrefetchConcurrency: HLS_PREFETCH_CONCURRENCY,
    hlsPrefetchLimit: HLS_PREFETCH_LIMIT,
  },
}));

app.get("/api/metrics", (c) => {
  const stats = getCacheStats();
  return c.text([
    `proxy_cache_bytes ${stats.bytes}`,
    `proxy_cache_max_bytes ${stats.maxBytes}`,
    `proxy_cache_entries ${stats.entries}`,
    `proxy_cache_hits_total ${stats.hits}`,
    `proxy_cache_misses_total ${stats.misses}`,
    `proxy_cache_bypasses_total ${stats.bypasses}`,
    `proxy_cache_coalesced_total ${stats.coalesced}`,
    `proxy_cache_inflight ${stats.inflight}`,
    `proxy_prefetch_queued_total ${stats.prefetches}`,
    `proxy_prefetch_hits_total ${stats.prefetchHits}`,
    `proxy_prefetch_failures_total ${stats.prefetchFailures}`,
    `proxy_prefetch_active ${activePrefetches}`,
    `proxy_prefetch_queue ${prefetchQueue.length}`,
    `proxy_cache_hit_rate ${stats.hitRate}`,
    `proxy_active_upstream_requests ${activeUpstreamRequests}`,
  ].join("\n") + "\n");
});

function getExtension(url: URL): string {
  const dotIdx = url.pathname.lastIndexOf(".");
  return dotIdx === -1 ? "" : url.pathname.slice(dotIdx + 1).toLowerCase();
}

function isMediaSegment(url: URL): boolean {
  return MEDIA_EXTENSIONS.has(getExtension(url));
}

function isWarmableHlsAsset(url: URL): boolean {
  const ext = getExtension(url);
  return WARMABLE_EXTENSIONS.has(ext) || url.pathname.toLowerCase().endsWith(".m3u8");
}

function isM3u8Response(url: URL, response: Response): boolean {
  const contentType = response.headers.get("content-type") ?? "";
  return contentType.includes("mpegurl") || url.pathname.toLowerCase().endsWith(".m3u8");
}

function filteredResponseHeaders(upstream: Response): Record<string, string> {
  const responseHeaders: Record<string, string> = {};
  for (const [name, value] of upstream.headers.entries()) {
    if (!BLACKLIST_HEADERS.has(name.toLowerCase())) responseHeaders[name] = value;
  }
  return responseHeaders;
}

function setResponseHeader(headers: Record<string, string>, name: string, value: string): void {
  const lowerName = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lowerName) delete headers[key];
  }
  headers[name] = value;
}

function applyExtraHeaders(raw: string | undefined, upstreamHeaders: Record<string, string>): void {
  if (!raw) return;
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;

    for (const [k, v] of Object.entries(parsed)) {
      const key = k.toLowerCase();
      if (!SAFE_EXTRA_HEADERS.has(key)) continue;
      upstreamHeaders[key] = String(v);
    }
  } catch {
    // Invalid optional header JSON should not break playback.
  }
}

function readContentLength(headers: Headers): number | null {
  const raw = headers.get("content-length");
  if (!raw) return null;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

async function readLimitedArrayBuffer(response: Response, maxBytes: number): Promise<ArrayBuffer | null> {
  const contentLength = readContentLength(response.headers);
  if (contentLength !== null && contentLength > maxBytes) {
    await response.body?.cancel();
    return null;
  }
  if (!response.body) return new ArrayBuffer(0);

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }

  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out.buffer;
}

function rewriteManifest(textBody: string, targetUrl: URL): string {
  let rewritten = "";
  let start = 0;
  const len = textBody.length;
  while (start < len) {
    let end = textBody.indexOf("\n", start);
    if (end === -1) end = len;
    const lineEnd = end > start && textBody[end - 1] === "\r" ? end - 1 : end;
    if (rewritten.length > 0) rewritten += "\n";
    rewritten += processM3u8Line(textBody.slice(start, lineEnd), targetUrl, encryptUrl);
    start = end + 1;
  }
  return rewritten;
}

async function fetchAndCacheResource(targetUrl: URL, kind: "manifest" | "segment"): Promise<void> {
  const cacheKey = buildCacheKey("GET", targetUrl);
  if (hasFreshCache(cacheKey)) return;

  const validationError = await validateTargetUrl(targetUrl);
  if (validationError) {
    notePrefetch("failed");
    return;
  }

  const upstreamHeaders = generateHeadersOriginal(targetUrl);
  let releaseSlot: (() => void) | null = null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    releaseSlot = releaseOnce(await acquireUpstreamSlot());
    const upstream = await fetch(targetUrl.href, {
      method: "GET",
      headers: upstreamHeaders,
      redirect: "manual",
      // @ts-ignore
      tls: { rejectUnauthorized: false },
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (upstream.status < 200 || upstream.status >= 300) {
      releaseSlot();
      await upstream.body?.cancel();
      notePrefetch("failed");
      return;
    }

    const responseHeaders = filteredResponseHeaders(upstream);
    if (isM3u8Response(targetUrl, upstream)) {
      const manifestBytes = await readLimitedArrayBuffer(upstream, MAX_MANIFEST_BYTES);
      releaseSlot();
      if (!manifestBytes) {
        notePrefetch("failed");
        return;
      }

      const textBody = new TextDecoder().decode(manifestBytes);
      if (!textBody.trimStart().startsWith("#EXTM3U")) {
        notePrefetch("failed");
        return;
      }

      const rewritten = rewriteManifest(textBody, targetUrl);
      const headers = { ...responseHeaders };
      setResponseHeader(headers, "Content-Type", "application/vnd.apple.mpegurl");
      setResponseHeader(headers, "Cache-Control", MANIFEST_CACHE_CONTROL);
      setResponseHeader(headers, "X-Proxy-Cache", "PREFETCH");
      const bodyBytes = new TextEncoder().encode(rewritten).buffer;
      putCachedResponse(cacheKey, bodyBytes.slice(0), headers, upstream.status, "manifest");
      enqueuePrefetch(extractM3u8Urls(textBody, targetUrl));
      return;
    }

    if (kind === "segment" || isMediaSegment(targetUrl)) {
      const bodyBytes = await readLimitedArrayBuffer(upstream, PROXY_CACHE_MAX_ENTRY_BYTES);
      releaseSlot();
      if (!bodyBytes) {
        notePrefetch("failed");
        return;
      }

      setResponseHeader(responseHeaders, "Cache-Control", MEDIA_CACHE_CONTROL);
      setResponseHeader(responseHeaders, "Accept-Ranges", "bytes");
      setResponseHeader(responseHeaders, "X-Proxy-Cache", "PREFETCH");
      setResponseHeader(responseHeaders, "Content-Length", String(bodyBytes.byteLength));
      putCachedResponse(cacheKey, bodyBytes.slice(0), responseHeaders, upstream.status, "segment");
      return;
    }

    releaseSlot();
    await upstream.body?.cancel();
  } catch {
    clearTimeout(timeout);
    releaseSlot?.();
    notePrefetch("failed");
  }
}

function drainPrefetchQueue(): void {
  if (!HLS_PREFETCH_ENABLED) return;

  while (activePrefetches < HLS_PREFETCH_CONCURRENCY && prefetchQueue.length > 0) {
    const next = prefetchQueue.shift();
    if (!next) break;
    queuedPrefetches.delete(next.href);

    const cacheKey = buildCacheKey("GET", next);
    if (hasFreshCache(cacheKey)) {
      notePrefetch("hit");
      continue;
    }

    const kind = next.pathname.toLowerCase().endsWith(".m3u8") ? "manifest" : "segment";
    activePrefetches++;
    const task = fetchAndCacheResource(next, kind).finally(() => {
      activePrefetches = Math.max(0, activePrefetches - 1);
      drainPrefetchQueue();
    });
    trackInflightCache(cacheKey, task);
  }
}

function enqueuePrefetch(urls: URL[]): void {
  if (!HLS_PREFETCH_ENABLED || HLS_PREFETCH_LIMIT === 0) return;

  let added = 0;
  for (const url of urls) {
    if (added >= HLS_PREFETCH_LIMIT) break;
    if (!isWarmableHlsAsset(url)) continue;

    const cacheKey = buildCacheKey("GET", url);
    if (hasFreshCache(cacheKey)) {
      notePrefetch("hit");
      continue;
    }
    if (queuedPrefetches.has(url.href)) continue;

    queuedPrefetches.add(url.href);
    prefetchQueue.push(url);
    notePrefetch("queued");
    added++;
  }

  drainPrefetchQueue();
}


// ─── Proxy ───────────────────────────────────────────────────────────────────
app.on(["GET", "POST", "HEAD"], "/proxy/:encrypted", async (c) => {
  const method = c.req.method;

  const targetUrlRaw = decryptUrl(c.req.param("encrypted"));
  if (!targetUrlRaw) return c.text("Invalid encrypted URL", 400);

  let targetUrl: URL;
  try { targetUrl = new URL(targetUrlRaw); } catch { return c.text(`Invalid URL: ${targetUrlRaw}`, 400); }

  const validationError = await validateTargetUrl(targetUrl);
  if (validationError) return c.text(validationError, 403);

  const upstreamHeaders = generateHeadersOriginal(targetUrl);

  // Forward standard headers
  const clientHeaders = c.req.raw.headers;
  const rangeVal = clientHeaders.get("range");
  if (rangeVal) upstreamHeaders["range"] = rangeVal;
  const ifRangeVal = clientHeaders.get("if-range");
  if (ifRangeVal) upstreamHeaders["if-range"] = ifRangeVal;
  const ifNoneMatchVal = clientHeaders.get("if-none-match");
  if (ifNoneMatchVal) upstreamHeaders["if-none-match"] = ifNoneMatchVal;
  const ifModifiedVal = clientHeaders.get("if-modified-since");
  if (ifModifiedVal) upstreamHeaders["if-modified-since"] = ifModifiedVal;

  applyExtraHeaders(c.req.query("headers"), upstreamHeaders);

  const cacheKey = buildCacheKey("GET", targetUrl);
  if (method === "GET" || method === "HEAD") {
    const cached = getCachedResponse(cacheKey, rangeVal, method);
    if (cached) return cached;
    if (await waitForInflightCache(cacheKey)) {
      const coalescedCached = getCachedResponse(cacheKey, rangeVal, method);
      if (coalescedCached) return coalescedCached;
    }
  }

  const requestCacheFill = method === "GET" && !rangeVal && isWarmableHlsAsset(targetUrl) ? createDeferred() : null;
  if (requestCacheFill) trackInflightCache(cacheKey, requestCacheFill.promise);

  let body: ArrayBuffer | null = null;
  if (method === "POST") {
    const contentLength = readContentLength(clientHeaders);
    if (contentLength !== null && contentLength > MAX_POST_BODY_BYTES) {
      return c.text("Request body too large", 413);
    }
    const ctVal = clientHeaders.get("content-type");
    if (ctVal) upstreamHeaders["content-type"] = ctVal;
    body = await c.req.arrayBuffer();
    if (body.byteLength > MAX_POST_BODY_BYTES) {
      return c.text("Request body too large", 413);
    }
  }

  let upstream: Response;
  let releaseSlot: (() => void) | null = null;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    releaseSlot = releaseOnce(await acquireUpstreamSlot());

    upstream = await fetch(targetUrl.href, {
      method,
      headers: upstreamHeaders,
      body,
      redirect: "manual",
      // @ts-ignore
      tls: { rejectUnauthorized: false },
      signal: controller.signal,
    });
    clearTimeout(timeout);
  } catch (err) {
    clearTimeout(timeout);
    releaseSlot?.();
    requestCacheFill?.reject();
    const errorMsg = err instanceof Error ? err.message : String(err);
    return c.text(`Target Fetch Failed: ${errorMsg}`, 502);
  }

  // Handle 3xx Redirects
  if (upstream.status >= 300 && upstream.status < 400) {
    const location = upstream.headers.get("location");
    if (location) {
      const resolvedLocation = resolveUrl(location, targetUrl);
      releaseSlot?.();
      requestCacheFill?.reject();
      return c.redirect(buildProxyPath(resolvedLocation, encryptUrl), upstream.status as any);
    }
  }

  const segment = isMediaSegment(targetUrl);
  const responseHeaders = filteredResponseHeaders(upstream);

  if (segment) {
    setResponseHeader(responseHeaders, "Cache-Control", MEDIA_CACHE_CONTROL);
    setResponseHeader(responseHeaders, "Accept-Ranges", "bytes");
  }

  if (isM3u8Response(targetUrl, upstream)) {
    const deferred = upstream.status === 200 ? requestCacheFill : null;
    try {
      const manifestBytes = await readLimitedArrayBuffer(upstream, MAX_MANIFEST_BYTES);
      releaseSlot?.();
      if (!manifestBytes) {
        noteCacheBypass();
        deferred?.reject();
        return c.text("Manifest too large", 413);
      }

      const textBody = new TextDecoder().decode(manifestBytes);
      if (!textBody) {
        deferred?.reject();
        return new Response(null, { status: upstream.status, headers: responseHeaders });
      }

      if (textBody.trimStart().startsWith("#EXTM3U")) {
        const rewritten = rewriteManifest(textBody, targetUrl);
        const headers = { ...responseHeaders };
        setResponseHeader(headers, "Content-Type", "application/vnd.apple.mpegurl");
        setResponseHeader(headers, "Cache-Control", MANIFEST_CACHE_CONTROL);
        setResponseHeader(headers, "X-Proxy-Cache", "MISS");
        const bodyBytes = new TextEncoder().encode(rewritten).buffer;
        if (upstream.status === 200 && method === "GET") {
          putCachedResponse(cacheKey, bodyBytes.slice(0), headers, upstream.status, "manifest");
          enqueuePrefetch(extractM3u8Urls(textBody, targetUrl));
          deferred?.resolve();
        }
        return new Response(method === "HEAD" ? null : bodyBytes, { status: upstream.status, headers });
      }
      deferred?.reject();
      return new Response(method === "HEAD" ? null : textBody, { status: upstream.status, headers: responseHeaders });
    } catch {
      releaseSlot?.();
      deferred?.reject();
      return c.text("Manifest processing error", 500);
    }
  }

  if (segment && method === "GET" && !rangeVal && upstream.status === 200) {
    const contentLength = readContentLength(upstream.headers);
    if (contentLength === null || contentLength <= PROXY_CACHE_MAX_ENTRY_BYTES) {
      const deferred = requestCacheFill;
      const bodyBytes = await readLimitedArrayBuffer(upstream, PROXY_CACHE_MAX_ENTRY_BYTES);
      releaseSlot?.();
      if (bodyBytes) {
        const headers = { ...responseHeaders };
        setResponseHeader(headers, "X-Proxy-Cache", "MISS");
        setResponseHeader(headers, "Content-Length", String(bodyBytes.byteLength));
        putCachedResponse(cacheKey, bodyBytes.slice(0), headers, upstream.status, "segment");
        deferred?.resolve();
        return new Response(bodyBytes, { status: upstream.status, headers });
      }
      noteCacheBypass();
      deferred?.reject();
      return c.text("Media segment too large", 413);
    }
    noteCacheBypass();
  }

  setResponseHeader(responseHeaders, "X-Proxy-Cache", "BYPASS");
  requestCacheFill?.reject();
  if (method === "HEAD") releaseSlot?.();
  const bodyStream = method === "HEAD" ? null : streamWithRelease(upstream.body, releaseSlot ?? (() => undefined));
  return new Response(bodyStream, { status: upstream.status, headers: responseHeaders });
});


export default {
  port: process.env.PORT || 3847,
  fetch: app.fetch,
}
