import { Hono } from 'hono'
import { cors } from "hono/cors";
import { logger } from 'hono/logger'
import type { ContentfulStatusCode } from "hono/utils/http-status";

import {
  ALLOWED_ORIGINS,
  BLACKLIST_HEADERS,
  UPSTREAM_PROXY,
  shouldProxyUpstream,
} from "./constants";
import { generateHeadersOriginal } from "./headers";
import { processM3u8Line, resolveUrl, buildProxyPath } from "./processor";

// ─── URL Encryption (XOR + base64url) ────────────────────────────────────────

const SECRET_KEY = process.env.SECRET_KEY || "aproxy2026";
function xorWithSecret(data: Uint8Array, secret: string): void {
  if (!secret || secret.length === 0) return;
  for (let i = 0; i < data.length; i++) {
    data[i] ^= secret.charCodeAt(i % secret.length);
  }
}

function decryptUrl(encrypted: string): string | null {
  try {
    const data = new Uint8Array(Buffer.from(encrypted, "base64url"));
    xorWithSecret(data, SECRET_KEY);

    let nullIdx = -1;
    for (let i = 0; i < data.length; i++) {
      if (data[i] === 0x00) { nullIdx = i; break; }
    }

    const targetURL =
      nullIdx === -1
        ? new TextDecoder().decode(data)
        : new TextDecoder().decode(data.subarray(0, nullIdx));
    return targetURL;
  } catch {
    return null;
  }
}

export function encryptUrl(url: string, referer = ""): string {
  const target = new TextEncoder().encode(url);
  const ref = new TextEncoder().encode(referer);
  const payload = new Uint8Array(target.length + 1 + ref.length);
  payload.set(target, 0);
  payload[target.length] = 0x00;
  payload.set(ref, target.length + 1);

  xorWithSecret(payload, SECRET_KEY);
  return Buffer.from(payload).toString("base64url");
}

const trustedOrigins = Array.from(ALLOWED_ORIGINS);


const app = new Hono()

if (process.env.LOG_REQUESTS === "1") {
  app.use(logger())
}

// CORS is intentionally wildcard with NO credentials. A media proxy never needs
// cookies, and `credentials: true` forces Hono to (a) reflect the specific
// request Origin instead of "*" and (b) emit `Vary: Origin` — both of which
// fragment/poison Cloudflare's edge cache so every viewer/origin misses. A flat
// "*" with no Vary is what lets one cached segment be shared by everyone (this
// is exactly what the fast rival proxy does).
app.use(
  cors({
    origin: "*",
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
      "Cache-Control", "Expires", "ETag", "Last-Modified",
    ],
    maxAge: 86400,
  })
);

app.get("/", (c) => c.json({ status: "Online" }));


// ─── Proxy ───────────────────────────────────────────────────────────────────
app.on(["GET", "POST", "HEAD"], ["/stream/:encrypted", "/m3u8/:encrypted", "/hls/:encrypted"], async (c) => {
  const method = c.req.method;
  const isM3u8Route = c.req.path.startsWith("/m3u8/");
  const isHlsRoute = c.req.path.startsWith("/hls/");

  const targetUrlRaw = decryptUrl(c.req.param("encrypted"));
  if (!targetUrlRaw) return c.text("Invalid encrypted URL", 400);

  let targetUrl: URL;
  try { targetUrl = new URL(targetUrlRaw); } catch { return c.text(`Invalid URL: ${targetUrlRaw}`, 400); }

  const pathname = targetUrl.pathname;
  const upstreamHeaders = generateHeadersOriginal(targetUrl);
  const originParam = c.req.query("origin");
  if (originParam) {
    upstreamHeaders["origin"] = originParam;
    upstreamHeaders["referer"] = originParam.endsWith("/") ? originParam : `${originParam}/`;
  }

  // Forward standard headers
  const clientHeaders = c.req.raw.headers;
  const rangeVal = clientHeaders.get("range");
  if (rangeVal) {
    delete upstreamHeaders["range"];
    delete upstreamHeaders["accept-encoding"];
    upstreamHeaders["Range"] = rangeVal;
    upstreamHeaders["Accept-Encoding"] = "identity";
  }
  const ifRangeVal = clientHeaders.get("if-range");
  if (ifRangeVal) upstreamHeaders["if-range"] = ifRangeVal;
  const ifNoneMatchVal = clientHeaders.get("if-none-match");
  if (ifNoneMatchVal) upstreamHeaders["if-none-match"] = ifNoneMatchVal;
  const ifModifiedVal = clientHeaders.get("if-modified-since");
  if (ifModifiedVal) upstreamHeaders["if-modified-since"] = ifModifiedVal;

  const headersParam = c.req.query("headers");
  if (headersParam) {
    try {
      const parsed = JSON.parse(headersParam);
      for (const [k, v] of Object.entries(parsed)) {
        const key = k.toLowerCase();
        if (key === "origin" || key === "referer") continue;
        upstreamHeaders[key] = String(v);
      }
    } catch { /* ignore */ }
  }

  let body: any = null;
  if (method === "POST") {
    const ctVal = clientHeaders.get("content-type");
    if (ctVal) upstreamHeaders["content-type"] = ctVal;
    body = await c.req.arrayBuffer();
  }

  // One controller for the whole request lifecycle: it aborts on the connect
  // timeout AND when the client disconnects. Without the client-disconnect
  // wiring, abandoned downloads (seeks, quality switches, closed tabs — the
  // dominant pattern for a video proxy) keep the upstream socket and its
  // in-flight buffers alive until the remote times out, leaking RAM until OOM.
  const controller = new AbortController();
  const clientSignal = c.req.raw.signal;
  if (clientSignal) {
    if (clientSignal.aborted) controller.abort();
    else clientSignal.addEventListener("abort", () => controller.abort(), { once: true });
  }

  let upstream: Response;
  try {
    const timeout = setTimeout(() => controller.abort(), 15000);

    const fetchInit: any = {
      method,
      headers: upstreamHeaders,
      body,
      redirect: "manual",
      tls: { rejectUnauthorized: false },
      signal: controller.signal,
    };
    // Route through a clean egress proxy for hosts that block our datacenter IP.
    if (shouldProxyUpstream(targetUrl.hostname)) {
      fetchInit.proxy = UPSTREAM_PROXY;
    }

    upstream = await fetch(targetUrl.href, fetchInit);
    clearTimeout(timeout);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    return c.text(`Target Fetch Failed: ${errorMsg}`, 502);
  }

  // Handle 3xx Redirects
  if (upstream.status >= 300 && upstream.status < 400) {
    const location = upstream.headers.get("location");
    if (location) {
      const resolvedLocation = resolveUrl(location, targetUrl);
      const routePrefix = isM3u8Route ? "/m3u8/" : isHlsRoute ? "/hls/" : "/stream/";
      return c.redirect(buildProxyPath(resolvedLocation, encryptUrl, routePrefix), upstream.status as any);
    }
  }

  const responseHeaders: Record<string, string> = {};
  for (const [name, value] of upstream.headers.entries()) {
    if (!BLACKLIST_HEADERS.has(name)) { responseHeaders[name] = value; }
  }

  const contentType = upstream.headers.get("content-type") ?? "";
  const isM3u8 = isM3u8Route || contentType.includes("mpegurl") || pathname.endsWith(".m3u8") || pathname.endsWith(".M3U8");
  if (!isM3u8) {
    const contentLength = upstream.headers.get("content-length");
    if (contentLength) responseHeaders["Content-Length"] = contentLength;
  }
  const lowerPathname = pathname.toLowerCase();
  const isCacheableAsset = /\.(?:ts|m4s|mp4|m4v|mov|webm|m4a|mp3|aac|vtt|jpg|jpeg|png|webp|gif|css|js|html?)$/i.test(lowerPathname);

  // Only success bodies are real content. 200 = full asset, 206 = a byte-range
  // (mp4 seeking) — both safe to cache. Anything else (403/404/5xx, often just a
  // transient upstream blip) must NEVER get a long cache header, or Cloudflare
  // would pin the failure at the edge for a year and break that episode.
  const isCacheableStatus = upstream.status === 200 || upstream.status === 206;

  if (!isCacheableStatus) {
    responseHeaders["Cache-Control"] = "no-store";
    responseHeaders["CDN-Cache-Control"] = "no-store";
    responseHeaders["Cloudflare-CDN-Cache-Control"] = "no-store";
  } else if (isHlsRoute || isCacheableAsset) {
    responseHeaders["Cache-Control"] = "public, max-age=31536000, s-maxage=31536000, immutable";
    responseHeaders["CDN-Cache-Control"] = "public, max-age=31536000, s-maxage=31536000, immutable";
    responseHeaders["Cloudflare-CDN-Cache-Control"] = "public, max-age=31536000, s-maxage=31536000, immutable";
  }

  if (isM3u8) {
    try {
      const textBody = await upstream.text();
      if (!textBody) {
        return c.body(null, upstream.status as ContentfulStatusCode, responseHeaders);
      }

      if (textBody.trimStart().startsWith("#EXTM3U")) {
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

        const manifestCache = isCacheableStatus
          ? {
              "Cache-Control": "public, max-age=300, s-maxage=14400",
              "CDN-Cache-Control": "public, max-age=14400",
              "Cloudflare-CDN-Cache-Control": "public, max-age=14400",
            }
          : {
              "Cache-Control": "no-store",
              "CDN-Cache-Control": "no-store",
              "Cloudflare-CDN-Cache-Control": "no-store",
            };
        return c.body(rewritten, upstream.status as ContentfulStatusCode, {
          ...responseHeaders,
          "Content-Type": "application/vnd.apple.mpegurl",
          ...manifestCache,
        });
      }
      return c.body(textBody, upstream.status as ContentfulStatusCode, responseHeaders);
    } catch {
      return c.text("Manifest processing error", 500);
    }
  }

  return c.body(upstream.body as ReadableStream, upstream.status as ContentfulStatusCode, responseHeaders);
});


const port = Number(process.env.PORT) || 3847;

// Start the listener explicitly. Bun's "auto-serve from default export" only
// fires when the file is run as the main entry in certain ways, and it does NOT
// trigger reliably under PM2 — so we call Bun.serve() directly instead.
Bun.serve({
  port,
  fetch: app.fetch,
  idleTimeout: 60, // seconds; long enough for slow segment fetches, short enough to reap dead conns
});

console.log(`proxy listening on :${port}`);
