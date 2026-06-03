import { Hono } from 'hono'
import { cors } from "hono/cors";
import { logger } from 'hono/logger'
import type { ContentfulStatusCode } from "hono/utils/http-status";

import {
  ALLOWED_ORIGINS,
  BLACKLIST_HEADERS,
  MEDIA_CACHE_CONTROL,
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

interface ByteRange {
  start: number;
  end: number;
}

function parseByteRange(range: string | null, total: number): ByteRange | null {
  if (!range || !Number.isFinite(total) || total <= 0) return null;

  const match = /^bytes=(\d*)-(\d*)$/i.exec(range.trim());
  if (!match) return null;

  const [, rawStart, rawEnd] = match;
  if (!rawStart && !rawEnd) return null;

  let start: number;
  let end: number;

  if (!rawStart) {
    const suffixLength = Number(rawEnd);
    if (!Number.isSafeInteger(suffixLength) || suffixLength <= 0) return null;
    start = Math.max(total - suffixLength, 0);
    end = total - 1;
  } else {
    start = Number(rawStart);
    end = rawEnd ? Number(rawEnd) : total - 1;
  }

  if (
    !Number.isSafeInteger(start) ||
    !Number.isSafeInteger(end) ||
    start < 0 ||
    end < start ||
    start >= total
  ) {
    return null;
  }

  return { start, end: Math.min(end, total - 1) };
}

function sliceStream(
  stream: ReadableStream<Uint8Array> | null,
  range: ByteRange,
): ReadableStream<Uint8Array> | null {
  if (!stream) return null;

  const reader = stream.getReader();
  let offset = 0;
  let sent = 0;
  const targetLength = range.end - range.start + 1;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      while (sent < targetLength) {
        const { done, value } = await reader.read();
        if (done) {
          controller.close();
          return;
        }

        const chunkStart = offset;
        const chunkEnd = offset + value.byteLength - 1;
        offset += value.byteLength;

        if (chunkEnd < range.start) continue;
        if (chunkStart > range.end) {
          controller.close();
          return;
        }

        const sliceStart = Math.max(range.start - chunkStart, 0);
        const sliceEnd = Math.min(range.end - chunkStart + 1, value.byteLength);
        const nextChunk = value.subarray(sliceStart, sliceEnd);
        sent += nextChunk.byteLength;
        controller.enqueue(nextChunk);
        return;
      }

      controller.close();
    },
    cancel(reason) {
      return reader.cancel(reason);
    },
  });
}

function parseTotalLength(headers: Headers): number | null {
  const contentRange = headers.get("content-range");
  if (contentRange) {
    const match = /\/(\d+)\s*$/.exec(contentRange);
    if (match) {
      const total = Number(match[1]);
      if (Number.isSafeInteger(total) && total > 0) return total;
    }
  }

  const contentLength = Number(headers.get("content-length"));
  return Number.isSafeInteger(contentLength) && contentLength > 0 ? contentLength : null;
}

function parseContentRangeLength(headers: Headers): number | null {
  const contentRange = headers.get("content-range");
  if (!contentRange) return null;

  const match = /^bytes\s+(\d+)-(\d+)\/(?:\d+|\*)\s*$/i.exec(contentRange);
  if (!match) return null;

  const start = Number(match[1]);
  const end = Number(match[2]);
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end < start) return null;

  return end - start + 1;
}

async function fetchContentLength(
  url: URL,
  headers: Record<string, string>,
): Promise<number | null> {
  const metadataHeaders = { ...headers };
  delete metadataHeaders["range"];
  delete metadataHeaders["if-range"];

  try {
    const metadata = await fetch(url.href, {
      method: "HEAD",
      headers: metadataHeaders,
      redirect: "manual",
      // @ts-ignore
      tls: { rejectUnauthorized: false },
    });
    return parseTotalLength(metadata.headers);
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
    ],
    maxAge: 86400,
    credentials: true,
  })
);

app.get("/", (c) => c.json({ status: "Online" }));


// ─── Proxy ───────────────────────────────────────────────────────────────────
app.on(["GET", "POST", "HEAD"], "/stream/:encrypted", async (c) => {
  const method = c.req.method;

  const targetUrlRaw = decryptUrl(c.req.param("encrypted"));
  if (!targetUrlRaw) return c.text("Invalid encrypted URL", 400);

  let targetUrl: URL;
  try { targetUrl = new URL(targetUrlRaw); } catch { return c.text(`Invalid URL: ${targetUrlRaw}`, 400); }

  const pathname = targetUrl.pathname;
  const dotIdx = pathname.lastIndexOf(".");
  const ext = dotIdx !== -1 ? pathname.slice(dotIdx + 1).toLowerCase() : "";
  const isMediaSegment = ext === "ts" || ext === "mp4" || ext === "m4s" || ext === "aac" || ext === "vtt" || ext === "webm";
  const isProgressiveMedia = ext === "mp4" || ext === "webm";

  const upstreamHeaders = generateHeadersOriginal(targetUrl);
  if (isMediaSegment) upstreamHeaders["accept-encoding"] = "identity";

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

  let upstream: Response;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);

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
    const errorMsg = err instanceof Error ? err.message : String(err);
    return c.text(`Target Fetch Failed: ${errorMsg}`, 502);
  }

  // Handle 3xx Redirects
  if (upstream.status >= 300 && upstream.status < 400) {
    const location = upstream.headers.get("location");
    if (location) {
      const resolvedLocation = resolveUrl(location, targetUrl);
      return c.redirect(buildProxyPath(resolvedLocation, encryptUrl), upstream.status as any);
    }
  }

  const responseHeaders: Record<string, string> = {};
  for (const [name, value] of upstream.headers.entries()) {
    if (!BLACKLIST_HEADERS.has(name)) { responseHeaders[name] = value; }
  }

  const upstreamLength =
    parseTotalLength(upstream.headers) ??
    (isProgressiveMedia && rangeVal ? await fetchContentLength(targetUrl, upstreamHeaders) : null);
  const requestedRange = upstreamLength == null ? null : parseByteRange(rangeVal, upstreamLength);
  if (isProgressiveMedia && rangeVal && !requestedRange && upstreamLength != null) {
    return c.body(null, 416, {
      ...responseHeaders,
      "Accept-Ranges": "bytes",
      "Content-Range": `bytes */${upstreamLength}`,
      "Cache-Control": "public, max-age=3600",
      "CDN-Cache-Control": "no-store",
      "Cloudflare-CDN-Cache-Control": "no-store",
    });
  }

  if (isMediaSegment) {
    // Progressive media must keep Range requests end-to-end. If Cloudflare is allowed
    // to cache these as immutable objects it can fetch a full 200 response on cache
    // miss, which makes the browser treat the video as non-seekable.
    const isRangeSeekable =
      isProgressiveMedia ||
      upstream.status === 206 ||
      rangeVal != null ||
      upstream.headers.get("accept-ranges") === "bytes";

    if (isRangeSeekable) {
      responseHeaders["Cache-Control"] = "public, max-age=3600";
      responseHeaders["CDN-Cache-Control"] = "no-store";
      responseHeaders["Cloudflare-CDN-Cache-Control"] = "no-store";
      responseHeaders["Accept-Ranges"] = "bytes";
      responseHeaders["Vary"] = "Origin, Range";
      if (isProgressiveMedia && upstream.status === 206) {
        const partialLength =
          Number(upstream.headers.get("content-length")) ||
          parseContentRangeLength(upstream.headers);
        if (partialLength && Number.isSafeInteger(partialLength)) {
          responseHeaders["Content-Length"] = String(partialLength);
        }
      }
    } else {
      responseHeaders["Cache-Control"] = MEDIA_CACHE_CONTROL;
      responseHeaders["CDN-Cache-Control"] = MEDIA_CACHE_CONTROL;
      responseHeaders["Cloudflare-CDN-Cache-Control"] = MEDIA_CACHE_CONTROL;
    }
  }

  if (isProgressiveMedia && upstream.status === 200 && requestedRange && upstreamLength != null) {
    const rangeLength = requestedRange.end - requestedRange.start + 1;
    return c.body(
      method === "HEAD" ? null : sliceStream(upstream.body as ReadableStream<Uint8Array>, requestedRange),
      206,
      {
        ...responseHeaders,
        "Accept-Ranges": "bytes",
        "Content-Range": `bytes ${requestedRange.start}-${requestedRange.end}/${upstreamLength}`,
        "Content-Length": String(rangeLength),
      },
    );
  }

  const contentType = upstream.headers.get("content-type") ?? "";
  const isM3u8 = contentType.includes("mpegurl") || pathname.endsWith(".m3u8") || pathname.endsWith(".M3U8");

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

        return c.body(rewritten, upstream.status as ContentfulStatusCode, {
          ...responseHeaders,
          "Content-Type": "application/vnd.apple.mpegurl",
          "Cache-Control": "public, max-age=300, s-maxage=14400",
          "CDN-Cache-Control": "public, max-age=14400",
          "Cloudflare-CDN-Cache-Control": "public, max-age=14400",
        });
      }
      return c.body(textBody, upstream.status as ContentfulStatusCode, responseHeaders);
    } catch {
      return c.text("Manifest processing error", 500);
    }
  }

  return c.body(upstream.body as ReadableStream, upstream.status as ContentfulStatusCode, responseHeaders);
});


export default {
  port: process.env.PORT || 3847,
  fetch: app.fetch,
}
