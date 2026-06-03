/**
 * Global constants for CORS and Header management.
 */

export const DEFAULT_HEADERS: Record<string, string> = {
    "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    accept: "*/*",
    "accept-language": "en-US,en;q=0.5",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "cross-site",
};

export const ALLOWED_ORIGINS = new Set(
    (process.env.ALLOWED_ORIGINS ?? "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
);

export const CORS_HEADERS: Record<string, string> = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
    "Access-Control-Allow-Headers":
        "Content-Type, Authorization, Range, X-Requested-With, Origin, Referer, Accept, Accept-Encoding, Accept-Language, Cache-Control, Pragma, Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site, Sec-Ch-Ua, Sec-Ch-Ua-Mobile, Sec-Ch-Ua-Platform, Connection",
    "Access-Control-Expose-Headers":
        "Content-Length, Content-Range, Accept-Ranges, Content-Type, Cache-Control, Expires, Vary, ETag, Last-Modified",
    "Access-Control-Max-Age": "86400",
    "Cross-Origin-Resource-Policy": "cross-origin",
    "Vary": "Origin",
};

export const PASSTHROUGH_HEADERS = new Set([
    "content-type",
    "content-length",
    "content-range",
    "accept-ranges",
    "cache-control",
    "expires",
    "last-modified",
    "etag",
    "vary",
]);

export const BLACKLIST_HEADERS = new Set([
    "alt-svc",
    "cf-cache-status",
    "cf-ray",
    "connection",
    "content-encoding",
    "content-length",
    "content-security-policy",
    "content-security-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "report-to",
    "server",
    "strict-transport-security",
    "transfer-encoding",
    "vary",
    "x-content-type-options",
    "x-frame-options",
    "x-runtime",
    "x-powered-by",
    "x-request-id",
    "x-xss-protection",
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "access-control-allow-credentials",
]);

export const MEDIA_CACHE_CONTROL = "public, max-age=31536000, s-maxage=31536000, immutable";

// ─── Upstream egress proxy ───────────────────────────────────────────────────
// Some CDNs (e.g. vid-cdn.xyz) sit behind Cloudflare and block our datacenter
// egress IP with a 403. Routing the upstream fetch through a clean/residential
// proxy bypasses that. Set UPSTREAM_PROXY to an http(s)/socks proxy URL, e.g.
//   UPSTREAM_PROXY=http://user:pass@host:port
// By default the proxy is only used for hosts listed in UPSTREAM_PROXY_DOMAINS
// (comma-separated hostname suffixes). Leave that empty to proxy ALL upstream
// traffic instead.
export const UPSTREAM_PROXY = (process.env.UPSTREAM_PROXY ?? "").trim();

export const UPSTREAM_PROXY_DOMAINS = (process.env.UPSTREAM_PROXY_DOMAINS ?? "vid-cdn.xyz")
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);

/** Whether the upstream fetch to `hostname` should be routed via UPSTREAM_PROXY. */
export function shouldProxyUpstream(hostname: string): boolean {
    if (!UPSTREAM_PROXY) return false;
    if (UPSTREAM_PROXY_DOMAINS.length === 0) return true; // proxy everything
    const h = hostname.toLowerCase();
    return UPSTREAM_PROXY_DOMAINS.some((d) => h === d || h.endsWith(`.${d}`));
}
