/**
 * M3U8 Manifest Processing & URL Resolution.
 */

export function resolveUrl(line: string, base: URL): URL {
    try {
        return new URL(line);
    } catch {
        return new URL(line, base);
    }
}

export function buildProxyPath(url: URL, encrypt: (u: string) => string, hls = false): string {
    const path = "/stream/" + encrypt(url.href);
    return hls ? `${path}?hls=1` : path;
}

/**
 * Parse a quoted-string attribute value from an HLS tag attribute list.
 */
function extractQuotedAttr(line: string, valueStart: number): [string, number] | null {
    if (line[valueStart] !== '"') return null;
    const closeQuote = line.indexOf('"', valueStart + 1);
    if (closeQuote === -1) return null;
    return [line.slice(valueStart + 1, closeQuote), closeQuote + 1];
}

/**
 * Rewrite all URI="..." and URL="..." occurrences in an HLS attribute list.
 */
function rewriteUriAttrs(attrs: string, scrapeUrl: URL, encrypt: (u: string) => string): string {
    let result = "";
    let i = 0;
    while (i < attrs.length) {
        const eqPos = attrs.indexOf("=", i);
        if (eqPos === -1) { result += attrs.slice(i); break; }

        const rawKey = attrs.slice(i, eqPos);
        // A preceding quoted attr leaves `i` on the trailing comma, so the raw key
        // can carry a leading "," (and/or whitespace). Strip it for matching, but
        // keep it as a separator in the output.
        const trimmedKey = rawKey.replace(/^[,\s]*/, "");
        const sep = rawKey.slice(0, rawKey.length - trimmedKey.length);
        const afterEq = eqPos + 1;

        if ((trimmedKey === "URI" || trimmedKey === "URL") && attrs[afterEq] === '"') {
            const parsed = extractQuotedAttr(attrs, afterEq);
            if (parsed) {
                const [value, afterClose] = parsed;
                const resolved = resolveUrl(value, scrapeUrl);
                result += `${sep}${trimmedKey}="${buildProxyPath(resolved, encrypt, true)}"`;
                i = afterClose;
                continue;
            }
        }

        if (attrs[afterEq] === '"') {
            const parsed = extractQuotedAttr(attrs, afterEq);
            if (parsed) {
                const [, afterClose] = parsed;
                result += attrs.slice(i, afterClose);
                i = afterClose;
                continue;
            }
        }

        const commaPos = attrs.indexOf(",", afterEq);
        if (commaPos === -1) { result += attrs.slice(i); break; }
        result += attrs.slice(i, commaPos + 1);
        i = commaPos + 1;
    }
    return result;
}

export function processM3u8Line(
    line: string,
    scrapeUrl: URL,
    encrypt: (u: string) => string,
): string {
    if (line.length === 0) return "";

    if (line[0] === "#") {
        if (line.length > 20 && (line.includes('URI="') || line.includes('URL="'))) {
            const colonPos = line.indexOf(":");
            if (colonPos !== -1) {
                const prefix = line.slice(0, colonPos + 1);
                const attrs = line.slice(colonPos + 1);
                return prefix + rewriteUriAttrs(attrs, scrapeUrl, encrypt);
            }
        }
        return line;
    }

    const resolved = resolveUrl(line, scrapeUrl);
    return buildProxyPath(resolved, encrypt, true);
}
