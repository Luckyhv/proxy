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

export function buildProxyPath(url: URL, encrypt: (u: string) => string, query = ""): string {
    return "/proxy/" + encrypt(url.href) + query;
}

/**
 * Rewrite all URI="..." and URL="..." occurrences in an HLS attribute list.
 */
function findQuotedUriAttrs(attrs: string, scrapeUrl: URL): URL[] {
    const urls: URL[] = [];
    const attrPattern = /\b(URI|URL)="([^"]*)"/gi;
    let match: RegExpExecArray | null;
    while ((match = attrPattern.exec(attrs)) !== null) {
        urls.push(resolveUrl(match[2], scrapeUrl));
    }
    return urls;
}

function rewriteUriAttrs(attrs: string, scrapeUrl: URL, encrypt: (u: string) => string): string {
    return attrs.replace(/\b(URI|URL)="([^"]*)"/gi, (match, key: string, value: string) => {
        if (!value) return match;
        const resolved = resolveUrl(value, scrapeUrl);
        return `${key}="${buildProxyPath(resolved, encrypt)}"`;
    });
}

export function processM3u8Line(
    line: string,
    scrapeUrl: URL,
    encrypt: (u: string) => string,
): string {
    if (line.length === 0) return "";

    if (line[0] === "#") {
        const upperLine = line.toUpperCase();
        if (line.length > 20 && (upperLine.includes('URI="') || upperLine.includes('URL="'))) {
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
    return buildProxyPath(resolved, encrypt);
}

export function extractM3u8Urls(textBody: string, scrapeUrl: URL): URL[] {
    const urls: URL[] = [];
    const seen = new Set<string>();

    function add(url: URL): void {
        if (seen.has(url.href)) return;
        seen.add(url.href);
        urls.push(url);
    }

    let start = 0;
    while (start < textBody.length) {
        let end = textBody.indexOf("\n", start);
        if (end === -1) end = textBody.length;
        const lineEnd = end > start && textBody[end - 1] === "\r" ? end - 1 : end;
        const line = textBody.slice(start, lineEnd).trim();
        start = end + 1;

        if (!line) continue;
        if (line[0] !== "#") {
            add(resolveUrl(line, scrapeUrl));
            continue;
        }

        if (line.includes("=") && (line.toUpperCase().includes('URI="') || line.toUpperCase().includes('URL="'))) {
            const colonPos = line.indexOf(":");
            if (colonPos !== -1) {
                for (const url of findQuotedUriAttrs(line.slice(colonPos + 1), scrapeUrl)) add(url);
            }
        }
    }

    return urls;
}
