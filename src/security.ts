import { lookup } from "node:dns/promises";
import { ALLOWED_TARGET_HOSTS, ALLOW_PRIVATE_TARGETS } from "./constants";

const privateHostnames = new Set(["localhost", "localhost.localdomain"]);
const dnsSafetyCache = new Map<string, { expiresAt: number; error: string | null }>();
const DNS_SAFETY_TTL_MS = 5 * 60 * 1000;
const DNS_SAFETY_CACHE_MAX = 2048;

function isIPv4Private(address: string): boolean {
    const parts = address.split(".").map(Number);
    if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;

    const [a, b] = parts;
    return (
        a === 0 ||
        a === 10 ||
        a === 127 ||
        a === 169 && b === 254 ||
        a === 172 && b >= 16 && b <= 31 ||
        a === 192 && b === 168 ||
        a >= 224
    );
}

function isIPv6Private(address: string): boolean {
    const normalized = address.toLowerCase();
    if (normalized.startsWith("::ffff:")) {
        return isIPv4Private(normalized.slice(7));
    }

    return (
        normalized === "::1" ||
        normalized === "::" ||
        normalized.startsWith("fc") ||
        normalized.startsWith("fd") ||
        normalized.startsWith("fe80:") ||
        normalized.startsWith("ff")
    );
}

function hostnameAllowed(hostname: string): boolean {
    if (ALLOWED_TARGET_HOSTS.size === 0) return true;
    const normalized = hostname.toLowerCase();
    for (const allowed of ALLOWED_TARGET_HOSTS) {
        if (normalized === allowed || normalized.endsWith(`.${allowed}`)) return true;
    }
    return false;
}

function getDnsSafetyCache(hostname: string): string | null | undefined {
    const cached = dnsSafetyCache.get(hostname);
    if (!cached) return undefined;
    if (cached.expiresAt <= Date.now()) {
        dnsSafetyCache.delete(hostname);
        return undefined;
    }
    return cached.error;
}

function setDnsSafetyCache(hostname: string, error: string | null): void {
    if (dnsSafetyCache.size >= DNS_SAFETY_CACHE_MAX) {
        const first = dnsSafetyCache.keys().next().value;
        if (first) dnsSafetyCache.delete(first);
    }
    dnsSafetyCache.set(hostname, { expiresAt: Date.now() + DNS_SAFETY_TTL_MS, error });
}

export async function validateTargetUrl(url: URL): Promise<string | null> {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
        return "Only http and https targets are allowed";
    }

    const hostname = url.hostname.toLowerCase();
    if (!hostnameAllowed(hostname)) {
        return "Target host is not allowed";
    }

    if (!ALLOW_PRIVATE_TARGETS && (privateHostnames.has(hostname) || isIPv4Private(hostname) || isIPv6Private(hostname))) {
        return "Private network targets are not allowed";
    }

    const cachedDnsResult = getDnsSafetyCache(hostname);
    if (cachedDnsResult !== undefined) return cachedDnsResult;

    try {
        const results = await lookup(hostname, { all: true, verbatim: true });
        if (!ALLOW_PRIVATE_TARGETS && results.some((result) => isIPv4Private(result.address) || isIPv6Private(result.address))) {
            setDnsSafetyCache(hostname, "Private network targets are not allowed");
            return "Private network targets are not allowed";
        }
    } catch {
        setDnsSafetyCache(hostname, "Target host could not be resolved");
        return "Target host could not be resolved";
    }

    setDnsSafetyCache(hostname, null);
    return null;
}
