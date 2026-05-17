To install dependencies:
```sh
bun install
```

To run:
```sh
bun run dev
```

open http://localhost:3000

Useful production knobs:

```sh
PORT=3847
XOR_KEY=change-me
ALLOWED_ORIGINS=https://your-site.example
ALLOWED_TARGET_HOSTS=cdn.example.com,media.example.com
PROXY_CACHE_MAX_BYTES=536870912
PROXY_CACHE_MAX_ENTRY_BYTES=67108864
SEGMENT_CACHE_TTL_SECONDS=21600
MANIFEST_CACHE_TTL_SECONDS=15
HLS_PREFETCH_ENABLED=true
HLS_PREFETCH_CONCURRENCY=24
HLS_PREFETCH_LIMIT=48
MAX_CONCURRENT_UPSTREAM=256
MAX_MANIFEST_BYTES=2097152
MAX_POST_BODY_BYTES=2097152
```

`ALLOW_PRIVATE_TARGETS=true` is only intended for local testing or trusted private deployments.
Cache and live limits are visible at `/api/info`; Prometheus-style metrics are available at `/api/metrics`.

For fast HLS startup, keep media segment URLs stable and cacheable. This proxy rewrites manifests, caches rewritten m3u8 files briefly, caches media/key/subtitle/init files aggressively, coalesces duplicate cold misses, and warms the cache from URLs discovered inside each manifest.
