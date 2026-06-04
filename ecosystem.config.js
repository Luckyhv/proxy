// PM2 config for the Bun proxy.
// Bun cannot run under PM2's "cluster" mode (that needs Node's cluster module),
// so we stay in "fork" mode and point PM2 at the bun interpreter.
//
// IMPORTANT: set `interpreter` to the ABSOLUTE path of bun on the server.
// Find it on the aaPanel box with:  which bun   (often ~/.bun/bin/bun)
// PM2's startup daemon has a minimal PATH, so a bare "bun" can fail to resolve.
//
// Start:   pm2 start ecosystem.config.js
// Persist: pm2 save && pm2 startup   (run the command it prints)

module.exports = {
  apps: [
    {
      name: "proxy",
      script: "src/index.ts",
      interpreter: "bun", // change to the absolute path from `which bun`, e.g. /root/.bun/bin/bun
      cwd: __dirname,
      exec_mode: "fork",
      instances: 1,

      // Safety net only — recycle if a leak runs the process away.
      // Box has 128GB shared with other services, so this sits well above the
      // proxy's normal working set; it should rarely (ideally never) fire once
      // the client-disconnect abort fix is deployed. Watch `pm2 list` and adjust.
      max_memory_restart: "6G",

      // Crash handling
      autorestart: true,
      max_restarts: 20, // crash-loop guard: stop flapping after 10 quick restarts
      min_uptime: "10s", // a run shorter than this counts as a failed start
      restart_delay: 2000, // wait 2s between restarts

      env: {
        NODE_ENV: "production",
        // PORT / SECRET_KEY / ALLOWED_ORIGINS / UPSTREAM_PROXY* come from .env
        // (Bun auto-loads .env, so you don't need to duplicate them here).
      },
    },
  ],
};
