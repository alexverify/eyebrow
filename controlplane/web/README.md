# agentguard dashboard (web)

The Next.js + TypeScript frontend for `agentguard dashboard`. It is
**static-exported** (`output: 'export'`) and the built site is embedded into
the Go binary via `go:embed`, so users get a single binary with no Node
runtime. The backend is the Go `/api/*` endpoints (inventory, drift, audit) —
there is no SSR or Next API route.

## Develop

```sh
npm ci
npm run dev        # http://localhost:3000, proxy /api to a running `agentguard dashboard`
```

For live data during `next dev`, run `agentguard dashboard` in another terminal
and point fetches at it (or use a dev proxy); the production path is the
embedded export talking to the same Go process.

## Build + embed

From the repo root:

```sh
make dashboard-web   # npm ci && next build, then sync out/ → internal/dashboard/assets
make build           # rebuild the Go binary, embedding the export
```

The built export under `internal/dashboard/assets` is committed (it is the
shipped artifact); `node_modules`, `.next`, and `out` are not.
