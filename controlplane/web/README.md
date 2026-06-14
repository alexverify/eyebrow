# assay dashboard (web)

The Next.js + TypeScript + Tailwind frontend for `assay dashboard`. It is
**static-exported** (`output: 'export'`) and the built site is embedded into the
Go binary via `go:embed`, so users get a single binary with no Node runtime.

The dashboard currently renders **mock scan data** (`lib/scan-data.ts`) so it is
fully demoable offline; the Go `/api/*` endpoints (inventory, drift, audit) are
served by the same process and the views will be wired to them next.

## Develop

```sh
npm ci
npm run dev        # http://localhost:3000
```

## Build + embed

From the repo root:

```sh
make dashboard-web   # npm ci && next build, then sync out/ → internal/dashboard/assets
make build           # rebuild the Go binary, embedding the export
```

The built export under `internal/dashboard/assets` is committed (it is the
shipped artifact); `node_modules`, `.next`, and `out` are not.

## Layout

- `app/page.tsx` — the dashboard (root route, what `assay dashboard` serves)
- `components/dashboard/` — dashboard UI (header, stat cards, badges, tabs)
- `components/ui/` — shadcn/base-ui primitives
- `lib/scan-data.ts` — mock inventory/findings/drift data
- `lib/scan-utils.ts` — severity/drift aggregation helpers
