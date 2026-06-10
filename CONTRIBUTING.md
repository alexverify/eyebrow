# Contributing to agentguard

Thanks for considering a contribution. agentguard is a security tool, so we
value clarity, determinism, and a small dependency surface over cleverness.

## Ground rules

1. **Respect the dependency rule.** Dependencies point inward:
   `cmd` → `cli` → `adapters` → `app` → `domain`. The `domain` package must
   stay pure — no IO, no third-party imports. If logic touches the disk,
   network, or a subprocess, it belongs in an adapter behind a `ports`
   interface. See [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md).
2. **Standard library first.** The MVP core has zero external dependencies
   ([ADR-0002](docs/architecture/adr/0002-standard-library-only.md)). Adding a
   dependency requires a short ADR explaining why the standard library is
   insufficient and why the dependency is trustworthy.
3. **Determinism.** Sort outputs, inject the clock (`ports.Clock`), and derive
   stable IDs so lockfiles diff cleanly and tests are reproducible.
4. **Degrade, don't crash.** Unknown or unresolvable inputs become findings, not
   errors that abort a scan.

## Workflow

```sh
make check     # gofmt + go vet + go test ./...  — must pass before you push
make lint      # golangci-lint, if installed (recommended)
```

- Add tests with every change. Domain logic gets pure unit tests; use cases use
  the `internal/app/apptest` fakes; adapters test against `t.TempDir()`
  fixtures.
- Keep packages focused. If a file is growing past one clear responsibility,
  that's a signal to split it.
- Match the surrounding style: small functions, doc comments on exported
  symbols, errors wrapped with `%w` and context.

## Good first contributions

The cleanest seams to fill (each is a localized change):

- A new tool discoverer (`Cursor`, `Codex`, `Gemini`, `OpenCode`) — follow
  `internal/adapters/discover/claudecode.go` and register it in `Default()`.
- A source resolver (`npm`, `git`, `url`) — implement `ports.Resolver` and
  register it in `resolve.NewRouter()`.
- New native analysis rules — add to `analyze.rules` with an OWASP mapping and a
  test.
- A tolerant JSONC or TOML parser behind `internal/adapters/parse`.

## Commit & PR

- Write focused commits with clear messages.
- PRs should describe the change, the reasoning, and how it was tested.
- By contributing you agree your work is licensed under
  [Apache-2.0](LICENSE).
