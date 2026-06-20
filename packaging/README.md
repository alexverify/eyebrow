# packaging/ — distribution (seam)

Release and distribution tooling. Empty today; `make build` produces a local
binary in the meantime.

## Outputs (GoReleaser)

- GitHub Releases with signed checksums (macOS/Linux/Windows, amd64/arm64).
- A Homebrew tap (`brew install alexverify/tap/eyebrow`) via the `brews:` block.
- `install.sh` (`curl | sh`) — checksum-verified binary download.

npm distribution was considered and **declined**: shipping a Go binary through
npm needs a package-per-platform fan-out (scope, publish token, N packages) and
is not the idiomatic Go path. See
`docs/superpowers/specs/2026-06-20-distribution-design.md`.
