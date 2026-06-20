# packaging/ — distribution (seam)

Release and distribution tooling: the GoReleaser config, the Homebrew cask, and `install.sh`. `make build` still produces a local binary directly.

## Outputs (GoReleaser)

- GitHub Releases with signed checksums (macOS/Linux/Windows, amd64/arm64).
- A Homebrew tap (`brew install alexverify/tap/eyebrow`) via the `homebrew_casks:` block.
- `install.sh` (`curl | sh`) — checksum-verified binary download.

npm distribution was considered and **declined**: shipping a Go binary through
npm needs a package-per-platform fan-out (scope, publish token, N packages) and
is not the idiomatic Go path. See
`docs/superpowers/specs/2026-06-20-distribution-design.md`.
