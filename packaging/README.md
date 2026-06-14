# packaging/ — distribution (seam)

Release and distribution tooling. Empty today; `make build` produces a local
binary in the meantime.

## Plan (GoReleaser)

Outputs:

- GitHub Releases with signed checksums (macOS arm64/amd64, Linux amd64/arm64).
- A Homebrew tap (`brew install assay`).
- `install.sh` (`curl | sh`).
- An **npm shim package** (`assay`) that downloads the platform binary on
  postinstall so the JS crowd can `npx assay scan`.

The npm shim's postinstall download must verify a pinned checksum and document
the trade-off loudly — a postinstall download in a supply-chain tool is ironic,
so it must be exemplary. (Note: the native matchers already flag
`postinstall`/`preinstall` scripts.)
