# action/ — GitHub composite Action (seam)

A composite GitHub Action wrapping the `agentguard` binary for CI. Empty today.

## Plan

The Action will:

1. Install the pinned `agentguard` binary and verify its checksum.
2. Pull org policy from the control plane (when configured).
3. Run `agentguard verify --ci`, failing the build on drift, unsigned entries,
   or new critical/high findings.
4. Post a PR comment summarizing drift and findings.

The same binary works in any CI; the Action is sugar. The stable exit-code
contract (`0` clean, `1` drift/findings, `2` usage, `3` error) is what CI keys
on — see [docs/architecture/ARCHITECTURE.md](../docs/architecture/ARCHITECTURE.md).
