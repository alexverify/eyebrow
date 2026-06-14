# assay verify — GitHub Action

Runs `assay verify --ci` against your committed `assaylock.json`: fails
the build on drift (rug pulls), unapproved artifacts, new findings over the
policy threshold, or a missing/untrusted lockfile signature. The verify output
lands in the job's step summary.

## Usage

```yaml
jobs:
  assay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: alexverify/assay/action@v0.1.0
```

One tag pins both the action and the binary it installs: the pinned release
binary is downloaded from this repository's releases and verified against the
published `checksums.txt` before it runs. If you pin the action to a branch or
SHA instead, set the `version` input explicitly.

## Inputs

| Input | Default | What |
|---|---|---|
| `version` | the action's own ref | Release tag of the binary to install (e.g. `v0.1.0`) |
| `path` | `.` | Project root to scan |
| `lockfile` | `assaylock.json` | Lockfile path |
| `policy` | `assay.policy.json` | Policy file applied by the gate |
| `trusted-keys` | `assay.trustedkeys` | Trusted-keys registry for `requireSignature` |

Exit codes are the binary's stable contract: `0` clean, `1` drift or policy
violation, `2` usage error, `3` internal error. The same binary works in any
CI; this Action is sugar — see
[docs/architecture/ARCHITECTURE.md](../docs/architecture/ARCHITECTURE.md).

Planned (with the control plane): org policy pull and a PR comment summarizing
drift and findings.
