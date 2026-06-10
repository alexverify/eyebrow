# ADR-0001: Pragmatic hexagonal architecture

- Status: Accepted
- Date: 2026-06-10

## Context

agentguard is a security tool whose credibility rests on a small amount of
trust-critical logic (content hashing, drift detection) surrounded by a large
amount of messy IO: parsing many tools' config formats, resolving npm/git/url
sources, shelling out to Semgrep, walking the filesystem. We need the core to be
provably correct and the edges to be swappable and degradable. The codebase
should also be approachable for open-source contributors.

## Decision

Adopt **ports and adapters (hexagonal) architecture** in an idiomatic Go form:

- A pure `domain` core with no IO and no third-party imports.
- An `app` layer of use-case services that depend only on the domain and on
  interfaces (`ports`) they declare.
- `adapters` that implement those ports (CLI, discovery, resolution, hashing,
  analysis, storage, signing, reporting).

Dependencies point strictly inward. The composition root is `internal/cli`,
wired from `cmd/agentguard`.

We explicitly reject a strict, ceremony-heavy "Clean Architecture" layout
(separate entities/usecases/interface-adapters/frameworks trees) as
un-idiomatic for Go and unnecessary indirection for this codebase's size.

## Consequences

- The trust-critical logic is unit-tested without touching disk or network.
- Use cases are tested against in-memory fakes (`internal/app/apptest`).
- Adding a tool, resolver, analyzer, or signature scheme is a localized change
  behind an interface.
- Contributors must respect the dependency rule; `go vet` and review enforce it.
  A future `depguard`/import-lint rule can make this mechanical.
