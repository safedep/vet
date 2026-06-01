# sync-binaries

Copies goreleaser-built binaries from `dist/` into the per-platform npm
packages under `packages/`, optionally stamping a release version. Driven by
nx (`sync-binaries:run` / `sync-binaries:run-release`).
