# Reach field run

This page records a run of vet on real projects on 2026-10-20, with the code of the change that
adds function reach. It is the release bar check of FOU-553 and the timing of FOU-574. The run is
not part of the test suite, because it needs the network. Each project is cloned at a tag, and
`go mod download` or `cargo fetch` puts its dependencies in the module or crate cache.

## First and second scan

The second scan reads the code index from `cache.db`.

| Project | Tag | First scan | Second scan |
| --- | --- | ---: | ---: |
| ffuf/ffuf | v1.5.0 | 2.4s | 0.5s |
| junegunn/fzf | 0.30.0 | 6.7s | 3.2s |
| BurntSushi/ripgrep | 13.0.0 | 5.0s | 2.0s |

## Comparison with govulncheck

vet and govulncheck v1.1.4 scanned 10 Go projects on the same commit: fzf 0.30.0, ffuf v1.5.0,
glow v1.4.1, task v3.9.0, duf v0.6.2, croc v9.5.0, cheat 4.2.3, yq v4.16.1, gron v0.7.1 and
lazydocker v0.12. The two tools gave 884 advisory rows.

| Result | Advisories |
| --- | ---: |
| govulncheck says called, vet says `not-called` | 0 |
| vet says `called`, govulncheck does not | 0 |
| govulncheck says called, vet keeps `imported` with a cause | 35 |
| govulncheck says called, vet says `unknown · no graph` (a package that the code does not import) | 18 |
| govulncheck says called, vet has no finding | 179 |
| Neither says called | 652 |

The 179 advisories with no vet finding are advisories of the standard library. govulncheck checks
the standard library of the Go toolchain that runs it (go1.24.7 here). vet checks the version that
`go.mod` names.

### What the first run found

The first run let a path with a weak call count as `called`. vet said `called` for 14 advisories
that govulncheck does not call. Each such path went through a call that the graph only guesses:
a call by `name` to each method with that name, or a `cha` call through an interface to each type
that implements it. One path went from `sha3.state.Sum` to `ssh.buffer.Read`, which is not a call.
So the engine now says `called` only for a path of `high` calls. A path with a weaker call keeps
the finding `imported · weak path`, with the path as evidence. After that change, vet said `called`
for no advisory of the 10 projects.

### Why vet says no `not-called` on these projects

- A `go.mod` holds no dependency graph, so vet cannot prove that no other module calls a package.
  A Go finding with no path stays `imported · no graph`.
- The reach corpus of Rust has a call that the search misses (a call through a trait object,
  FOU-578). So vet says `not-called` for no Rust finding yet.

### The causes of the imported findings

The most common causes were `unresolved-call` (the search reaches a call that it cannot resolve),
`weak-path`, `no-symbol-data` and `no-symbol-in-graph`.
