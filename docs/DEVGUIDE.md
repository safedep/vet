# vet developer guide

This guide holds the rules for vet v2 commands and their documentation. The conventions test,
`internal/cmd/conventions_test.go`, checks each rule marked **(lint)**. `go test ./...` runs it.

## Command shape

### The tree

- `cmd/vet/main.go` holds the wiring only. `internal/cmd.New` builds the full tree. `main` and the
  tests call it, so both walk the same tree.
- Each top-level noun has one Go package, `internal/cmd/<noun>/`. A package under
  `internal/cmd/<x>` does not import `internal/cmd/<y>`. **(lint)** Shared code goes in
  `internal/app` or in a package outside `internal/cmd`.
- The top-level set is pinned in `topLevelCommands`, and the leaves in `leafCommands`. **(lint)** A
  change to either list needs the program owner.

### The path

- A leaf command path is `vet <noun> [<noun>...] <verb>`. The minimum depth is 2. **(lint)**
- The last token of a leaf path is a verb from `internal/cmd/verbs.go`. **(lint)**
- The maximum depth is 3. **(lint)**
- A command with `Run` or `RunE` is a leaf. A command without them is a parent noun.
- A command name has no hyphen. `run-scan` is wrong. `scan run` is correct. **(lint)** The one
  exception is `github-actions`, the product name that `vet fix github-actions run` rewrites. The
  list `hyphenExceptions` holds it.
- Every command, parent or leaf, has a `Short` and a `Long`. **(lint)**

### Root exceptions

Three leaves sit at depth 1. **(lint)** The default answer to a new one is no.

| Command | Reason |
| --- | --- |
| `vet scan` | vet is a scanner, and `scan` is the command that users type most. |
| `vet doctor` | It checks the state, the config, the credentials and the endpoints. No single noun owns all of them. |
| `vet version` | The same exception as in the safedep cli. |

### Verbs

vet uses the verb list of the safedep cli and adds `diff`, `validate` and `audit`. A new verb goes
into `verbs.go` with a one-line reason in the pull request. Keep the list sorted.

The allowed verbs:

<!-- verbs:start -->
`add`, `audit`, `create`, `delete`, `diff`, `disable`, `edit`, `enable`, `exec`, `get`, `init`,
`install`, `list`, `login`, `logout`, `open`, `pricing`, `remove`, `run`, `set`, `show`, `status`,
`sync`, `token`, `uninstall`, `update`, `validate`
<!-- verbs:end -->

| Verb | Meaning |
| --- | --- |
| `show` | Render one object for a person. |
| `get` | Return one object whole, for scripts and agents. |
| `list` | Return many objects. |
| `status` | Report health or state. |
| `run` | Do the main job of a noun. |
| `diff` | Compare two objects. |
| `validate` | Check a file. Change nothing. Exit with code 2 on an error. |
| `audit` | Check what is installed on a machine against rules. |
| `add`, `remove` | Attach or detach a catalog item. |
| `create`, `delete` | Make or destroy a resource that the user defines. |

### Flags

- Only the root declares persistent flags. **(lint)** The global flags are `-o`, `--mode`, `-v`,
  `-q`, `--no-input`, `--config` and `--profile`.
- A flag that only some commands read is a local flag on those commands, for example `--report`,
  `--state-dir`, `--cache-dir` and `--ephemeral`.
- `-o` names a data format on stdout. It never names a file. `--report FORMAT=PATH` writes a file.

### Output and errors

- Stdout is data. Stderr is everything else.
- Every command uses `internal/tui`. Only `internal/tui` imports `dry/tui`.
- Escape text from scanned repositories with `internal/tui/escape` before display.
- Return a `usefulerror` with a code and a help text. `app.ExitCode` maps the error to the exit
  code.

| Code | Meaning |
| --- | --- |
| 0 | The command completed. A scan with no gate, or with a gate that passed. |
| 1 | The gate that the user set failed. |
| 2 | A usage or configuration error. No scan ran. |
| 3 | A runtime error. |
| 130 | A signal stopped the scan. vet saved the progress. |

## Documentation

- Each leaf has one page at `docs/cmd/<path joined with ->.md`. **(lint)** For example
  `vet report finding show` has `docs/cmd/report-finding-show.md`. The root exceptions have
  `docs/cmd/scan.md`, `docs/cmd/doctor.md` and `docs/cmd/version.md`.
- Each page has a leaf. A renamed command does not leave its old page behind. **(lint)**
- A person writes each page. vet does not generate pages.
- The README has one short section for each top-level noun, then the full reference table. The
  table links every page. **(lint)** The rows follow the order of the tree.

### Page template

A page starts with `# vet <path>` and has `## Synopsis` and `## Exit codes`. **(lint)** Keep the
other sections short. Leave out a section that has no content.

````markdown
# vet <path>

One sentence that says what the command does.

## Synopsis

```text
vet <path> [ARGS] [FLAGS]
```

## Description

What the command reads, what it writes and when to use it.

## Arguments

| Argument | Description |
| --- | --- |

## Flags

| Flag | Description |
| --- | --- |

## Examples

```text
vet <path> ...
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | ... |
````

### Checklist for a new command

1. Find the noun that owns the object. Do not add a top-level noun when a noun owns it.
2. Pick the verb from `verbs.go`.
3. Write `Short` and `Long`.
4. Write the page from the template.
5. Add the README row in tree order.
6. For a new user-facing guarantee, add an acceptance script and its catalog row.
7. Run `go test ./internal/cmd/`.
