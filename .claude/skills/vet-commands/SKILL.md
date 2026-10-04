---
name: vet-commands
description: Use when you add, rename, move or remove a vet command, a subcommand or a command
  flag, or when you write or change a page under docs/cmd/ or the command index docs/cmd/README.md.
  Also use it when someone asks where a new command belongs, which verb to use, or why the
  conventions test fails.
---

# Add or change a vet command

The rules are in docs/DEVGUIDE.md, sections "Command shape" and "Documentation". Read both first.

## Steps

1. Find the noun that owns the object. Do not add a top-level noun when an existing noun owns it.
2. Pick the verb from internal/cmd/verbs.go. A new verb needs a one-line reason in the pull request.
3. Write Short and Long for every new command, parent or leaf.
4. Write docs/cmd/<path joined with ->.md from the template in the guide. Keep Synopsis and Exit codes.
5. Add the row to docs/cmd/README.md in tree order. Do not list commands in the root README.md.
6. For a new user-facing guarantee, add an acceptance script and its catalog row.
7. Run go test ./internal/cmd/, then make check before the push.

## Invariants

- No hyphen in a command name, except the names in `hyphenExceptions`. The list holds only `github-actions`.
- The root exceptions are scan, doctor and version. The default answer to a new one is no.
- The top-level set is pinned in the conventions test. A change to it needs the program owner.
- The maximum depth is 3.
- Every leaf has one page, and docs/cmd/README.md links it. Every page has one leaf.

## Keep the guide correct

If the code and the guide disagree, fix the guide in the same change. Do not copy rules into this skill.
