# AGENTS.md

This file gives guidance to AI coding agents that work on vet.

## Build and test

```bash
go build ./...
go test ./... -count=1
golangci-lint run ./...
```

## Rules

- Read [docs/DEVGUIDE.md](docs/DEVGUIDE.md) before you add, rename or remove a command or a flag.
  Obey each rule that it marks **(lint)**. The sections "Command shape" and "Documentation" hold
  the rules.
- Use the skill `.claude/skills/vet-commands/SKILL.md` for command work.
- Only `internal/tui` imports `dry/tui`.
- Only the enrichers and the cloud plugins import the SafeDep API contract.
- The public packages `model`, `finding`, `report` and `plugin` import nothing from `internal`.
- Use `testify` and table-driven tests.

## Writing

Write in ASD-STE100, Simplified Technical English. This applies to code comments, user-facing
messages, commit messages, pull requests and docs.

- One sentence, one idea.
- Use the active voice and name the actor.
- Cut every word that does no work.
- Do not end a message with a full stop right after a value that a user copies: a path, a scan
  id, a config key, a flag or a command. Put the value earlier in the sentence, or end the message
  with the value and no full stop.
