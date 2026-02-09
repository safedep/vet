# Agents

`vet` natively supports AI agents with MCP based integration for tools.

To get started, set an API key for the LLM you want to use. Example:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-...
export GEMINI_API_KEY=AIza...
```

> **Note:** You can also set the model to use with `OPENAI_MODEL_OVERRIDE`, `ANTHROPIC_MODEL_OVERRIDE` and `GEMINI_MODEL_OVERRIDE` environment variables to override the default model used by the agent.

## Fast Mode

All agents support a `--fast` flag to use a faster LLM model instead of a slower but more powerful reasoning model. This is only for influencing the default choice of model. It can be overridden by setting model provider specific environment variables such as `OPENAI_MODEL_OVERRIDE`, `ANTHROPIC_MODEL_OVERRIDE` and `GEMINI_MODEL_OVERRIDE`.

## Available Agents

### Query Agent

The query agent helps run query and analysis over vet's sqlite3 reporting database. To use it:

* Run a `vet` scan and generate report in sqlite3 format

```bash
vet scan --insights-v2 -M package-lock.json --report-sqlite3 report.db
```

**Note:** Agents only work with `--insights-v2`

* Start the query agent

```bash
vet agent query --db report.db
```

* Thats it! Start asking questions about the scan results.

### ClawHub Skill Scanner

The ClawHub skill scanner agent analyzes [ClawHub](https://clawhub.ai) skills for security issues using AI. It reads skill metadata, lists files, and inspects source code to produce a security assessment.

```bash
vet agent clawhub-scanner --skill <skill-slug>
```

Use `--interactive` to start a conversational TUI where you can ask follow-up questions about the skill's security:

```bash
vet agent clawhub-scanner --skill <skill-slug> --interactive
```

Use `--prompt` to provide a custom analysis prompt instead of the default:

```bash
vet agent clawhub-scanner --skill <skill-slug> --prompt "Check for credential leaks"
```
