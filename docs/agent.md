# Agents

`vet` natively supports AI agents with MCP based integration for tools.

To get started, set an API key for the LLM you want to use. Example:

```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-...
export GEMINI_API_KEY=AIza...
```

## Query Agent

The query agent helps run query and analysis over vet's sqlite3 reporting database. To use it:

* Run a `vet` scan and generate report in sqlite3 format

```bash
vet scan -M package-lock.json --report-sqlite3 report.db
```

* Start the query agent

```bash
vet agent query --db report.db
```

* Thats it! Start asking questions about the scan results.

