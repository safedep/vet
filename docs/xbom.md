# xBOM: Component Detection using Static Code Analysis

vet analyzes source code to detect what APIs and libraries an application actually calls. It produces an extended Bill of Materials (xBOM) covering AI/ML services, cryptographic operations, cloud integrations, and standard library capabilities, persisted in the CycloneDX SBOM output.

## Quick Start

```bash
# Phase 1: Scan source code, store results in SQLite DB
vet code scan --db code.db --app ./src

# Phase 2: Run SCA scan enriched with code analysis
vet scan -D ./src --code code.db --report-cdx sbom.json
```

## Examples

Scanning a Python project, excluding tests and virtualenv:

```bash
vet code scan --db code.db \
  --app ./src \
  --import-dir ./venv/lib \
  --exclude ".*test.*" --exclude ".*__pycache__.*"

vet scan -D ./src --code code.db --report-cdx sbom.json
```

Scanning a Go monorepo with vendored dependencies:

```bash
vet code scan --db code.db \
  --app ./cmd --app ./internal \
  --import-dir ./vendor \
  --exclude ".*_test\\.go"

vet scan -D . --code code.db --report-cdx sbom.json
```

Showing only packages that are actually used in code:

```bash
vet scan -D . --code code.db \
  --report-summary --report-summary-used-only
```

Querying scan results from the database:

```bash
# List all signature matches (default limit: 50)
vet code query --db code.db

# Filter by tag
vet code query --db code.db --tag ai --tag crypto

# Filter by language and vendor
vet code query --db code.db --language go --vendor lang/golang

# Filter by file path substring
vet code query --db code.db --file auth/

# Show more results
vet code query --db code.db --limit 200
```

Validating that all embedded signatures are well-formed:

```bash
vet code validate
```

The full list of flags is available via `vet code scan --help`, `vet code query --help`, and `vet scan --help`.

## What Gets Detected

Signatures cover three language ecosystems (**Go**, **Python**, **JavaScript/TypeScript**) across these categories:

| Category | Examples |
|----------|---------|
| **AI/LLM** | OpenAI client, Anthropic (Claude, Bedrock, VertexAI), LangChain, CrewAI |
| **Cryptography** | AES/RSA encryption, SHA/MD5 hashing, key derivation |
| **Cloud** | GCP Pub/Sub, Azure Service Bus, Azure AI, Microsoft Office integrations |
| **Network** | HTTP client/server, TCP/UDP sockets, DNS lookups |
| **Database** | SQL connections (database/sql, sqlite3, etc.) |
| **Filesystem** | Read/write/delete/mkdir/chmod/symlink operations |
| **Process** | Command execution, environment variable access, process info |

## How It Works

1. The **code scanner** parses source files, builds call graphs, and matches function calls against embedded signature patterns
2. It stores matches with file path, line number, and the matched call pattern
3. Matches under `--import-dir` directories are tagged with a package hint (linked to a dependency); matches under `--app` directories are tagged as application-level
4. During `vet scan --code`, package-level matches enrich the corresponding dependency with evidence; application-level matches appear as standalone xBOM components

## CycloneDX Output

### Package-level matches

Dependencies with detected code usage receive `source-code-analysis` evidence with file locations:

```json
{
  "bom-ref": "pkg:pypi/openai@1.0.0",
  "evidence": {
    "identity": [
      { "methods": [{ "technique": "source-code-analysis", "confidence": 1.0 }] }
    ],
    "occurrences": [
      { "location": "src/ai.py", "line": 42, "additionalContext": "openai.OpenAI" }
    ]
  },
  "properties": [
    { "name": "ai", "value": "true" }
  ]
}
```

### Application-level matches

Capabilities detected in first-party code (not tied to a specific dependency) appear as standalone components:

```json
{
  "bom-ref": "xbom:golang.network.http.server",
  "type": "library",
  "name": "Standard Library HTTP server",
  "publisher": "Go",
  "evidence": {
    "occurrences": [
      { "location": "cmd/server/main.go", "line": 25, "additionalContext": "net/http.ListenAndServe" }
    ]
  }
}
```

### Tag properties

Matched signatures with known tags produce CycloneDX properties: `ai`, `cryptography`, `encryption`, `hash`, `ml`, `iaas`, `paas`, `saas`.

## Signatures

Signatures are YAML files that define function call patterns to detect. They are embedded into the binary at build time from `signatures/`.

### Directory layout

```
signatures/
├── lang/                    # Standard library capabilities
│   ├── golang/              #   crypto.yaml, network.yaml, filesystem.yaml, ...
│   ├── python/
│   └── javascript/
├── openai/                  # Third-party vendors
│   └── llm/
├── anthropic/
│   └── ai/
├── langchain/
├── crewai/
├── google/
│   └── gcp/
├── microsoft/
│   ├── azure/
│   └── office/
├── cryptography/
│   └── algorithms/
└── loader.go                # Registers embedded files via go:embed
```

The path hierarchy is `<vendor>/<product>/<service>.yaml`.

### Signature format

```yaml
version: 0.1

signatures:
  - id: golang.crypto.hash
    description: "Cryptographic hash operations"
    vendor: "Go"
    product: "Standard Library"
    service: "Cryptographic hashing"
    tags: [crypto, hash, capability]
    languages:
      go:
        match: any
        conditions:
          - type: call
            value: "crypto/sha256/New"
          - type: call
            value: "crypto/sha256/Sum256"
```

**Fields:**

| Field | Description |
|-------|-------------|
| `id` | Unique identifier, follows `<vendor>.<product>.<service>` convention |
| `description` | What this signature detects |
| `vendor`, `product`, `service` | Categorization metadata |
| `tags` | Classification labels used in reports and CycloneDX output |
| `languages.<lang>.match` | `any` (match at least one condition) or `all` (match every condition) |
| `languages.<lang>.conditions` | List of call patterns. `type` is always `call`. `value` supports wildcards (`openai.*`) |

### Contributing signatures

1. Create or edit a YAML file under `signatures/<vendor>/<product>/`. Follow the naming convention above.
2. If adding a new top-level vendor directory, add it to the `//go:embed` directive in `signatures/loader.go`.
3. Run `vet code validate` to check that all signatures are well-formed and have no duplicate IDs.
4. Test with a real codebase: `vet code scan --db /tmp/test.db --app ./path && vet code query --db /tmp/test.db`
