# Code usage, AI and crypto inventory

With `plugins.codeusage.enabled: true`, a scan of a directory also reads the source files of
Python, JavaScript, TypeScript, Java, Go, C#, Rust, PHP and Ruby. vet then reports:

- **Code usage.** The packages that the code imports, and the files that import them. Each package
  finding says whether the project uses the package.
- **AI capabilities.** The LLM SDKs, agent frameworks, MCP libraries, ML frameworks, model
  runtimes, vector stores and tokenizers that the code calls, with each call site.
- **Crypto capabilities.** The algorithms (such as SHA-256, AES, RSA and Argon2), the protocols
  (TLS, SSH), the certificates (X.509) and the tokens (JWT) that the code uses. A weak algorithm,
  such as MD5, SHA-1, DES or RC4, has the `weak` tag.

```bash
vet config set plugins.codeusage.enabled true
vet scan . --report cyclonedx=../bom.json
```

Write the BOM outside the project directory. vet reads the CycloneDX and SPDX files in the
directory as SBOMs, so a `bom.json` in the project becomes part of the next scan.

## xBOM and CBOM

The `cyclonedx` report holds each AI capability as a component and each crypto capability as a
`cryptographic-asset`. The format is CycloneDX 1.7.

## Read the capabilities

In a terminal, the scan view shows an "AI and crypto" table under the findings. The table shows AI
first, then weak crypto, then the other crypto, with the first call site of each. To list every
capability and every call site of the last scan, with no new scan:

```bash
vet report capability list
vet report capability list --tag cryptography --tag weak
```

## Pull request mode

With `--base-ref`, each capability says whether the change adds or removes it. The `ai-bom-delta`
control reports a new LLM SDK, agent framework or MCP library. A policy rule can fail the gate on
it:

```yaml
  - id: no-new-ai-library
    when: finding.control_id == "ai-bom-delta"
    action: fail
```

## Requirements

The code analysis runs on your machine and sends no source code. It needs a vet build with CGO.
Each channel of [install.md](install.md) ships one. A build with `CGO_ENABLED=0` records a
diagnostic and scans with no code usage.
