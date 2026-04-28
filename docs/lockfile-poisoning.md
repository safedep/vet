# Lockfile Poisoning Detection

## What is Lockfile Poisoning?

Lockfile poisoning is a supply chain attack where an attacker modifies a package manager's lockfile (e.g., `package-lock.json`) to redirect dependency resolution to malicious packages. Since lockfiles are auto-generated and often rubber-stamped in code review, subtle changes to resolved URLs or integrity hashes can go unnoticed.

For example, an attacker might change:

```json
"node_modules/lodash": {
  "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
}
```

to:

```json
"node_modules/lodash": {
  "resolved": "https://registry.npmjs.org/evil-pkg/-/evil-pkg-1.0.0.tgz"
}
```

When `npm install` runs, `evil-pkg` is downloaded and placed at `node_modules/lodash/`. Application code importing `lodash` now executes attacker-controlled code.

## How vet Detects It

vet applies two checks to every package in a `package-lock.json` (lockfile version 2+):

### 1. Trusted Source Check

Verifies that the `resolved` URL points to a known, trusted registry host. By default, only `https://registry.npmjs.org` is trusted. Additional trusted registries (e.g., private registries) can be configured.

This catches attacks where the URL points to an attacker-controlled server.

### 2. Path Convention Check

Verifies that the package name derived from the `node_modules/...` key matches the package name in the resolved URL path. For example, `node_modules/lodash` should resolve to a URL containing `lodash/-/`.

This catches attacks where the URL points to a different package on the same trusted registry.

## Usage

```bash
# Scan a project for lockfile poisoning
vet scan -D /path/to/project --lockfile-poisoning

# With a private registry trusted
vet scan -D /path/to/project --lockfile-poisoning --lockfile-poisoning-trusted-urls="https://registry.internal.example.com"
```

## Known Limitations

### npm Aliased Dependencies

npm supports [dependency aliases](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#dependencies) using the `npm:` prefix syntax:

```json
{
  "dependencies": {
    "codex": "npm:@openai/codex@^0.77.0"
  }
}
```

This installs `@openai/codex` under `node_modules/codex`. The resulting lockfile has a path/URL mismatch that is indistinguishable from a poisoning attack, causing a false positive.

**Workaround:** Add the aliased package's registry URL to the trusted URLs list:

```bash
vet scan -D /path/to/project --lockfile-poisoning \
  --lockfile-poisoning-trusted-urls="https://registry.npmjs.org/@openai/codex"
```

### Lockfile Version Support

Only npm lockfile version 2+ is supported. Older lockfile formats (version 1) use a different structure and are not analyzed.
