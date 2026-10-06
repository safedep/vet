# Glossary

The terms of vet v2. Code, comments, flags, report fields, docs and commit messages use these words.

- Read this file before you add a type, a package, a flag, a report field or a plugin. If a term here
  covers your concept, use it and its code. Do not add a second word or a second type for it.
- When a change adds a concept, or overrules a term, update this file in the same pull request.

A definition says what the term **is**, and names the code that owns it. When several words exist
for one concept, this file picks one and puts the rest under `_Avoid_`. General programming terms
do not belong here.

## Packages

**Ecosystem**:
The namespace that a package name and version belong to, as a person writes it in a flag, a config
key, a policy or a report: `npm`, `pypi`, `maven`, `go`, `cargo`, `rubygems`, `nuget`, `packagist`,
`pub`, `github-actions`, `terraform-provider`, `vscode`, `openvsx`. `model.Ecosystem` holds it.
`dry/api/pb` owns the names, and each name maps to one `packagev1.Ecosystem`.
_Avoid_: package manager, registry, PURL type (a PURL type such as `pip` or `golang` is an input alias)

**Package version**:
The identity of one version of one package. It holds the raw form and the canonical form.
`model.PackageVersion` in [`model/package_version.go`](../model/package_version.go) is the only
type for it, and `model` is the only package that imports the identity rules of `dry/api/pb`. It is
not comparable with `==`. Compare with `Equal`, `SamePackage` or `Compare`.
_Avoid_: package id, PackageID, coordinates, name@version strings

**Raw form**:
The name and the version as the manifest writes them, such as `Zope.Interface` and `1.0.0.0`.
`RawName` and `RawVersion` return them. vet shows the raw form to a person and sends it to remote
APIs with `RawProto`. Only the API clients call `RawProto`.
_Avoid_: original name, display name

**Canonical form**:
The name and the version under the rule of the ecosystem, such as `zope-interface` and `1.0` for
PyPI. `Name` and `Version` return them. Logic and policy compare the canonical form.
_Avoid_: normalized name

**Package key**:
The comparable string form of a package version: ecosystem, rule version, canonical name and
canonical version. `model.PackageKey`, from `PackageVersion.Key()`. Maps, database rows and finding
ids use it. **Name key** (`NameKey()`) is a package key with no version. It groups the versions of
one package.
_Avoid_: PURL as a key (a name can form no PURL, and the PURL is for display and the wire)

**PURL**:
The package URL of a package version, from `PackageVersion.PURL()`. It follows the purl-spec type
definition of its ecosystem. It keeps the version as the manifest writes it, so `0.1.0` stays `0.1.0`
for PyPI. It is for display, for report fields and for formats such as SARIF and CycloneDX. It can be
empty. Never compare it and never use it as a map key. `internal/archtest` fails on both.
`PackageVersion.CanonicalPURL()` is the PURL of the canonical name and version. Only the target key
of a PURL target uses it.

**Package**:
One package version that a manifest declares or resolves, with the data that the enrichers add.
`model.Package` holds the identity (`ID`), `Direct`, `Dev`, `Local`, `Change`, the lockfile facts
(`Line`, `Resolved`, `Integrity`) and the data fields (`Insight`, `PreviousInsight`, `Malware`,
`Usage`). A nil data field means the data source did not answer.
_Avoid_: dependency (as a type name), component

**Local package**:
A workspace, path or editable package. It is not a registry package, and no enricher looks it up.
`Package.Local`.
_Avoid_: internal package (see dependency confusion), project package

**Manifest**:
One file or input that declares packages: a lockfile, a dependency manifest, a workflow, an SBOM, an
image, a PURL, the endpoint or an agent config file. `model.Manifest` holds its path, kind,
extractor, packages and optional graph. Its id is `m-` plus 12 hex characters of the path and the
extractor.
_Avoid_: lockfile (when you mean any manifest), dependency file

**Manifest kind**:
What a manifest is: `lockfile`, `manifest`, `workflow`, `sbom`, `image`, `purl`, `endpoint`,
`agent-config`, `installed`. `model.ManifestKind`. The value `manifest` means a file of declared
dependencies with no lockfile, such as `package.json` in manifest mode. A `workflow` or `agent-config`
manifest can hold no package, because its controls read the file. An `installed` manifest is the
metadata of a package on disk, such as `node_modules/left-pad/package.json`, or a Go binary.

**Package selection**:
Where a scan finds packages: `declared` (the lockfiles and the manifests), `installed` (the
packages on disk) or `all`. `model.Packages`, the `--packages` flag and the `scan.packages` config
key. A directory defaults to `declared`, an image to `all`. `internal/plugins/extractors/installed`
holds the extractors of installed packages.
_Avoid_: mode (a scan mode is full or delta)

**Package origin**:
Where the manifest of a package found it: `declared` or `installed`. `model.ManifestKind.Origin`, and
`package.origin` in the policy input. The packages of an `installed` or an `endpoint` manifest are
installed. The others are declared.

**Dependency graph**:
The edges between the packages of one manifest. Its roots are the direct dependencies. `model.Graph`
keys its nodes by package key, so two spellings of one version are one node.
_Avoid_: tree

## Scans

**Target**:
What the user names for a scan: a directory, a git URL, an image, an SBOM file or a PURL. `vet endpoint
audit` has the machine as its target. The **target label** is the target as the user typed it. The
**target key** is the canonical form that groups the scans of one target, such as an absolute path,
`git:github.com/owner/repo`, `image:...`, `purl:...` or `endpoint:<hostname>`. `plugin.Artifact.Label`
and `plugin.Artifact.Key` hold them.
_Avoid_: source (when you mean what the user typed), project, repository

**Source**:
The plugin that reads a target and yields its artifacts: `dir`, `git`, `image`, `sbom`, `purl` and
`endpoint`. `plugin.Source`. `sources.Detect` picks the source from the target.
_Avoid_: input, provider

**Artifact**:
One input that a source yields for a scan: a directory, an image, an SBOM, a PURL or the endpoint.
`plugin.Artifact` and `plugin.ArtifactKind`. A git repository yields a directory artifact. A source
can put manifests and inventory items in the artifact itself.
_Avoid_: target (when you mean the input that the source yields)

**Scan**:
One evaluation of one target, saved under one scan id in one scan file and one row of the scan
index. A scan can span several process runs when vet continues it. `report.ScanInfo` describes it in
a report.
_Avoid_: run (a run is one process execution of a scan), job, analysis

**Scan kind**:
What a scan looks at: `scan` (a project) or `endpoint` (this machine). `report.ScanKind`.

**Scan mode**:
How a scan treats the target: `full` or `delta`. `report.ScanMode`. **Pull request mode** is the
user-facing name of `delta`. A scan is in pull request mode when it has a base ref.
_Avoid_: diff mode, `--mode` (that flag sets the messaging mode)

**Base ref**:
The git ref that pull request mode compares the target with: `--base-ref` and `ScanInfo.BaseRef`.
The engine reads the manifests at the base ref, and caches that **base extraction** in
`<state dir>/bases`.
_Avoid_: base (alone), base branch

**Change**:
How pull request mode saw a package, a manifest, an inventory item or a capability change against the
base ref: `ADDED`, `UPGRADED`, `DOWNGRADED`, `MODIFIED`, `REMOVED`, `UNCHANGED`, or empty in a full
scan. `model.Change`. `MODIFIED` means the same version with another resolved URL, integrity or local
mark. A change **introduces** content when it is `ADDED`, `UPGRADED`, `DOWNGRADED` or `MODIFIED`
(`Change.Introduces`). Pull request mode keeps only the findings on introduced content.
_Avoid_: diff, delta status

**Previous version**:
The base version of an upgraded or downgraded package. `Package.PreviousVersion`, with its data in
`Package.PreviousInsight`. It is not a previous scan.
_Avoid_: prior version, old version

**Stage**:
One step of the engine: `extract`, `enrich`, `evaluate` and `report`. The scan file records the
state of each stage. **Finalize** is not a stage. It is the hook (`engine.Finalizer`) that applies the
policy after the stages.
_Avoid_: phase (the plan uses phase for its work items), step (the view's line for a stage)

**Batch**:
The packages that one enricher call gets: at most `BatchSize`, default 100, in package key order. Each
batch commits in its own transaction, so an interrupted scan keeps the batches that finished.

**Continue**:
What `vet scan` does with a stopped scan of the same target. It keeps the work that finished, when
the options hash and the vet version match and the scan is younger than `state.continue_within`.
vet looks only at the newest scan of the target. A newer scan supersedes a stopped scan.
`--resume` takes the newest stopped scan, also when a newer scan exists.
`--resume` continues a stopped scan of any age. `--fresh` always starts a new scan.
_Avoid_: retry, restart. Use stopped or interrupted for the scan, and `interrupted` for the index status.

**Fail open**:
The rule that a scan goes on when a remote backend does not answer. The plugin returns
`plugin.ErrUnavailable`, the scan records a diagnostic, and the controls that need that data report
nothing. `--strict` turns any diagnostic into exit 3.
_Avoid_: best effort, soft fail

**Diagnostic**:
An error or a limit that did not stop the scan, with a level (`warning` or `error`), a code, a
component and a count. `report.Diagnostic`. In pull request mode, a parse error also has the change
of its file. The codes of the scan engine are constants in `report`, such as
`report.CodeEnrichUnavailable`, because a reader of a report acts on them. Each other code is a
constant next to the code that records it, such as `policy.CodeRuleFailed`.
_Avoid_: warning (as a type), error record, issue

## Data

**Enricher**:
The plugin that adds data to a batch of packages: `insights`, `malysis`, `codeusage` and
`actionrefs`. `plugin.Enricher`. Each enricher has a **version** that changes when its mapping
changes, so the enrichment cache drops old results. Each enricher sets one field of
`model.Enrichment`, which `model.Package` embeds. The engine, the scan file and the enrichment cache
copy the data through that struct.
_Avoid_: analyzer, fetcher, provider

**Insight**:
The package data from SafeDep Insights v2: vulnerabilities, licenses, publish dates, deprecation,
provenance, OpenSSF Scorecard, source repository, stars, downloads and the latest version.
`model.Insight`, set by the `insights` enricher.
_Avoid_: metadata, package info

**License expression**:
The license of a package as an SPDX license expression (SPDX 2.3 Annex D), such as `MIT OR
Apache-2.0`. `spdxlicense.Parse` builds it from the declared license values of a package and joins
two or more values with `AND`. `spdxlicense.Policy` checks it against the allow and the deny list of
the license control. `spdxlicense.Equal` compares the canonical form of two licenses.
_Avoid_: license string (a string compare misses `GPL-3.0` and `GPL-3.0-only`)

**SafeDep Threat Intel**:
The user-facing name of the malware verdict service. `model.MalwareAnalysis` holds its verdict on
`Package.Malware`. Malysis is the internal name. The enricher, the package and the config key keep the
name `malysis`. The evidence source is `threat-intel`.
_Avoid_: Malysis in user-facing text, malware scanner

**Enrichment cache**:
The shared SQLite file `cache.db` in the cache directory that keeps enricher results, keyed by package
key, enricher and enricher version. `state.Cache`. The `cache.*` config keys and `--no-cache` set it.
_Avoid_: cache (alone, when the base cache or the config section could be meant)

**Gap**:
A missing backend contract that limits a control or a plugin, numbered G1 to G11. The vet v2 plan in
`safedep/control-tower` holds the gap table. A code comment names the gap where the code works around
it, as in `// gap G2: ...`.
_Avoid_: TODO, limitation

**Impostor commit**:
A commit that an action pins with a SHA, and that no branch and no tag of the named repository
contains. GitHub serves each commit of a fork network through each repository of the network, so the
commit can come from a fork. `model.ActionCommit` on `Package.Action`, set by the `actionrefs`
enricher. The `impostor-commit` control reports it.
_Avoid_: fork commit, orphan commit, dangling commit

**Code usage**:
The evidence that the target's code imports a package, and in which files. `model.Usage`, set by the
`codeusage` enricher. The engine adds it to package findings as evidence. It is import-level evidence,
not call-graph reachability.
_Avoid_: reachability (except in "reachability annotation"), usage graph

**Signature**:
A rule that names a call in source code, such as a call to the OpenAI client. The `codeusage` enricher
embeds the signatures as YAML under `signatures/`. A **match** is one call that hits a signature.
_Avoid_: pattern, rule (when you mean a signature)

**Capability**:
A behavior of the application that a signature finds, with each matched call as an **occurrence**.
`report.Capability` and `report.Occurrence`. Its id is the signature id. Tags (`ai`, `cryptography`,
`weak`) give it a capability kind: `ai`, `crypto` or `other`.
_Avoid_: feature, signature (when you mean the result)

**xBOM**:
All the capabilities of a scan. The **AI BOM** is the capabilities with the `ai` tag. The **CBOM** is
the capabilities with the `cryptography` tag, which the CycloneDX format writes as cryptographic
assets.
_Avoid_: SBOM (an SBOM lists packages)

## Findings

**Control**:
A plugin that evaluates one manifest with its packages and returns findings. `plugin.Control`, built
in under `internal/plugins/controls`. A **control id** is one kind of finding that a control emits,
such as `unpinned-action` or `typosquat`. One control emits one or more control ids, and
`plugin.Describer` lists them as `plugin.ControlInfo`. An **application control**
(`plugin.ApplicationControl`) also evaluates the application once per scan.
_Avoid_: check (a doctor check or a Scorecard check), rule (a policy rule), analyzer, filter

**Control catalog**:
The list of controls and their phases in the vet scanning program design in `safedep/control-tower`.
Package docs cite it as "control catalog, phase N".

**Family**:
The group of a control id for the report summary: `malware`, `vulnerability`, `cooldown`,
`workflow`, `lockfile`, `agent-config`, `ai-bom`, `license`, `hygiene`, `reputation`.
`finding.Family`. A family is not a control name. The `hygiene` control emits the `license` family,
for example.
_Avoid_: category, type

**Finding**:
One problem that a control found. `finding.Finding` is the one struct for every control. Build it with
`finding.ForPackage`, `ForFile`, `ForManifest` or `ForApplication`.
_Avoid_: issue, violation, alert, result

**Finding id**:
The stable id of a finding: `f-` plus 16 hex characters of a hash over the control id, the subject and
the **finding key** (`finding.Key`: a discriminator such as the advisory id, and an occurrence count).
The hash leaves out the line, the severity, the text and the vet version, so the id stays the same
across scans. A **short id** is a prefix of at least 10 characters.
_Avoid_: finding hash, fingerprint

**Subject**:
What a finding is about: exactly one of a package (in one manifest), a file, a manifest or an
application. `finding.Subject` and `finding.SubjectKind`. The **locus** (`finding.Locus`) is the place
in a file: path, lines and snippet.
_Avoid_: target, resource, location (when you mean the subject)

**Severity**:
How bad a finding is: `critical`, `high`, `medium`, `low`, `info`. `finding.Severity`. A control id
has a default severity in `ControlInfo`. A finding can differ.
_Avoid_: priority, level

**Confidence**:
How sure the control is: `high`, `medium`, `low`. `finding.Confidence`, default `high`.

**Evidence**:
One fact that supports a finding, with its source, such as `threat-intel` or `codeusage`.
`finding.Evidence`.

**Remediation**:
How the user fixes a finding: a summary, and optionally a fixed version or a command.
`finding.Remediation`.
_Avoid_: advice, fix (as a type; `vet fix` is a command)

## Policy and gate

**Policy**:
A version 2 YAML document of rules and suppressions. `internal/policy`. A **policy source**
(`plugin.PolicySource`) loads policy documents: the `file` source and the `tenant-policy` cloud plugin.
A **policy name** with no separator and no extension resolves to `<config dir>/policies/NAME.yml`.
_Avoid_: filter suite, policy file (when a policy source is meant)

**Rule**:
A policy entry with an id, a CEL condition (`when`) and an action: `fail` or `warn`. `policy.Rule`.
The CEL input is `finding`, `package` and `manifest` (`policy.Input`). `package.is(name)` and
`package.version_cmp(version)` compare under the rule of the ecosystem. With no version order,
`version_cmp` gives no answer, and a condition that needs the answer does not match. A **broken rule** is a fail rule
that errors at evaluation, and it fails the gate. `Finding.PolicyRule` names the rule that matched.
_Avoid_: filter, check, control

**Suppression**:
A policy entry that hides a finding from the gate, selected by finding id, PURL or control id, with a
required reason and an optional expiry. `policy.Suppression`. The finding keeps a
`finding.Suppression` record and stays in the report. An expired suppression matches nothing and adds
a diagnostic.
_Avoid_: exception, ignore, waiver, allowlist

**Gate**:
The pass or fail decision of a scan: `NONE` (no gate set), `PASS` or `FAIL`, with the severity, the
policies, the rules and the finding ids that decided it. `report.Gate`. `--fail-on SEVERITY` or
`--fail-on attacks` sets the `report.FailOn` part, and policy fail rules set the rule part. A plain
scan has no gate and exits 0. A failed gate exits 1.
_Avoid_: threshold, build breaker

**Attacks gate**:
The gate of `--fail-on attacks`. It fails on an unsuppressed finding of an attack control, and each
other finding warns. `plugin.ControlInfo.Attack` marks the attack controls: `malware`,
`impostor-commit` and `suspicious-command`. `controls.AttackIDs` lists them. It is the default gate
of the vet GitHub Action.
_Avoid_: malware-only mode, safe mode

## Reports and output

**Report**:
The stream that a scan produces: a header, then records, then a trailer. The `report` package owns the
types and the JSON Schema (`schema/`). `plugin.Report` is the read view of a completed scan. The report
stream is the public contract. The scan file is not.
_Avoid_: result, output (when you mean the report)

**Record**:
One item of a report: exactly one of a manifest, a package entry, an inventory item, a capability, a
finding or a diagnostic. `report.Record` and `report.Kind`. The **header** (`report.Header`) and the
**trailer** (`report.Trailer`, with the summary and the gate) frame the records.

**Report format**:
One way to write a report, provided by one sink plugin: `table`, `plain`, `json`, `jsonl`, `markdown`,
`sarif`, `cyclonedx`, `gitlab`, `bitbucket`, `cloud` and `pr-comment`. The format name is the sink
name. `-o FORMAT` writes to stdout, and `--report FORMAT=PATH` writes to a file. A **sink**
(`plugin.Sink`) is the plugin. A **publisher** (`plugin.Publisher`) is a sink that also takes
`--report FORMAT` with no path, and sends the report to a place of its own, such as a pull request.
_Avoid_: reporter, exporter

**Printer format**:
The output format of a command that prints data but no report, such as `vet report list` or `vet
doctor`: `table`, `plain`, `json`, `jsonl`. `internal/tui/printer`. It is not a report format.

**Messaging mode**:
How vet writes messages to stderr: `rich`, `plain` or `agent`, with `auto` to detect it. `--mode` and
`output.mode`. vet picks `agent` when it runs under an AI agent.
_Avoid_: scan mode, output mode (when you mean the messaging mode)

**View**:
The stderr text of a scan: the step lines, the progress, the diagnostics, the gate line and the next
steps. `internal/view`. The report goes to stdout through a sink, never through the view.

## CI

**CI context**:
The CI run that runs vet: the platform, the repository, the links and the change that it builds.
`ci.Context`, from `ci.Detect`. The change (`ci.Change`) is a pull request, with its number, its base
and head commits, and whether it comes from a fork. A push and a schedule have no change.
_Avoid_: CI environment, build info

**Pull request comment**:
The one comment that the `pr-comment` publisher posts on a pull request and edits on each push. A
marker at the start finds it, and a key keeps apart the comments of two vet steps.
`internal/plugins/sinks/prcomment`. An **adapter** (`ci.Commenter`) writes it to one platform:
`githubci` with the token of the run, or `ghcp` through the comment proxy.
_Avoid_: PR bot, sticky comment, review

**State block**:
The hidden block at the end of the pull request comment. It holds the head commit and the finding ids
of the last run, so the next run can say what a push resolved. It never changes the gate. A block
that does not parse gives no progress line.
_Avoid_: comment state, metadata

**Comment proxy**:
The SafeDep service that posts the pull request comment of a fork run of a public repository, because
the token of a fork run cannot write. `ghcp`, in `internal/plugins/cloud/ghcp`.
_Avoid_: comment bot, relay

**GitHub Action**:
`action.yml` and the `action/` scripts of this repository. `install.sh` picks, checks and installs a
vet release. `scan.sh` runs `vet scan` and maps the report to the outputs. Each rule of the gate, the
comment and the state is in Go. `vet ci init` writes the workflow that uses it.
_Avoid_: vet-action (the v1 action)

**Release channel**:
The set of releases that the action takes with `version: auto`: `prerelease` or `stable`.
`action/channel.json` on the default branch selects it. It never shortens the release cooldown.
_Avoid_: track, ring

**Release cooldown**:
The age that a release needs before the action or `vet ci update` takes it. The age counts from the
latest of the publish time, the asset update times and, in the action, the attestation time.
`github.Choice` and `action/resolve.jq`. It is not the dependency cooldown of the
`dependency-cooldown` control.

## State and configuration

**State directory**:
The directory of the scan index and the scan files. The **scan index** (`vet.db`, `state.Index`)
holds one row for each scan. The **scan file** (`scans/<id>.db`, `state.Scan`) holds one scan as it
runs, and implements `plugin.State` and `plugin.Report`. `state.Store` is the handle for both.
**Retention** deletes old scans, and never the last completed scan of a target. A scan file
records its **format**. vet refuses a scan file of another format and does not migrate it.
_Avoid_: database, history

**Saved scan**:
A completed scan that `vet report` commands read by id, by `last`, or from a scan file or a `json` or
`jsonl` report file. `reportdoc.Doc` holds one in memory.
_Avoid_: saved report (when you mean the scan)

**Config layer**:
One origin of a config value: `default`, `managed`, `file`, `env` or `flag`, from lowest to highest.
`config.Layer`. Only one file layer applies.

**Managed config**:
A config file that an administrator puts in the managed directory. It applies only when root owns it.
**Lockdown** (`managed.lockdown: true`) locks each key that the managed file sets: an env var for a
locked key is ignored, and a flag for it exits 2.

**Plugin options**:
The config section of one plugin: `plugins.<name>.enabled` and `plugins.<name>.options`.
`plugin.Config` decodes the options and rejects an unknown key. `internal/plugins/builtin` is the one
list of built-in plugins with a config section.

**Ephemeral**:
A run with no saved state: `--ephemeral` or `VET_EPHEMERAL`. vet also falls back to it when the
default state directory is not writable.

## Endpoint

**Endpoint**:
The machine that `vet endpoint audit` checks: a developer machine or a CI runner. Its target key is
`endpoint:<hostname>`. The endpoint source reads its AI tools, MCP servers, agent skills, editor
plugins, IDE extensions, global npm packages and agent config files. A `cloud.endpoints.*` key or a
`vet doctor` `endpoint.*` check names a SafeDep service URL, not an endpoint.
_Avoid_: host, device, agent

**Inventory item**:
A tool on an endpoint that is not a package of a manifest: `ai-tool`, `mcp-server`, `skill` or
`editor-plugin`. `report.InventoryItem` and `report.InventoryKind`. `inventory.Item` in
`internal/endpoint/inventory` is the one detailed form that every endpoint scanner builds and that
the cloud sync sends. Its `inventory.Kind` is finer than the report kind, and the endpoint source
maps it to the report kind. `inventory.ItemIdentity` and `inventory.SourceID` make its keys. An IDE
extension that a marketplace serves is a package of an `endpoint` manifest, not an inventory item.
_Avoid_: asset, tool (as a type name), AI tool (as a type; the report kind is `ai-tool`)

**Agent config**:
A file that tells an AI agent or an editor to run commands or connect to servers: editor tasks, agent
settings and hooks, devcontainer files, git hooks, MCP configs and agent instruction files.
`internal/plugins/internal/agentfiles` classifies them, and the `agent-config` control checks them.
`agentfiles.HomeFiles` is the one list of the files that a home directory can hold.

## Tests

**Golden file**:
A file that holds the expected output of a test. `internal/golden` compares it. `make golden`
rewrites the golden files and the report schemas.

**Acceptance catalog**:
The list of user-facing guarantees in `test/acceptance/catalog.yaml`. Each row has a feature id (the
script path), a tier (`P0` an incident if it breaks, `P1` important, `P2` tracked) and labels. A
`testscript` script under `test/acceptance/scripts/` checks the guarantee. A script with no row fails
`TestCatalogIntegrity`.

**Conformance check**:
A test in `plugin/plugintest` that a plugin of each kind must pass, such as `TestControl` or
`TestSink`. `plugintest.MemState` and `plugintest.SampleReport` are the in-memory scan and the sample
report for these tests.

## Overloaded words

Some words name more than one thing in the code. Qualify them.

| Word | Meanings | Write |
| --- | --- | --- |
| base | the base ref of pull request mode; the older scan of `vet report diff` | base ref; base scan |
| cache | the enrichment cache; the base extraction cache; the `cache` config section | enrichment cache; base cache |
| check | a `vet doctor` check; `plugin.Checker`; an OpenSSF Scorecard check | doctor check; Scorecard check. Never for a control |
| cooldown | the dependency cooldown of the `dependency-cooldown` control; the release cooldown of the action | dependency cooldown; release cooldown |
| endpoint | the machine; a SafeDep service URL | endpoint; service URL |
| key | package key; finding key; target key | the full term |
| kind | scan, artifact, manifest, record, subject, inventory, capability and plugin kinds | the full term |
| mode | scan mode (`full`, `delta`); messaging mode (`--mode`) | scan mode or pull request mode; messaging mode |
| report | the report stream; `plugin.Report`; a report format; the `cloud` report sink | the full term |
| root | the roots of a dependency graph; `Artifact.Root`; an application root | graph root; target root; application root |
| rule | a policy rule; a workflow control rule; the identity rule of an ecosystem | policy rule; identity rule |
| source | a source plugin; a policy source; an evidence source | the full term |
| store | `state.Store`; the `policy.Store` interface | state store |
