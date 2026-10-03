package workflow

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/finding"
)

// The workflow hardening controls (control catalog, phase 4).
const (
	IDExcessivePermissions = "excessive-permissions"
	IDSecretsExposure      = "secrets-exposure"
	IDEnvInjection         = "github-env-injection"
	IDCachePoisoning       = "cache-poisoning"
	IDArtifactPoisoning    = "artifact-poisoning"
	IDSelfHostedRunner     = "self-hosted-runner"
	IDSpoofableBot         = "spoofable-bot-condition"
)

func init() {
	for _, i := range []struct {
		id    string
		sev   finding.Severity
		title string
		desc  string
	}{
		{
			IDExcessivePermissions, finding.SeverityMedium, "Workflow with excessive permissions",
			"The workflow sets no permissions, so its token gets the default permissions of the repository, or it asks for write-all. A step that an attacker controls can then write to the repository.",
		},
		{
			IDSecretsExposure, finding.SeverityHigh, "Secrets exposed to more code than needs them",
			"The workflow passes every secret to a reusable workflow with secrets: inherit, dumps them with toJSON(secrets), or puts a secret in a script. A step that prints or leaks the script leaks the secret.",
		},
		{
			IDEnvInjection, finding.SeverityHigh, "Untrusted write to GITHUB_ENV or GITHUB_PATH",
			"A script writes to GITHUB_ENV or GITHUB_PATH in a workflow that handles the input of an outside user. The user can set an environment variable or a path, such as LD_PRELOAD, for the next steps.",
		},
		{
			IDCachePoisoning, finding.SeverityMedium, "Cache in a release or deploy workflow",
			"A release or deploy job restores a cache. A pull request workflow can write a poisoned cache, and the release then builds with it.",
		},
		{
			IDArtifactPoisoning, finding.SeverityMedium, "Artifact download in a workflow_run workflow",
			"A workflow_run workflow downloads an artifact of the triggering run. A pull request controls that artifact, and the privileged workflow uses it.",
		},
		{
			IDSelfHostedRunner, finding.SeverityMedium, "Job on a self-hosted runner",
			"A job runs on a self-hosted runner. In a public repository, a pull request from a fork can run code on the runner and keep a foothold on it.",
		},
		{
			IDSpoofableBot, finding.SeverityMedium, "Condition on a bot actor name",
			"A condition trusts the actor name of a bot, such as dependabot[bot]. github.actor is the last actor of the run, and a user can make the bot the actor of a run that the user controls.",
		},
	} {
		infos[i.id] = pluginInfo(i.id, i.sev, i.title, i.desc)
	}
}

var hardeningIDs = []string{
	IDExcessivePermissions, IDSecretsExposure, IDEnvInjection, IDCachePoisoning,
	IDArtifactPoisoning, IDSelfHostedRunner, IDSpoofableBot,
}

var (
	toJSONSecrets  = regexp.MustCompile(`(?i)tojson\(\s*secrets\s*\)`)
	secretInScript = regexp.MustCompile(`(?i)\$\{\{\s*secrets\.([a-z0-9_]+)\s*\}\}`)
	envFileWrite   = regexp.MustCompile(`(?i)(>>?\s*"?\$\{?(GITHUB_ENV|GITHUB_PATH)\}?"?|\$env:(GITHUB_ENV|GITHUB_PATH))`)
	privilegedJob  = regexp.MustCompile(`(?i)release|deploy|publish`)
	botCondition   = regexp.MustCompile(`(?i)github\.(triggering_)?actor\s*[!=]=\s*['"][^'"]*\[bot\]['"]`)
)

var cacheActions = []string{"actions/cache@", "actions/cache/restore@"}

var setupActions = []string{"actions/setup-node@", "actions/setup-python@", "actions/setup-go@", "actions/setup-java@", "actions/setup-dotnet@"}

var artifactDownloads = []string{"actions/download-artifact@", "dawidd6/action-download-artifact@"}

func (c *Control) hardening(e *emitter) {
	d := e.doc
	if get(d.root, "jobs") == nil {
		// A composite action has no jobs, no token and no runner.
		c.secretsInScripts(e)
		c.envInjection(e)
		return
	}
	c.permissions(e)
	c.secretsExposure(e)
	c.envInjection(e)
	c.cachePoisoning(e)
	c.artifactPoisoning(e)
	c.selfHosted(e)
	c.spoofableBot(e)
}

func (c *Control) permissions(e *emitter) {
	d := e.doc
	top := get(d.root, "permissions")
	if scalar(top) == "write-all" {
		e.add(IDExcessivePermissions, top.Line, "workflow", "permissions: write-all", "The workflow asks for write-all permissions",
			&finding.Remediation{Summary: "Set permissions: contents: read at the top, and give each job only the write permissions that it needs."})
	}
	for _, j := range d.jobs() {
		p := get(j.node, "permissions")
		if scalar(p) == "write-all" {
			e.add(IDExcessivePermissions, p.Line, j.job, "permissions: write-all", fmt.Sprintf("Job %s asks for write-all permissions", j.job),
				&finding.Remediation{Summary: "Give the job only the write permissions that it needs."})
		}
	}
	if top != nil {
		return
	}
	for _, j := range d.jobs() {
		if get(j.node, "permissions") == nil && get(j.node, "uses") == nil {
			on := keyLine(d.root, "on")
			e.add(IDExcessivePermissions, on, "default", "permissions", "The workflow sets no permissions, so its token gets the repository default",
				&finding.Remediation{Summary: "Add permissions: contents: read at the top of the workflow."})
			return
		}
	}
}

func (c *Control) secretsExposure(e *emitter) {
	d := e.doc
	for _, j := range d.jobs() {
		if s := get(j.node, "secrets"); scalar(s) == "inherit" {
			e.add(IDSecretsExposure, s.Line, j.job, "secrets: inherit", fmt.Sprintf("Job %s passes every secret to %s", j.job, scalar(get(j.node, "uses"))),
				&finding.Remediation{Summary: "Pass only the secrets that the reusable workflow needs, by name."})
		}
	}
	walkScalars(d.root, func(n *yaml.Node) {
		if loc := toJSONSecrets.FindStringIndex(n.Value); loc != nil {
			e.add(IDSecretsExposure, line(n, loc[0]), "toJSON", "toJSON(secrets)", "The workflow reads every secret with toJSON(secrets)",
				&finding.Remediation{Summary: "Read each secret that the step needs by name."})
		}
	})
	c.secretsInScripts(e)
}

func (c *Control) secretsInScripts(e *emitter) {
	for _, s := range e.doc.steps() {
		run := get(s.node, "run")
		if scalar(run) == "" {
			continue
		}
		for _, m := range secretInScript.FindAllStringSubmatchIndex(run.Value, -1) {
			name := run.Value[m[2]:m[3]]
			e.add(IDSecretsExposure, line(run, m[0]), name, "secrets."+name, fmt.Sprintf("The script reads secrets.%s directly", name),
				&finding.Remediation{Summary: fmt.Sprintf("Set env: %s: ${{ secrets.%s }} on the step, and read \"$%s\" in the script.", name, name, name)})
		}
	}
}

func (c *Control) envInjection(e *emitter) {
	dangerous := slices.ContainsFunc(e.doc.triggers(), func(t string) bool {
		return slices.Contains(dangerousTriggers, t) || t == "issue_comment" || t == "issues"
	})
	for _, s := range e.doc.steps() {
		run := get(s.node, "run")
		loc := envFileWrite.FindStringSubmatchIndex(scalar(run))
		if loc == nil {
			continue
		}
		untrustedInput := false
		for _, m := range expression.FindAllStringSubmatch(run.Value, -1) {
			if len(untrusted(m[1])) > 0 {
				untrustedInput = true
			}
		}
		if !dangerous && !untrustedInput {
			continue
		}
		e.add(IDEnvInjection, line(run, loc[0]), s.job, envFile(run.Value, loc), "A script writes to GITHUB_ENV or GITHUB_PATH with input that an outside user controls",
			&finding.Remediation{Summary: "Do not write untrusted input to GITHUB_ENV or GITHUB_PATH. Pass it to the next step as a step output, and quote it there."})
	}
}

func (c *Control) cachePoisoning(e *emitter) {
	d := e.doc
	privilegedRun := slices.Contains(d.triggers(), "release") || pushesTags(d)
	for _, j := range d.jobs() {
		if !privilegedRun && !privilegedJob.MatchString(j.job) && !privilegedJob.MatchString(scalar(get(j.node, "name"))) {
			continue
		}
		for _, s := range d.steps() {
			if s.job != j.job {
				continue
			}
			uses := get(s.node, "uses")
			v := scalar(uses)
			restores := hasPrefixAny(v, cacheActions) || (hasPrefixAny(v, setupActions) && scalar(get(get(s.node, "with"), "cache")) != "")
			if !restores {
				continue
			}
			e.add(IDCachePoisoning, uses.Line, j.job, v, fmt.Sprintf("Release job %s restores a cache with %s", j.job, v),
				&finding.Remediation{Summary: "Build releases with no cache, or with a cache key that only the release workflow writes."})
		}
	}
}

func pushesTags(d *document) bool {
	push := get(get(d.root, "on"), "push")
	return get(push, "tags") != nil
}

func (c *Control) artifactPoisoning(e *emitter) {
	if !slices.Contains(e.doc.triggers(), "workflow_run") {
		return
	}
	for _, s := range e.doc.steps() {
		uses := get(s.node, "uses")
		if v := scalar(uses); hasPrefixAny(v, artifactDownloads) {
			e.add(IDArtifactPoisoning, uses.Line, s.job, v, fmt.Sprintf("Job %s downloads an artifact of the triggering run", s.job),
				&finding.Remediation{Summary: "Treat the artifact as untrusted: check it, and do not run it or write it to the paths of the workflow."})
		}
	}
}

func (c *Control) selfHosted(e *emitter) {
	// Known uncovered case: vet does not know whether the repository is
	// public, so the control warns on every self-hosted job.
	for _, j := range e.doc.jobs() {
		r := get(j.node, "runs-on")
		labels := []string{scalar(r)}
		if r != nil && r.Kind == yaml.SequenceNode {
			labels = nil
			for _, n := range r.Content {
				labels = append(labels, scalar(resolve(n)))
			}
		}
		if slices.Contains(labels, "self-hosted") {
			e.add(IDSelfHostedRunner, r.Line, j.job, "runs-on: self-hosted", fmt.Sprintf("Job %s runs on a self-hosted runner", j.job),
				&finding.Remediation{Summary: "In a public repository, run pull request jobs on GitHub-hosted runners, or use ephemeral self-hosted runners."})
		}
	}
}

func (c *Control) spoofableBot(e *emitter) {
	check := func(job string, n *yaml.Node) {
		if loc := botCondition.FindStringIndex(scalar(n)); loc != nil {
			e.add(IDSpoofableBot, line(n, loc[0]), job, scalar(n)[loc[0]:loc[1]], "A condition trusts the actor name of a bot",
				&finding.Remediation{Summary: "Check github.event.pull_request.user.login, which a user cannot spoof, in place of github.actor."})
		}
	}
	for _, j := range e.doc.jobs() {
		check(j.job, get(j.node, "if"))
	}
	for _, s := range e.doc.steps() {
		check(s.job, get(s.node, "if"))
	}
}

// envFile returns GITHUB_ENV or GITHUB_PATH from a match of envFileWrite.
func envFile(script string, loc []int) string {
	for i := 4; i+1 < len(loc); i += 2 {
		if loc[i] >= 0 {
			return script[loc[i]:loc[i+1]]
		}
	}
	return ""
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// keyLine returns the line of a key of a mapping, or 1.
func keyLine(m *yaml.Node, key string) int {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i].Line
		}
	}
	return 1
}

// walkScalars calls fn for each scalar value of a node tree.
func walkScalars(n *yaml.Node, fn func(*yaml.Node)) {
	n = resolve(n)
	if n == nil {
		return
	}
	if n.Kind == yaml.ScalarNode {
		fn(n)
		return
	}
	for i, c := range n.Content {
		if n.Kind == yaml.MappingNode && i%2 == 0 {
			continue
		}
		walkScalars(c, fn)
	}
}
