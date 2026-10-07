// Package action_test runs the scripts of the GitHub Action with a fake gh
// and a fake vet, so the release choice and the checks run with no network.
package action_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// needTools skips the test when a tool of the scripts is missing, except
// in CI, where the test must run.
func needTools(t *testing.T, tools ...string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the action tests run on Linux and macOS")
	}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			require.Empty(t, os.Getenv("CI"), "CI needs %s for the action tests", tool)
			t.Skipf("needs %s", tool)
		}
	}
}

// run runs a script with env on top of a clean environment. It returns the
// output and the exit code.
func run(t *testing.T, dir string, env map[string]string, script string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + t.TempDir()}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return string(out), exit.ExitCode()
	}
	require.NoError(t, err, string(out))
	return string(out), 0
}

func writeFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(data), mode))
}

type resolveCase struct {
	Name          string `json:"name"`
	Releases      string `json:"releases"`
	Channel       string `json:"channel"`
	CooldownHours int    `json:"cooldown_hours"`
	MinVersion    string `json:"min_version"`
	Now           string `json:"now"`
	Want          string `json:"want"`
}

// internal/github runs the same cases on Choice, so the two rules cannot
// drift.
func TestResolveOnTheSharedCases(t *testing.T) {
	needTools(t, "jq")
	data, err := os.ReadFile(filepath.Join("testdata", "resolve-cases.json"))
	require.NoError(t, err)
	var cases []resolveCase
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			out, err := exec.Command("jq", "-r", "-f", "resolve.jq",
				"--arg", "major", "v2",
				"--arg", "channel", tc.Channel,
				"--arg", "cooldown_hours", fmt.Sprint(tc.CooldownHours),
				"--arg", "min_version", tc.MinVersion,
				"--arg", "now", tc.Now,
				filepath.Join("testdata", tc.Releases)).Output()
			require.NoError(t, err)
			first, _, _ := strings.Cut(string(out), "\n")
			tag, _, _ := strings.Cut(first, "\t")
			assert.Equal(t, tc.Want, tag)
		})
	}
}

// release is a release that the fake gh serves.
type release struct {
	tag        string
	prerelease bool
	age        time.Duration
	// signedAge is the age of the attestation. Zero means the age of the
	// release.
	signedAge time.Duration
	unsigned  bool
	// noTime is an attestation that verifies with no verified time.
	noTime bool
	badSum bool
}

const archive = "vet_Linux_x86_64.tar.gz"

// fakeGH serves the channel file, the release list, the downloads and the
// attestations from $FAKE, and logs each call.
const fakeGH = `#!/usr/bin/env bash
echo "$*" >>"$FAKE/calls"
case "$1 $2" in
  "api repos/safedep/vet/contents/action/channel.json") cat "$FAKE/channel.json" 2>/dev/null ;;
  "api --paginate") cat "$FAKE/releases.json" ;;
  "release download")
    tag=$3
    shift 3
    while [ $# -gt 0 ]; do
      case $1 in --dir) dir=$2; shift 2 ;; *) shift ;; esac
    done
    cp "$FAKE/assets/$tag/"* "$dir/"
    ;;
  "attestation verify") cat "$FAKE/attestations/$(basename "$(dirname "$3")").json" 2>/dev/null ;;
  *) exit 2 ;;
esac
`

// tarball returns a tar.gz archive with a vet script that prints tag.
func tarball(t *testing.T, tag string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	script := "#!/bin/sh\necho " + tag + "\n"
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "vet", Mode: 0o755, Size: int64(len(script))}))
	_, err := tw.Write([]byte(script))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())
	return buf.Bytes()
}

// attestation is the output of gh attestation verify --format json. The
// CurrentTime entry is not a verified time.
func attestation(signed time.Time, noTime bool) string {
	stamps := `{"type": "CurrentTime", "uri": "", "timestamp": "` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`
	if !noTime {
		stamps += `, {"type": "Tlog", "uri": "https://rekor.sigstore.dev", "timestamp": "` + signed.Format(time.RFC3339Nano) + `"}`
	}
	return `[{"verificationResult": {"verifiedTimestamps": [` + stamps + `]}}]`
}

// installFixture writes the action copy and the fake gh data.
func installFixture(t *testing.T, now time.Time, remoteChannel string, releases []release) (actionDir, fake, bin string) {
	t.Helper()
	root := t.TempDir()
	actionDir = filepath.Join(root, "action")
	for _, name := range []string{"install.sh", "resolve.jq"} {
		data, err := os.ReadFile(name)
		require.NoError(t, err)
		writeFile(t, filepath.Join(actionDir, name), string(data), 0o755)
	}
	writeFile(t, filepath.Join(actionDir, "channel.json"), `{"v2": {"channel": "prerelease"}}`, 0o644)
	writeFile(t, filepath.Join(actionDir, "min-version"), "2.0.0-alpha.20261001000000\n", 0o644)

	fake = filepath.Join(root, "fake")
	bin = filepath.Join(root, "bin")
	writeFile(t, filepath.Join(bin, "gh"), fakeGH, 0o755)
	if remoteChannel != "" {
		writeFile(t, filepath.Join(fake, "channel.json"), remoteChannel, 0o644)
	}

	var list []map[string]any
	for _, r := range releases {
		published := now.Add(-r.age)
		list = append(list, map[string]any{
			"tag_name": r.tag, "draft": false, "prerelease": r.prerelease, "immutable": true,
			"published_at": published.Format(time.RFC3339),
			"assets":       []map[string]any{{"name": archive, "updated_at": published.Format(time.RFC3339)}},
		})
		data := tarball(t, r.tag)
		sum := sha256.Sum256(data)
		if r.badSum {
			sum[0] ^= 0xff
		}
		writeFile(t, filepath.Join(fake, "assets", r.tag, archive), string(data), 0o644)
		writeFile(t, filepath.Join(fake, "assets", r.tag, "checksums.txt"), hex.EncodeToString(sum[:])+"  "+archive+"\n", 0o644)
		if r.unsigned {
			continue
		}
		signed := published
		if r.signedAge != 0 {
			signed = now.Add(-r.signedAge)
		}
		writeFile(t, filepath.Join(fake, "attestations", r.tag+".json"), attestation(signed, r.noTime), 0o644)
	}
	data, err := json.Marshal(list)
	require.NoError(t, err)
	writeFile(t, filepath.Join(fake, "releases.json"), string(data), 0o644)
	return actionDir, fake, bin
}

func TestInstall(t *testing.T) {
	needTools(t, "jq", "tar", "awk", "mktemp")
	needOneOf(t, "sha256sum", "shasum")
	const (
		old    = "v2.0.0-alpha.20261002000000"
		middle = "v2.0.0-alpha.20261003000000"
		young  = "v2.0.0-alpha.20261004000000"
		stable = "v2.0.0"
	)
	day := 24 * time.Hour
	tests := []struct {
		name     string
		version  string
		cooldown string
		channel  string
		releases []release
		want     string
		exit     int
		output   string
	}{
		{
			name:     "auto takes the newest release older than the cooldown",
			releases: []release{{tag: old, prerelease: true, age: 3 * day}, {tag: young, prerelease: true, age: time.Hour}},
			want:     old,
			output:   "The choice comes from the prerelease channel and a release cooldown of 24 hours",
		},
		{
			name:     "the channel file on the default branch picks the stable releases",
			channel:  `{"v2": {"channel": "stable"}}`,
			releases: []release{{tag: stable, age: 3 * day}, {tag: "v2.0.1-alpha.20261003000000", prerelease: true, age: 2 * day}},
			want:     stable,
		},
		{
			name:     "the channel file cannot take a release inside the cooldown",
			channel:  `{"v2": {"channel": "prerelease", "cooldown": 0}}`,
			releases: []release{{tag: young, prerelease: true, age: time.Hour}},
			exit:     1,
			output:   "No vet release passes the release cooldown of 24 hours. The newest release " + young + " is 1 hour old. To use it now, set the version input to " + strings.TrimPrefix(young, "v"),
		},
		{
			name:     "a channel file that is not valid falls back to the copy of the action",
			channel:  `{"v2": {"channel": "nightly"}}`,
			releases: []release{{tag: old, prerelease: true, age: 3 * day}},
			want:     old,
			output:   "The action uses its own copy",
		},
		{
			name: "a young attestation makes the action take the next release",
			releases: []release{
				{tag: old, prerelease: true, age: 3 * day},
				{tag: middle, prerelease: true, age: 2 * day, signedAge: time.Hour},
			},
			want:   old,
			output: "The action skips " + middle + ", because its attestation is 1 hour old",
		},
		{
			name: "a wrong checksum fails the job",
			releases: []release{
				{tag: old, prerelease: true, age: 3 * day},
				{tag: middle, prerelease: true, age: 2 * day, badSum: true},
			},
			exit:   1,
			output: "The SHA-256 sum of " + archive + " does not match checksums.txt in the release " + middle,
		},
		{
			name: "an attestation that does not verify fails the job",
			releases: []release{
				{tag: old, prerelease: true, age: 3 * day},
				{tag: middle, prerelease: true, age: 2 * day, unsigned: true},
			},
			exit:   1,
			output: "The build attestation of " + archive + " does not verify. Do not use the release " + middle,
		},
		{
			name:     "an attestation with no verified time fails the job",
			releases: []release{{tag: old, prerelease: true, age: 3 * day, noTime: true}},
			exit:     1,
			output:   "The build attestation of " + old + " has no verified time",
		},
		{
			name:     "the cooldown input changes the age",
			cooldown: "0",
			releases: []release{{tag: old, prerelease: true, age: 3 * day}, {tag: young, prerelease: true, age: time.Hour}},
			want:     young,
		},
		{
			name:     "an exact version skips the cooldown",
			version:  strings.TrimPrefix(young, "v"),
			releases: []release{{tag: old, prerelease: true, age: 3 * day}, {tag: young, prerelease: true, age: time.Hour}},
			want:     young,
			output:   "The choice comes from the version input",
		},
		{
			name:     "an exact version still checks the checksum",
			version:  young,
			releases: []release{{tag: young, prerelease: true, age: time.Hour, badSum: true}},
			exit:     1,
			output:   "does not match checksums.txt in the release " + young,
		},
		{
			name:     "an exact version still checks the attestation",
			version:  young,
			releases: []release{{tag: young, prerelease: true, age: time.Hour, unsigned: true}},
			exit:     1,
			output:   "Do not use the release " + young,
		},
		{
			name:     "an exact version below the minimum fails",
			version:  "2.0.0-alpha.20260901000000",
			releases: []release{{tag: "v2.0.0-alpha.20260901000000", prerelease: true, age: 30 * day}},
			exit:     1,
			output:   "The version input names v2.0.0-alpha.20260901000000",
		},
		{
			name:    "a version of another major fails",
			version: "1.12.0",
			exit:    1,
			output:  "The version input is not valid: '1.12.0'",
		},
		{
			name:     "a cooldown that is not a number fails",
			cooldown: "1d",
			exit:     1,
			output:   "The release-cooldown input is not a count of hours: '1d'",
		},
		{
			name:     "a cooldown with a leading zero fails",
			cooldown: "024",
			exit:     1,
			output:   "The release-cooldown input is not a count of hours: '024'",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			actionDir, fake, bin := installFixture(t, now, tc.channel, tc.releases)
			runner := t.TempDir()
			path := filepath.Join(runner, "path")
			out, code := run(t, runner, map[string]string{
				"PATH":                    bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"FAKE":                    fake,
				"ACTION_VERSION":          tc.version,
				"ACTION_RELEASE_COOLDOWN": tc.cooldown,
				"RUNNER_OS":               "Linux",
				"RUNNER_ARCH":             "X64",
				"RUNNER_TEMP":             runner,
				"GITHUB_PATH":             path,
			}, filepath.Join(actionDir, "install.sh"))
			require.Equal(t, tc.exit, code, out)
			assert.Contains(t, out, tc.output)
			if tc.exit != 0 {
				assert.NoFileExists(t, path)
				return
			}

			dirs, err := os.ReadFile(path)
			require.NoError(t, err)
			got, err := exec.Command(filepath.Join(strings.TrimSpace(string(dirs)), "vet")).Output()
			require.NoError(t, err)
			assert.Equal(t, tc.want, strings.TrimSpace(string(got)))

			calls, err := os.ReadFile(filepath.Join(fake, "calls"))
			require.NoError(t, err)
			assert.NotContains(t, string(calls), "releases/latest")
			assert.Contains(t, string(calls), "release download "+tc.want+" --repo safedep/vet")
			assert.Contains(t, string(calls), `--cert-identity-regex ^https://github\.com/safedep/vet/\.github/workflows/(release-edge\.yml@refs/heads/(v2|main)|release\.yml@refs/tags/v2\.[0-9]+\.[0-9]+)$ --deny-self-hosted-runners`)
		})
	}
}

func needOneOf(t *testing.T, tools ...string) {
	t.Helper()
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			return
		}
	}
	needTools(t, tools[0])
}

// fakeVet logs its arguments and the comment options, writes the markdown
// and SARIF reports, prints the JSON report and exits with FAKE_EXIT. With
// FAKE_EXIT=3 it prints no report, as vet does on a runtime error.
const fakeVet = `#!/usr/bin/env bash
printf '%s\n' "$@" >"$FAKE/args"
echo "create=${VET_PLUGINS_PR_COMMENT_OPTIONS_CREATE:-} proxy=${VET_PLUGINS_PR_COMMENT_OPTIONS_PROXY:-}" >"$FAKE/env"
for arg in "$@"; do
  case $arg in
    markdown=*) head -c "${FAKE_SUMMARY_BYTES:-20}" /dev/zero | tr '\0' 'x' >"${arg#markdown=}" ;;
    sarif=*) echo '{}' >"${arg#sarif=}" ;;
  esac
done
if [ "${FAKE_EXIT:-0}" != 3 ]; then
  echo '{"trailer": {"summary": {"findings": 2}, "gate": {"outcome": "FAIL"}}}'
fi
exit "${FAKE_EXIT:-0}"
`

// fakeGit logs the auth header of a fetch and runs git.
const fakeGit = `#!/usr/bin/env bash
if [ "$1" = fetch ]; then
  echo "${GIT_CONFIG_KEY_0:-none}" >>"$FAKE/fetch"
fi
exec "$REAL_GIT" "$@"
`

func TestScan(t *testing.T) {
	needTools(t, "jq", "git", "base64", "mktemp")
	realGit, err := exec.LookPath("git")
	require.NoError(t, err)
	tests := []struct {
		name         string
		event        string
		env          map[string]string
		policy       bool
		policyDir    bool
		config       bool
		summaryBytes int
		// baseInOrigin puts the base commit only in the origin, so the
		// script fetches it. header is a token header of the checkout.
		baseInOrigin bool
		header       bool
		exit         int
		args         []string
		noArgs       []string
		comment      string
		outputs      []string
		noOutputs    []string
		output       string
		fetch        string
	}{
		{
			name:    "a pull request scans the change, applies the policy and comments",
			event:   "pull_request",
			policy:  true,
			env:     map[string]string{"FAKE_EXIT": "1"},
			exit:    1,
			args:    []string{"--fail-on\nattacks", "--base-ref\nBASE", "--report\npr-comment", "--policy\n.github/vet/policy.yml"},
			comment: "create=changes proxy=true",
			outputs: []string{"gate=fail\n", "findings=2\n", "report="},
		},
		{
			name:  "a pull request passes the policy, and vet reads it at the base",
			event: "pull_request",
			args:  []string{"--policy\n.github/vet/policy.yml"},
		},
		{
			name:    "a push scans the checkout with no comment",
			event:   "push",
			noArgs:  []string{"--base-ref", "pr-comment", "--policy"},
			comment: "create= proxy=",
			output:  "vet applies no policy file, because the checkout has no .github/vet/policy.yml",
		},
		{
			name:      "a push applies a policy directory",
			event:     "push",
			policyDir: true,
			env:       map[string]string{"ACTION_POLICY": ".github/vet"},
			args:      []string{"--policy\n.github/vet"},
		},
		{
			name:    "the inputs map to the gate and the comment options",
			event:   "pull_request",
			env:     map[string]string{"ACTION_FAIL_ON": "none", "ACTION_COMMENT": "findings", "ACTION_COMMENT_PROXY": "false"},
			noArgs:  []string{"--fail-on"},
			comment: "create=findings proxy=false",
		},
		{
			name:    "comment never posts no comment",
			event:   "pull_request",
			env:     map[string]string{"ACTION_COMMENT": "never"},
			noArgs:  []string{"pr-comment"},
			comment: "create= proxy=",
		},
		{
			name:  "the args input goes to vet as words and the shell never runs it",
			event: "push",
			env:   map[string]string{"ACTION_ARGS": "--exclude 'a b' $(touch${IFS}pwned)\n--strict"},
			args:  []string{"--exclude\n'a\nb'\n$(touch${IFS}pwned)\n--strict"},
		},
		{
			name:    "sarif writes a SARIF report for the upload step",
			event:   "push",
			env:     map[string]string{"ACTION_SARIF": "true"},
			args:    []string{"sarif="},
			outputs: []string{"sarif="},
		},
		{
			name:         "the step summary stops at 1 MiB",
			event:        "push",
			summaryBytes: 2 << 20,
		},
		{
			name:         "the script fetches the base with the token for the server only",
			event:        "pull_request",
			baseInOrigin: true,
			args:         []string{"--base-ref\nBASE"},
			fetch:        "http.https://github.com/.extraheader",
		},
		{
			name:         "the script uses the token header of the checkout",
			event:        "pull_request",
			baseInOrigin: true,
			header:       true,
			fetch:        "none",
		},
		{
			name:      "a vet error leaves the outputs empty and fails the step",
			event:     "push",
			env:       map[string]string{"FAKE_EXIT": "3"},
			exit:      3,
			noOutputs: []string{"gate=", "findings=", "report="},
		},
		{
			name:  "package-cooldown sets the window of the dependency-cooldown control",
			event: "push",
			env:   map[string]string{"ACTION_PACKAGE_COOLDOWN": "7"},
			args:  []string{"--cooldown-days\n7"},
		},
		{
			name:   "a package-cooldown that is not a count of days fails",
			event:  "push",
			env:    map[string]string{"ACTION_PACKAGE_COOLDOWN": "2d"},
			exit:   1,
			output: "The package-cooldown input is not a count of days: '2d'",
		},
		{
			name:   "a pull request reads the config at the base commit",
			event:  "pull_request",
			config: true,
			env:    map[string]string{"ACTION_CONFIG": ".github/vet/config.yml"},
			args:   []string{"--config\n"},
			noArgs: []string{"--config\n.github/vet/config.yml"},
			output: "vet reads the config .github/vet/config.yml at the base commit",
		},
		{
			name:   "a pull request with no config at the base reads no config",
			event:  "pull_request",
			env:    map[string]string{"ACTION_CONFIG": ".github/vet/config.yml"},
			noArgs: []string{"--config"},
			output: "vet reads no config file, because the base commit has no .github/vet/config.yml",
		},
		{
			name:   "a push reads the config of the checkout",
			event:  "push",
			config: true,
			env:    map[string]string{"ACTION_CONFIG": ".github/vet/config.yml"},
			args:   []string{"--config\n.github/vet/config.yml"},
		},
		{
			name:   "a push with a missing config fails",
			event:  "push",
			env:    map[string]string{"ACTION_CONFIG": ".github/vet/config.yml"},
			exit:   1,
			output: "The config input names a file that does not exist: '.github/vet/config.yml'",
		},
		{
			name:   "a comment input that is not valid fails",
			event:  "push",
			env:    map[string]string{"ACTION_COMMENT": "always"},
			exit:   1,
			output: "The comment input is not valid: 'always'",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			repo := filepath.Join(root, "repo")
			writeFile(t, filepath.Join(repo, "package.json"), "{}", 0o644)
			if tc.policy {
				writeFile(t, filepath.Join(repo, ".github/vet/policy.yml"), "version: 2\n", 0o644)
			}
			if tc.policyDir {
				writeFile(t, filepath.Join(repo, ".github/vet/a.yml"), "version: 2\n", 0o644)
			}
			if tc.config {
				writeFile(t, filepath.Join(repo, ".github/vet/config.yml"), "plugins: {}\n", 0o644)
			}
			gitIn := func(dir string, args ...string) string {
				cmd := exec.Command("git", append([]string{"-c", "user.email=t@example.com", "-c", "user.name=t"}, args...)...)
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))
				return strings.TrimSpace(string(out))
			}
			gitIn(repo, "init", "-q")
			gitIn(repo, "add", "-A")
			gitIn(repo, "commit", "-q", "-m", "base")
			base := gitIn(repo, "rev-parse", "HEAD")
			if tc.baseInOrigin {
				origin := filepath.Join(root, "origin")
				gitIn(root, "clone", "-q", repo, origin)
				gitIn(origin, "config", "uploadpack.allowAnySHA1InWant", "true")
				gitIn(origin, "commit", "-q", "--allow-empty", "-m", "new base")
				base = gitIn(origin, "rev-parse", "HEAD")
				gitIn(repo, "remote", "add", "origin", origin)
			}
			if tc.header {
				gitIn(repo, "config", "http.https://github.com/.extraheader", "AUTHORIZATION: basic eA==")
			}

			fake := filepath.Join(root, "fake")
			bin := filepath.Join(root, "bin")
			writeFile(t, filepath.Join(bin, "vet"), fakeVet, 0o755)
			writeFile(t, filepath.Join(bin, "git"), fakeGit, 0o755)
			event := filepath.Join(root, "event.json")
			writeFile(t, event, `{"pull_request": {"base": {"sha": "`+base+`"}}}`, 0o644)
			runner := filepath.Join(root, "runner")
			require.NoError(t, os.MkdirAll(fake, 0o755))
			require.NoError(t, os.MkdirAll(runner, 0o755))
			summary := filepath.Join(runner, "summary")
			outputs := filepath.Join(runner, "outputs")

			env := map[string]string{
				"PATH":                 bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"FAKE":                 fake,
				"REAL_GIT":             realGit,
				"FAKE_SUMMARY_BYTES":   fmt.Sprint(max(tc.summaryBytes, 20)),
				"ACTION_POLICY":        ".github/vet/policy.yml",
				"GITHUB_EVENT_NAME":    tc.event,
				"GITHUB_EVENT_PATH":    event,
				"GITHUB_STEP_SUMMARY":  summary,
				"GITHUB_OUTPUT":        outputs,
				"GITHUB_SERVER_URL":    "https://github.com",
				"RUNNER_TEMP":          runner,
				"GH_TOKEN":             "ghs_test",
				"GIT_CONFIG_NOSYSTEM":  "1",
				"GIT_CONFIG_GLOBAL":    filepath.Join(root, "gitconfig"),
				"GIT_TERMINAL_PROMPT":  "0",
				"ACTION_COMMENT_PROXY": "true",
			}
			for k, v := range tc.env {
				env[k] = v
			}
			script, err := filepath.Abs("scan.sh")
			require.NoError(t, err)
			out, code := run(t, repo, env, script)
			require.Equal(t, tc.exit, code, out)
			assert.Contains(t, out, tc.output)
			if tc.exit == 1 && len(tc.outputs) == 0 {
				return
			}

			argData, err := os.ReadFile(filepath.Join(fake, "args"))
			require.NoError(t, err)
			args := strings.ReplaceAll(string(argData), base, "BASE")
			for _, a := range tc.args {
				assert.Contains(t, args, a)
			}
			for _, a := range tc.noArgs {
				assert.NotContains(t, args, a)
			}
			assert.NoFileExists(t, filepath.Join(repo, "pwned"))
			if tc.comment != "" {
				got, err := os.ReadFile(filepath.Join(fake, "env"))
				require.NoError(t, err)
				assert.Equal(t, tc.comment, strings.TrimSpace(string(got)))
			}
			if tc.fetch != "" {
				got, err := os.ReadFile(filepath.Join(fake, "fetch"))
				require.NoError(t, err)
				assert.Equal(t, tc.fetch, strings.TrimSpace(string(got)))
				assert.NotContains(t, out, "ghs_test", "the log never shows the token")
			}

			outData, err := os.ReadFile(outputs)
			require.NoError(t, err)
			for _, o := range tc.outputs {
				assert.Contains(t, string(outData), o)
			}
			for _, o := range tc.noOutputs {
				assert.NotContains(t, string(outData), o)
			}

			got, err := os.ReadFile(summary)
			require.NoError(t, err)
			assert.LessOrEqual(t, len(got), 1<<20)
			if tc.summaryBytes > 1<<20 {
				assert.Contains(t, string(got), "The report is too long for the step summary")
			}
		})
	}
}

// A run line that holds an expression runs the text of the expression as
// shell. Each input goes to a script through env.
func TestRunLinesHoldNoExpression(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "action.yml"))
	require.NoError(t, err)
	var action struct {
		Runs struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"runs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &action))
	require.NotEmpty(t, action.Runs.Steps)
	for _, step := range action.Runs.Steps {
		assert.NotContains(t, step.Run, "${{", step.Name)
	}
}
