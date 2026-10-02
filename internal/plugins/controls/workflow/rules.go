package workflow

import (
	"regexp"
	"slices"
	"strings"
)

// dangerousTriggers run with a write token and the secrets of the base
// repository, also for a pull request from a fork.
var dangerousTriggers = []string{"pull_request_target", "workflow_run"}

// headRefs name the code of the pull request or of the triggering run.
var headRefs = []string{
	"github.event.pull_request.head.sha",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.repo.full_name",
	"github.event.pull_request.merge_commit_sha",
	"github.head_ref",
	"github.event.workflow_run.head_sha",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_repository.full_name",
	"refs/pull/",
}

var checkoutCommand = regexp.MustCompile(`\bgit\s+(checkout|fetch|switch|pull)\b|\bgh\s+pr\s+checkout\b`)

// untrustedFields is the list of actionlint: the fields of an event that
// the author of an issue, a comment or a pull request controls. "*" is one
// array element.
//
// Known uncovered case: an expression that passes a whole object, such as
// toJSON(github.event.pull_request), is not reported.
var untrustedFields = []string{
	"github.event.issue.title",
	"github.event.issue.body",
	"github.event.pull_request.title",
	"github.event.pull_request.body",
	"github.event.comment.body",
	"github.event.review.body",
	"github.event.review_comment.body",
	"github.event.pages.*.page_name",
	"github.event.commits.*.message",
	"github.event.commits.*.author.email",
	"github.event.commits.*.author.name",
	"github.event.head_commit.message",
	"github.event.head_commit.author.email",
	"github.event.head_commit.author.name",
	"github.event.pull_request.head.ref",
	"github.event.pull_request.head.label",
	"github.event.pull_request.head.repo.default_branch",
	"github.event.workflow_run.head_branch",
	"github.event.workflow_run.head_commit.message",
	"github.event.workflow_run.head_commit.author.email",
	"github.event.workflow_run.head_commit.author.name",
	"github.event.workflow_run.pull_requests.*.head.ref",
	"github.event.discussion.title",
	"github.event.discussion.body",
	"github.head_ref",
}

var (
	expression    = regexp.MustCompile(`\$\{\{(.*?)\}\}`)
	contextPath   = regexp.MustCompile(`(?i)\bgithub(?:\s*\.\s*[a-z0-9_-]+|\s*\[[^\]]*\])+`)
	quotedIndex   = regexp.MustCompile(`\[\s*['"]([^'"]*)['"]\s*\]`)
	numericIndex  = regexp.MustCompile(`\[[^\]]*\]`)
	spaces        = regexp.MustCompile(`\s+`)
	commitSHA     = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	imageDigest   = regexp.MustCompile(`@sha256:[0-9a-fA-F]{64}$`)
	githubScript  = "actions/github-script@"
	checkoutUsing = "actions/checkout@"
)

// normalizePath turns github.event.commits[0]['message'] into
// github.event.commits.*.message.
func normalizePath(p string) string {
	p = spaces.ReplaceAllString(p, "")
	p = quotedIndex.ReplaceAllString(p, ".$1")
	p = numericIndex.ReplaceAllString(p, ".*")
	return strings.ToLower(p)
}

func matchField(path, pattern string) bool {
	ps, qs := strings.Split(path, "."), strings.Split(pattern, ".")
	if len(ps) != len(qs) {
		return false
	}
	for i := range ps {
		if qs[i] != "*" && ps[i] != qs[i] {
			return false
		}
	}
	return true
}

// untrusted returns the untrusted fields that an expression reads.
func untrusted(expr string) []string {
	var out []string
	for _, raw := range contextPath.FindAllString(expr, -1) {
		path := normalizePath(raw)
		for _, f := range untrustedFields {
			if matchField(path, f) && !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	return out
}

func readsHead(s string) bool {
	s = strings.ToLower(spaces.ReplaceAllString(s, ""))
	for _, r := range headRefs {
		if strings.Contains(s, r) {
			return true
		}
	}
	return false
}

// pinned reports whether a uses: value names an immutable version, and
// returns the action name without the ref.
func pinned(uses string) (name string, ok bool) {
	if strings.HasPrefix(uses, "./") {
		return "", true
	}
	if image, found := strings.CutPrefix(uses, "docker://"); found {
		name, _, _ = strings.Cut(image, "@")
		if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
			name = name[:i]
		}
		return "docker://" + name, imageDigest.MatchString(image)
	}
	name, ref, found := strings.Cut(uses, "@")
	return name, found && commitSHA.MatchString(ref)
}
