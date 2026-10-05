package workflow

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/model"
)

// Control ids of the commit checks. They read Package.Action, which the
// actionrefs enricher sets.
const (
	IDImpostorCommit     = "impostor-commit"
	IDPinCommentMismatch = "pin-comment-mismatch"
)

func init() {
	infos[IDImpostorCommit] = pluginInfo(IDImpostorCommit, finding.SeverityCritical,
		"Action pinned to a commit outside its repository",
		"A step pins an action to a commit that no branch and no tag of the named repository contains. GitHub serves each commit of a fork through the repository, so the commit can come from a fork that an attacker controls.")
	infos[IDPinCommentMismatch] = pluginInfo(IDPinCommentMismatch, finding.SeverityMedium,
		"Pin comment names another tag",
		"A step pins an action to a commit, and the comment names a release tag that does not point to that commit. A reviewer who reads the comment expects other code than the code that runs.")
}

// releaseTag matches a full release version, such as v4.2.0. The owner of
// an action moves a major or a minor tag, such as v4, to each new release,
// so a comment with such a tag can name an older commit.
var releaseTag = regexp.MustCompile(`^v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)

// pins checks the commit of each pinned uses: against the data of the
// actionrefs enricher. A package with no data gets no finding, because the
// diagnostic of the enricher says why. In pull request mode, a pin that the
// change does not add or change gets no finding.
func (c *Control) pins(e *emitter, m *model.Manifest) {
	for _, u := range e.doc.uses() {
		value := scalar(u.node)
		name, sha, ok := strings.Cut(value, "@")
		parts := strings.SplitN(name, "/", 3)
		if !ok || len(parts) < 2 || !github.IsCommitSHA(sha) {
			continue
		}
		repo := parts[0] + "/" + parts[1]
		id, err := model.NewPackageVersion(model.EcosystemGitHubActions, repo, sha)
		if err != nil {
			continue
		}
		p := m.Package(id)
		if p == nil || p.Action == nil || (p.Change != model.ChangeNone && !p.Change.Introduces()) {
			continue
		}
		l := line(u.node, 0)
		short := sha[:12]
		if !p.Action.Reachable {
			e.add(IDImpostorCommit, l, repo+"@"+sha, value,
				fmt.Sprintf("No branch or tag of %s contains commit %s", repo, short),
				&finding.Remediation{Summary: "Pin the action to the commit of a release tag of the repository. Find out who added this commit, and treat the workflow as compromised until you know."})
			continue
		}
		tag := commentTag(e.doc.text(l))
		if tag == "" || slices.ContainsFunc(p.Action.Tags, func(t string) bool { return sameTag(t, tag) }) {
			continue
		}
		summary := fmt.Sprintf("Pin the commit of %s, or change the comment to a tag of the pinned commit.", tag)
		if len(p.Action.Tags) > 0 {
			summary += fmt.Sprintf(" The pinned commit has the tags %s.", strings.Join(p.Action.Tags, ", "))
		}
		e.add(IDPinCommentMismatch, l, repo+"@"+sha, value,
			fmt.Sprintf("Tag %s in the comment does not point to commit %s of %s", tag, short, repo),
			&finding.Remediation{Summary: summary})
	}
}

// sameTag compares two tags with no regard to a v prefix, as in v4.2.0 and
// 4.2.0.
func sameTag(a, b string) bool { return strings.TrimPrefix(a, "v") == strings.TrimPrefix(b, "v") }

// commentTag returns the release tag that the comment of a uses: line
// names, as in "# v4.2.0", "# v4.2.0; note" or "# tag=v4.2.0", or "".
func commentTag(source string) string {
	_, comment, ok := strings.Cut(source, " #")
	if !ok {
		return ""
	}
	fields := strings.FieldsFunc(comment, func(r rune) bool { return r == ' ' || r == '\t' || r == ';' })
	if len(fields) == 0 {
		return ""
	}
	tag := strings.TrimPrefix(fields[0], "tag=")
	if !releaseTag.MatchString(tag) {
		return ""
	}
	return tag
}
