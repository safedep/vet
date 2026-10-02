// Package git is the source of a git repository: vet clones it into a
// temporary directory and scans the clone.
package git

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the registered name of the source.
const Name = "git"

// Options configure the source.
type Options struct {
	// Target is the repository URL. A "#ref" suffix names the branch or
	// tag to clone.
	Target string `json:"target"`
	// Tokens gives the token for GitHub. Nil means no token.
	Tokens github.TokenProvider `json:"-"`
}

// Source yields the clone of one repository.
type Source struct {
	opts Options
}

// New returns the source.
func New(o Options) *Source { return &Source{opts: o} }

// Artifacts clones the repository with depth 1 and yields the clone. The
// key is "git:" and the host and path of the URL, without ".git".
func (s *Source) Artifacts(ctx context.Context) iter.Seq2[plugin.Artifact, error] {
	return func(yield func(plugin.Artifact, error) bool) {
		repoURL, ref := splitRef(s.opts.Target)
		key, err := Key(repoURL)
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		dir, err := os.MkdirTemp("", "vet-git-")
		if err != nil {
			yield(plugin.Artifact{}, err)
			return
		}
		cleanup := func() error { return os.RemoveAll(dir) }

		auth, err := s.auth(ctx, repoURL)
		if err != nil {
			yield(plugin.Artifact{}, errors.Join(err, cleanup()))
			return
		}
		cloneURL := repoURL
		if p, ok := LocalPath(repoURL); ok {
			cloneURL = p
		}
		co := &gogit.CloneOptions{URL: cloneURL, Depth: 1, Auth: auth, SingleBranch: true, Tags: gogit.NoTags}
		if ref != "" {
			co.ReferenceName = plumbing.ReferenceName(ref)
		}
		if err := clone(ctx, dir, co, ref); err != nil {
			yield(plugin.Artifact{}, errors.Join(fmt.Errorf("clone %s: %w", repoURL, err), cleanup()))
			return
		}
		yield(plugin.Artifact{
			Kind:  plugin.ArtifactDirectory,
			Root:  os.DirFS(dir),
			Path:  dir,
			Label: s.opts.Target,
			Key:   key,
			Close: cleanup,
		}, nil)
	}
}

// clone tries the ref as a branch, then as a tag.
func clone(ctx context.Context, dir string, co *gogit.CloneOptions, ref string) error {
	if ref == "" || strings.HasPrefix(ref, "refs/") {
		_, err := gogit.PlainCloneContext(ctx, dir, false, co)
		return err
	}
	var errs []error
	for _, name := range []plumbing.ReferenceName{plumbing.NewBranchReferenceName(ref), plumbing.NewTagReferenceName(ref)} {
		co.ReferenceName = name
		_, err := gogit.PlainCloneContext(ctx, dir, false, co)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
		if rmErr := removeContents(dir); rmErr != nil {
			return errors.Join(append(errs, rmErr)...)
		}
	}
	return errors.Join(errs...)
}

func removeContents(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := os.RemoveAll(dir + string(os.PathSeparator) + e.Name()); err != nil {
			return err
		}
	}
	return nil
}

// auth returns the token of the provider for a github.com HTTPS URL, and
// nil for any other URL or when there is no token.
func (s *Source) auth(ctx context.Context, repoURL string) (transport.AuthMethod, error) {
	if s.opts.Tokens == nil {
		return nil, nil
	}
	u, err := url.Parse(repoURL)
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "github.com") {
		return nil, nil
	}
	token, err := s.opts.Tokens.Token(ctx)
	if errors.Is(err, github.ErrNoToken) {
		log.Debugf("git: no GitHub token, the clone of %s is anonymous", repoURL)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &http.BasicAuth{Username: "x-access-token", Password: token}, nil
}

func splitRef(target string) (string, string) {
	repo, ref, _ := strings.Cut(target, "#")
	return repo, ref
}

// Key returns the target key of a repository URL, for example
// "git:github.com/safedep/vet".
func Key(repoURL string) (string, error) {
	if rest, ok := strings.CutPrefix(repoURL, "git@"); ok {
		host, path, found := strings.Cut(rest, ":")
		if !found {
			return "", fmt.Errorf("bad repository URL %q", repoURL)
		}
		return "git:" + strings.ToLower(host) + "/" + trimGit(path), nil
	}
	if p, ok := LocalPath(repoURL); ok {
		return "git:file:" + trimGit(filepath.ToSlash(filepath.Clean(p))), nil
	}
	u, err := url.Parse(repoURL)
	if err != nil {
		return "", fmt.Errorf("bad repository URL %q: %w", repoURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("bad repository URL %q", repoURL)
	}
	return "git:" + strings.ToLower(u.Host) + "/" + trimGit(strings.TrimPrefix(u.Path, "/")), nil
}

// LocalPath returns the path of a file:// URL. It takes a Windows path in
// both forms, file://C:\repo and file:///C:/repo, which url.Parse rejects.
func LocalPath(repoURL string) (string, bool) {
	p, ok := strings.CutPrefix(repoURL, "file://")
	if !ok {
		return "", false
	}
	if len(p) > 2 && p[0] == '/' && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), true
}

func trimGit(p string) string {
	return strings.TrimSuffix(strings.TrimSuffix(p, "/"), ".git")
}
