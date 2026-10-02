// Package sources picks and registers the source plugins of a scan
// target: a directory, a git repository, an image, an SBOM or a PURL.
package sources

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/github"
	"github.com/safedep/vet/v2/internal/plugins/sources/dir"
	"github.com/safedep/vet/v2/internal/plugins/sources/git"
	"github.com/safedep/vet/v2/internal/plugins/sources/image"
	"github.com/safedep/vet/v2/internal/plugins/sources/purl"
	"github.com/safedep/vet/v2/internal/plugins/sources/sbom"
	"github.com/safedep/vet/v2/plugin"
)

// CodeTarget is the usefulerror code of a target that vet cannot read.
// The command exits with code 2.
const CodeTarget = "usage_target"

// Detect returns the name of the source for a target:
//   - "pkg:..." is a PURL;
//   - "oci://..." or a .tar file is an image;
//   - an http(s), ssh or git URL, or "git@host:path", is a repository;
//   - a directory is a directory;
//   - any other file is an SBOM.
func Detect(target string) (string, error) {
	switch {
	case strings.HasPrefix(target, "pkg:"):
		return purl.Name, nil
	case strings.HasPrefix(target, image.Scheme):
		return image.Name, nil
	case isRepositoryURL(target):
		return git.Name, nil
	}
	info, err := os.Stat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return "", targetError(target, "the target does not exist",
			"Give a directory, a repository URL, oci://IMAGE, an image .tar file, an SBOM file or a PURL.")
	}
	if err != nil {
		return "", err
	}
	switch {
	case info.IsDir():
		return dir.Name, nil
	case image.IsTarball(target):
		return image.Name, nil
	}
	return sbom.Name, nil
}

func isRepositoryURL(target string) bool {
	for _, prefix := range []string{"https://", "http://", "ssh://", "git://", "git@", "file://"} {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

func targetError(target, msg, help string) error {
	m := fmt.Sprintf("%s: %s", target, msg)
	return usefulerror.NewUsefulError().WithCode(CodeTarget).WithHumanError(m).WithHelp(help).WithMsg(m)
}

// Options are what every source needs beside the target.
type Options struct {
	Tokens github.TokenProvider
}

// New returns the source for a target.
func New(target string, o Options) (plugin.Source, error) {
	name, err := Detect(target)
	if err != nil {
		return nil, err
	}
	return build(name, target, o), nil
}

func build(name, target string, o Options) plugin.Source {
	switch name {
	case purl.Name:
		return purl.New(purl.Options{Target: target})
	case image.Name:
		return image.New(image.Options{Target: target})
	case git.Name:
		return git.New(git.Options{Target: target, Tokens: o.Tokens})
	case sbom.Name:
		return sbom.New(sbom.Options{Target: target})
	}
	return dir.New(dir.Options{Target: filepath.Clean(target)})
}

// Register adds the source plugins to the registry. Each one reads the
// target from its options.
func Register(o Options) {
	for _, name := range []string{dir.Name, git.Name, image.Name, sbom.Name, purl.Name} {
		plugin.RegisterSource(name, func(cfg plugin.Config) (plugin.Source, error) {
			var opts struct {
				Target string `json:"target"`
			}
			if err := cfg.Decode(&opts); err != nil {
				return nil, err
			}
			if opts.Target == "" {
				return nil, fmt.Errorf("source %s: no target", name)
			}
			return build(name, opts.Target, o), nil
		})
	}
}
