// Package file is the built-in policy source. It reads a policy v2 file,
// or every .yml and .yaml file of a directory in name order.
package file

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the plugin name.
const Name = "file"

// Options are the options of the source.
type Options struct {
	Path string `json:"path"`
}

// Source reads policy documents from a file or a directory of a file
// system.
type Source struct {
	fsys fs.FS
	name string
	// label names a document by its path in fsys, for the gate and the
	// errors.
	label func(name string) string
}

// New returns a source for a file or a directory on disk. A document
// keeps the path as the user wrote it.
func New(p string) *Source {
	clean := filepath.Clean(p)
	base := filepath.Base(clean)
	return NewFS(os.DirFS(filepath.Dir(clean)), base, func(name string) string {
		if name == base {
			return p
		}
		return filepath.Join(p, filepath.FromSlash(strings.TrimPrefix(name, base+"/")))
	})
}

// NewFS returns a source for the file or the directory name of fsys.
// label names a document by its path in fsys.
func NewFS(fsys fs.FS, name string, label func(name string) string) *Source {
	return &Source{fsys: fsys, name: name, label: label}
}

// Factory builds the source from its options.
func Factory(cfg plugin.Config) (plugin.PolicySource, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	if o.Path == "" {
		return nil, errors.New("file policy source: path is empty")
	}
	return New(o.Path), nil
}

// Register adds the source to the plugin registry.
func Register() { plugin.RegisterPolicySource(Name, Factory) }

// Policies reads the documents.
func (s *Source) Policies(_ context.Context) ([]plugin.PolicyDoc, error) {
	info, err := fs.Stat(s.fsys, s.name)
	if err != nil {
		return nil, notFound(s.label(s.name), err)
	}
	names := []string{s.name}
	if info.IsDir() {
		if names, err = s.policyFiles(); err != nil {
			return nil, err
		}
	}
	docs := make([]plugin.PolicyDoc, 0, len(names))
	for _, n := range names {
		b, err := fs.ReadFile(s.fsys, n)
		if err != nil {
			return nil, notFound(s.label(n), err)
		}
		docs = append(docs, plugin.PolicyDoc{Name: s.label(n), Content: b})
	}
	return docs, nil
}

// policyFiles returns the .yml and .yaml files of the directory, in name
// order.
func (s *Source) policyFiles() ([]string, error) {
	entries, err := fs.ReadDir(s.fsys, s.name)
	if err != nil {
		return nil, notFound(s.label(s.name), err)
	}
	var out []string
	for _, e := range entries {
		ext := strings.ToLower(path.Ext(e.Name()))
		if e.Type().IsRegular() && (ext == ".yml" || ext == ".yaml") {
			out = append(out, path.Join(s.name, e.Name()))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, notFound(s.label(s.name), fs.ErrNotExist)
	}
	return out, nil
}

func notFound(path string, err error) error {
	msg := fmt.Sprintf("read policy %s: %v", path, err)
	return usefulerror.NewUsefulError().
		WithCode(policy.CodeInvalid).
		WithHumanError(msg).
		WithHelp("Check the --policy flag or the policy.file key. vet policy init writes a starter file.").
		WithMsg(msg)
}

var _ plugin.PolicySource = (*Source)(nil)
