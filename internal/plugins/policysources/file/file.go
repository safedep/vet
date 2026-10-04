// Package file is the built-in policy source. It reads a policy v2 file,
// or every .yml and .yaml file of a directory in name order.
package file

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
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

// Source reads policy documents from a path.
type Source struct {
	path string
}

// New returns a source for a file or a directory.
func New(path string) *Source { return &Source{path: path} }

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
	info, err := os.Stat(s.path)
	if err != nil {
		return nil, notFound(s.path, err)
	}
	paths := []string{s.path}
	if info.IsDir() {
		if paths, err = policyFiles(s.path); err != nil {
			return nil, err
		}
	}
	docs := make([]plugin.PolicyDoc, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, notFound(p, err)
		}
		docs = append(docs, plugin.PolicyDoc{Name: p, Content: b})
	}
	return docs, nil
}

func policyFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, notFound(dir, err)
	}
	var out []string
	for _, e := range entries {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if e.Type().IsRegular() && (ext == ".yml" || ext == ".yaml") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, notFound(dir, fs.ErrNotExist)
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
