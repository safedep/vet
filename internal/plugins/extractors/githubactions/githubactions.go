// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package githubactions extracts GitHub Actions workflow dependencies from
// .github/workflows/*.{yml,yaml} files.
//
// vet copies it from OSV-Scalibr v0.5.3 and adds two things (decisions
// D17). It reads the composite actions under .github/actions/, and it keeps
// the sub-path of an action such as github/codeql-action/init. The copy goes
// when the upstream pull request merges.
package githubactions

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"gopkg.in/yaml.v3"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/units"
)

const (
	// Name is the unique name of this extractor.
	Name = "github/actions"

	// defaultMaxFileSizeBytes is the default maximum file size the extractor will
	// attempt to extract. If a file is encountered that is larger than this
	// limit, the file is ignored by FileRequired.
	defaultMaxFileSizeBytes = 10 * units.MiB

	workflowsDir = ".github/workflows"
	actionsDir   = ".github/actions"
)

// commitSHARegexp matches a 40-character hexadecimal Git commit SHA.
var commitSHARegexp = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)

// Extractor extracts GitHub Actions dependencies from workflow files.
type Extractor struct {
	Stats            stats.Collector
	maxFileSizeBytes int64
}

// New returns a GitHub Actions workflow dependency extractor.
//
// For most use cases, initialize with:
// ```
// e := New(&cpb.PluginConfig{})
// ```
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxFileSize := defaultMaxFileSizeBytes
	if cfg.GetMaxFileSizeBytes() > 0 {
		maxFileSize = cfg.GetMaxFileSizeBytes()
	}
	return &Extractor{maxFileSizeBytes: maxFileSize}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired returns true if the file is a GitHub Actions workflow file,
// i.e. is located directly under a .github/workflows/ directory and has a
// .yml or .yaml extension.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := filepath.ToSlash(api.Path())
	ext := filepath.Ext(path)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	dir := filepath.ToSlash(filepath.Dir(path))
	if !isWorkflowDir(dir) && !isCompositeAction(path) {
		return false
	}

	fi, err := api.Stat()
	if err != nil {
		return false
	}
	if e.maxFileSizeBytes > 0 && fi.Size() > e.maxFileSizeBytes {
		e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultSizeLimitExceeded)
		return false
	}

	e.reportFileRequired(path, fi.Size(), stats.FileRequiredResultOK)
	return true
}

func isWorkflowDir(dir string) bool {
	return dir == workflowsDir || strings.HasSuffix(dir, "/"+workflowsDir)
}

// isCompositeAction reports an action.yml or action.yaml file under
// .github/actions/.
func isCompositeAction(path string) bool {
	base := filepath.Base(path)
	if base != "action.yml" && base != "action.yaml" {
		return false
	}
	return strings.HasPrefix(path, actionsDir+"/") || strings.Contains(path, "/"+actionsDir+"/")
}

func (e Extractor) reportFileRequired(path string, fileSizeBytes int64, result stats.FileRequiredResult) {
	if e.Stats == nil {
		return
	}
	e.Stats.AfterFileRequired(e.Name(), &stats.FileRequiredStats{
		Path:          path,
		Result:        result,
		FileSizeBytes: fileSizeBytes,
	})
}

// Extract extracts GitHub Actions dependencies from a workflow file passed
// through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := parse(input.Reader, input.Path)
	if err != nil {
		e.reportFileExtracted(input.Path, input.Info, err)
		return inventory.Inventory{}, fmt.Errorf("githubactions.parse(%q): %w", input.Path, err)
	}

	e.reportFileExtracted(input.Path, input.Info, nil)
	return inventory.Inventory{Packages: pkgs}, nil
}

func (e Extractor) reportFileExtracted(path string, fileinfo fs.FileInfo, err error) {
	if e.Stats == nil {
		return
	}
	var fileSizeBytes int64
	if fileinfo != nil {
		fileSizeBytes = fileinfo.Size()
	}
	e.Stats.AfterFileExtracted(e.Name(), &stats.FileExtractedStats{
		Path:          path,
		Result:        filesystem.ExtractorErrorToFileExtractedResult(err),
		FileSizeBytes: fileSizeBytes,
	})
}

func parse(r io.Reader, path string) ([]*extractor.Package, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		// Files inside .github/workflows/ are not always valid workflow files
		// (e.g. partial templates). Don't fail the scan.
		log.Debugf("githubactions: yaml unmarshal failed for %s: %v", path, err)
		return nil, nil
	}
	if len(root.Content) == 0 {
		return nil, nil
	}

	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, nil
	}

	// A composite action holds its steps under runs.steps.
	if runs := mappingValue(doc, "runs"); runs != nil && runs.Kind == yaml.MappingNode {
		return packagesFromJob(runs, path), nil
	}

	jobs := mappingValue(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, nil
	}

	var pkgs []*extractor.Package
	// MappingNode content alternates [key, value, key, value, ...].
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		jobNode := jobs.Content[i+1]
		if jobNode.Kind != yaml.MappingNode {
			continue
		}
		pkgs = append(pkgs, packagesFromJob(jobNode, path)...)
	}
	return pkgs, nil
}

// packagesFromJob extracts dependencies from a single job node, covering both
// reusable workflow references (jobs.<id>.uses) and step references
// (jobs.<id>.steps[].uses).
func packagesFromJob(job *yaml.Node, path string) []*extractor.Package {
	var pkgs []*extractor.Package

	if uses := mappingValue(job, "uses"); uses != nil && uses.Kind == yaml.ScalarNode {
		if pkg := packageFromUses(uses.Value, uses.Line, path); pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}

	steps := mappingValue(job, "steps")
	if steps == nil || steps.Kind != yaml.SequenceNode {
		return pkgs
	}
	for _, step := range steps.Content {
		if step.Kind != yaml.MappingNode {
			continue
		}
		uses := mappingValue(step, "uses")
		if uses == nil || uses.Kind != yaml.ScalarNode {
			continue
		}
		if pkg := packageFromUses(uses.Value, uses.Line, path); pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

// packageFromUses parses a `uses:` value and returns the corresponding Package,
// or nil if the value does not reference a versioned GitHub action / reusable
// workflow (e.g. local actions like ./action and Docker actions are skipped).
func packageFromUses(uses string, line int, path string) *extractor.Package {
	uses = strings.TrimSpace(uses)
	// Local actions (./path, ../path) live in the same repository and have
	// no independent version, so they are not GitHub Actions ecosystem deps.
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "../") {
		return nil
	}
	// Docker action references aren't GitHub Actions ecosystem packages.
	if strings.HasPrefix(uses, "docker://") {
		return nil
	}

	atIdx := strings.LastIndex(uses, "@")
	if atIdx <= 0 || atIdx == len(uses)-1 {
		return nil
	}
	repoRef, ref := uses[:atIdx], uses[atIdx+1:]

	// owner/repo[/sub/path]
	parts := strings.SplitN(repoRef, "/", 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	name := parts[0] + "/" + parts[1]

	pkg := &extractor.Package{
		Name:     name,
		Version:  ref,
		PURLType: purl.TypeGithub,
		Location: extractor.LocationFromPathAndLine(path, line),
		SourceCode: &extractor.SourceCodeIdentifier{
			Repo: "https://github.com/" + name,
		},
	}
	if len(parts) == 3 && parts[2] != "" {
		pkg.Metadata = &Metadata{ActionSubpath: strings.Trim(parts[2], "/")}
	}
	if commitSHARegexp.MatchString(ref) {
		pkg.SourceCode.Commit = ref
	}
	return pkg
}

// mappingValue returns the value node associated with key in a YAML mapping
// node, or nil if the key isn't present.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		k := node.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// Metadata records the sub-path of an action in its repository. The
// scalibr adapter reads Subpath into the PURL subpath.
type Metadata struct {
	ActionSubpath string
}

// IsProtoable marks Metadata as package metadata.
func (*Metadata) IsProtoable() {}

// Subpath returns the sub-path of the action.
func (m *Metadata) Subpath() string { return m.ActionSubpath }

var _ filesystem.Extractor = Extractor{}
