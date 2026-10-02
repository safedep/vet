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

// Package gemfilelock extracts Gemfile.lock files.
// Package gemfilelock is a copy of the Scalibr Gemfile.lock extractor. The
// vet patch marks the gems of a PATH section as local: they are gems that
// the project builds from its own tree.
package gemfilelock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/lockmeta"
)

const (
	// Name is the unique name of this extractor.
	Name = "ruby/gemfilelock"
)

var (
	// Gemfile.lock spec lines follow the format "name (version)"
	nameVersionRegexp = regexp.MustCompile(`^(.*?)(?: \(([^-]*)(?:-(.*))?\))?(!)?$`)
	indentRegexp      = regexp.MustCompile(`^( +)`)
)

// Extractor extracts package info from Gemfile.lock files.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) { return &Extractor{}, nil }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired return true if the specified file is a Gemfile.lock file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return slices.Contains([]string{"Gemfile.lock", "gems.locked"}, filepath.Base(api.Path()))
}

// specInfo contains the line content and line number for a spec in the lockfile.
type specInfo struct {
	lineContent string
	lineNumber  int
}

type gemlockSection struct {
	name     string
	revision string
	specs    []specInfo
}

func parseLockfileSections(input *filesystem.ScanInput) ([]*gemlockSection, error) {
	sections := []*gemlockSection{}
	var currentSection *gemlockSection
	scanner := bufio.NewScanner(input.Reader)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("error while scanning: %w", err)
		}
		line := scanner.Text()
		if len(line) == 0 {
			// Skip empty lines.
			continue
		}
		m := indentRegexp.FindStringSubmatch(line)
		if m == nil { // No spaces at the start, this is a new section.
			if currentSection != nil {
				sections = append(sections, currentSection)
			}
			currentSection = &gemlockSection{name: line}
		} else if len(m[0]) == 4 {
			// Indented with 4 spaces: This line contains a top-level spec for the current section.
			if currentSection == nil {
				return nil, errors.New("invalid lockfile: specs entry before a section declaration")
			}
			currentSection.specs = append(currentSection.specs, specInfo{
				lineContent: strings.TrimPrefix(line, "    "),
				lineNumber:  lineNumber,
			})
		} else if strings.HasPrefix(line, "  revision: ") {
			// The commit for the given section. Always stored at an indentation level of 2.
			if currentSection == nil {
				return nil, errors.New("invalid lockfile: revision entry before a section declaration")
			}
			currentSection.revision = strings.TrimPrefix(line, "  revision: ")
		}
		// We don't store info about any other entries at the moment.
	}
	// Append the trailing section too.
	if currentSection != nil {
		sections = append(sections, currentSection)
	}
	return sections, nil
}

// Extract extracts packages from the Gemfile.lock file.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	sections, err := parseLockfileSections(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("error parsing: %w", err)
	}

	pkgs := []*extractor.Package{}
	for _, section := range sections {
		if !slices.Contains([]string{"GIT", "GEM", "PATH", "PLUGIN SOURCE"}, section.name) {
			// Not a source section.
			continue
		}
		for _, s := range section.specs {
			m := nameVersionRegexp.FindStringSubmatch(s.lineContent)
			if len(m) < 3 || m[1] == "" || m[2] == "" {
				log.Errorf("Invalid spec line: %s", s.lineContent)
				continue
			}
			name, version := m[1], m[2]
			p := &extractor.Package{
				Name:     name,
				Version:  version,
				PURLType: purl.TypeGem,
				Location: extractor.LocationFromPathAndLine(input.Path, s.lineNumber),
			}
			p.Metadata = &lockmeta.Metadata{LocalSource: section.name == "PATH"}
			if section.revision != "" {
				p.SourceCode = &extractor.SourceCodeIdentifier{
					Commit: section.revision,
				}
			}
			pkgs = append(pkgs, p)
		}
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

var _ filesystem.Extractor = Extractor{}
