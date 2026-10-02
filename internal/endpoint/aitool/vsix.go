package aitool

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/model"
)

const vsixExtensionsFile = "extensions.json"

// editors are the editors whose extensions vet lists, keyed by name. Path
// is the extensions directory relative to the home directory.
var editors = map[string]editorInfo{
	"code":        {Path: ".vscode/extensions", Ecosystem: model.EcosystemVSCode, DisplayName: "VS Code"},
	"vscodium":    {Path: ".vscode-oss/extensions", Ecosystem: model.EcosystemOpenVSX, DisplayName: "VSCodium"},
	"cursor":      {Path: ".cursor/extensions", Ecosystem: model.EcosystemOpenVSX, DisplayName: "Cursor"},
	"windsurf":    {Path: ".windsurf/extensions", Ecosystem: model.EcosystemOpenVSX, DisplayName: "Windsurf"},
	"antigravity": {Path: ".antigravity/extensions", Ecosystem: model.EcosystemOpenVSX, DisplayName: "Antigravity"},
}

type editorInfo struct {
	Path        string
	Ecosystem   model.Ecosystem
	DisplayName string
}

// vsixManifest is the extensions.json of one editor.
type vsixManifest struct {
	Path       string
	Ecosystem  model.Ecosystem
	Extensions []vsixExtension
}

type vsixExtension struct {
	ID      string
	Version string
}

// vsixManifestReader lists the extension manifests of the installed
// editors.
type vsixManifestReader interface {
	Manifests() ([]vsixManifest, error)
}

type vsixDirs []struct {
	dir string
	eco model.Ecosystem
}

// newVSIXReader reads the extensions of each known editor under home.
func newVSIXReader(home string) vsixDirs {
	names := make([]string, 0, len(editors))
	for n := range editors {
		names = append(names, n)
	}
	sort.Strings(names)
	var out vsixDirs
	for _, n := range names {
		e := editors[n]
		out = append(out, struct {
			dir string
			eco model.Ecosystem
		}{filepath.Join(home, filepath.FromSlash(e.Path)), e.Ecosystem})
	}
	return out
}

// newVSIXReaderFromDirs reads the extensions of the given extensions
// directories. A directory must end in a known editor path.
func newVSIXReaderFromDirs(dirs []string) (vsixDirs, error) {
	var out vsixDirs
	for _, d := range dirs {
		eco, ok := ecosystemOfDir(d)
		if !ok {
			return nil, fmt.Errorf("unsupported editor path: %s", d)
		}
		out = append(out, struct {
			dir string
			eco model.Ecosystem
		}{d, eco})
	}
	return out, nil
}

func (v vsixDirs) Manifests() ([]vsixManifest, error) {
	var out []vsixManifest
	for _, d := range v {
		path := filepath.Join(d.dir, vsixExtensionsFile)
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			log.Warnf("endpoint: read %s: %v", path, err)
			continue
		}
		var list []struct {
			Identifier struct {
				ID string `json:"id"`
			} `json:"identifier"`
			Version string `json:"version"`
		}
		if err := json.Unmarshal(b, &list); err != nil {
			log.Warnf("endpoint: decode %s: %v", path, err)
			continue
		}
		m := vsixManifest{Path: path, Ecosystem: d.eco}
		for _, e := range list {
			m.Extensions = append(m.Extensions, vsixExtension{ID: e.Identifier.ID, Version: e.Version})
		}
		out = append(out, m)
	}
	return out, nil
}

// ecosystemOfDir compares the last two path parts, such as ".vscode" and
// "extensions", so the OS path separator does not matter.
func ecosystemOfDir(dir string) (model.Ecosystem, bool) {
	base, editor := filepath.Base(dir), filepath.Base(filepath.Dir(dir))
	for _, e := range editors {
		p := filepath.FromSlash(e.Path)
		if base == filepath.Base(p) && editor == filepath.Base(filepath.Dir(p)) {
			return e.Ecosystem, true
		}
	}
	return "", false
}

// editorDisplayName returns the name of the editor of an extensions parent
// directory, for example "VS Code" for ".vscode".
func editorDisplayName(editorDir string) string {
	for _, e := range editors {
		if filepath.Base(filepath.Dir(filepath.FromSlash(e.Path))) == editorDir {
			return e.DisplayName
		}
	}
	return ""
}
