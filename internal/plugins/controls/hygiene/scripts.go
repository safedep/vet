package hygiene

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/safedep/vet/v2/model"
)

// installScripts returns the packages of an npm lockfile that run install
// scripts, by name@version. npm records hasInstallScript in the lockfile.
//
// gap G4: Insights v2 has no install scripts of a version, so the control
// covers the npm lockfile only, and it cannot tell an upgrade that adds a
// script from one that keeps it.
func installScripts(m *model.Manifest) (map[string]bool, error) {
	if path.Base(m.Path) != "package-lock.json" || m.Root == nil {
		return nil, nil
	}
	data, err := fs.ReadFile(m.Root, m.Path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", m.Path, err)
	}
	var lf struct {
		Packages map[string]struct {
			Name             string `json:"name"`
			Version          string `json:"version"`
			HasInstallScript bool   `json:"hasInstallScript"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, nil
	}
	out := map[string]bool{}
	for p, e := range lf.Packages {
		if !e.HasInstallScript {
			continue
		}
		name := e.Name
		if i := strings.LastIndex(p, "node_modules/"); name == "" && i >= 0 {
			name = p[i+len("node_modules/"):]
		}
		if name == "" {
			continue
		}
		id := model.PackageID{Ecosystem: model.EcosystemNpm, Name: name, Version: e.Version}
		if scope, n, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
			id.Namespace, id.Name = scope, n
		}
		out[id.String()] = true
	}
	return out, nil
}
