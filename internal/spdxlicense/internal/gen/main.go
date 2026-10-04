// Command gen writes list.json, the SPDX License List data that the
// spdxlicense package embeds. It reads licenses.json from the go-spdx module
// that go.mod pins, so the flags and the ids of go-spdx come from one list.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type source struct {
	Version     string `json:"licenseListVersion"`
	ReleaseDate string `json:"releaseDate"`
	Licenses    []struct {
		ID         string `json:"licenseId"`
		Deprecated bool   `json:"isDeprecatedLicenseId"`
		OSI        bool   `json:"isOsiApproved"`
		FSF        bool   `json:"isFsfLibre"`
	} `json:"licenses"`
}

type license struct {
	ID         string `json:"id"`
	Deprecated bool   `json:"deprecated,omitempty"`
	OSI        bool   `json:"osi,omitempty"`
	FSF        bool   `json:"fsf,omitempty"`
}

type list struct {
	Version     string    `json:"version"`
	ReleaseDate string    `json:"release_date"`
	Licenses    []license `json:"licenses"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

func run() error {
	dir, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/github/go-spdx/v2").Output()
	if err != nil {
		return fmt.Errorf("find the go-spdx module: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(dir)), "cmd", "licenses.json"))
	if err != nil {
		return err
	}
	var src source
	if err := json.Unmarshal(data, &src); err != nil {
		return err
	}
	out := list{Version: src.Version, ReleaseDate: src.ReleaseDate}
	for _, l := range src.Licenses {
		out.Licenses = append(out.Licenses, license{ID: l.ID, Deprecated: l.Deprecated, OSI: l.OSI, FSF: l.FSF})
	}
	sort.Slice(out.Licenses, func(i, j int) bool { return out.Licenses[i].ID < out.Licenses[j].ID })
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile("list.json", append(b, '\n'), 0o644)
}
