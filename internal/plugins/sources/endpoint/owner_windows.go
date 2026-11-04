//go:build windows

package endpoint

import (
	"path/filepath"

	"github.com/safedep/vet/v2/report"
)

// homeUser returns the account of a profile folder. The folder name is the
// account name. Windows has no numeric uid.
func homeUser(home string) *report.InventoryUser {
	return &report.InventoryUser{Name: filepath.Base(home)}
}
