//go:build !windows

package endpoint

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/safedep/vet/v2/report"
)

// homeUser returns the account that owns a home directory. With
// --all-users the inventory of each home goes to its own user.
func homeUser(home string) *report.InventoryUser {
	u := &report.InventoryUser{Name: filepath.Base(home)}
	info, err := os.Stat(home)
	if err != nil {
		return u
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return u
	}
	u.UID = strconv.FormatUint(uint64(st.Uid), 10)
	if acct, err := user.LookupId(u.UID); err == nil {
		u.Name = acct.Username
	}
	return u
}
