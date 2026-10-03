package state

import (
	"strconv"

	"github.com/spf13/pflag"
)

// Flags are the local flags of the commands that read or write the state:
// --state-dir, --cache-dir and --ephemeral.
type Flags struct {
	StateDir  string
	CacheDir  string
	Ephemeral bool
}

// Register adds the flags to a command.
func (f *Flags) Register(fs *pflag.FlagSet) {
	fs.StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	fs.StringVar(&f.CacheDir, "cache-dir", "", "Directory of the enrichment cache")
	fs.BoolVar(&f.Ephemeral, "ephemeral", false, "Keep no state and no cache after the command exits")
}

// EphemeralFrom returns true when the flag or VET_EPHEMERAL turns on
// --ephemeral.
func (f *Flags) EphemeralFrom(lookupEnv func(string) (string, bool)) bool {
	if f.Ephemeral {
		return true
	}
	v, ok := lookupEnv(EphemeralEnv)
	if !ok {
		return false
	}
	on, err := strconv.ParseBool(v)
	return err == nil && on
}
