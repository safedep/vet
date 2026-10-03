package state

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/safedep/dry/localdb"
	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/config/appdir"
)

// Error codes of the state directories. Each one exits with code 2.
const (
	CodeDirUnwritable = "state_dir_unwritable"
	CodeDirNetworkFS  = "state_dir_network_fs"
)

// EphemeralEnv turns on --ephemeral. It has no config key.
const EphemeralEnv = "VET_EPHEMERAL"

// DirRequest holds the inputs of PrepareDirs.
type DirRequest struct {
	// Dirs are the resolved directories with the origin of each one.
	Dirs appdir.Dirs
	// Ephemeral is --ephemeral or VET_EPHEMERAL.
	Ephemeral bool
	// CheckFS rejects a network file system. It defaults to
	// localdb.CheckLocalFilesystem.
	CheckFS func(dir string) error
}

// Dirs are the state and cache directories of one run.
type Dirs struct {
	State, Cache string
	// Ephemeral reports that the directories are temporary. Close removes
	// them.
	Ephemeral bool
	// Warning tells why vet runs ephemeral when the user did not ask.
	Warning string
	tmp     string
}

// Close removes the temporary directories of an ephemeral run.
func (d *Dirs) Close() error {
	if d.tmp == "" {
		return nil
	}
	return os.RemoveAll(d.tmp)
}

// PrepareDirs creates and checks the state and cache directories, with the
// rules of the scan state design, section 5.3. A default directory that
// fails gives an ephemeral run with a warning. A directory that the user set
// and that fails is an error.
func PrepareDirs(r DirRequest) (*Dirs, error) {
	if r.CheckFS == nil {
		r.CheckFS = localdb.CheckLocalFilesystem
	}
	if r.Ephemeral {
		return ephemeralDirs("")
	}
	for _, k := range []appdir.Kind{appdir.State, appdir.Cache} {
		dir, origin := r.Dirs.Get(k), r.Dirs.Origin[k]
		err := checkDir(dir, r.CheckFS)
		if err == nil {
			continue
		}
		if origin == "default" && !errors.Is(err, errNetworkFS) {
			return ephemeralDirs(fmt.Sprintf("vet cannot write to the %s directory %s. vet runs with temporary state.", k, dir))
		}
		return nil, dirError(k, dir, origin, err)
	}
	return &Dirs{State: r.Dirs.State, Cache: r.Dirs.Cache}, nil
}

var errNetworkFS = errors.New("network file system")

func checkDir(dir string, checkFS func(string) error) error {
	if err := appdir.Ensure(dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".vet-write-*")
	if err != nil {
		return err
	}
	if err := errors.Join(f.Close(), os.Remove(f.Name())); err != nil {
		return err
	}
	if err := checkFS(dir); err != nil {
		return fmt.Errorf("%w: %w", errNetworkFS, err)
	}
	return nil
}

// CheckDir reports whether vet can keep its state in a directory. vet
// doctor runs it on the state and cache directories.
func CheckDir(dir string) error {
	return checkDir(dir, localdb.CheckLocalFilesystem)
}

func ephemeralDirs(warning string) (*Dirs, error) {
	tmp, err := os.MkdirTemp("", "vet-ephemeral-")
	if err != nil {
		return nil, fmt.Errorf("create the temporary state directory: %w", err)
	}
	return &Dirs{
		State: filepath.Join(tmp, "state"), Cache: filepath.Join(tmp, "cache"),
		Ephemeral: true, Warning: warning, tmp: tmp,
	}, nil
}

func dirError(k appdir.Kind, dir, origin string, cause error) error {
	code, help := CodeDirUnwritable, fmt.Sprintf("Set another directory with --%s-dir, or run with --ephemeral.", k)
	msg := fmt.Sprintf("vet cannot write to the %s directory %s (from %s): %v", k, dir, origin, cause)
	if errors.Is(cause, errNetworkFS) {
		code = CodeDirNetworkFS
		msg = fmt.Sprintf("the %s directory %s is on a network file system. SQLite is not safe there: %v", k, dir, cause)
		help = fmt.Sprintf("Set a local directory with --%s-dir, or run with --ephemeral.", k)
	}
	return usefulerror.NewUsefulError().WithCode(code).WithHumanError(msg).WithHelp(help).WithMsg(msg)
}
