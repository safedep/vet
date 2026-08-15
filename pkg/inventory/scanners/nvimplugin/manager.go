package nvimplugin

import "context"

// Manager discovers plugins installed by one Neovim plugin manager. Adding
// a manager is one implementation plus one defaultManagers entry.
type Manager interface {
	// Name is the manager identifier recorded as plugin.manager.
	Name() string
	// Discover returns every plugin this manager installed. A manager whose
	// layout is absent returns (nil, nil), not an error.
	Discover(ctx context.Context, env Env) ([]Plugin, error)
}

// Plugin is the manager-agnostic discovery result; one Plugin becomes one
// inventory.Item.
type Plugin struct {
	Name       string // manager-local name (lock key / install dir base)
	Repository string // normalized https URL; empty when unresolvable
	Ecosystem  string // github | gitlab | bitbucket | git
	Owner      string
	Repo       string
	Commit     string // actual HEAD
	LockCommit string // pinned commit, when declared
	LockBranch string // pinned branch, when declared
	InstallDir string
	SourcePath string // declaring file (lock file); groups a config's plugins via SourceID
	Declared   bool   // present in the lock file
	Installed  bool   // present on disk
}

// defaultManagers is the shipped manager set. It is a function, not a var,
// so tests can drive the adapter with a fake manager without mutating
// shared state.
func defaultManagers() []Manager {
	return []Manager{newLazyManager()}
}
