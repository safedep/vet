package nvimplugin

import (
	"encoding/json"
	"os"
)

// lockEntry is one plugin's pinned state in lazy-lock.json. The lock file
// records only commit and branch, not the repository (the key is the
// plugin display name, not owner/repo).
type lockEntry struct {
	Commit string `json:"commit"`
	Branch string `json:"branch"`
}

// readLockfile parses lazy-lock.json, keyed by plugin display name. A
// missing file returns (nil, nil) — an unsynced config is not an error. A
// malformed file returns an error so the caller can record it while still
// emitting installed clones as undeclared.
func readLockfile(path string) (map[string]lockEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var lock map[string]lockEntry
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, err
	}
	return lock, nil
}
