package inventory

import (
	"fmt"
	"hash/fnv"
	"strconv"
)

// ItemIdentity returns the dedup key of an item: the FNV-64a hash of
// app/kind/scope/name/config_path, in hex.
func ItemIdentity(app string, kind Kind, scope Scope, name, configPath string) string {
	return fnvHex(fmt.Sprintf("%s/%d/%d/%s/%s", app, kind, scope, name, configPath))
}

// SourceID returns the key that groups the items of one source, such as one
// config file. The hash keeps the key within the backend limit of 100
// characters for long paths.
func SourceID(app, path string) string {
	return fnvHex(app + ":" + path)
}

func fnvHex(s string) string {
	h := fnv.New64a()
	// hash.Hash.Write never returns an error.
	_, _ = h.Write([]byte(s))
	return strconv.FormatUint(h.Sum64(), 16)
}
