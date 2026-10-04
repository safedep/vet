package cmd

import "slices"

// allowedVerbs are the verbs that can end a leaf command path. vet uses the
// list of the safedep cli and adds diff, validate and audit. A new verb
// needs a one-line reason in the pull request. Keep the list sorted.
//
// add and remove attach or detach a catalog item. create and delete make
// or destroy a resource that the user defines.
var allowedVerbs = []string{
	"add",
	"audit",
	"create",
	"delete",
	"diff",
	"disable",
	"edit",
	"enable",
	"exec",
	"get",
	"init",
	"install",
	"list",
	"login",
	"logout",
	"open",
	"pricing",
	"remove",
	"run",
	"set",
	"show",
	"status",
	"sync",
	"token",
	"uninstall",
	"update",
	"validate",
}

// IsAllowedVerb reports whether a verb can end a leaf command path.
func IsAllowedVerb(v string) bool {
	_, found := slices.BinarySearch(allowedVerbs, v)
	return found
}
