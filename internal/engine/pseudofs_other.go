//go:build !linux

package engine

// pseudoFS reports a directory on a pseudo file system. Only Linux mounts
// them inside the tree, so other systems have none.
func pseudoFS(string) bool { return false }
