//go:build !linux

package engine

// pseudoMounts returns the mount points of the pseudo file systems. Only
// Linux mounts them inside the tree, so other systems have none.
func pseudoMounts() map[string]bool { return nil }
