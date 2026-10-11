//go:build !cgo

package hiddencode

// DynamicCodeAvailable reports that this build reads configs for dynamic
// code. A build with no CGO has no tree-sitter, so it skips the check. The
// release builds have CGO.
const DynamicCodeAvailable = false

func dynamicCode(Class, string, []byte) []Signal { return nil }
