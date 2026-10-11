//go:build !cgo

package hiddencode

// dynamicCodeAvailable reports that this build parses JavaScript. A build
// with no CGO has no tree-sitter, so it skips the dynamic-code check and
// reads text assets by their start and their script tokens. The release
// builds have CGO.
const dynamicCodeAvailable = false

func dynamicCode(Class, string, []byte) []Signal { return nil }

func runsAsScript([]byte) (runs, parsed bool) { return false, false }
