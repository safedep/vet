package parser

import (
	"path/filepath"
	"slices"
	"strings"
)

type TargetScopeType string

const (
	TargetScopeAll                TargetScopeType = "all"
	TargetScopeEmbeddedType       TargetScopeType = "embedded"
	TargetScopeResolveByExtension TargetScopeType = "extension"
)

// ResolveParseTarget resolves the actual path and lockfileAs
// based on the provided path and lockfileAs. It supports some
// conventions such as embedded lockfileAs in path and auto-detection
// of lockfileAs based on file extension
func ResolveParseTarget(path, lockfileAs string, scopes []TargetScopeType) (string, string, error) {
	// Always use explicitly set type
	if lockfileAs != "" {
		return path, lockfileAs, nil
	}

	// We will support the format `lockfileAs:lockfile` to allow
	// type override per lockfile. Use it when such an override
	// is available
	if resolveTargetScopeAllows(scopes, TargetScopeEmbeddedType) && strings.Contains(path, ":") {
		parts := strings.Split(path, ":")
		if len(parts) == 2 {
			lft, err := filepath.Abs(parts[1])
			if err != nil {
				return "", "", err
			}

			return lft, parts[0], nil
		}
	}

	// Try to resolve by extension
	if resolveTargetScopeAllows(scopes, TargetScopeResolveByExtension) {
		ext := strings.TrimPrefix(filepath.Ext(path), ".")
		if ext != "" {
			lft, err := FindLockFileAsByExtension(ext)
			if err == nil {
				return path, lft, nil
			}
		}
	}

	// Fallback to having parser auto-discover based on file name
	return path, "", nil

}

func resolveTargetScopeAllows(scopes []TargetScopeType, required TargetScopeType) bool {
	if slices.Contains(scopes, TargetScopeAll) {
		return true
	}

	for _, s := range scopes {
		if s == required {
			return true
		}
	}

	return false
}
