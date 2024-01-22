package utils

import (
	"path"
	"strings"
)

// Re-use from: https://github.com/google/osv-scanner/blob/main/pkg/lockfile/parse-npm-lock.go#L128
func NpmNodeModulesPackagePathToName(name string) string {
	maybeScope := path.Base(path.Dir(name))
	pkgName := path.Base(name)

	if strings.HasPrefix(maybeScope, "@") {
		pkgName = maybeScope + "/" + pkgName
	}

	return pkgName
}
