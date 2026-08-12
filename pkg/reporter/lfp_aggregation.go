package reporter

import (
	"regexp"
)

// lfpURLRe extracts the resolved URL from backtick-quotes in a lockfile poisoning message.
// Messages look like:
//
//	Package `name` resolved to an untrusted host `https://...`
//	Package `name` resolved to an untrusted host `git+ssh://...`
//
// The scheme is intentionally generic (not just http/https) because npm lockfiles
// can resolve packages to git+ssh, git+https, git, ssh, etc. Restricting this to
// http(s) caused such findings to be silently dropped, producing an empty
// "Lockfile Poisoning Detected" section. The package name is the first backtick
// group and does not contain "://", so the URL group is matched unambiguously.
var lfpURLRe = regexp.MustCompile("`([a-zA-Z][a-zA-Z0-9+.-]*://[^`]+)`")

// Package `name` resolved to an URL `https://...` that does not follow...
var lfpPackageNameConventionRe = regexp.MustCompile("package name path convention")

// lfpPkgRe extracts the package name from a lockfile poisoning message.
var lfpPkgRe = regexp.MustCompile("^Package `([^`]+)`")

// lfpGroup holds a resolved URL and the deduplicated set of affected package names.
type lfpGroup struct {
	url                         string
	doesNotFollowPathConvention bool
	pkgSet                      map[string]struct{}
	pkgOrder                    []string // insertion order for deterministic output
}

// aggregateLFPMessages groups raw lockfile poisoning messages by resolved URL.
// Multiple messages for the same (URL, package) pair — e.g. "untrusted host"
// and "path convention" — are collapsed into one entry.
func aggregateLFPMessages(msgs []string) []*lfpGroup {
	groupMap := map[string]*lfpGroup{}

	for _, msg := range msgs {
		urlM := lfpURLRe.FindStringSubmatch(msg)
		if len(urlM) < 2 {
			continue
		}
		resolvedURL := urlM[1]

		pkgM := lfpPkgRe.FindStringSubmatch(msg)
		pkgName := ""
		if len(pkgM) >= 2 {
			pkgName = pkgM[1]
		}

		if _, ok := groupMap[resolvedURL]; !ok {
			groupMap[resolvedURL] = &lfpGroup{
				url:                         resolvedURL,
				pkgSet:                      map[string]struct{}{},
				doesNotFollowPathConvention: lfpPackageNameConventionRe.MatchString(msg),
			}
		}

		g := groupMap[resolvedURL]
		g.doesNotFollowPathConvention = g.doesNotFollowPathConvention || lfpPackageNameConventionRe.MatchString(msg)
		if pkgName != "" {
			if _, seen := g.pkgSet[pkgName]; !seen {
				g.pkgSet[pkgName] = struct{}{}
				g.pkgOrder = append(g.pkgOrder, pkgName)
			}
		}
	}

	groups := make([]*lfpGroup, 0, len(groupMap))
	for _, g := range groupMap {
		groups = append(groups, g)
	}

	return groups
}
