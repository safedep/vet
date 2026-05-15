package reporter

import (
	"regexp"
	"sort"
)

// lfpURLRe extracts the first https URL from backtick-quotes in a lockfile poisoning message.
// Messages look like:
//
//	Package `name` resolved to an untrusted host `https://...`
//	Package `name` resolved to an URL `https://...` that does not follow...
var lfpURLRe = regexp.MustCompile("`(https?://[^`]+)`")

// lfpPkgRe extracts the package name from a lockfile poisoning message.
var lfpPkgRe = regexp.MustCompile("^Package `([^`]+)`")

// lfpGroup holds a resolved URL and the deduplicated set of affected package names.
type lfpGroup struct {
	url      string
	pkgSet   map[string]struct{}
	pkgOrder []string // insertion order for deterministic output
}

// aggregateLFPMessages groups raw lockfile poisoning messages by resolved URL.
// Multiple messages for the same (URL, package) pair — e.g. "untrusted host"
// and "path convention" — are collapsed into one entry.
func aggregateLFPMessages(msgs []string) []*lfpGroup {
	groupMap := map[string]*lfpGroup{}
	keyOrder := []string{}

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
				url:    resolvedURL,
				pkgSet: map[string]struct{}{},
			}
			keyOrder = append(keyOrder, resolvedURL)
		}

		g := groupMap[resolvedURL]
		if pkgName != "" {
			if _, seen := g.pkgSet[pkgName]; !seen {
				g.pkgSet[pkgName] = struct{}{}
				g.pkgOrder = append(g.pkgOrder, pkgName)
			}
		}
	}

	groups := make([]*lfpGroup, 0, len(keyOrder))
	for _, key := range keyOrder {
		g := groupMap[key]
		sort.Strings(g.pkgOrder)
		groups = append(groups, g)
	}

	return groups
}
