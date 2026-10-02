package reputation

import (
	"regexp"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/model"
)

var separators = regexp.MustCompile(`[-_.]+`)

// homoglyphs are the character swaps that a squat uses to look like a
// name.
var homoglyphs = strings.NewReplacer("0", "o", "1", "l", "rn", "m", "vv", "w")

// squatOf returns the popular name that the package name squats, or "". A
// package with many downloads is popular itself, and a package with no
// data fails open.
func squatOf(p *model.Package) string {
	in := p.Insight
	if in == nil || in.Downloads >= popularDownloads {
		return ""
	}
	name := strings.ToLower(p.ID.QualifiedName())
	names := popular[p.ID.Ecosystem]
	if slices.Contains(names, name) {
		return ""
	}
	for _, target := range names {
		if len(target) < 4 || canonical(p.ID.Ecosystem, name) == canonical(p.ID.Ecosystem, target) {
			continue
		}
		if similar(name, target) {
			return target
		}
	}
	return ""
}

// canonical is the name that a registry treats as the same: PyPI ignores
// the case and the separators (PEP 503).
func canonical(eco model.Ecosystem, name string) string {
	if eco == model.EcosystemPyPI {
		return separators.ReplaceAllString(name, "-")
	}
	return name
}

func similar(name, target string) bool {
	if separators.ReplaceAllString(name, "") == separators.ReplaceAllString(target, "") {
		return true
	}
	if homoglyphs.Replace(name) == homoglyphs.Replace(target) {
		return true
	}
	return distance(name, target) == 1
}

// distance is the Damerau-Levenshtein distance with adjacent swaps.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range rb {
		d[0][j+1] = j + 1
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}
