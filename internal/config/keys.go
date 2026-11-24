package config

import (
	"reflect"
	"sort"
	"strings"
)

// keyKind is how a variable or a flag value parses for one key.
type keyKind int

const (
	kindString keyKind = iota
	kindBool
	kindInt
	kindList
)

// keyInfo describes one known leaf key, for example "scan.include_dev".
type keyInfo struct {
	Key  string
	Kind keyKind
}

// knownKeys lists the leaf keys of Config. The keys of the plugins section
// depend on the built-in plugins, so pluginSet checks them.
var knownKeys = func() map[string]keyInfo {
	out := map[string]keyInfo{}
	walkKeys(reflect.TypeFor[Config](), "", out)
	return out
}()

func walkKeys(t reflect.Type, prefix string, out map[string]keyInfo) {
	for i := range t.NumField() {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		switch f.Type.Kind() {
		case reflect.Struct:
			walkKeys(f.Type, key, out)
		case reflect.Map:
			// pluginSet checks the keys of the plugins section.
		case reflect.Bool:
			out[key] = keyInfo{key, kindBool}
		case reflect.Int:
			out[key] = keyInfo{key, kindInt}
		case reflect.Slice:
			out[key] = keyInfo{key, kindList}
		default:
			out[key] = keyInfo{key, kindString}
		}
	}
}

// Keys returns the known leaf keys, sorted.
func Keys() []string {
	out := make([]string, 0, len(knownKeys))
	for k := range knownKeys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EnvName returns the variable for a key: VET_ and the key in upper case,
// with "." and "-" changed to "_".
func EnvName(key string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return "VET_" + strings.ToUpper(r.Replace(key))
}

// hintDistance is the edit distance under which vet suggests a name for a
// misspelled one.
const hintDistance = 4

// suggestKey returns the known key closest to an unknown key, or "".
func suggestKey(key string) string {
	best, bestDist := "", hintDistance
	for k := range knownKeys {
		if d := levenshtein(key, k); d < bestDist {
			best, bestDist = k, d
		}
	}
	return best
}

func levenshtein(a, b string) int {
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}
