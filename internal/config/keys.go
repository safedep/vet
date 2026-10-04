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

// knownKeys lists the leaf keys of Config, sorted. The plugins section is
// open: "plugins.<name>.enabled" and "plugins.<name>.options.<option>".
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
			// The plugins section is open.
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

// isPluginKey reports whether a key is in the open plugins section.
func isPluginKey(key string) bool {
	parts := strings.Split(key, ".")
	if len(parts) < 3 || parts[0] != "plugins" || parts[1] == "" {
		return false
	}
	switch parts[2] {
	case "enabled":
		return len(parts) == 3
	case "options":
		return len(parts) >= 4
	}
	return false
}

// IsKnownKey reports whether a key is a known leaf key or a plugin key.
func IsKnownKey(key string) bool {
	_, ok := knownKeys[key]
	return ok || isPluginKey(key)
}

// EnvName returns the variable for a key: VET_ and the key in upper case,
// with "." and "-" changed to "_".
func EnvName(key string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return "VET_" + strings.ToUpper(r.Replace(key))
}

// suggestKey returns the known key closest to an unknown key, or "".
func suggestKey(key string) string {
	best, bestDist := "", 4
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
