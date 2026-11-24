package config

import (
	"fmt"
	"strings"
)

// Plugin is a built-in plugin as the config sees it. The app gives the list
// to Load, because the plugins live in packages that import this one.
type Plugin struct {
	Name        string
	Description string
	// Switch is true when plugins.<name>.enabled turns the plugin on and
	// off. A report format has no switch, because -o and --report select it.
	Switch bool
	// On is the state of a plugin with a switch and no enabled key.
	On bool
}

// pluginSet holds the plugins that the keys of a config can name.
type pluginSet struct {
	list   []Plugin
	byName map[string]Plugin
}

func newPluginSet(ps []Plugin) pluginSet {
	s := pluginSet{list: ps, byName: make(map[string]Plugin, len(ps))}
	for _, p := range ps {
		s.byName[p.Name] = p
	}
	return s
}

// splitPluginKey returns the plugin name and the field of a key of the
// plugins section: "enabled" for plugins.<name>.enabled and "options" for
// plugins.<name>.options.<option>.
func splitPluginKey(key string) (name, field string, ok bool) {
	parts := strings.Split(key, ".")
	if len(parts) < 3 || parts[0] != "plugins" || parts[1] == "" {
		return "", "", false
	}
	switch parts[2] {
	case "enabled":
		return parts[1], "enabled", len(parts) == 3
	case "options":
		return parts[1], "options", len(parts) >= 4
	}
	return "", "", false
}

// known reports whether vet reads a key of the plugins section.
func (s pluginSet) known(key string) bool {
	name, field, ok := splitPluginKey(key)
	if !ok {
		return false
	}
	p, ok := s.byName[name]
	return ok && (field == "options" || p.Switch)
}

// knownKey reports whether vet reads a key. vet reads each leaf key of
// Config and the keys of the built-in plugins.
func (s pluginSet) knownKey(key string) bool {
	_, ok := knownKeys[key]
	return ok || s.known(key)
}

// advice tells how to fix an unknown key, or returns "".
func (s pluginSet) advice(key string) string {
	name, field, ok := splitPluginKey(key)
	if !ok {
		if k := s.fieldHint(key); k != "" {
			return fmt.Sprintf("Did you mean %s?", k)
		}
		if k := suggestKey(key); k != "" {
			return fmt.Sprintf("Did you mean %s?", k)
		}
		return ""
	}
	if p, found := s.byName[name]; found && field == "enabled" && !p.Switch {
		return fmt.Sprintf("%s is a report format with no enabled key. The flags -o and --report select it.", name)
	}
	if close := s.closest(name, field, identity); close != "" {
		return fmt.Sprintf("Did you mean %s?", strings.Replace(key, "plugins."+name+".", "plugins."+close+".", 1))
	}
	return "vet config schema get lists the plugins."
}

// fieldHint returns the key of a built-in plugin with its field spelled
// right, as plugins.malware.enabled for plugins.malware.enabld, or "".
func (s pluginSet) fieldHint(key string) string {
	parts := strings.Split(key, ".")
	if len(parts) < 3 || parts[0] != "plugins" {
		return ""
	}
	p, ok := s.byName[parts[1]]
	if !ok {
		return ""
	}
	switch {
	case len(parts) == 3 && p.Switch && levenshtein(parts[2], "enabled") < hintDistance:
		parts[2] = "enabled"
	case len(parts) >= 4 && levenshtein(parts[2], "options") < hintDistance:
		parts[2] = "options"
	default:
		return ""
	}
	return strings.Join(parts, ".")
}

// closest returns the plugin whose name, in the form that form gives, is
// nearest to name and that takes the field. It returns "" when no name is
// near.
func (s pluginSet) closest(name, field string, form func(string) string) string {
	best, bestDist := "", hintDistance
	for _, p := range s.list {
		if field == "enabled" && !p.Switch {
			continue
		}
		if d := levenshtein(name, form(p.Name)); d < bestDist {
			best, bestDist = p.Name, d
		}
	}
	return best
}

func identity(s string) string { return s }

// envAdvice tells how to fix a VET_PLUGINS_* variable that names no key
// that vet reads.
func (s pluginSet) envAdvice(name string) string {
	if key, ok := pluginEnvKey(name, s.names()); ok {
		return s.advice(key)
	}
	rest := strings.TrimPrefix(name, "VET_PLUGINS_")
	plugin, option, ok := strings.Cut(rest, "_OPTIONS_")
	field := "options." + strings.ToLower(option)
	if !ok {
		plugin, ok = strings.CutSuffix(rest, "_ENABLED")
		field = "enabled"
	}
	if !ok || plugin == "" || option == "" && field != "enabled" {
		return "A plugin variable ends with _ENABLED, or with _OPTIONS_ and the option name."
	}
	best := s.closest(plugin, field, envPart)
	if best == "" {
		return "vet config schema get lists the plugins."
	}
	return fmt.Sprintf("Did you mean %s?", EnvName("plugins."+best+"."+field))
}

// envPart returns a plugin name as a variable writes it, as
// DEPENDENCY_COOLDOWN for dependency-cooldown.
func envPart(name string) string {
	return strings.TrimPrefix(EnvName("plugins."+name), "VET_PLUGINS_")
}

// names returns the plugin names, for pluginEnvKey.
func (s pluginSet) names() []string {
	out := make([]string, 0, len(s.list))
	for _, p := range s.list {
		out = append(out, p.Name)
	}
	return out
}

// switchKeys returns the enabled key of each plugin with a switch, with
// the state of the plugin when no layer sets the key.
func (s pluginSet) switchKeys() map[string]bool {
	out := map[string]bool{}
	for _, p := range s.list {
		if p.Switch {
			out["plugins."+p.Name+".enabled"] = p.On
		}
	}
	return out
}
