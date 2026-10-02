package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Layer names where a value came from.
type Layer string

const (
	LayerDefault Layer = "default"
	LayerManaged Layer = "managed"
	LayerFile    Layer = "file"
	LayerEnv     Layer = "env"
	LayerFlag    Layer = "flag"
)

// Origin is the layer and the file or variable behind one key.
type Origin struct {
	Layer  Layer  `json:"layer"`
	Source string `json:"source,omitempty"`
}

// Origins records the origin of each key, for "vet config show --origin".
type Origins struct {
	byKey map[string]Origin
}

// Of returns the origin of a key. A key with no record is a default.
func (o *Origins) Of(key string) Origin {
	if v, ok := o.byKey[key]; ok {
		return v
	}
	return Origin{Layer: LayerDefault}
}

// Keys returns the keys that a layer above the defaults set, sorted.
func (o *Origins) Keys() []string {
	out := make([]string, 0, len(o.byKey))
	for k := range o.byKey {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (o *Origins) set(key string, origin Origin) { o.byKey[key] = origin }

// LoadOptions are the inputs of Load. The caller resolves the file paths.
type LoadOptions struct {
	// ManagedFile is the administrator's file. It applies only when it
	// exists and TrustManaged accepts it.
	ManagedFile string
	// ConfigFile is the file of --config. It must exist when it is set.
	ConfigFile string
	// UserFile is the user's config.yml. It is optional.
	UserFile string
	// Flags maps a key to the raw value of the flag that sets it.
	Flags map[string]string
	// LookupEnv reads a variable. It defaults to os.LookupEnv.
	LookupEnv func(string) (string, bool)
	// TrustManaged checks the owner of the managed file and its directories.
	// It defaults to ManagedFileTrusted.
	TrustManaged func(path string) bool
}

// Loaded is the effective config and how vet built it.
type Loaded struct {
	Config   *Config
	Origins  *Origins
	Warnings []string
	// File is the config file that applied, or "".
	File string
	// FileLayer is LayerManaged, LayerFile or "" when no file applied.
	FileLayer Layer
	// Locked holds the keys that the managed file locks.
	Locked map[string]bool
	// UnknownKeys holds the unknown keys of the file. "vet config validate"
	// reports them as errors.
	UnknownKeys []string
}

// Load builds the effective config from the defaults, one config file, the
// VET_* variables and the flags, from the lowest layer to the highest.
func Load(opts LoadOptions) (*Loaded, error) {
	if opts.LookupEnv == nil {
		opts.LookupEnv = os.LookupEnv
	}
	if opts.TrustManaged == nil {
		opts.TrustManaged = ManagedFileTrusted
	}

	tree, err := toTree(Default())
	if err != nil {
		return nil, err
	}

	l := &Loaded{Origins: &Origins{byKey: map[string]Origin{}}, Locked: map[string]bool{}}

	path, layer, err := pickFile(opts)
	if err != nil {
		return nil, err
	}
	if path != "" {
		fileTree, err := readTree(path)
		if err != nil {
			return nil, err
		}
		l.File, l.FileLayer = path, layer
		for _, key := range leaves(fileTree, "") {
			if !IsKnownKey(key) && !isSectionKey(key) {
				msg := fmt.Sprintf("%s: unknown key %s", path, key)
				if s := suggestKey(key); s != "" {
					msg += fmt.Sprintf(". Did you mean %s?", s)
				}
				l.Warnings = append(l.Warnings, msg)
				l.UnknownKeys = append(l.UnknownKeys, key)
				continue
			}
			l.Origins.set(key, Origin{Layer: layer, Source: path})
		}
		merge(tree, fileTree)

		if layer == LayerManaged && lockdown(fileTree) {
			for _, key := range leaves(fileTree, "") {
				l.Locked[key] = true
			}
		}
	}

	for _, key := range Keys() {
		name := EnvName(key)
		raw, ok := opts.LookupEnv(name)
		if !ok {
			continue
		}
		if l.Locked[key] {
			l.Warnings = append(l.Warnings, fmt.Sprintf("%s is ignored: the managed file %s locks %s", name, l.File, key))
			continue
		}
		if err := setKey(tree, key, raw); err != nil {
			return nil, invalidValue(key, raw, Origin{Layer: LayerEnv, Source: name}, err)
		}
		l.Origins.set(key, Origin{Layer: LayerEnv, Source: name})
	}

	flagKeys := make([]string, 0, len(opts.Flags))
	for k := range opts.Flags {
		flagKeys = append(flagKeys, k)
	}
	sort.Strings(flagKeys)
	for _, key := range flagKeys {
		raw := opts.Flags[key]
		if !IsKnownKey(key) {
			return nil, unknownKey(key)
		}
		if l.Locked[key] {
			return nil, lockedKey(key, l.File)
		}
		if err := setKey(tree, key, raw); err != nil {
			return nil, invalidValue(key, raw, Origin{Layer: LayerFlag}, err)
		}
		l.Origins.set(key, Origin{Layer: LayerFlag})
	}

	cfg, err := fromTree(tree)
	if err != nil {
		return nil, newError(CodeInvalid, fmt.Sprintf("invalid config: %v", err), "Run vet config validate to see the key.")
	}
	l.Config = cfg
	return l, nil
}

func pickFile(opts LoadOptions) (string, Layer, error) {
	if opts.ManagedFile != "" && fileExists(opts.ManagedFile) && opts.TrustManaged(opts.ManagedFile) {
		return opts.ManagedFile, LayerManaged, nil
	}
	if opts.ConfigFile != "" {
		if !fileExists(opts.ConfigFile) {
			return "", "", newError(CodeFileMissing,
				fmt.Sprintf("config file %s does not exist", opts.ConfigFile),
				"Check the path of --config.")
		}
		return opts.ConfigFile, LayerFile, nil
	}
	if opts.UserFile != "" && fileExists(opts.UserFile) {
		return opts.UserFile, LayerFile, nil
	}
	return "", "", nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

func readTree(path string) (map[string]any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]any{}, nil
		}
		return nil, newError(CodeFileUnreadable, fmt.Sprintf("read config file %s: %v", path, err), "Check the file mode.")
	}
	tree := map[string]any{}
	if len(bytes.TrimSpace(b)) == 0 {
		return tree, nil
	}
	if err := yaml.Unmarshal(b, &tree); err != nil {
		return nil, newError(CodeFileInvalid, fmt.Sprintf("parse config file %s: %v", path, err), "Fix the YAML syntax.")
	}
	return tree, nil
}

func lockdown(tree map[string]any) bool {
	m, ok := tree["managed"].(map[string]any)
	if !ok {
		return false
	}
	v, ok := m["lockdown"].(bool)
	return ok && v
}

// isSectionKey accepts a key that is a whole section set to an empty value,
// for example "plugins: {}".
func isSectionKey(key string) bool {
	prefix := key + "."
	for k := range knownKeys {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return key == "plugins"
}

func toTree(c Config) (map[string]any, error) {
	b, err := yaml.Marshal(c)
	if err != nil {
		return nil, err
	}
	tree := map[string]any{}
	if err := yaml.Unmarshal(b, &tree); err != nil {
		return nil, err
	}
	return tree, nil
}

func fromTree(tree map[string]any) (*Config, error) {
	b, err := yaml.Marshal(tree)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if c.Plugins == nil {
		c.Plugins = map[string]PluginConfig{}
	}
	return &c, nil
}

// leaves returns the dotted keys of the scalar and list values of a tree.
func leaves(tree map[string]any, prefix string) []string {
	var out []string
	for k, v := range tree {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok && len(sub) > 0 {
			out = append(out, leaves(sub, key)...)
			continue
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func merge(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if d, ok := dst[k].(map[string]any); ok {
				merge(d, sub)
				continue
			}
		}
		dst[k] = v
	}
}

// setKey parses a raw value for a key and sets it in the tree.
func setKey(tree map[string]any, key, raw string) error {
	v, err := parseValue(key, raw)
	if err != nil {
		return err
	}
	parts := strings.Split(key, ".")
	node := tree
	for _, p := range parts[:len(parts)-1] {
		next, ok := node[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			node[p] = next
		}
		node = next
	}
	node[parts[len(parts)-1]] = v
	return nil
}

func parseValue(key, raw string) (any, error) {
	info, known := knownKeys[key]
	if !known {
		// A plugin key takes a YAML scalar, so "14" is a number and "true" a bool.
		var v any
		if err := yaml.Unmarshal([]byte(raw), &v); err != nil || v == nil {
			return raw, nil // A value that is not a YAML scalar stays a string.
		}
		return v, nil
	}
	switch info.Kind {
	case kindBool:
		return strconv.ParseBool(strings.TrimSpace(raw))
	case kindInt:
		return strconv.Atoi(strings.TrimSpace(raw))
	case kindList:
		var out []any
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return raw, nil
	}
}
