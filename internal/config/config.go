package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config is the effective configuration of one vet run.
type Config struct {
	Output  OutputConfig            `yaml:"output" json:"output"`
	Scan    ScanConfig              `yaml:"scan" json:"scan"`
	Policy  PolicyConfig            `yaml:"policy" json:"policy"`
	State   StateConfig             `yaml:"state" json:"state"`
	Cache   CacheConfig             `yaml:"cache" json:"cache"`
	Cloud   CloudConfig             `yaml:"cloud" json:"cloud"`
	GitHub  GitHubConfig            `yaml:"github" json:"github"`
	Managed ManagedConfig           `yaml:"managed" json:"managed"`
	Plugins map[string]PluginConfig `yaml:"plugins" json:"plugins"`
}

// OutputConfig sets the messaging mode and the color.
type OutputConfig struct {
	// Mode is auto, rich, plain or agent.
	Mode string `yaml:"mode" json:"mode"`
	// Color is auto, always or never.
	Color string `yaml:"color" json:"color"`
}

// ScanConfig sets what a scan reads and how it works.
type ScanConfig struct {
	IncludeDev  bool     `yaml:"include_dev" json:"include_dev"`
	Exclude     []string `yaml:"exclude" json:"exclude"`
	Concurrency int      `yaml:"concurrency" json:"concurrency"`
	// Strict turns a diagnostic into exit code 3.
	Strict bool `yaml:"strict" json:"strict"`
}

// PolicyConfig sets the gate. Both empty means report only, with no gate.
type PolicyConfig struct {
	File   string `yaml:"file" json:"file"`
	FailOn string `yaml:"fail_on" json:"fail_on"`
}

// StateConfig sets the scan state directory, continue and retention.
type StateConfig struct {
	Dir            string          `yaml:"dir" json:"dir"`
	ContinueWithin Duration        `yaml:"continue_within" json:"continue_within"`
	Retention      RetentionConfig `yaml:"retention" json:"retention"`
}

// RetentionConfig sets which scans retention deletes.
type RetentionConfig struct {
	PerTarget   int      `yaml:"per_target" json:"per_target"`
	Interrupted Duration `yaml:"interrupted" json:"interrupted"`
	MaxSize     ByteSize `yaml:"max_size" json:"max_size"`
}

// CacheConfig sets the enrichment cache.
type CacheConfig struct {
	Dir     string   `yaml:"dir" json:"dir"`
	Enabled bool     `yaml:"enabled" json:"enabled"`
	TTL     Duration `yaml:"ttl" json:"ttl"`
}

// CloudConfig sets the SafeDep profile and the service addresses.
type CloudConfig struct {
	Profile   string          `yaml:"profile" json:"profile"`
	Endpoints EndpointsConfig `yaml:"endpoints" json:"endpoints"`
}

// EndpointsConfig holds the SafeDep service addresses. Tests point them at a
// stub server.
type EndpointsConfig struct {
	API       string `yaml:"api" json:"api"`
	Community string `yaml:"community" json:"community"`
}

// GitHubConfig sets the GitHub API address. Tests point it at a stub server.
type GitHubConfig struct {
	APIURL string `yaml:"api_url" json:"api_url"`
}

// ManagedConfig holds the keys that only a managed file uses.
type ManagedConfig struct {
	// Lockdown turns off the variables and the flags for every key that the
	// managed file sets.
	Lockdown bool `yaml:"lockdown" json:"lockdown"`
}

// PluginConfig is the section of one plugin.
type PluginConfig struct {
	Enabled *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Options map[string]any `yaml:"options,omitempty" json:"options,omitempty"`
}

// PluginEnabled reports whether a plugin is on. A plugin with no section
// keeps its own default.
func (c *Config) PluginEnabled(name string, def bool) bool {
	p, ok := c.Plugins[name]
	if !ok || p.Enabled == nil {
		return def
	}
	return *p.Enabled
}

// PluginOptions returns the options of a plugin. It is never nil.
func (c *Config) PluginOptions(name string) map[string]any {
	if p, ok := c.Plugins[name]; ok && p.Options != nil {
		return p.Options
	}
	return map[string]any{}
}

// Default returns the built-in defaults. It is the only place that states a
// default value.
func Default() Config {
	return Config{
		Output: OutputConfig{Mode: "auto", Color: "auto"},
		Scan:   ScanConfig{Concurrency: 8},
		State: StateConfig{
			ContinueWithin: "24h",
			Retention:      RetentionConfig{PerTarget: 10, Interrupted: "7d", MaxSize: "2GB"},
		},
		Cache: CacheConfig{Enabled: true, TTL: "24h"},
		Cloud: CloudConfig{
			Endpoints: EndpointsConfig{
				API:       "https://api.safedep.io",
				Community: "https://community-api.safedep.io",
			},
		},
		GitHub:  GitHubConfig{APIURL: "https://api.github.com"},
		Plugins: map[string]PluginConfig{},
	}
}

// Duration is a duration as text, for example "24h" or "7d".
type Duration string

// Value parses the duration. A "d" suffix counts days.
func (d Duration) Value() (time.Duration, error) {
	s := strings.TrimSpace(string(d))
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	return v, nil
}

// ByteSize is a size as text, for example "2GB" or "500MB".
type ByteSize string

// Bytes parses the size.
func (b ByteSize) Bytes() (int64, error) {
	s := strings.ToUpper(strings.TrimSpace(string(b)))
	if s == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		mult   int64
	}{{"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}}
	for _, u := range units {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("invalid size %q", string(b))
			}
			return n * u.mult, nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid size %q", string(b))
	}
	return n, nil
}
