package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v2"
)

const (
	apiUrlEnvKey          = "VET_INSIGHTS_API_URL"
	apiKeyEnvKey          = "VET_INSIGHTS_API_KEY"
	apiKeyAlternateEnvKey = "VET_API_KEY"
	communityModeEnvKey   = "VET_COMMUNITY_MODE"

	defaultApiUrl             = "https://api.safedep.io/insights/v1"
	defaultCommunityApiUrl    = "https://api.safedep.io/insights-community/v1"
	defaultControlPlaneApiUrl = "https://api.safedep.io/control-plane/v1"
	defaultSyncApiUrl         = "https://api.safedep.io/sync/v1"

	homeRelativeConfigPath = ".safedep/vet-auth.yml"
)

type Config struct {
	ApiUrl             string `yaml:"api_url"`
	ApiKey             string `yaml:"api_key"`
	Community          bool   `yaml:"community"`
	ControlPlaneApiUrl string `yaml:"cp_api_url"`
	SyncApiUrl         string `yaml:"sync_api_url"`
}

// Global config to be used during runtime
var globalConfig *Config

func init() {
	loadConfiguration()
}

func Configure(m Config) error {
	globalConfig = &m
	return persistConfiguration()
}

func DefaultApiUrl() string {
	return defaultApiUrl
}

func DefaultCommunityApiUrl() string {
	return defaultCommunityApiUrl
}

func DefaultControlPlaneApiUrl() string {
	if (globalConfig != nil) && (globalConfig.ControlPlaneApiUrl != "") {
		return globalConfig.ControlPlaneApiUrl
	}

	return defaultControlPlaneApiUrl
}

func DefaultSyncApiUrl() string {
	if (globalConfig != nil) && (globalConfig.SyncApiUrl != "") {
		return globalConfig.SyncApiUrl
	}

	return defaultSyncApiUrl
}

func ApiUrl() string {
	if url, ok := os.LookupEnv(apiUrlEnvKey); ok {
		return url
	}

	if globalConfig != nil {
		return globalConfig.ApiUrl
	}

	if CommunityMode() {
		return defaultCommunityApiUrl
	}

	return defaultApiUrl
}

func ApiKey() string {
	if key, ok := os.LookupEnv(apiKeyEnvKey); ok {
		return key
	}

	if key, ok := os.LookupEnv(apiKeyAlternateEnvKey); ok {
		return key
	}

	if globalConfig != nil {
		return globalConfig.ApiKey
	}

	return ""
}

func CommunityMode() bool {
	bRet, err := strconv.ParseBool(os.Getenv(communityModeEnvKey))
	if (err == nil) && bRet {
		return true
	}

	if globalConfig != nil {
		return globalConfig.Community
	}

	return false
}

// Set the runtime mode to community without
// persisting it to the configuration file
func SetRuntimeCommunityMode() {
	os.Setenv(communityModeEnvKey, "true")
}

func loadConfiguration() error {
	path, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	path = filepath.Join(path, homeRelativeConfigPath)

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return fmt.Errorf("config deserialization failed: %w", err)
	}

	globalConfig = &config
	return nil
}

func persistConfiguration() error {
	data, err := yaml.Marshal(globalConfig)
	if err != nil {
		return fmt.Errorf("config serialization failed: %w", err)
	}

	path, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	path = filepath.Join(path, homeRelativeConfigPath)

	os.MkdirAll(filepath.Dir(path), os.ModePerm)
	return os.WriteFile(path, data, 0600)
}
