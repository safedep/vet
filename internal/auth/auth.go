package auth

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

const (
	apiUrlEnvKey          = "VET_INSIGHTS_API_URL"
	apiKeyEnvKey          = "VET_INSIGHTS_API_KEY"
	apiKeyAlternateEnvKey = "VET_API_KEY"

	defaultApiUrl             = "https://api.safedep.io/insights/v1"
	defaultControlPlaneApiUrl = "https://api.safedep.io/control-plane/v1"

	homeRelativeConfigPath = ".safedep/vet-auth.yml"
)

type Config struct {
	ApiUrl             string `yaml:"api_url"`
	ApiKey             string `yaml:"api_key"`
	ControlPlaneApiUrl string `yaml:"cp_api_url"`
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

func DefaultControlPlaneApiUrl() string {
	if (globalConfig != nil) && (globalConfig.ControlPlaneApiUrl != "") {
		return globalConfig.ControlPlaneApiUrl
	}

	return defaultControlPlaneApiUrl
}

func ApiUrl() string {
	if url, ok := os.LookupEnv(apiUrlEnvKey); ok {
		return url
	}

	if globalConfig != nil {
		return globalConfig.ApiUrl
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

func loadConfiguration() error {
	path, err := os.UserHomeDir()
	path = filepath.Join(path, homeRelativeConfigPath)

	data, err := ioutil.ReadFile(path)
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
	path = filepath.Join(path, homeRelativeConfigPath)

	os.MkdirAll(filepath.Dir(path), os.ModePerm)
	return ioutil.WriteFile(path, data, 0600)
}
