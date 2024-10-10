package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	apiUrlEnvKey          = "VET_INSIGHTS_API_URL"
	apiKeyEnvKey          = "VET_INSIGHTS_API_KEY"
	apiKeyAlternateEnvKey = "VET_API_KEY"
	communityModeEnvKey   = "VET_COMMUNITY_MODE"

	defaultApiUrl          = "https://api.safedep.io/insights/v1"
	defaultCommunityApiUrl = "https://api.safedep.io/insights-community/v1"

	// gRPC service base URL.
	defaultSyncApiUrl         = "https://api.safedep.io"
	defaultControlPlaneApiUrl = "https://cloud.safedep.io"

	homeRelativeConfigPath = ".safedep/vet-auth.yml"

	// https://dev-dkwn3e2k4k1fornc.us.auth0.com/.well-known/openid-configuration
	cloudIdentityServiceClientId      = "xidzYke2rDMJmNyXId2dLpNs4DLm4yZX" // gitleaks:allow
	cloudIdentityServiceAudience      = "https://cloud.safedep.io"
	cloudIdentityServiceBaseUrl       = "https://dev-dkwn3e2k4k1fornc.us.auth0.com"
	cloudIdentityServiceDeviceCodeUrl = "https://dev-dkwn3e2k4k1fornc.us.auth0.com/oauth/device/code"
	cloudIdentityServiceTokenUrl      = "https://dev-dkwn3e2k4k1fornc.us.auth0.com/oauth/token"
)

type Config struct {
	ApiUrl                    string    `yaml:"api_url"`
	ApiKey                    string    `yaml:"api_key"`
	Community                 bool      `yaml:"community"`
	ControlPlaneApiUrl        string    `yaml:"control_api_url"`
	SyncApiUrl                string    `yaml:"sync_api_url"`
	TenantDomain              string    `yaml:"tenant_domain"`
	CloudAccessToken          string    `yaml:"cloud_access_token"`
	CloudRefreshToken         string    `yaml:"cloud_refresh_token"`
	CloudAccessTokenUpdatedAt time.Time `yaml:"cloud_access_token_updated_at"`
}

// Global config to be used during runtime
var globalConfig *Config

func init() {
	loadConfiguration()
}

func DefaultConfig() Config {
	return Config{
		ApiUrl:             defaultApiUrl,
		Community:          false,
		ControlPlaneApiUrl: defaultControlPlaneApiUrl,
		SyncApiUrl:         defaultSyncApiUrl,
	}
}

func PersistApiKey(key, domain string) error {
	if globalConfig == nil {
		c := DefaultConfig()
		globalConfig = &c
	}

	if domain != "" {
		globalConfig.TenantDomain = domain
	}

	globalConfig.ApiUrl = defaultApiUrl
	globalConfig.ApiKey = key

	return persistConfiguration()
}

func PersistCloudTokens(accessToken, refreshToken, domain string) error {
	if globalConfig == nil {
		c := DefaultConfig()
		globalConfig = &c
	}

	// We are explicitly check for empty string for domain
	// because we do not want to overwrite the domain if it is
	// not provided.
	if domain != "" {
		globalConfig.TenantDomain = domain
	}

	globalConfig.CloudAccessToken = accessToken
	globalConfig.CloudRefreshToken = refreshToken
	globalConfig.CloudAccessTokenUpdatedAt = time.Now()

	return persistConfiguration()
}

func PersistTenantDomain(domain string) error {
	if globalConfig == nil {
		c := DefaultConfig()
		globalConfig = &c
	}

	globalConfig.TenantDomain = domain
	return persistConfiguration()
}

func DefaultApiUrl() string {
	return defaultApiUrl
}

func DefaultCommunityApiUrl() string {
	return defaultCommunityApiUrl
}

func CloudIdentityServiceClientId() string {
	return cloudIdentityServiceClientId
}

func CloudIdentityServiceBaseUrl() string {
	return cloudIdentityServiceBaseUrl
}

func CloudIdentityServiceDeviceCodeUrl() string {
	return cloudIdentityServiceDeviceCodeUrl
}

func CloudIdentityServiceAudience() string {
	return cloudIdentityServiceAudience
}

func CloudIdentityServiceTokenUrl() string {
	return cloudIdentityServiceTokenUrl
}

func CloudAccessToken() string {
	if globalConfig != nil {
		return globalConfig.CloudAccessToken
	}

	return ""
}

func CloudRefreshToken() string {
	if globalConfig != nil {
		return globalConfig.CloudRefreshToken
	}

	return ""
}

func SyncApiUrl() string {
	if (globalConfig != nil) && (globalConfig.SyncApiUrl != "") {
		return globalConfig.SyncApiUrl
	}

	return defaultSyncApiUrl
}

func ControlTowerUrl() string {
	if (globalConfig != nil) && (globalConfig.ControlPlaneApiUrl != "") {
		return globalConfig.ControlPlaneApiUrl
	}

	return defaultControlPlaneApiUrl
}

func TenantDomain() string {
	if globalConfig != nil {
		return globalConfig.TenantDomain
	}

	return ""
}

func ApiUrl() string {
	if url, ok := os.LookupEnv(apiUrlEnvKey); ok {
		return url
	}

	if CommunityMode() {
		return defaultCommunityApiUrl
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
