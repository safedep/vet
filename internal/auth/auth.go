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
	apiUrlEnvKey                  = "VET_INSIGHTS_API_URL"
	apiV2UrlEnvKey                = "VET_INSIGHTS_API_V2_URL" // gitleaks:allow
	communityServicesApiUrlEnvKey = "VET_COMMUNITY_SERVICES_API_URL"
	syncUrlEnvKey                 = "VET_SYNC_API_URL"
	controlPlaneUrlEnvKey         = "VET_CONTROL_PLANE_API_URL"
	dataPlaneUrlEnvKey            = "VET_DATA_PLANE_API_URL"
	apiKeyEnvKey                  = "VET_API_KEY"
	apiKeyAlternateEnvKey         = "VET_INSIGHTS_API_KEY"
	communityModeEnvKey           = "VET_COMMUNITY_MODE"
	controlTowerTenantEnvKey      = "VET_CONTROL_TOWER_TENANT_ID"

	defaultSafeDepApiKeyEnvKey   = "SAFEDEP_API_KEY"
	defaultSafeDepTenantIdEnvKey = "SAFEDEP_TENANT_ID"

	defaultApiUrl          = "https://api.safedep.io/insights/v1"
	defaultCommunityApiUrl = "https://api.safedep.io/insights-community/v1"

	// gRPC service base URL.
	defaultDataPlaneApiUrl    = "https://api.safedep.io"
	defaultSyncApiUrl         = "https://api.safedep.io"
	defaultInsightsApiV2Url   = "https://api.safedep.io"
	defaultControlPlaneApiUrl = "https://cloud.safedep.io"

	// Community services is a new unauthenticated endpoint through
	// which we can serve the community features without authentication.
	defaultCommunityServicesApiUrl = "https://community-api.safedep.io"

	homeRelativeConfigPath = ".safedep/vet-auth.yml"

	cloudIdentityServiceClientId      = "QtXHUN3hOdbJbCiGU8FiNCnC2KtuROCu" // gitleaks:allow
	cloudIdentityServiceAudience      = "https://cloud.safedep.io"
	cloudIdentityServiceBaseUrl       = "https://auth.safedep.io"
	cloudIdentityServiceDeviceCodeUrl = "https://auth.safedep.io/oauth/device/code"
	cloudIdentityServiceTokenUrl      = "https://auth.safedep.io/oauth/token"
)

type Config struct {
	ApiUrl                    string    `yaml:"api_url"`
	ApiKey                    string    `yaml:"api_key"`
	Community                 bool      `yaml:"community"`
	DataPlaneApiUrl           string    `yaml:"data_plane_api_url"`
	ControlPlaneApiUrl        string    `yaml:"control_api_url"`
	SyncApiUrl                string    `yaml:"sync_api_url"`
	InsightsApiV2Url          string    `yaml:"insights_api_v2_url"`
	CommunityServicesApiUrl   string    `yaml:"community_services_api_url"`
	TenantDomain              string    `yaml:"tenant_domain"`
	CloudAccessToken          string    `yaml:"cloud_access_token"`
	CloudRefreshToken         string    `yaml:"cloud_refresh_token"`
	CloudAccessTokenUpdatedAt time.Time `yaml:"cloud_access_token_updated_at"`
}

// Global config to be used during runtime
var globalConfig *Config

func init() {
	_ = loadConfiguration()
}

func DefaultConfig() Config {
	return Config{
		ApiUrl:                  defaultApiUrl,
		Community:               false,
		DataPlaneApiUrl:         defaultDataPlaneApiUrl,
		ControlPlaneApiUrl:      defaultControlPlaneApiUrl,
		SyncApiUrl:              defaultSyncApiUrl,
		InsightsApiV2Url:        defaultInsightsApiV2Url,
		CommunityServicesApiUrl: defaultCommunityServicesApiUrl,
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

func DataPlaneUrl() string {
	envOverride := os.Getenv(dataPlaneUrlEnvKey)
	if envOverride != "" {
		return envOverride
	}

	if (globalConfig != nil) && (globalConfig.DataPlaneApiUrl != "") {
		return globalConfig.DataPlaneApiUrl
	}

	return defaultDataPlaneApiUrl
}

func SyncApiUrl() string {
	envOverride := os.Getenv(syncUrlEnvKey)
	if envOverride != "" {
		return envOverride
	}

	if (globalConfig != nil) && (globalConfig.SyncApiUrl != "") {
		return globalConfig.SyncApiUrl
	}

	return defaultSyncApiUrl
}

func ControlTowerUrl() string {
	envOverride := os.Getenv(controlPlaneUrlEnvKey)
	if envOverride != "" {
		return envOverride
	}

	if (globalConfig != nil) && (globalConfig.ControlPlaneApiUrl != "") {
		return globalConfig.ControlPlaneApiUrl
	}

	return defaultControlPlaneApiUrl
}

func InsightsApiV2Url() string {
	envOverride := os.Getenv(apiV2UrlEnvKey)
	if envOverride != "" {
		return envOverride
	}

	if (globalConfig != nil) && (globalConfig.InsightsApiV2Url != "") {
		return globalConfig.InsightsApiV2Url
	}

	return defaultInsightsApiV2Url
}

func CommunityServicesApiUrl() string {
	envOverride := os.Getenv(communityServicesApiUrlEnvKey)
	if envOverride != "" {
		return envOverride
	}

	if (globalConfig != nil) && (globalConfig.CommunityServicesApiUrl != "") {
		return globalConfig.CommunityServicesApiUrl
	}

	return defaultCommunityServicesApiUrl
}

func TenantDomain() string {
	if tenantFromEnv, ok := os.LookupEnv(controlTowerTenantEnvKey); ok && tenantFromEnv != "" {
		return tenantFromEnv
	}

	if tenantFromEnv, ok := os.LookupEnv(defaultSafeDepTenantIdEnvKey); ok && tenantFromEnv != "" {
		return tenantFromEnv
	}

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

	if key, ok := os.LookupEnv(defaultSafeDepApiKeyEnvKey); ok {
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

// SetRuntimeCommunityMode sets the runtime mode to community without
// persisting it to the configuration file.
func SetRuntimeCommunityMode() {
	os.Setenv(communityModeEnvKey, "true")
}

func SetRuntimeCloudTenant(domain string) {
	os.Setenv(controlTowerTenantEnvKey, domain)
}

func SetRuntimeApiKey(key string) {
	os.Setenv(apiKeyEnvKey, key)
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

	_ = os.MkdirAll(filepath.Dir(path), os.ModePerm)
	return os.WriteFile(path, data, 0o600)
}
