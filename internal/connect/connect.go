package connect

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v2"

	"github.com/safedep/vet/pkg/common/logger"
)

const (
	homeRelativeConfigPath = ".safedep/vet-connected-apps.yml"
)

type Config struct {
	GithubAccessToken string `yaml:"github_access_token"`
}

type ConfigUpdaterFn func(*Config)

var (
	globalConfig             *Config
	globalConfigUpdaterMutex sync.Mutex
)

func init() {
	err := loadConfiguration()
	if err != nil {
		logger.Debugf("Error while loading connected apps configuration: %v", err)
		globalConfig = &Config{}
	}
}

// We are not exposing the actual path, but just hint of where the connected
// app credentials may be stored so that UI packages can be transparent about it
func GetConfigFileHint() string {
	return fmt.Sprintf("~/%s", homeRelativeConfigPath)
}

func updateConfig(fn ConfigUpdaterFn) error {
	globalConfigUpdaterMutex.Lock()
	defer globalConfigUpdaterMutex.Unlock()

	fn(globalConfig)
	return persistConfiguration()
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

	err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		logger.Debugf("Error while creatinng directory %s %v", filepath.Dir(path), err)
	}

	return os.WriteFile(path, data, 0o600)
}
