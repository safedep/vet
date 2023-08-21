package connect

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/safedep/vet/pkg/common/logger"
	"gopkg.in/yaml.v2"
)

const (
	homeRelativeConfigPath = ".safedep/connected-apps.yml"
)

type Config struct {
	GithubAccessToken string `yaml:"github_access_token"`
}

// Global config to be used during runtime
var globalConfig *Config

func init() {
	err := loadConfiguration()
	logger.Debugf("Error while loading connected apps configuration %v", err)
}

func Configure(m Config) error {
	globalConfig = &m
	return persistConfiguration()
}

func GetConfigFile() string {
	return homeRelativeConfigPath
}

func loadConfiguration() error {
	path, err := os.UserHomeDir()
	if err != nil {
		return err
	}

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
	if err != nil {
		return err
	}

	path = filepath.Join(path, homeRelativeConfigPath)

	err = os.MkdirAll(filepath.Dir(path), os.ModePerm)
	if err != nil {
		logger.Debugf("Error while creatinng directory %s %v", filepath.Dir(path), err)
	}
	return ioutil.WriteFile(path, data, 0600)
}
