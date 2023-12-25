package analyzer

import (
	specmodels "github.com/safedep/vet/gen/models"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

const lfpAnalyzerName = "LockfilePoisoningAnalyzer"

type LockfilePoisoningAnalyzerConfig struct {
	FailFast bool
}

type lockfilePoisoningAnalyzer struct {
	config LockfilePoisoningAnalyzerConfig
}

type lockfilePoisoningAnalyzerPlugin interface {
	Analyze(manifest *models.PackageManifest, handler AnalyzerEventHandler) error
}

type lockfileAnalyzerPluginBuilder = func(config *LockfilePoisoningAnalyzerConfig) lockfilePoisoningAnalyzerPlugin

var lockfilePoisoningAnalyzers = map[specmodels.Ecosystem]lockfileAnalyzerPluginBuilder{
	specmodels.Ecosystem_Npm: func(config *LockfilePoisoningAnalyzerConfig) lockfilePoisoningAnalyzerPlugin {
		return &npmLockfilePoisoningAnalyzer{
			config: *config,
		}
	},
}

func NewLockfilePoisoningAnalyzer(config LockfilePoisoningAnalyzerConfig) (Analyzer, error) {
	return &lockfilePoisoningAnalyzer{
		config: config,
	}, nil
}

func (lfp *lockfilePoisoningAnalyzer) Name() string {
	return lfpAnalyzerName
}

func (lfp *lockfilePoisoningAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	logger.Debugf("LockfilePoisoningAnalyzer: Analyzing [%s] %s",
		manifest.GetSpecEcosystem(), manifest.GetDisplayPath())

	pluginBuilder, ok := lockfilePoisoningAnalyzers[manifest.GetSpecEcosystem()]
	if !ok {
		logger.Warnf("No lockfile poisoning analyzer for ecosystem %s", manifest.Ecosystem)
		return nil
	}

	plugin := pluginBuilder(&lfp.config)
	return plugin.Analyze(manifest, handler)
}

func (lfp *lockfilePoisoningAnalyzer) Finish() error {
	return nil
}
