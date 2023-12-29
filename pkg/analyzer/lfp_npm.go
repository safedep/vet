package analyzer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

const npmRegistryTrustedUrlBase = "https://registry.npmjs.org"

type npmPackageLockPackage struct {
	Version   string `json:"version"`
	License   string `json:"license"`
	Resolved  string `json:"resolved"`
	Integrity string `json:"integrity"`
	Dev       bool   `json:"dev"`
	Optional  bool   `json:"optional"`
}

// https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
type npmPackageLock struct {
	Name            string                           `json:"name"`
	Version         string                           `json:"version"`
	LockfileVersion int                              `json:"lockfileVersion"`
	Packages        map[string]npmPackageLockPackage `json:"packages"`
}

type npmLockfilePoisoningAnalyzer struct {
	config LockfilePoisoningAnalyzerConfig
}

func (npm *npmLockfilePoisoningAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	logger.Debugf("npmLockfilePoisoningAnalyzer: Analyzing [%s] %s",
		manifest.GetSpecEcosystem(), manifest.GetDisplayPath())

	data, err := os.ReadFile(manifest.GetPath())
	if err != nil {
		return err
	}

	var lockfile npmPackageLock
	err = json.NewDecoder(bytes.NewReader(data)).Decode(&lockfile)
	if err != nil {
		return err
	}

	if lockfile.LockfileVersion < 2 {
		return fmt.Errorf("npmLockfilePoisoningAnalyzer: Unsupported lockfile version %d",
			lockfile.LockfileVersion)
	}

	logger.Debugf("npmLockfilePoisoningAnalyzer: Found %d packages in lockfile",
		len(lockfile.Packages))

	// Build a map of packages to query by name
	pkgMap := map[string]*models.Package{}
	err = readers.NewManifestModelReader(manifest).EnumPackages(func(p *models.Package) error {
		pkgMap[p.Name] = p
		return nil
	})

	if err != nil {
		return err
	}

	logger.Debugf("npmLockfilePoisoningAnalyzer: Found %d packages in manifest", len(pkgMap))

	// Poisoning can happen in the following cases:
	// 1. If the package is fetched from an untrusted host
	// 2. If the package path on filesystem does not match the URL path convention
	// 3. If a new entry is added to package-lock.json dependency list
	for path, lockfilePackage := range lockfile.Packages {
		// The root package is not a dependency, it is the application itself
		if path == "" {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Skipping root package")
			continue
		}

		if lockfilePackage.Resolved == "" {
			logger.Warnf("npmLockfilePoisoningAnalyzer: Node Module [%s] does not have a resolved URL", path)
			continue
		}

		packageName := npmNodeModulesPackagePathToName(path)
		if packageName == "" {
			logger.Warnf("npmLockfilePoisoningAnalyzer: Failed to extract package name from path %s", path)
			continue
		}

		pkg, ok := pkgMap[packageName]
		if !ok {
			logger.Warnf("npmLockfilePoisoningAnalyzer: Package [%s] not found in manifest", packageName)
			continue
		}

		trustedRegistryUrls := []string{npmRegistryTrustedUrlBase}
		trustedRegistryUrls = append(trustedRegistryUrls, npm.config.TrustedRegistryUrls...)

		logger.Debugf("npmLockfilePoisoningAnalyzer: Analyzing package [%s] with %d trusted registry URLs in config",
			packageName, len(trustedRegistryUrls))

		if !npmIsTrustedSource(lockfilePackage.Resolved, trustedRegistryUrls) {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Package [%s] resolved to an untrusted host [%s]",
				packageName, lockfilePackage.Resolved)

			message := fmt.Sprintf("Package [%s] resolved to an untrusted host [%s]",
				packageName, lockfilePackage.Resolved)

			_ = handler(&AnalyzerEvent{
				Source:   lfpAnalyzerName,
				Type:     ET_LockfilePoisoningSignal,
				Message:  message,
				Manifest: manifest,
				Package:  pkg,
				Threat: &jsonreportspec.ReportThreat{
					Id: jsonreportspec.ReportThreat_LockfilePoisoning,
					InstanceId: ThreatInstanceId(jsonreportspec.ReportThreat_LockfilePoisoning,
						jsonreportspec.ReportThreat_Manifest,
						manifest.GetDisplayPath()),
					Message:     message,
					SubjectType: jsonreportspec.ReportThreat_Manifest,
					Subject:     manifest.GetDisplayPath(),
					Confidence:  jsonreportspec.ReportThreat_Medium,
					Source:      lfpThreatSource,
					SourceId:    lfpThreatSourceId,
				},
			})
		}

		if !npmIsUrlFollowsPathConvention(lockfilePackage.Resolved, packageName) {
			logger.Debugf("npmLockfilePoisoningAnalyzer: Package [%s] resolved to an unconventional URL [%s]",
				packageName, lockfilePackage.Resolved)

			message := fmt.Sprintf("Package [%s] resolved to an URL [%s] that does not follow the "+
				"package name path convention", packageName, lockfilePackage.Resolved)

			_ = handler(&AnalyzerEvent{
				Source:   lfpAnalyzerName,
				Type:     ET_LockfilePoisoningSignal,
				Message:  message,
				Manifest: manifest,
				Package:  pkg,
				Threat: &jsonreportspec.ReportThreat{
					Id: jsonreportspec.ReportThreat_LockfilePoisoning,
					InstanceId: ThreatInstanceId(jsonreportspec.ReportThreat_LockfilePoisoning,
						jsonreportspec.ReportThreat_Manifest,
						manifest.GetDisplayPath()),
					Message:     message,
					SubjectType: jsonreportspec.ReportThreat_Manifest,
					Subject:     manifest.GetDisplayPath(),
					Confidence:  jsonreportspec.ReportThreat_Medium,
					Source:      lfpThreatSource,
					SourceId:    lfpThreatSourceId,
				},
			})
		}
	}

	return nil
}

// Analyze the artifact URL and determine if the source is trusted
func npmIsTrustedSource(sourceUrl string, trusteUrls []string) bool {
	// Go url parser cannot handle git+ssh://host:project/repo.git#commit
	if len(sourceUrl) > 10 && strings.EqualFold(sourceUrl[0:10], "git+ssh://") {
		if cIndex := strings.Index(sourceUrl[10:], ":"); cIndex != -1 {
			sourceUrl = sourceUrl[0:10+cIndex] + "/" + sourceUrl[10+cIndex+1:]
		}
	}

	parsedUrl, err := url.Parse(sourceUrl)
	if err != nil {
		logger.Errorf("npmIsTrustedSource: Failed to parse URL %s: %v",
			sourceUrl, err)
		return false
	}

	scheme := parsedUrl.Scheme
	host := parsedUrl.Hostname()
	port := parsedUrl.Port()
	path := parsedUrl.Path

	// Always true for local filesystem URLs
	if scheme == "file" || scheme == "" {
		return true
	}

	// Compare with trusted URLs
	for _, trusteUrl := range trusteUrls {
		parsedTrustedUrl, err := url.Parse(trusteUrl)
		if err != nil {
			logger.Errorf("npmIsTrustedSource: Failed to parse trusted URL %s: %v",
				trusteUrl, err)
			continue
		}

		if parsedTrustedUrl.Scheme != "" && parsedTrustedUrl.Scheme != scheme {
			continue
		}

		if !strings.EqualFold(parsedTrustedUrl.Host, host) {
			continue
		}

		if parsedTrustedUrl.Port() != "" && parsedTrustedUrl.Port() != port {
			continue
		}

		if parsedTrustedUrl.Path != "" && !strings.HasPrefix(path, parsedTrustedUrl.Path) {
			continue
		}

		return true
	}

	return false
}

// Extract the package name from the node_modules filesystem path
func npmNodeModulesPackagePathToName(path string) string {
	// Extract the package name from the node_modules filesystem path
	// Example: node_modules/express -> express
	// Example: node_modules/@angular/core -> @angular/core
	// Example: node_modules/@angular/core/node_modules/express -> express
	// Example: node_modules/@angular/core/node_modules/@angular/common -> @angular/common

	for i := len(path) - 1; i >= 0; i-- {
		if (len(path[i:]) > 13) && (path[i:i+13] == "node_modules/") {
			return path[i+13:]
		}
	}

	return ""
}

// Test if URL follows the pkg name path convention as per NPM package registry
// specification https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
func npmIsUrlFollowsPathConvention(sourceUrl string, pkg string) bool {
	// Example: https://registry.npmjs.org/express/-/express-4.17.1.tgz
	parsedUrl, err := url.Parse(sourceUrl)
	if err != nil {
		logger.Errorf("npmIsUrlFollowsPathConvention: Failed to parse URL %s: %v",
			sourceUrl, err)
		return false
	}

	path := parsedUrl.Path
	if path == "" {
		return false
	}

	if path[0] == '/' {
		path = path[1:]
	}

	scopedPackageName := strings.Split(path, "/-/")[0]
	return scopedPackageName == pkg
}
